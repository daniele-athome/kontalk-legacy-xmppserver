#!/usr/bin/env python


from twisted.internet import reactor, defer
from twisted.internet.task import LoopingCall
from twisted.words.protocols.jabber import xmlstream, sasl, sasl_mechanisms, jid, client
from twisted.words.protocols.jabber.client import CheckVersionInitializer, BindInitializer,\
    SessionInitializer
from twisted.words.xish import domish

from wokkel import xmppim

from zope.interface import implements

# pyme
from pyme import core
from pyme.constants.sig import mode

import sys, base64

from kontalk.xmppserver import util, xmlstream2


class KontalkTokenMechanism(object):
    """Implements the Kontalk token SASL authentication mechanism."""
    implements(sasl_mechanisms.ISASLMechanism)

    name = 'KONTALK-TOKEN'

    def __init__(self, token=None):
        self.token = token

    def getInitialResponse(self):
        return self.token.encode('utf-8')


class KontalkSASLInitiatingInitializer(xmlstream.BaseFeatureInitiatingInitializer):
    """Stream initializer that performs SASL authentication (only Kontalk)."""

    feature = (sasl.NS_XMPP_SASL, 'mechanisms')
    _deferred = None

    def setMechanism(self):
        """
        Select and setup authentication mechanism.
        """

        token = self.xmlstream.authenticator.token

        mechanisms = sasl.get_mechanisms(self.xmlstream)
        if token is not None and 'KONTALK-TOKEN' in mechanisms:
            self.mechanism = KontalkTokenMechanism(token)
        else:
            raise sasl.SASLNoAcceptableMechanism()

    def start(self):
        """
        Start SASL authentication exchange.
        """

        self.setMechanism()
        self._deferred = defer.Deferred()
        self.xmlstream.addOnetimeObserver('/success', self.onSuccess)
        self.xmlstream.addOnetimeObserver('/failure', self.onFailure)
        self.sendAuth(self.mechanism.getInitialResponse())
        return self._deferred

    def sendAuth(self, data=None):
        """
        Initiate authentication protocol exchange.

        If an initial client response is given in C{data}, it will be
        sent along.

        @param data: initial client response.
        @type data: L{str} or L{None}.
        """

        auth = domish.Element((sasl.NS_XMPP_SASL, 'auth'))
        auth['mechanism'] = self.mechanism.name
        if data is not None:
            # token is already base64
            auth.addContent(data)
        self.xmlstream.send(auth)

    def onSuccess(self, success):
        self.xmlstream.removeObserver('/failure', self.onFailure)
        self.xmlstream.reset()
        self.xmlstream.sendHeader()
        self._deferred.callback(xmlstream.Reset)

    def onFailure(self, failure):
        self.xmlstream.removeObserver('/success', self.onSuccess)
        try:
            condition = failure.firstChildElement().name
        except AttributeError:
            condition = None
        self._deferred.errback(sasl.SASLAuthError(condition))


class KontalkXMPPAuthenticator(xmlstream.ConnectAuthenticator):
    namespace = 'jabber:client'

    def __init__(self, network, token):
        xmlstream.ConnectAuthenticator.__init__(self, network)
        self.token = token
        # this is for making twisted bits not complaining
        self.jid = jid.JID('anon@example.com')


    def associateWithStream(self, xs):
        """
        Register with the XML stream.

        Populates stream's list of initializers, along with their
        requiredness. This list is used by
        L{ConnectAuthenticator.initializeStream} to perform the initalization
        steps.
        """
        xmlstream.ConnectAuthenticator.associateWithStream(self, xs)

        xs.initializers = [CheckVersionInitializer(xs)]
        inits = [
            (KontalkSASLInitiatingInitializer, True),
            (BindInitializer, True),
            (SessionInitializer, True),
        ]

        for initClass, required in inits:
            init = initClass(xs)
            init.required = required
            xs.initializers.append(init)


class Client(object):
    logTrafficOut = True
    logTrafficIn = False

    def __init__(self, network, token, peer=None):
        a = KontalkXMPPAuthenticator(network, token)
        f = xmlstream.XmlStreamFactory(a)
        f.addBootstrap(xmlstream.STREAM_CONNECTED_EVENT, self.connected)
        f.addBootstrap(xmlstream.STREAM_END_EVENT, self.disconnected)
        f.addBootstrap(xmlstream.STREAM_AUTHD_EVENT, self.authenticated)
        f.addBootstrap(xmlstream.INIT_FAILED_EVENT, self.init_failed)
        reactor.connectTCP('localhost', 5222, f)
        self.network = network
        self.peer = peer

    def connected(self, xs):
        print 'Connected.'

        self.xmlstream = xs

        if self.logTrafficIn:
            def logDataIn(buf):
                print "RECV: %s" % unicode(buf, 'utf-8').encode('utf-8')
            xs.rawDataInFn = logDataIn

        if self.logTrafficOut:
            def logDataOut(buf):
                print "SEND: %s" % unicode(buf, 'utf-8').encode('utf-8')
            xs.rawDataOutFn = logDataOut


    def disconnected(self, xs):
        print 'Disconnected.'

        reactor.stop()


    def authenticated(self, xs):
        print "Authenticated."
        xs.addObserver('/*', self.stanza, xs=xs)
        xs.addObserver('/message', self.message, xs=xs)

        presence = xmppim.AvailablePresence(statuses={None: 'status message'})
        xs.send(presence)

        ver = client.IQ(xs, 'get')
        ver.addElement((xmlstream2.NS_IQ_VERSION, 'query'))
        ver.send(self.network)

        def testProbe():
            if self.peer is not None:
                userid, resource = util.split_userid(self.peer)
                presence = xmppim.Presence(jid.JID(tuple=(userid, self.network, resource)), 'probe')
                xs.send(presence)

        def testRoster():
            if self.peer is not None:
                _jid = util.userid_to_jid(self.peer, self.network)
                r = domish.Element((None, 'iq'))
                r['type'] = 'get'
                r['id'] = util.rand_str(8)
                q = r.addElement((xmppim.NS_ROSTER, 'query'))
                item = q.addElement((None, 'item'))
                item['jid'] = _jid.userhost()
                xs.send(r)

        def testSubscribe():
            # subscription request
            self.index = 0
            if self.peer is not None:
                userid, resource = util.split_userid(self.peer)
                presence = xmppim.Presence(jid.JID(tuple=(userid, self.network, None)), 'subscribe')
                xs.send(presence)
            else:
                def pres():
                    self.index += 1
                    presence = xmppim.AvailablePresence(statuses={None: 'status message (%d)' % (self.index, )})
                    xs.send(presence)

                LoopingCall(pres).start(2, False)

        def testMessage():
            jid = xs.authenticator.jid
            message = domish.Element((None, 'message'))
            message['id'] = 'kontalk' + util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
            message['type'] = 'chat'
            if self.peer:
                message['to'] = util.userid_to_jid(self.peer, self.network).full()
            else:
                message['to'] = jid.userhost()
            message.addElement((None, 'body'), content='test message')
            message.addElement(('urn:xmpp:server-receipts', 'request'))
            xs.send(message)
            #xs.sendFooter()

        #reactor.callLater(1, testProbe)
        #reactor.callLater(1, testSubscribe)
        reactor.callLater(1, testMessage)
        #reactor.callLater(1, testRoster)
        reactor.callLater(30, xs.sendFooter)

    def message(self, stanza, xs):
        print "message from %s" % (stanza['from'], )
        if stanza.type == 'chat' and stanza.request and stanza.request.uri == 'urn:xmpp:server-receipts':
            def sendReceipt(stanza):
                receipt = domish.Element((None, 'message'))
                receipt['to'] = stanza['from']
                child = receipt.addElement(('urn:xmpp:server-receipts', 'received'))
                child['id'] = stanza.request['id']
                xs.send(receipt)
            reactor.callLater(5, sendReceipt, stanza)

    def stanza(self, stanza, xs):
        print 'STANZA: %r' % (stanza.toXml().encode('utf-8'), )

    def init_failed(self, failure):
        print "Initialization failed."
        print failure

        self.xmlstream.sendFooter()


def user_token(userid, fp):
    '''Generates a user token.'''

    '''
    token is made up of the hashed phone number (the user id)
    plus the resource (in one big string, 40+8 characters),
    and the fingerprint of the server he registered to
    '''
    string = '%s|%s' % (userid, fp)
    plain = core.Data(string)
    cipher = core.Data()
    ctx = core.Context()
    ctx.set_armor(0)

    # signing key
    ctx.signers_add(ctx.get_key(fp, True))

    ctx.op_sign(plain, cipher, mode.NORMAL)
    cipher.seek(0, 0)
    token = cipher.read()
    return base64.b64encode(token)


FINGERPRINT = '37D0E678CDD19FB9B182B3804C9539B401F8229C'

token = user_token(sys.argv[1], FINGERPRINT)
c = Client('kontalk.net', token, sys.argv[2] if len(sys.argv) > 2 else None)

reactor.run()
