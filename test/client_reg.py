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


class RegistrationInitializer(xmlstream.BaseFeatureInitiatingInitializer):
    feature = ('http://jabber.org/features/iq-register', 'register')

    def start(self):
        """
        Start SASL authentication exchange.
        """

        self.xmlstream.addObserver("/iq[@type='result']/query[xmlns='%s']" % (xmlstream2.NS_IQ_REGISTER), self.onRequestData)

    def onRequestData(self, stanza):
        print "on request data: %r" % (stanza.toXml(), )


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
            (RegistrationInitializer, True),
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
    logTrafficIn = True

    def __init__(self, network, token, peer=None):
        a = xmlstream.ConnectAuthenticator(network)
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

        def testRegisterRequest():
            reg = client.IQ(xs, 'get')
            reg.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))
            reg.send(self.network)

        def testRegister():
            reg = client.IQ(xs, 'set')
            query = reg.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))
            form = query.addElement(('jabber:x:data', 'x'))
            form['type'] = 'submit'

            hidden = form.addElement((None, 'field'))
            hidden['type'] = 'hidden'
            hidden['var'] = 'FORM_TYPE'
            hidden.addElement((None, 'value'), content=xmlstream2.NS_IQ_REGISTER)

            phone = form.addElement((None, 'field'))
            phone['type'] = 'text-single'
            phone['label'] = 'Phone number'
            phone['var'] = 'phone'
            phone.addElement((None, 'value'), content='+39123456')

            reg.send(self.network)

        def testValidate():
            reg = client.IQ(xs, 'set')
            query = reg.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))
            form = query.addElement(('jabber:x:data', 'x'))
            form['type'] = 'submit'

            hidden = form.addElement((None, 'field'))
            hidden['type'] = 'hidden'
            hidden['var'] = 'FORM_TYPE'
            hidden.addElement((None, 'value'), content='http://kontalk.org/protocol/register#code')

            code = form.addElement((None, 'field'))
            code['type'] = 'text-single'
            code['label'] = 'Validation code'
            code['var'] = 'code'
            code.addElement((None, 'value'), content='726321')

            reg.send(self.network)

            reactor.callLater(1, xs.reset)


        #reactor.callLater(1, testProbe)
        #reactor.callLater(1, testSubscribe)
        #reactor.callLater(1, testMessage)
        #reactor.callLater(1, testRoster)
        reactor.callLater(1, testRegisterRequest)
        reactor.callLater(2, testRegister)
        #reactor.callLater(3, testValidate)
        reactor.callLater(30, xs.sendFooter)

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
