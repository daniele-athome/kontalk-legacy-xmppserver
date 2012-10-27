#!/usr/bin/env python

from twisted.internet import reactor, defer
from twisted.words.xish import domish
from twisted.words.protocols.jabber import xmlstream, sasl, sasl_mechanisms, jid
from twisted.words.protocols.jabber.client import CheckVersionInitializer, BindInitializer
from zope.interface import implements
from wokkel import xmppim

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

    def __init__(self, token):
        xmlstream.ConnectAuthenticator.__init__(self, 'kontalk.net')
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
            (BindInitializer, False)
        ]

        for initClass, required in inits:
            init = initClass(xs)
            init.required = required
            xs.initializers.append(init)


class Client(object):
    def __init__(self, token):
        a = KontalkXMPPAuthenticator(token)
        f = xmlstream.XmlStreamFactory(a)
        f.addBootstrap(xmlstream.STREAM_CONNECTED_EVENT, self.connected)
        f.addBootstrap(xmlstream.STREAM_END_EVENT, self.disconnected)
        f.addBootstrap(xmlstream.STREAM_AUTHD_EVENT, self.authenticated)
        f.addBootstrap(xmlstream.INIT_FAILED_EVENT, self.init_failed)
        reactor.connectTCP('localhost', 5222, f)

    def connected(self, xs):
        print 'Connected.'

        self.xmlstream = xs

        def logDataIn(buf):
            print "RECV: %r" % buf

        def logDataOut(buf):
            print "SEND: %r" % buf

        # Log all traffic
        xs.rawDataInFn = logDataIn
        xs.rawDataOutFn = logDataOut


    def disconnected(self, xs):
        print 'Disconnected.'

        reactor.stop()


    def authenticated(self, xs):
        print "Authenticated."

        presence = xmppim.Presence()
        xs.send(presence)
        jid = xs.authenticator.jid
        message = domish.Element((None, 'message'))
        message['to'] = jid.full()
        message.addElement('body', content='test message')
        xs.send(message)

        #reactor.callLater(5, xs.sendFooter)


    def init_failed(self, failure):
        print "Initialization failed."
        print failure

        self.xmlstream.sendFooter()


fp = open('auth.token', 'r')
token = fp.read()
fp.close()

c = Client(token)

reactor.run()
