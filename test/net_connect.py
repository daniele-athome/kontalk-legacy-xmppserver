#!/usr/bin/env python

from twisted.internet import reactor

from twisted.words.xish import domish
from twisted.words.protocols.jabber import xmlstream

from wokkel import server

from kontalk.xmppserver.component import net

class NetConnector(object):
    def __init__(self, host, port):
        authenticator = net.XMPPNetConnectAuthenticator('beta.kontalk.net', 'prime.kontalk.net')
        factory = server.DeferredS2SClientFactory(authenticator)
        factory.addBootstrap(xmlstream.STREAM_CONNECTED_EVENT, self.connected)
        factory.addBootstrap(xmlstream.STREAM_END_EVENT, self.disconnected)
        factory.addBootstrap(xmlstream.STREAM_AUTHD_EVENT, self.authenticated)
        factory.addBootstrap(xmlstream.INIT_FAILED_EVENT, self.init_failed)

        factory.logTraffic = True

        domain = factory.authenticator.otherHost
        c = net.XMPPNetConnector(reactor, domain, factory)
        c.connect()

    def rawDataIn(self, buf):
        print "RECV: %s" % unicode(buf, 'utf-8').encode('ascii', 'replace')


    def rawDataOut(self, buf):
        print "SEND: %s" % unicode(buf, 'utf-8').encode('ascii', 'replace')


    def connected(self, xs):
        print 'Connected.'

        self.xmlstream = xs

        # Log all traffic
        xs.rawDataInFn = self.rawDataIn
        xs.rawDataOutFn = self.rawDataOut


    def disconnected(self, xs):
        print 'Disconnected.'

        reactor.stop()


    def authenticated(self, xs):
        print "Authenticated."

        xs.addOnetimeObserver('/proceed', self.startTLS)

        starttls = domish.Element((xmlstream.NS_XMPP_TLS, 'starttls'))
        xs.send(starttls)

        reactor.callLater(20, xs.sendFooter)


    def init_failed(self, failure):
        print "Initialization failed."
        print failure

        self.xmlstream.sendFooter()


    def startTLS(self, stanza):
        print "starting TLS"


NetConnector('localhost', 5270)

reactor.run()
