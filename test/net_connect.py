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

        factory.logTraffic = False

        """
        TEST
        domain = factory.authenticator.otherHost
        c = net.XMPPNetConnector(reactor, domain, factory)
        """
        c = net.XMPPNetConnector(reactor, host, factory)
        c.connect()

    def rawDataIn(self, buf):
        print "RECV: %s" % unicode(buf, 'utf-8').encode('utf-8')

    def rawDataOut(self, buf):
        print "SEND: %s" % unicode(buf, 'utf-8').encode('utf-8')


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

        xs.addObserver("/presence[@type='probe']", self.probe)

        """
        presence = domish.Element((None, 'presence'))
        presence['type'] = 'probe'
        presence['from'] = 'beta.kontalk.net'
        #presence['to'] = 'e73ea3be23d0449597a82c62ed981f584a5c181b@prime.kontalk.net'
        presence['to'] = '584fb3000e857d399b0c99fe14ba65df8663e697@prime.kontalk.net/DKDJ3K2KJ'
        #presence['to'] = '584fb3000e857d399b0c99fe14ba65df8663e697@kontalk.net'
        xs.send(presence)
        """

        msg = domish.Element((None, 'message'))
        msg['type'] = 'chat'
        msg['from'] = 'beta.kontalk.net'
        msg['origin'] = 'kontalk.net'
        #msg['to'] = 'e73ea3be23d0449597a82c62ed981f584a5c181b@prime.kontalk.net'
        #msg['to'] = '584fb3000e857d399b0c99fe14ba65df8663e697@prime.kontalk.net/DKDJ3K2KJ'
        msg['to'] = '584fb3000e857d399b0c99fe14ba65df8663e697@kontalk.net'
        xs.send(msg)

        reactor.callLater(20, xs.sendFooter)

    def probe(self, stanza):
        print "presence probe for %s" % (stanza['to'], )


    def init_failed(self, failure):
        print "Initialization failed."
        print failure

        self.xmlstream.sendFooter()



NetConnector('localhost', 5270)

reactor.run()
