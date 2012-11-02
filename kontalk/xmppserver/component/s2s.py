# -*- coding: utf-8 -*-
'''Kontalk XMPP s2s component.'''
'''
  Kontalk XMPP server
  Copyright (C) 2011 Kontalk Devteam <devteam@kontalk.org>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''


from twisted.application import strports
from twisted.python import randbytes
from twisted.words.protocols.jabber import jid, xmlstream, error
from twisted.words.xish import domish

from wokkel import component, server

from zope.interface import Interface, implements

from kontalk.xmppserver import log, util


class IS2SService(Interface):

    def validateConnection(thisHost, otherHost, sid, key):
        pass

    def dispatch(xs, stanza):
        pass


class S2SService(object):
    """S2S service. Used by S2S component class."""

    implements(IS2SService)

    def __init__(self, config, router):
        self.config = config
        self.defaultDomain = config['network']
        self.domains = set()
        self.domains.add(self.defaultDomain)
        self.secret = randbytes.secureRandom(16).encode('hex')
        self.router = router

        self._outgoingStreams = {}
        self._outgoingQueues = {}
        self._outgoingConnecting = set()
        self.serial = 0

    def outgoingInitialized(self, xs):
        thisHost = xs.thisEntity.host
        otherHost = xs.otherEntity.host

        log.debug("Outgoing connection %d from %r to %r established" %
                (xs.serial, thisHost, otherHost))

        self._outgoingStreams[thisHost, otherHost] = xs
        xs.addObserver(xmlstream.STREAM_END_EVENT,
                       lambda _: self.outgoingDisconnected(xs))

        if (thisHost, otherHost) in self._outgoingQueues:
            for element in self._outgoingQueues[thisHost, otherHost]:
                xs.send(element)
            del self._outgoingQueues[thisHost, otherHost]

    def outgoingDisconnected(self, xs):
        thisHost = xs.thisEntity.host
        otherHost = xs.otherEntity.host

        log.debug("Outgoing connection %d from %r to %r disconnected" %
                (xs.serial, thisHost, otherHost))

        del self._outgoingStreams[thisHost, otherHost]

    def initiateOutgoingStream(self, thisHost, otherHost):
        """
        Initiate an outgoing XMPP server-to-server connection.
        """

        def resetConnecting(_):
            self._outgoingConnecting.remove((thisHost, otherHost))

        if (thisHost, otherHost) in self._outgoingConnecting:
            return

        authenticator = server.XMPPServerConnectAuthenticator(thisHost,
                                                       otherHost,
                                                       self.secret)
        factory = server.DeferredS2SClientFactory(authenticator)
        factory.addBootstrap(xmlstream.STREAM_AUTHD_EVENT,
                             self.outgoingInitialized)
        factory.logTraffic = self.logTraffic

        self._outgoingConnecting.add((thisHost, otherHost))

        """
        d = server.initiateS2S(factory)
        d.addBoth(resetConnecting)
        return d
        """
        # TEST with no SRV
        #return server.initiateS2S(factory)
        from twisted.internet import reactor
        reactor.connectTCP(factory.authenticator.otherHost, 5269, factory)
        factory.deferred.addBoth(resetConnecting)
        return factory.deferred

    def validateConnection(self, thisHost, otherHost, sid, key):
        """
        Validate an incoming XMPP server-to-server connection.
        """

        log.debug("validating connection from %s (sid=%r)" % (otherHost, sid))
        def connected(xs):
            # Set up stream for immediate disconnection.
            def disconnect(_):
                xs.transport.loseConnection()
            xs.addObserver(xmlstream.STREAM_AUTHD_EVENT, disconnect)
            xs.addObserver(xmlstream.INIT_FAILED_EVENT, disconnect)

        authenticator = server.XMPPServerVerifyAuthenticator(thisHost, otherHost,
                                                      sid, key)
        factory = server.DeferredS2SClientFactory(authenticator)
        factory.addBootstrap(xmlstream.STREAM_CONNECTED_EVENT, connected)
        factory.logTraffic = self.logTraffic

        # TEST with no SRV
        #return server.initiateS2S(factory)
        from twisted.internet import reactor
        reactor.connectTCP(factory.authenticator.otherHost, 5269, factory)
        return factory.deferred

    def send(self, stanza):
        """
        Send stanza to the proper XML Stream.

        This uses addressing embedded in the stanza to find the correct stream
        to forward the stanza to.
        """

        otherHost = jid.internJID(stanza["to"]).host
        thisHost = jid.internJID(stanza["from"]).host

        if (thisHost, otherHost) not in self._outgoingStreams:
            # There is no connection with the destination (yet). Cache the
            # outgoing stanza until the connection has been established.
            # XXX: If the connection cannot be established, the queue should
            #      be emptied at some point.
            if (thisHost, otherHost) not in self._outgoingQueues:
                self._outgoingQueues[(thisHost, otherHost)] = []
            self._outgoingQueues[(thisHost, otherHost)].append(stanza)
            self.initiateOutgoingStream(thisHost, otherHost)
        else:
            self._outgoingStreams[(thisHost, otherHost)].send(stanza)

    def dispatch(self, xs, stanza):
        """
        Send a stanza to the router, checking some stuff first.
        """

        # TODO take this from the stream?
        util.resetNamespace(stanza, 'jabber:server')
        stanzaFrom = stanza.getAttribute('from')
        stanzaTo = stanza.getAttribute('to')

        if not stanzaFrom or not stanzaTo:
            xs.sendStreamError(error.StreamError('improper-addressing'))
        else:
            try:
                sender = jid.internJID(stanzaFrom)
                jid.internJID(stanzaTo)
            except jid.InvalidFormat:
                log.debug("Dropping error stanza with malformed JID")

            log.debug("sender = %s, otherEntity = %s" % (sender.full(), xs.otherEntity.full()))
            if sender.host != xs.otherEntity.host:
                xs.sendStreamError(error.StreamError('invalid-from'))
            else:
                self.router.send(stanza)


class S2SComponent(component.Component):
    """
    Kontalk server-to-server component.
    L{StreamManager} is for the connection with the router.
    """

    def __init__(self, config):
        router_cfg = config['router']
        component.Component.__init__(self, router_cfg['host'], router_cfg['port'], router_cfg['jid'], router_cfg['secret'])
        self.config = config
        self.logTraffic = config['debug']
        self.network = config['network']
        self.servername = config['host']

    def setup(self):
        self.service = S2SService(self.config, self)
        self.service.logTraffic = self.logTraffic
        self.sfactory = server.XMPPS2SServerFactory(self.service)
        self.sfactory.logTraffic = self.logTraffic

        return strports.service('tcp:' + str(self.config['bind'][1]) +
            ':interface=' + str(self.config['bind'][0]), self.sfactory)

    """ Connection with router """

    def _authd(self, xs):
        component.Component._authd(self, xs)
        log.debug("connected to router.")

        # bind to the default route
        bind = domish.Element((None, 'bind'), attribs={'name': '*'})
        self.send(bind)

        self.xmlstream.addObserver("/error", self.onError)
        self.xmlstream.addObserver("/bind", self.consume)
        self.xmlstream.addObserver("/presence", self.dispatch)
        self.xmlstream.addObserver("/iq", self.dispatch)
        self.xmlstream.addObserver("/message", self.dispatch)

    def consume(self, stanza):
        stanza.consumed = True
        log.debug("consuming stanza %s" % (stanza.toXml(), ))

    def onError(self, stanza):
        stanza.consmued = True
        log.debug("routing error %s" % (stanza.toXml(), ))

    def dispatch(self, stanza):
        """Handle incoming stanza from router to the proper server stream."""
        if not stanza.consumed:
            stanza.consumed = True
            log.debug("incoming stanza from router %s" % (stanza.toXml(), ))
            util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)
            stanza['from'] = self.resolveJID(stanza['from']).full()
            to = stanza.getAttribute('to')

            if to is not None:
                sender = jid.JID(to)
                if sender.host in (self.network, self.servername):
                    log.debug("stanza is for %s - resolver is down?" % (sender.host, ))
                else:
                    self.service.send(stanza)

    def _disconnected(self, reason):
        component.Component._disconnected(self, reason)
        log.debug("lost connection to router (%s)" % (reason, ))

    def resolveJID(self, _jid):
        """Transform host attribute of JID from server name to network name."""
        if isinstance(_jid, jid.JID):
            return jid.JID(tuple=(_jid.user, self.network, _jid.resource))
        else:
            _jid = jid.JID(_jid)
            _jid.host = self.network
            return _jid
