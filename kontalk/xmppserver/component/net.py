# -*- coding: utf-8 -*-
"""Kontalk XMPP net component."""
"""
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
"""


from twisted.internet import reactor
from twisted.application import strports
from twisted.names.srvconnect import SRVConnector
from twisted.words.protocols.jabber import jid, xmlstream, error
from twisted.words.xish import domish

from wokkel import component, server

from zope.interface import Interface, implements

from kontalk.xmppserver import log, util, keyring, storage, xmlstream2, auth

try:
    from twisted.internet import ssl
except ImportError:
    ssl = None
if ssl and not ssl.supported:
    ssl = None


def initiateNet(factory):
    domain = factory.authenticator.otherHost
    """
    TEST
    c = XMPPNetConnector(reactor, domain, factory)
    c.connect()
    """
    ports = {
        'prime.kontalk.net': 5270,
        'beta.kontalk.net': 6270,
    }
    c = reactor.connectTCP('localhost', ports[domain], factory)
    return factory.deferred


class XMPPNetConnector(SRVConnector):
    def __init__(self, reactor, domain, factory):
        SRVConnector.__init__(self, reactor, 'xmpp-net', domain, factory)


    def pickServer(self):
        host, port = SRVConnector.pickServer(self)

        if not self.servers and not self.orderedServers:
            # no SRV record, fall back..
            port = 5270

        return host, port


class XMPPNetConnectAuthenticator(xmlstream.ConnectAuthenticator):
    """
    Authenticator for an outgoing XMPP server-to-server connection in this
    Kontalk network.

    @ivar thisHost: The domain this server connects from (the Originating
                    Server) .
    @ivar otherHost: The domain of the server this server connects to (the
                     Receiving Server).
    """
    namespace = 'jabber:net'

    def __init__(self, thisHost, otherHost):
        self.thisHost = thisHost
        self.otherHost = otherHost
        xmlstream.ConnectAuthenticator.__init__(self, otherHost)

    def connectionMade(self):
        self.xmlstream.thisEntity = jid.internJID(self.thisHost)
        xmlstream.ConnectAuthenticator.connectionMade(self)

    def associateWithStream(self, xs):
        xmlstream.ConnectAuthenticator.associateWithStream(self, xs)
        # TODO initializers
        xs.initializers = []

    def streamStarted(self, rootElement):
        xmlstream.ConnectAuthenticator.streamStarted(self, rootElement)


class XMPPNetListenAuthenticator(xmlstream.ListenAuthenticator):
    """
    XMPP authenticator for receiving entity in this Kontalk network.
    STARTTLS negotiation using GPG keys is required.
    """
    namespace = 'jabber:net'

    def __init__(self, service):
        xmlstream.ListenAuthenticator.__init__(self)
        self.service = service

    def associateWithStream(self, xs):
        xmlstream.ListenAuthenticator.associateWithStream(self, xs)
        xs.addObserver(xmlstream2.INIT_SUCCESS_EVENT, self.onSuccess)

        xs.initializers = []
        """
        inits = (
            (xmlstream2.GnuPGTLSReceivingInitializer, True, True),
        )
        for initClass, required, exclusive in inits:
            init = initClass(xs, self.canInitialize)
            init.required = required
            init.exclusive = exclusive
            xs.initializers.append(init)
            init.initialize()
        """

    def streamStarted(self, rootElement):
        xmlstream.ListenAuthenticator.streamStarted(self, rootElement)

        self.xmlstream.sendHeader()

        try:
            if self.xmlstream.version < (1, 0):
                raise error.StreamError('unsupported-version')
            if self.xmlstream.thisEntity.host != self.service.defaultDomain:
                raise error.StreamError('not-authorized')
        except error.StreamError, exc:
            self.xmlstream.sendHeader()
            self.xmlstream.sendStreamError(exc)
            return

        if self.xmlstream.version >= (1, 0):
            features = domish.Element((xmlstream.NS_STREAMS, 'features'))

            for initializer in self.xmlstream.initializers:
                feature = initializer.feature()
                if feature is not None:
                    features.addChild(feature)
                if hasattr(initializer, 'required') and initializer.required and \
                    hasattr(initializer, 'exclusive') and initializer.exclusive:
                    break

            self.xmlstream.send(features)

            # TEST auto auth :)
            self.xmlstream.otherEntity = jid.internJID(rootElement['from'])
            self.xmlstream.dispatch(self.xmlstream, xmlstream.STREAM_AUTHD_EVENT)

    def canInitialize(self, initializer):
        inits = self.xmlstream.initializers[0:self.xmlstream.initializers.index(initializer)]

        # check if there are required inits that should have been run first
        for init in inits:
            if hasattr(init, 'required') and init.required:
                return False

        # remove the skipped inits
        for init in inits:
            init.deinitialize()
            self.xmlstream.initializers.remove(init)

        return True

    def onSuccess(self, initializer):
        self.xmlstream.initializers.remove(initializer)

        required = False
        for init in self.xmlstream.initializers:
            if hasattr(init, 'required') and init.required:
                required = True

        if not required:
            self.xmlstream.dispatch(self.xmlstream, xmlstream.STREAM_AUTHD_EVENT)


class XMPPNetServerFactory(xmlstream.XmlStreamServerFactory):
    """
    XMPP Kontalk Server-to-Server Server factory.
    This factory accepts XMPP server-to-server connections for this Kontalk
    network.
    """

    logTraffic = False

    def __init__(self, service):
        self.service = service

        def authenticatorFactory():
            return XMPPNetListenAuthenticator(service)

        xmlstream.XmlStreamServerFactory.__init__(self, authenticatorFactory)
        self.addBootstrap(xmlstream.STREAM_CONNECTED_EVENT,
                          self.onConnectionMade)
        self.addBootstrap(xmlstream.STREAM_AUTHD_EVENT,
                          self.onAuthenticated)

        self.serial = 0

    def loadKey(self, fingerprint):
        if ssl is None:
            raise xmlstream.TLSNotSupported()

        self.tls_ctx = auth.DefaultGnuPGContextFactory(self.service.fingerprint)

    def onConnectionMade(self, xs):
        """
        Called when a server-to-server connection was made.

        This enables traffic debugging on incoming streams.
        """
        xs.serial = self.serial
        self.serial += 1

        def logDataIn(buf):
            log.debug("RECV (%d): %r" % (xs.serial, buf))

        def logDataOut(buf):
            log.debug("SEND (%d): %r" % (xs.serial, buf))

        if self.logTraffic:
            xs.rawDataInFn = logDataIn
            xs.rawDataOutFn = logDataOut

        xs.addObserver(xmlstream.STREAM_ERROR_EVENT, self.onError)


    def onAuthenticated(self, xs):
        thisHost = xs.thisEntity.host
        otherHost = xs.otherEntity.host

        log.debug("Incoming connection %d from %s to %s established" %
                (xs.serial, otherHost, thisHost))

        xs.addObserver(xmlstream.STREAM_END_EVENT, self.onConnectionLost,
                                                   0, xs)
        xs.addObserver('/*', self.onElement, 0, xs)

        self.service.validateConnection(xs)


    def onConnectionLost(self, xs, reason):
        thisHost = xs.thisEntity.host
        otherHost = xs.otherEntity.host

        log.debug("Incoming connection %d from %s to %s disconnected" %
                (xs.serial, otherHost, thisHost))
        self.service.invalidateConnection(xs)

    def onError(self, reason):
        log.error("Stream Error: %r" % (reason, ))


    def onElement(self, xs, element):
        """
        Called when an element was received from one of the connected streams.
        """
        if element.handled:
            return
        else:
            self.service.dispatch(xs, element)


class IS2SService(Interface):

    def validateConnection(xs):
        pass

    def invalidateConnection(xs):
        pass

    def dispatch(xs, stanza):
        pass


class NetService(object):
    """Net service. Used by Net component class."""

    implements(IS2SService)

    def __init__(self, config, router, keyring):
        self.config = config
        self.fingerprint = config['fingerprint']
        self.defaultDomain = config['host']
        self.network = config['network']
        self.domains = set()
        self.domains.add(self.defaultDomain)
        self.router = router
        self.keyring = keyring

        self._outgoingStreams = {}
        self._outgoingQueues = {}
        self._outgoingConnecting = set()
        self.serial = 0

    def outgoingInitialized(self, xs):
        thisHost = xs.thisEntity.host
        otherHost = xs.otherEntity.host

        log.debug("Outgoing connection %d from %s to %s established" %
                (xs.serial, thisHost, otherHost))

        self._outgoingStreams[otherHost] = xs
        xs.addObserver(xmlstream.STREAM_END_EVENT,
                       lambda _: self.outgoingDisconnected(xs))
        xs.addObserver('/*', self.onElement, 0, xs)

        if otherHost in self._outgoingQueues:
            for element in self._outgoingQueues[otherHost]:
                xs.send(element)
            del self._outgoingQueues[otherHost]

    def outgoingDisconnected(self, xs):
        thisHost = xs.thisEntity.host
        otherHost = xs.otherEntity.host

        log.debug("Outgoing connection %d from %s to %s disconnected" %
                (xs.serial, thisHost, otherHost))

        del self._outgoingStreams[otherHost]

    def initiateOutgoingStream(self, otherHost):
        """
        Initiate an outgoing XMPP server-to-server connection.
        """

        def resetConnecting(_):
            self._outgoingConnecting.remove(otherHost)

        if otherHost in self._outgoingConnecting:
            return

        authenticator = XMPPNetConnectAuthenticator(self.defaultDomain, otherHost)
        factory = server.DeferredS2SClientFactory(authenticator)
        factory.addBootstrap(xmlstream.STREAM_AUTHD_EVENT,
                             self.outgoingInitialized)
        factory.logTraffic = self.logTraffic

        self._outgoingConnecting.add(otherHost)

        d = initiateNet(factory)
        d.addBoth(resetConnecting)
        return d

    def validateConnection(self, xs):
        otherHost = xs.otherEntity.host
        if otherHost in self._outgoingStreams:
            xs.sendStreamError(error.StreamError('conflict'))
        self._outgoingStreams[otherHost] = xs

    def invalidateConnection(self, xs):
        otherHost = xs.otherEntity.host
        if otherHost in self._outgoingStreams:
            del self._outgoingStreams[otherHost]

    def onElement(self, xs, element):
        """
        Called when an element was received from one of the connected streams.
        """
        if element.handled:
            return
        else:
            self.dispatch(xs, element)

    def send(self, stanza):
        """
        Send stanza to the proper XML Stream.

        This uses addressing embedded in the stanza to find the correct stream
        to forward the stanza to.
        """

        otherHost = jid.internJID(stanza["to"]).host

        if stanza['from'] != self.defaultDomain:
            stanza['origin'] = stanza['from']
            stanza['from'] = self.defaultDomain

        if otherHost not in self._outgoingStreams:
            # There is no connection with the destination (yet). Cache the
            # outgoing stanza until the connection has been established.
            # XXX: If the connection cannot be established, the queue should
            #      be emptied at some point.
            if otherHost not in self._outgoingQueues:
                self._outgoingQueues[otherHost] = []
            self._outgoingQueues[otherHost].append(stanza)
            self.initiateOutgoingStream(otherHost)
        else:
            self._outgoingStreams[otherHost].send(stanza)

    def dispatch(self, xs, stanza):
        """
        Send a stanza to the router, checking some stuff first.
        """

        log.debug("stanza from %s: %s" % (xs.otherEntity.full(), stanza.toXml()))
        util.resetNamespace(stanza, xs.namespace)
        stanzaFrom = stanza.getAttribute('from')
        stanzaTo = stanza.getAttribute('to')

        if not stanzaFrom or not stanzaTo:
            xs.sendStreamError(error.StreamError('improper-addressing'))
        else:
            try:
                sender = jid.internJID(stanzaFrom)
                to = jid.internJID(stanzaTo)
            except jid.InvalidFormat:
                log.debug("dropping stanza with malformed JID")

            log.debug("sender = %s, otherEntity = %s" % (sender.full(), xs.otherEntity.full()))
            if sender.host != xs.otherEntity.host and sender.host != self.defaultDomain:
                xs.sendStreamError(error.StreamError('invalid-from'))
            else:
                # set destination host to network so it will be delivered to resolver
                to.host = self.network
                stanza['to'] = to.full()
                # replace from with origin (if any)
                origin = stanza.getAttribute('origin')
                if origin:
                    stanza['from'] = origin
                    del stanza['origin']
                self.router.send(stanza)


class NetComponent(component.Component):
    """
    Kontalk server-to-server component with other Kontalk servers on this network.
    L{StreamManager} is for the connection with the router.
    """

    """
    TODO connection with other Kontalk servers should be SSL certificate authenticated
    """

    def __init__(self, config):
        router_cfg = config['router']
        component.Component.__init__(self, router_cfg['host'], router_cfg['port'], router_cfg['jid'], router_cfg['secret'])
        self.config = config
        self.logTraffic = config['debug']
        self.network = config['network']
        self.servername = config['host']

    def setup(self):
        storage.init(self.config['database'])

        ring = keyring.Keyring(storage.MySQLNetworkStorage(), self.config['fingerprint'], self.servername)
        self.service = NetService(self.config, self, ring)
        self.service.logTraffic = self.logTraffic
        self.sfactory = XMPPNetServerFactory(self.service)
        self.sfactory.logTraffic = self.logTraffic
        self.sfactory.loadKey(self.config['fingerprint'])

        return strports.service('tcp:' + str(self.config['bind'][1]) +
            ':interface=' + str(self.config['bind'][0]), self.sfactory)

    """ Connection with router """

    def _authd(self, xs):
        component.Component._authd(self, xs)
        log.debug("connected to router.")

        # bind to our network host names
        bind = domish.Element((None, 'bind'))
        for host in self.service.keyring.hostlist():
            if host != self.servername:
                bind['name'] = host
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
            log.debug("incoming stanza from router %s" % (stanza.toXml().encode('utf-8'), ))
            to = stanza.getAttribute('to')

            if to is not None:
                to = jid.JID(to)
                if to.host != self.xmlstream.thisEntity.host:
                    util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)
                    self.service.send(stanza)

    def _disconnected(self, reason):
        component.Component._disconnected(self, reason)
        log.debug("lost connection to router (%s)" % (reason, ))
