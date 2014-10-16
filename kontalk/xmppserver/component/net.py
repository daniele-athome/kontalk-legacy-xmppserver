# -*- coding: utf-8 -*-
"""Kontalk XMPP net component."""
"""
  Kontalk XMPP server
  Copyright (C) 2014 Kontalk Devteam <devteam@kontalk.org>

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


import os

from twisted.internet import reactor
from twisted.names.srvconnect import SRVConnector, _SRVConnector_ClientFactoryWrapper
from twisted.application.internet import StreamServerEndpointService
from twisted.words.protocols.jabber import jid, xmlstream, error
from twisted.words.xish import domish

from wokkel import component, server

from zope.interface import Interface, implements

import gnutls.interfaces.twisted as tls_reactor
from gnutls.crypto import OpenPGPCertificate, OpenPGPPrivateKey

from kontalk.xmppserver import auth, tls, log, util, keyring, storage, xmlstream2


def initiateNet(factory, credentials):
    domain = factory.authenticator.otherHost
    # TEST :)
    if os.getenv('TEST', '0') == '1':
        ports = {
            'prime.kontalk.net': 5270,
            'beta.kontalk.net': 6270,
        }
        c = tls_reactor.connectTLS(reactor, 'localhost', ports[domain], factory, credentials)
    else:
        c = XMPPNetConnector(reactor, domain, factory, credentials, tls_reactor)
        c.connect()
    return factory.deferred


class XMPPNetConnector(SRVConnector):
    def __init__(self, reactor, domain, factory, credentials, tls_reactor):
        self.tls_reactor = tls_reactor
        SRVConnector.__init__(self, reactor, 'xmpp-net', str(domain), factory,
            connectFuncName='connectTLS', connectFuncKwArgs={'credentials':credentials})

    # HACK HACK HACK
    def _reallyConnect(self):
        if self.stopAfterDNS:
            self.stopAfterDNS=0
            return

        self.host, self.port = self.pickServer()
        assert self.host is not None, 'Must have a host to connect to.'
        assert self.port is not None, 'Must have a port to connect to.'

        connectFunc = getattr(self.tls_reactor, self.connectFuncName)
        self.connector=connectFunc(
            self.reactor, self.host, self.port,
            _SRVConnector_ClientFactoryWrapper(self, self.factory),
            *self.connectFuncArgs, **self.connectFuncKwArgs)


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

    def __init__(self, thisHost, otherHost, keyring):
        self.thisHost = thisHost
        self.otherHost = otherHost
        self.keyring = keyring
        xmlstream.ConnectAuthenticator.__init__(self, otherHost)

    def connectionMade(self):
        self.xmlstream.thisEntity = jid.internJID(self.thisHost)
        xmlstream.ConnectAuthenticator.connectionMade(self)

    def associateWithStream(self, xs):
        xmlstream.ConnectAuthenticator.associateWithStream(self, xs)
        # TODO initializers
        xs.initializers = []

    def streamStarted(self, rootElement):
        # TODO same checking code on listening authenticator

        # check that from attribute is associated to the right key
        host = rootElement['from']
        fingerprint = self.xmlstream.transport.getPeerCertificate().fingerprint
        log.debug("%s fingerprint is %s" % (host, fingerprint, ))

        valid = False
        # FIXME accessing Keyring internals
        for fpr, fhost in self.keyring._list.iteritems():
            if fhost == host and fpr.upper() == fingerprint:
                log.debug("fingerprint matching (%s = %s)" % (host, fpr))
                valid = True

        if valid:
            xmlstream.ConnectAuthenticator.streamStarted(self, rootElement)
        else:
            self.xmlstream.sendStreamError(error.StreamError('not-authorized'))


class XMPPNetListenAuthenticator(xmlstream.ListenAuthenticator):
    """XMPP authenticator for receiving entity in this Kontalk network."""
    namespace = 'jabber:net'

    def __init__(self, defaultDomain, keyring):
        xmlstream.ListenAuthenticator.__init__(self)
        self.defaultDomain = defaultDomain
        self.keyring = keyring

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
            if self.xmlstream.thisEntity.host != self.defaultDomain:
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

            # check that from attribute is associated to the right key
            host = rootElement['from']
            fingerprint = self.xmlstream.transport.getPeerCertificate().fingerprint
            log.debug("%s fingerprint is %s" % (host, fingerprint, ))

            # FIXME accessing Keyring internals
            for fpr, fhost in self.keyring._list.iteritems():
                if fhost == host and fpr.upper() == fingerprint:
                    log.debug("fingerprint matching (%s = %s)" % (host, fpr))
                    self.xmlstream.otherEntity = jid.internJID(host)
                    self.xmlstream.dispatch(self.xmlstream, xmlstream.STREAM_AUTHD_EVENT)

            if not self.xmlstream.otherEntity:
                self.xmlstream.sendStreamError(error.StreamError('not-authorized'))

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
            return XMPPNetListenAuthenticator(service.defaultDomain, service.keyring)

        xmlstream.XmlStreamServerFactory.__init__(self, authenticatorFactory)
        self.addBootstrap(xmlstream.STREAM_CONNECTED_EVENT,
                          self.onConnectionMade)
        self.addBootstrap(xmlstream.STREAM_AUTHD_EVENT,
                          self.onAuthenticated)

        self.serial = 0

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
        xs.addObserver("/*", self.onElement, 0, xs)
        xs.addObserver("/presence[not(@type)]", self.service.onPresenceAvailable, 100, xs)
        xs.addObserver("/presence[@type='unavailable']", self.service.onPresenceUnavailable, 100, xs)

        if self.service.validateConnection(xs):
            # bind the "net" component route of the remote server which just connected
            self.service.bindNetRoute(otherHost)

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

    def verifyPeer(self, connection, x509, errnum, errdepth, ok):
        # TODO other checks
        return ok


class INetService(Interface):

    def validateConnection(xs):
        pass

    def invalidateConnection(xs):
        pass

    def dispatch(xs, stanza):
        pass


class NetService(object):
    """Net service. Used by Net component class."""

    implements(INetService)

    def __init__(self, config, router, keyring, credentials):
        self.config = config
        self.fingerprint = config['fingerprint']
        self.defaultDomain = config['host']
        self.network = config['network']
        self.domains = set()
        self.domains.add(self.defaultDomain)
        self.router = router
        self.keyring = keyring
        self.credentials = credentials

        self._outgoingStreams = {}
        self._outgoingConnecting = set()
        self.serial = 0

    def bindNetRoute(self, host):
        name = util.component_jid(host, util.COMPONENT_NET)
        self.router.bind(name)

    def outgoingInitialized(self, xs):
        thisHost = xs.thisEntity.host
        otherHost = xs.otherEntity.host

        log.debug("Outgoing connection %d from %s to %s established" %
                (xs.serial, thisHost, otherHost))

        self._outgoingStreams[otherHost] = xs
        xs.addObserver(xmlstream.STREAM_END_EVENT,
                       lambda _: self.outgoingDisconnected(xs))
        xs.addObserver('/*', self.onElement, 0, xs)
        xs.addObserver("/presence[not(@type)]", self.onPresenceAvailable, 100, xs)
        xs.addObserver("/presence[@type='unavailable']", self.onPresenceUnavailable, 100, xs)

        # bind the "net" component route of the remote server which just connected
        self.bindNetRoute(otherHost)

    def outgoingDisconnected(self, xs):
        thisHost = xs.thisEntity.host
        otherHost = xs.otherEntity.host

        log.debug("Outgoing connection %d from %s to %s disconnected" %
                (xs.serial, thisHost, otherHost))

        # TODO this actually does the same as invalidateConnection
        del self._outgoingStreams[otherHost]

        self.router.serverDisconnected(otherHost)


    def initiateOutgoingStream(self, otherHost):
        """
        Initiate an outgoing XMPP server-to-server connection.
        """

        def resetConnecting(_):
            self._outgoingConnecting.remove(otherHost)

        def bounceError(_):
            resetConnecting(None)
            log.debug("unable to connect to remote server")

        if otherHost in self._outgoingConnecting:
            log.debug("pending connection found to %s - aborting" % otherHost)
            return

        log.debug("connecting to %s" % otherHost)
        authenticator = XMPPNetConnectAuthenticator(self.defaultDomain, otherHost, self.keyring)
        factory = server.DeferredS2SClientFactory(authenticator)
        factory.addBootstrap(xmlstream.STREAM_AUTHD_EVENT,
                             self.outgoingInitialized)
        factory.logTraffic = self.logTraffic

        self._outgoingConnecting.add(otherHost)

        d = initiateNet(factory, self.credentials)
        d.addCallback(resetConnecting)
        d.addErrback(bounceError)
        return d

    def validateConnection(self, xs):
        otherHost = xs.otherEntity.host
        if otherHost in self._outgoingStreams:
            xs.sendStreamError(error.StreamError('conflict'))
            return False
        self._outgoingStreams[otherHost] = xs
        return True

    def invalidateConnection(self, xs):
        otherHost = xs.otherEntity.host
        if otherHost in self._outgoingStreams:
            del self._outgoingStreams[otherHost]

        self.router.serverDisconnected(otherHost)

    def onElement(self, xs, element):
        """
        Called when an element was received from one of the connected streams.
        """
        if element.handled:
            return
        else:
            self.dispatch(xs, element)

    def onPresenceAvailable(self, xs, stanza):
        # if component (i.e. no user part of JID) bind name to router
        stanzaFrom = jid.internJID(stanza['from'])
        if not stanzaFrom.user and stanzaFrom.host.endswith(xs.otherEntity.full()):
            stanza.handled = True
            log.debug("binding name %s" % (stanzaFrom.host, ))
            self.router.bind(stanzaFrom.host)

    def onPresenceUnavailable(self, xs, stanza):
        # if component (i.e. no user part of JID) unbind name from router
        stanzaFrom = jid.internJID(stanza['from'])
        if not stanzaFrom.user and stanzaFrom.host.endswith(xs.otherEntity.full()):
            stanza.handled = True
            log.debug("unbinding name %s" % (stanzaFrom.host, ))
            self.router.unbind(stanzaFrom.host)

    def send(self, stanza):
        """
        Send stanza to the proper XML Stream.

        This uses addressing embedded in the stanza to find the correct stream
        to forward the stanza to.
        """

        otherHost = jid.internJID(stanza['to']).host

        if self.logTraffic:
          log.debug("sending data to %s [%r]" % (otherHost, self._outgoingStreams, ))
        for host in self._outgoingStreams.iterkeys():
            if util.hostjid_server(otherHost, host):
                self._outgoingStreams[host].send(stanza)
        # else: shouldn't happen because the router should bounce the stanza

    def dispatch(self, xs, stanza):
        """
        Send a stanza to the router, checking some stuff first.
        """

        if self.logTraffic:
            try:
                log.debug("stanza from %s: %s" % (xs.otherEntity.full(), stanza.toXml().encode('utf-8')))
            except UnicodeDecodeError:
                log.debug("stanza from %s: <%s/> (cannot encode)" % (xs.otherEntity.full(), stanza.name))
        util.resetNamespace(stanza, xs.namespace)
        stanzaFrom = stanza.getAttribute('from')
        stanzaTo = stanza.getAttribute('to')

        if not stanza.bind and not stanzaFrom or not stanzaTo:
            xs.sendStreamError(error.StreamError('improper-addressing'))
        else:
            try:
                sender = jid.internJID(stanzaFrom)
                jid.internJID(stanzaTo)
            except jid.InvalidFormat:
                log.debug("dropping stanza with malformed JID")

            log.debug("sender = %s, otherEntity = %s" % (sender.full(), xs.otherEntity.full()))

            try:
                unused, host = util.jid_component(sender.host)
                if host in self.keyring.hostlist():
                    self.router.send(stanza)
                else:
                    raise Exception()
            except:
                xs.sendStreamError(error.StreamError('invalid-from'))


class NetComponent(xmlstream2.SocketComponent):
    """
    Kontalk server-to-server component with other Kontalk servers on this network.
    L{StreamManager} is for the connection with the router.
    """

    def __init__(self, config):
        router_cfg = config['router']
        for key in ('socket', 'host', 'port'):
            if key not in router_cfg:
                router_cfg[key] = None

        router_jid = '%s.%s' % (router_cfg['jid'], config['host'])
        xmlstream2.SocketComponent.__init__(self, router_cfg['socket'], router_cfg['host'], router_cfg['port'], router_jid, router_cfg['secret'])
        self.config = config
        self.logTraffic = config['debug']
        self.network = config['network']
        self.servername = config['host']

        """
        This dict will hold the registered routes. This will be used when a
        connection to a server suddendly interrupts so we can unbind the
        registered names accordingly.
        Keys: server host name, values: list of names
        """
        self.routes = {}

    def setup(self):
        storage.init(self.config['database'])

        cert = OpenPGPCertificate(open(self.config['pgp_cert']).read())
        key = OpenPGPPrivateKey(open(self.config['pgp_key']).read())

        cred = auth.OpenPGPKontalkCredentials(cert, key, str(self.config['pgp_keyring']))
        cred.verify_peer = True

        ring = keyring.Keyring(storage.MySQLNetworkStorage(), self.config['fingerprint'], self.network, self.servername, disable_cache=True)
        self.service = NetService(self.config, self, ring, cred)
        self.service.logTraffic = self.logTraffic
        self.sfactory = XMPPNetServerFactory(self.service)
        self.sfactory.logTraffic = self.logTraffic

        tls_svc = StreamServerEndpointService(
            tls.TLSServerEndpoint(reactor=reactor,
                port=int(self.config['bind'][1]),
                interface=str(self.config['bind'][0]),
                credentials=cred),
            self.sfactory)
        tls_svc._raiseSynchronously = True

        return tls_svc

    """ Connection with router """

    def _authd(self, xs):
        component.Component._authd(self, xs)
        log.debug("connected to router.")

        # initiate outgoing connection to servers
        for fpr in iter(self.service.keyring):
            host = self.service.keyring[fpr]
            if host != self.servername and self.service.keyring.is_enabled(fpr):
                # connect to server immediately
                self.service.initiateOutgoingStream(host)

        self.xmlstream.addObserver("/bind", self.consume)
        self.xmlstream.addObserver("/presence", self.dispatch)
        self.xmlstream.addObserver("/iq", self.dispatch)
        self.xmlstream.addObserver("/message", self.dispatch)
        self.xmlstream.addObserver("/stanza", self.dispatch)

    def consume(self, stanza):
        stanza.consumed = True
        if self.logTraffic:
            log.debug("consuming stanza %s" % (stanza.toXml().encode('utf-8'), ))

    def dispatch(self, stanza):
        """Handle incoming stanza from router to the proper server stream."""
        if not stanza.consumed:
            stanza.consumed = True
            if self.logTraffic:
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

    def serverDisconnected(self, host):
        # unbind all routes from this server
        if host in self.routes:
            for name in list(self.routes[host]):
                self.unbind(name)

        # broadcast unavailable presence
        p = domish.Element((None, 'presence'))
        p['type'] = 'unavailable'
        p['from'] = host
        self.send(p)

    def bind(self, name):
        stanzaId = util.rand_str(8)

        # register for response
        def _bind(stanza, name):
            if not stanza.hasAttribute('error'):
                # no errors, register route
                unused, host = util.jid_component(name)

                if host not in self.routes:
                    self.routes[host] = []

                self.routes[host].append(name)
                if self.logTraffic:
                    log.debug("ROUTES: %s" % (self.routes, ))

        self.xmlstream.addOnetimeObserver("/bind[@id='%s']" % (stanzaId, ), _bind, name=name)

        bind = domish.Element((None, 'bind'))
        bind['id'] = stanzaId
        bind['name'] = name
        self.send(bind)

    def unbind(self, name):
        # send unbind command to router
        unbind = domish.Element((None, 'unbind'))
        unbind['name'] = name
        self.send(unbind)

        # unregister route
        unused, host = util.jid_component(name)
        if host in self.routes:
            try:
                self.routes[host].remove(name)
            except ValueError:
                pass

            if len(self.routes[host]) == 0:
                del self.routes[host]

        else:
            # this is an error, it shouldn't happen
            log.warn("unbinding non-registered route: %s" % (name, ))
