# -*- coding: utf-8 -*-
"""Kontalk XMPP c2s component."""
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


import time

from twisted.application import strports
from twisted.cred import portal
from twisted.internet.protocol import ServerFactory

from twisted.words.protocols.jabber import xmlstream, jid, error
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish, xmlstream as xish_xmlstream

from wokkel import xmppim, component

from kontalk.xmppserver import log, auth, keyring, util, storage
from kontalk.xmppserver import xmlstream2, version


class PresenceHandler(XMPPHandler):
    """
    Handle presence stanzas and client disconnection.
    @type parent: L{C2SManager}
    """

    def connectionInitialized(self):
        # presence probes MUST be handled by server so the high priority
        self.xmlstream.addObserver("/presence[@type='probe']", self.probe, 600)

    def connectionLost(self, reason):
        if self.xmlstream.otherEntity is not None:
            stanza = xmppim.UnavailablePresence()
            stanza['from'] = self.xmlstream.otherEntity.full()
            self.parent.forward(stanza, True)

    def probe(self, stanza):
        stanza.consumed = True
        sender = jid.JID(stanza['from'])
        to = jid.JID(stanza['to'])

        def _db(presence, stanza):
            log.debug("presence: %r" % (presence, ))
            if type(presence) == list:
                response = domish.Element((None, 'presence'))
                response['to'] = sender.full()

                for user in presence:
                    response_from = util.userid_to_jid(user['userid'], self.parent.servername)
                    response['from'] = response_from.full()

                    if user['status'] is not None:
                        response.addElement((None, 'status'), content=user['status'])
                    if user['show'] is not None:
                        response.addElement((None, 'show'), content=user['show'])

                    if not self.parent.factory.client_connected(response_from):
                        response['type'] = 'unavailable'
                        delay = domish.Element(('urn:xmpp:delay', 'delay'))
                        delay['stamp'] = user['timestamp'].strftime('%Y-%m-%dT%H:%M:%SZ')
                        response.addChild(delay)

                    self.send(response)
                    log.debug("probe result sent: %s" % (response.toXml().encode('utf-8'), ))
            else:
                response = domish.Element((None, 'presence'))
                response['to'] = sender.full()
                response['from'] = to.full()

                if presence['status'] is not None:
                    response.addElement((None, 'status'), content=presence['status'])
                if presence['show'] is not None:
                    response.addElement((None, 'show'), content=presence['show'])

                self.send(response)
                log.debug("probe result sent: %s" % (response.toXml().encode('utf-8'), ))

        d = self.parent.presencedb.get(to)
        d.addCallback(_db, stanza)

    def features(self):
        return tuple()


class PingHandler(XMPPHandler):
    """
    XEP-0199: XMPP Ping
    http://xmpp.org/extensions/xep-0199.html
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='get']/ping[@xmlns='%s']" % (xmlstream2.NS_XMPP_PING, ), self.ping, 100)

    def ping(self, stanza):
        if not stanza.hasAttribute('to') or stanza['to'] == self.parent.network:
            self.parent.bounce(stanza)
        else:
            self.parent.forward(stanza)

    def features(self):
        return (xmlstream2.NS_XMPP_PING, )


class IQHandler(XMPPHandler):
    """Handle various iq stanzas."""

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='get']/query[@xmlns='%s']" % (xmlstream2.NS_IQ_ROSTER), self.parent.bounce, 100)
        self.xmlstream.addObserver("/iq/query[@xmlns='%s']" % (xmlstream2.NS_IQ_LAST), self.forward_check, 100,
            fn=self.parent.forward, componentfn=self.last_activity)
        self.xmlstream.addObserver("/iq/query[@xmlns='%s']" % (xmlstream2.NS_IQ_VERSION), self.forward_check, 100,
            fn=self.parent.forward, componentfn=self.version)
        self.xmlstream.addObserver("/iq[@type='result']", self.parent.forward, 100)

        # fallback: service unavailable
        self.xmlstream.addObserver("/iq", self.parent.error, 50)

    def forward_check(self, stanza, fn, componentfn):
        if not stanza.consumed:
            if stanza['to'] == self.parent.servername:
                return componentfn(stanza)
            else:
                return fn(stanza)

    def last_activity(self, stanza):
        stanza.consumed = True
        seconds = self.parent.router.uptime()
        response = xmlstream.toResponse(stanza, 'result')
        response.addChild(domish.Element((xmlstream2.NS_IQ_LAST, 'query'), attribs={'seconds': str(int(seconds))}))
        self.send(response)

    def version(self, stanza):
        stanza.consumed = True
        response = xmlstream.toResponse(stanza, 'result')
        query = domish.Element((xmlstream2.NS_IQ_VERSION, 'query'))
        query.addElement((None, 'name'), content=version.NAME + '-c2s')
        query.addElement((None, 'version'), content=version.VERSION)
        response.addChild(query)
        self.send(response)

    def features(self):
        return (
            xmlstream2.NS_IQ_REGISTER,
            xmlstream2.NS_IQ_VERSION,
            xmlstream2.NS_IQ_ROSTER,
            xmlstream2.NS_IQ_LAST,
        )


class MessageHandler(XMPPHandler):
    """Message stanzas handler."""

    def connectionInitialized(self):
        # messages for the server
        #self.xmlstream.addObserver("/message[@to='%s']" % (self.parent.servername), self.parent.error, 100)
        pass

    def features(self):
        return tuple()


class DiscoveryHandler(XMPPHandler):
    """Handle iq stanzas for discovery."""

    def __init__(self):
        self.supportedFeatures = []

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='get'][@to='%s']/query[@xmlns='%s']" % (self.parent.network, xmlstream2.NS_DISCO_ITEMS), self.onDiscoItems, 100)
        self.xmlstream.addObserver("/iq[@type='get'][@to='%s']/query[@xmlns='%s']" % (self.parent.network, xmlstream2.NS_DISCO_INFO), self.onDiscoInfo, 100)

    def onDiscoItems(self, stanza):
        if not stanza.consumed:
            stanza.consumed = True
            response = xmlstream.toResponse(stanza, 'result')
            response.addElement((xmlstream2.NS_DISCO_ITEMS, 'query'))
            self.send(response)

    def onDiscoInfo(self, stanza):
        if not stanza.consumed:
            stanza.consumed = True
            response = xmlstream.toResponse(stanza, 'result')
            query = response.addElement((xmlstream2.NS_DISCO_INFO, 'query'))
            query.addChild(domish.Element((None, 'identity'), attribs={'category': 'server', 'type' : 'im', 'name': version.IDENTITY}))

            for feature in self.supportedFeatures:
                query.addChild(domish.Element((None, 'feature'), attribs={'var': feature }))
            self.send(response)



class C2SManager(xmlstream2.StreamManager):
    """
    Handles communication with a client. Note that this is the L{StreamManager}
    towards the client, not the router!!

    @param router: the connection with the router
    @type router: L{xmlstream.StreamManager}
    """

    namespace = 'jabber:client'

    disco_handler = DiscoveryHandler
    init_handlers = (
        PresenceHandler,
        PingHandler,
        IQHandler,
        MessageHandler,
    )

    def __init__(self, xs, factory, router, network, servername):
        self.factory = factory
        self.router = router
        self.network = network
        self.servername = servername
        xmlstream2.StreamManager.__init__(self, xs)

        """
        Register the discovery handler first so it can process features from
        the other handlers.
        """
        disco = self.disco_handler()
        disco.setHandlerParent(self)

        for handler in self.init_handlers:
            h = handler()
            h.setHandlerParent(self)
            disco.supportedFeatures.extend(h.features())

    def _connected(self, xs):
        xmlstream2.StreamManager._connected(self, xs)
        # add an observer for unauthorized stanzas
        xs.addObserver("/iq", self._unauthorized)
        xs.addObserver("/presence", self._unauthorized)
        xs.addObserver("/message", self._unauthorized)

    def _unauthorized(self, stanza):
        if not stanza.consumed and (not stanza.hasAttribute('to') or stanza['to'] != self.network):
            stanza.consumed = True
            self.xmlstream.sendStreamError(error.StreamError('not-authorized'))

    def _authd(self, xs):
        xmlstream2.StreamManager._authd(self, xs)

        # remove unauthorized stanzas handler
        xs.removeObserver("/iq", self._unauthorized)
        xs.removeObserver("/presence", self._unauthorized)
        xs.removeObserver("/message", self._unauthorized)
        self.factory.connectionInitialized(xs)

        # stanza server processing rules - before they are sent to handlers
        xs.addObserver('/iq', self.iq, 500)
        xs.addObserver('/presence', self.presence, 500)
        xs.addObserver('/message', self.message, 500)

        # forward everything that is not handled
        xs.addObserver('/*', self.forward)

    def handle(self, stanza):
        to = stanza.getAttribute('to')
        if to is not None:
            to = jid.JID(to)
            # stanza is for us
            if to.host == self.network:
                # sending to full JID, forward to router
                if to.user is not None and to.resource is not None:
                    self.forward(stanza)

            # stanza is not intended to component either
            elif to.host != self.servername:
                self.forward(stanza)

            # everything else is handled by handlers

    def iq(self, stanza):
        return self.handle(stanza)

    def presence(self, stanza):
        return self.handle(stanza)

    def message(self, stanza):
        # no to address, presume sender bare JID
        if not stanza.hasAttribute('to'):
            stanza['to'] = self.xmlstream.otherEntity.full()
            # try again
            self.message(stanza)
        else:
            self.handle(stanza)

    def _disconnected(self, reason):
        self.factory.connectionLost(self.xmlstream, reason)
        xmlstream2.StreamManager._disconnected(self, reason)

    def error(self, stanza, condition='service-unavailable'):
        if not stanza.consumed:
            log.debug("error %s" % (stanza.toXml(), ))
            stanza.consumed = True
            util.resetNamespace(stanza, self.namespace)
            e = error.StanzaError(condition, 'cancel')
            self.send(e.toResponse(stanza), True)

    def bounce(self, stanza):
        """Bounce stanzas as results."""
        if not stanza.consumed:
            util.resetNamespace(stanza, self.namespace)
            log.debug("bouncing %s" % (stanza.toXml(), ))
            stanza.consumed = True
            self.send(xmlstream.toResponse(stanza, 'result'))

    def send(self, stanza, force=False):
        """Send stanza to client, setting to and id attributes if not present."""
        util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT, self.namespace)

        # handle original to address
        if stanza.hasAttribute('destination'):
            stanza['to'] = stanza['destination']
            del stanza['destination']

        if not stanza.hasAttribute('to'):
            stanza['to'] = self.xmlstream.otherEntity.full()

        if not stanza.hasAttribute('id'):
            stanza['id'] = util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
        xmlstream2.StreamManager.send(self, stanza, force)

    def forward(self, stanza, useFrom=False):
        """
        Forward incoming stanza from clients to the router, setting the from
        attribute to the sender entity.
        """
        if not stanza.consumed:
            util.resetNamespace(stanza, self.namespace)
            log.debug("forwarding %s" % (stanza.toXml().encode('utf-8'), ))
            stanza.consumed = True
            util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)
            stanza['from'] = self.resolveJID(stanza['from'] if useFrom else self.xmlstream.otherEntity).full()
            self.router.send(stanza)

    def resolveJID(self, _jid):
        """Transform host attribute of JID from network name to server name."""
        if isinstance(_jid, jid.JID):
            return jid.JID(tuple=(_jid.user, self.servername, _jid.resource))
        else:
            _jid = jid.JID(_jid)
            _jid.host = self.servername
            return _jid


class XMPPServerFactory(xish_xmlstream.XmlStreamFactoryMixin, ServerFactory):
    """
    The XMPP server factory for incoming client connections.
    @type streams: C{dict}
    """

    protocol = xmlstream.XmlStream
    manager = C2SManager

    def __init__(self, portal, router, network, servername):
        xish_xmlstream.XmlStreamFactoryMixin.__init__(self)
        self.portal = portal
        self.router = router
        self.network = network
        self.servername = servername
        self.streams = {}

    def buildProtocol(self, addr):
        xs = self.protocol(XMPPListenAuthenticator(self.network))
        xs.factory = self
        xs.portal = self.portal
        xs.manager = self.manager(xs, self, self.router, self.network, self.servername)
        xs.manager.logTraffic = self.logTraffic

        # install bootstrap handlers
        self.installBootstraps(xs)

        return xs

    def connectionInitialized(self, xs):
        """Called from the handler when a client has authenticated."""
        userid, resource = util.jid_to_userid(xs.otherEntity, True)
        if userid not in self.streams:
            self.streams[userid] = {}
        self.streams[userid][resource] = xs.manager

    def connectionLost(self, xs, reason):
        """Called from the handler when connection to a client is lost."""
        if xs.otherEntity is not None:
            userid, resource = util.jid_to_userid(xs.otherEntity, True)
            if userid in self.streams and resource in self.streams[userid]:
                del self.streams[userid][resource]
                if len(self.streams[userid]) == 0:
                    del self.streams[userid]

    def client_connected(self, _jid):
        """Return true if the given L{JID} is found connected locally."""
        userid, resource = util.jid_to_userid(_jid, True)
        if userid in self.streams:
            if resource:
                return resource in self.streams[userid]
            else:
                return len(self.streams[userid]) > 0

        return False

    def dispatch(self, stanza, to=None):
        """
        Dispatch a stanza to a JID all to all available resources found locally.
        @raise L{KeyError}: if a destination route is not found
        """
        # deliver to the requested jid
        if to:
            stanza['to'] = to.full()
        else:
            to = jid.JID(stanza['to'])

        userid, resource = util.jid_to_userid(to, True)

        stanza.defaultUri = stanza.uri = None

        if to.resource is not None:
            self.streams[userid][resource].send(stanza)
        else:
            for resource, manager in self.streams[userid].iteritems():
                manager.send(stanza)


class XMPPListenAuthenticator(xmlstream.ListenAuthenticator):
    """
    Initializes an XmlStream accepted from an XMPP client as a Server.

    This authenticator performs the initialization steps needed to start
    exchanging XML stanzas with an XMPP cient as an XMPP server. It checks if
    the client advertises XML stream version 1.0, performs TLS encryption, SASL
    authentication, and binds a resource. Note: This does not establish a
    session. Sessions are part of XMPP-IM, not XMPP Core.

    Upon successful stream initialization, the L{xmlstream.STREAM_AUTHD_EVENT}
    event will be dispatched through the XML stream object. Otherwise, the
    L{xmlstream.INIT_FAILED_EVENT} event will be dispatched with a failure
    object.
    """

    namespace = 'jabber:client'

    def __init__(self, network):
        xmlstream.ListenAuthenticator.__init__(self)
        self.network = network

    def associateWithStream(self, xs):
        """
        Perform stream initialization procedures.

        An L{XmlStream} holds a list of initializer objects in its
        C{initializers} attribute. This method calls these initializers in
        order up to the first required initializer. This way, a client
        cannot use an initializer before passing all the previous initializers that
        are marked as required. When a required initializer is successful it is removed,
        and all preceding optional initializers are removed as well.

        It dispatches the C{STREAM_AUTHD_EVENT} event when the list has
        been successfully processed. The initializers themselves are responsible
        for sending an C{INIT_FAILED_EVENT} event on failure.
        """

        xmlstream.ListenAuthenticator.associateWithStream(self, xs)
        xs.addObserver(xmlstream2.INIT_SUCCESS_EVENT, self.onSuccess)

        xs.initializers = []
        inits = (
            #(xmlstream.TLSInitiatingInitializer, False),
            (xmlstream2.SASLReceivingInitializer, True, True),
            (xmlstream2.BindInitializer, True, False),
            (xmlstream2.SessionInitializer, True, False),
        )
        for initClass, required, exclusive in inits:
            init = initClass(xs, self.canInitialize)
            init.required = required
            init.exclusive = exclusive
            xs.initializers.append(init)
            init.initialize()

    def streamStarted(self, rootElement):
        xmlstream.ListenAuthenticator.streamStarted(self, rootElement)

        self.xmlstream.sendHeader()

        try:
            if self.xmlstream.version < (1, 0):
                raise error.StreamError('unsupported-version')
            if self.xmlstream.thisEntity.host != self.network:
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


class C2SComponent(component.Component):
    """
    Kontalk c2s component.
    L{StreamManager} is for the connection with the router.
    """

    def __init__(self, config):
        router_cfg = config['router']
        component.Component.__init__(self, router_cfg['host'], router_cfg['port'], router_cfg['jid'], router_cfg['secret'])
        self.config = config
        self.logTraffic = config['debug']
        self.network = config['network']
        self.servername = config['host']
        self.start_time = time.time()

    def setup(self):
        storage.init(self.config['database'])
        self.stanzadb = storage.MySQLStanzaStorage()
        self.presencedb = storage.MySQLPresenceStorage()

        authrealm = auth.SASLRealm("Kontalk")
        ring = keyring.Keyring(storage.MySQLNetworkStorage(), self.config['fingerprint'], self.servername)
        authportal = portal.Portal(authrealm, [auth.AuthKontalkToken(self.config['fingerprint'], ring)])

        self.sfactory = XMPPServerFactory(authportal, self, self.network, self.servername)
        self.sfactory.logTraffic = self.config['debug']

        return strports.service('tcp:' + str(self.config['bind'][1]) +
            ':interface=' + str(self.config['bind'][0]), self.sfactory)

    def uptime(self):
        return time.time() - self.start_time

    """ Connection with router """

    def _connected(self, xs):
        """
        Called when the transport connection has been established.

        Here we optionally set up traffic logging (depending on L{logTraffic})
        and call each handler's C{makeConnection} method with the L{XmlStream}
        instance.
        """
        def logDataIn(buf):
            log.debug("RECV: %s" % unicode(buf, 'utf-8').encode('utf-8'))

        def logDataOut(buf):
            log.debug("SEND: %s" % unicode(buf, 'utf-8').encode('utf-8'))

        if self.logTraffic:
            xs.rawDataInFn = logDataIn
            xs.rawDataOutFn = logDataOut

        self.xmlstream = xs

        for e in self:
            e.makeConnection(xs)

    def _authd(self, xs):
        component.Component._authd(self, xs)
        log.debug("connected to router.")
        self.xmlstream.addObserver("/error", self.onError)
        self.xmlstream.addObserver("/presence", self.dispatch)
        self.xmlstream.addObserver("/iq", self.dispatch)
        self.xmlstream.addObserver("/message", self.dispatch)

    def _disconnected(self, reason):
        component.Component._disconnected(self, reason)
        log.debug("lost connection to router (%s)" % (reason, ))

    def dispatch(self, stanza):
        log.debug("incoming stanza: %s" % (stanza.toXml()))
        """
        Stanzas from router must be intended to a server JID (e.g.
        prime.kontalk.net), since the resolver should already have resolved it.
        Otherwise it is an error.
        Sender host has already been translated to network JID by the resolver
        at this point - if it's from our network.
        """

        if stanza.hasAttribute('to'):
            to = jid.JID(stanza['to'])
            # process only our JIDs
            if to.host == self.servername:
                if to.user is not None:
                    sender = jid.JID(stanza['from'])
                    sender.host = self.network
                    stanza['from'] = sender.full()

                    to.host = self.network
                    stanza['to'] = to.full()
                    try:
                        self.sfactory.dispatch(stanza)
                    except:
                        # full JID doesn't exist, send to bare JID
                        if to.resource is not None:
                            # remove resource to avoid loops
                            to.resource = None
                            stanza['to'] = to.full()
                            self.sfactory.dispatch(stanza)

                        # bare JID doesn't exist, send back to resolver
                        else:
                            self.send(stanza)
                else:
                    self.local(stanza)
            else:
                log.debug("stanza is not our concern or is an error")

    def onError(self, stanza):
        log.debug("routing error: %s" % (stanza.toXml()))

        # unroutable stanza :(
        if stanza['type'] == 'unroutable':
            e = error.StanzaError('service-unavailable', 'cancel')
            self.dispatch(e.toResponse(stanza.firstChildElement()))

    def local(self, stanza):
        """Handle stanzas delivered to this component."""

        # resolver is up! Broadcast all of our local presence data
        if stanza.name == 'presence' and stanza['from'] == self.network:
            log.debug("resolver is online - restoring presence state")

            for userid, resources in self.sfactory.streams.iteritems():
                for resource in resources:
                    sender = jid.JID(tuple=(userid, self.servername, resource))
                    def send_presence(data, sender):
                        presence = domish.Element((None, 'presence'))
                        presence['from'] = sender.full()

                        if data['status'] is not None:
                            presence.addElement((None, 'status'), content=data['status'])
                        if data['show'] is not None:
                            presence.addElement((None, 'show'), content=data['show'])

                        self.send(presence)

                    d = self.presencedb.get(sender)
                    d.addCallback(send_presence, sender=sender)
