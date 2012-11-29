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

from wokkel import component

from kontalk.xmppserver import log, auth, keyring, util, storage
from kontalk.xmppserver import xmlstream2
import sm


class XMPPServerFactory(xish_xmlstream.XmlStreamFactoryMixin, ServerFactory):
    """
    The XMPP server factory for incoming client connections.
    @type streams: C{dict}
    """

    protocol = xmlstream.XmlStream
    manager = sm.C2SManager

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

    def dispatch(self, stanza):
        """
        Dispatch a stanza to a JID all to all available resources found locally.
        @raise L{KeyError}: if a destination route is not found
        """
        to = jid.JID(stanza['to'])
        userid, resource = util.jid_to_userid(to, True)

        util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)

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


class PresenceProbeHandler(XMPPHandler):
    """Handles presence stanza with type 'probe'."""

    def __init__(self):
        XMPPHandler.__init__(self)

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence[@type='probe']", self.probe, 100)

    def probe(self, stanza):
        """Handle presence probes from router."""
        log.debug("local presence probe: %s" % (stanza.toXml(), ))
        stanza.consumed = True

        def _db(presence, stanza):
            log.debug("presence: %r" % (presence, ))
            if type(presence) == list:
                if len(presence) > 1:
                    chain = domish.Element((xmlstream2.NS_XMPP_STANZA_GROUP, 'group'))
                    chain['id'] = stanza['id']
                    chain['count'] = str(len(presence))
                else:
                    chain = None

                for user in presence:
                    response = xmlstream2.toResponse(stanza)
                    response['id'] = util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
                    response_from = util.userid_to_jid(user['userid'], self.parent.servername)
                    response['from'] = response_from.full()

                    if user['status'] is not None:
                        response.addElement((None, 'status'), content=user['status'])
                    if user['show'] is not None:
                        response.addElement((None, 'show'), content=user['show'])

                    if not self.parent.sfactory.client_connected(response_from):
                        response['type'] = 'unavailable'
                        delay = domish.Element(('urn:xmpp:delay', 'delay'))
                        delay['stamp'] = user['timestamp'].strftime('%Y-%m-%dT%H:%M:%SZ')
                        response.addChild(delay)

                    if chain:
                        response.addChild(chain)

                    self.send(response)
                    log.debug("probe result sent: %s" % (response.toXml().encode('utf-8'), ))
            elif presence is not None:
                response = xmlstream2.toResponse(stanza)

                if presence['status'] is not None:
                    response.addElement((None, 'status'), content=presence['status'])
                if presence['show'] is not None:
                    response.addElement((None, 'show'), content=presence['show'])

                self.send(response)
                log.debug("probe result sent: %s" % (response.toXml().encode('utf-8'), ))
            else:
                # TODO return error?
                log.debug("probe: user not found")

        to = jid.JID(stanza['to'])
        d = self.parent.presencedb.get(to)
        d.addCallback(_db, stanza)


class LastActivityHandler(XMPPHandler):
    """
    XEP-0012: Last activity
    http://xmpp.org/extensions/xep-0012.html
    """
    def __init__(self):
        XMPPHandler.__init__(self)

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='get']/query[@xmlns='%s']" % (xmlstream2.NS_IQ_LAST, ), self.last_activity, 100)

    def last_activity(self, stanza):
        log.debug("local last activity request: %s" % (stanza.toXml(), ))
        stanza.consumed = True

        def _db(presence, stanza):
            log.debug("iq/last: presence=%r" % (presence, ))
            if type(presence) == list and len(presence) > 0:
                user = presence[0]

                response = xmlstream2.toResponse(stanza, 'result')
                response_from = util.userid_to_jid(user['userid'], self.parent.servername)
                response['from'] = response_from.userhost()

                query = response.addElement((xmlstream2.NS_IQ_LAST, 'query'))
                if self.parent.sfactory.client_connected(response_from):
                    query['seconds'] = '0'
                else:
                    latest = None
                    for user in presence:
                        if latest is None or max['timestam'] > user['timestamp']:
                            latest = user
                    # TODO timediff from latest
                    log.debug("max timestamp: %r" % (max, ))
                    query['seconds'] = '123456'

                self.send(response)
                log.debug("iq/last result sent: %s" % (response.toXml().encode('utf-8'), ))

            else:
                # TODO return error?
                log.debug("iq/last: user not found")

        to = jid.JID(stanza['to'])
        d = self.parent.presencedb.get(to)
        d.addCallback(_db, stanza)


class MessageHandler(XMPPHandler):
    """Message stanzas handler."""

    def connectionInitialized(self):
        self.xmlstream.addObserver("/message", self.dispatch)

    def features(self):
        return tuple()

    def dispatch(self, stanza):
        if not stanza.consumed:
            log.debug("incoming stanza: %s" % (stanza.toXml().encode('utf-8')))
            stanza.consumed = True

            util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)

            if stanza.hasAttribute('to'):
                to = jid.JID(stanza['to'])
                # process only our JIDs
                if to.host == self.parent.servername:
                    if to.user is not None:
                        msgId = util.rand_str(30, util.CHARSBOX_AZN_LOWERCASE)
                        try:
                            self.parent.sfactory.dispatch(stanza)
                            status = 'received'
                        except:
                            # manager not found - send error or send to offline storage
                            log.debug("c2s manager for %s not found" % (stanza['to'], ))
                            self.not_found(stanza)
                            status = 'stored'

                        # send ack
                        if not stanza.received and not stanza.stored:
                            self.send_ack(stanza, msgId, status)

                    else:
                        # deliver local stanza
                        self.parent.local(stanza)
                else:
                    log.debug("stanza is not our concern or is an error")

    def send_ack(self, stanza, msgId, status):
        ack = xmlstream2.toResponse(stanza, stanza['type'])
        rec = ack.addElement(('urn:xmpp:receipts', status))
        rec['id'] = msgId
        self.send(ack)

    def not_found(self, stanza):
        """Handle messages for unavailable resources."""

        # store message for bare JID
        stanza['to'] = jid.JID(stanza['to']).userhost()
        # safe uri for persistance
        stanza.uri = stanza.defaultUri = sm.C2SManager.namespace
        self.message_offline(stanza)

    def message_offline(self, stanza):
        """Stores a message stanza to the storage."""

        log.debug("storing offline message for %s" % (stanza['to'], ))
        self.stanzadb.store(stanza)


class C2SComponent(component.Component):
    """
    Kontalk c2s component.
    L{StreamManager} is for the connection with the router.
    """

    protocolHandlers = (
        PresenceProbeHandler,
        LastActivityHandler,
        MessageHandler,
    )

    def __init__(self, config):
        router_cfg = config['router']
        component.Component.__init__(self, router_cfg['host'], router_cfg['port'], router_cfg['jid'], router_cfg['secret'])
        self.config = config
        self.logTraffic = config['debug']
        self.network = config['network']
        self.servername = config['host']
        self.start_time = time.time()

        # protocol handlers here!!
        for handler in self.protocolHandlers:
            handler().setHandlerParent(self)

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

    def _disconnected(self, reason):
        component.Component._disconnected(self, reason)
        log.debug("lost connection to router (%s)" % (reason, ))

    def dispatch(self, stanza):
        """
        Stanzas from router must be intended to a server JID (e.g.
        prime.kontalk.net), since the resolver should already have resolved it.
        Otherwise it is an error.
        Sender host has already been translated to network JID by the resolver
        at this point - if it's from our network.
        """

        if not stanza.consumed:
            log.debug("incoming stanza: %s" % (stanza.toXml().encode('utf-8')))
            stanza.consumed = True

            util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)

            if stanza.hasAttribute('to'):
                to = jid.JID(stanza['to'])
                # process only our JIDs
                if to.host == self.servername:
                    if to.user is not None:
                        try:
                            """ TEST to store message anyway :)
                            if stanza.name == 'message':
                                raise Exception()
                            """
                            self.sfactory.dispatch(stanza)
                        except:
                            # manager not found - send error or send to offline storage
                            log.debug("c2s manager for %s not found" % (stanza['to'], ))
                            self.not_found(stanza)
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
        pass

    def not_found(self, stanza):
        """Handle stanzas for unavailable resources."""
        # TODO if stanza.name == ...
        pass
