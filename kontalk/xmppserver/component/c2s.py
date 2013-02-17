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
import traceback

from twisted.application import strports
from twisted.cred import portal
from twisted.internet.protocol import ServerFactory

from twisted.words.protocols.jabber import xmlstream, jid, error
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish, xmlstream as xish_xmlstream

try:
    from OpenSSL import crypto
    from twisted.internet import ssl
except ImportError:
    ssl = None
if ssl and not ssl.supported:
    ssl = None

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

    def loadPEM(self, certfile, keyfile):
        if ssl is None:
            raise xmlstream.TLSNotSupported()

        cert = open(certfile, 'rb')
        cert_buf = cert.read()
        cert.close()
        cert = open(keyfile, 'rb')
        key_buf = cert.read()
        cert.close()

        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key_buf)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_buf)
        self.tls_ctx = ssl.CertificateOptions(privateKey=pkey, certificate=cert)

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

        # TODO what about network conflicts??
        if resource in self.streams[userid]:
            log.debug("resource conflict for %s" % (xs.otherEntity, ))
            self.streams[userid][resource].conflict()
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


# TODO this class need to be tested extensively
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
            (xmlstream2.TLSReceivingInitializer, False, False),
            (xmlstream2.SASLReceivingInitializer, True, True),
            (xmlstream2.RegistrationInitializer, True, True),
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

            required = False
            for initializer in self.xmlstream.initializers:
                if required and (not hasattr(initializer, 'exclusive') or not initializer.exclusive):
                    log.debug("skipping %r" % (initializer, ))
                    continue

                feature = initializer.feature()
                if feature is not None:
                    features.addChild(feature)
                if hasattr(initializer, 'required') and initializer.required and \
                        hasattr(initializer, 'exclusive') and initializer.exclusive:
                    log.debug("required and exclusive: %r" % (initializer, ))
                    if not required:
                        required = True

            self.xmlstream.send(features)

    def canInitialize(self, initializer):
        inits = self.xmlstream.initializers[0:self.xmlstream.initializers.index(initializer)]

        # check if there are required inits that should have been run first
        if not hasattr(initializer, 'exclusive') or not initializer.exclusive:
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
        remove = []
        for init in self.xmlstream.initializers:
            if hasattr(initializer, 'exclusive') and initializer.exclusive and hasattr(init, 'exclusive') and init.exclusive:
                remove.append(init)
            if hasattr(init, 'required') and init.required:
                required = True

        for init in remove:
            log.debug("removing initializer %r" % (init, ))
            self.xmlstream.initializers.remove(init)

        log.debug("initializers=%r" % (self.xmlstream.initializers, ))
        if not required:
            self.xmlstream.dispatch(self.xmlstream, xmlstream.STREAM_AUTHD_EVENT)


class InitialPresenceHandler(XMPPHandler):
    """
    Handle presence stanzas and client disconnection.
    @type parent: L{C2SManager}
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence[not(@type)][@to='%s']" % (self.parent.servername, ), self.presence)

    def presence(self, stanza):
        """
        This initial presence is from a broadcast sent by external entities
        (e.g. not the sm); sm wouldn't see it because it has no observer.
        Here we are sending offline messages to the resolver which will deliver
        them through the actual route.
        """

        # initial presence - deliver offline storage
        def output(data):
            log.debug("data: %r" % (data, ))
            for msgId, msg in data.iteritems():
                log.debug("msg[%s]=%s" % (msgId, msg['stanza'].toXml().encode('utf-8'), ))
                try:
                    """
                    Mark the stanza with our server name, so we'll receive a
                    copy of the receipt
                    """
                    if msg['stanza'].request:
                        msg['stanza'].request['origin'] = self.parent.servername

                    self.send(msg['stanza'])
                    """
                    We don't delete the message from storage now; we must be
                    sure remote sm has received it.
                    """
                except:
                    traceback.print_exc()
                    log.debug("offline message delivery failed (%s)" % (msgId, ))

        d = self.parent.stanzadb.get_by_recipient(jid.JID(stanza['from']))
        d.addCallback(output)


class PresenceProbeHandler(XMPPHandler):
    """Handles presence stanza with type 'probe'."""

    def __init__(self):
        XMPPHandler.__init__(self)

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence[@type='probe']", self.probe, 100)

    def probe(self, stanza):
        """Handle presence probes from router."""
        #log.debug("local presence probe: %s" % (stanza.toXml(), ))
        stanza.consumed = True

        def _db(presence, stanza):
            #log.debug("presence: %r" % (presence, ))
            if type(presence) == list:
                chain = domish.Element((xmlstream2.NS_XMPP_STANZA_GROUP, 'group'))
                chain['id'] = stanza['id']
                chain['count'] = str(len(presence))

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
                        delay['stamp'] = user['timestamp'].strftime(xmlstream2.XMPP_STAMP_FORMAT)
                        response.addChild(delay)

                    response.addChild(chain)

                    self.send(response)
                    log.debug("probe result sent: %s" % (response.toXml().encode('utf-8'), ))
            elif presence is not None:
                chain = domish.Element((xmlstream2.NS_XMPP_STANZA_GROUP, 'group'))
                chain['id'] = stanza['id']
                chain['count'] = '1'

                response = xmlstream2.toResponse(stanza)

                if presence['status'] is not None:
                    response.addElement((None, 'status'), content=presence['status'])
                if presence['show'] is not None:
                    response.addElement((None, 'show'), content=presence['show'])

                response.addChild(chain)
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
                        if latest is None or latest['timestamp'] > user['timestamp']:
                            latest = user
                    # TODO timediff from latest
                    #log.debug("max timestamp: %r" % (max, ))
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
        self.xmlstream.addObserver("/message[@type='error']/error/network-server-timeout", self.network_timeout, 100)

    def features(self):
        return tuple()

    def network_timeout(self, stanza):
        """
        Handles errors from the net component (e.g. kontalk server not responding).
        """
        stanza.consumed = True
        util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)
        message = stanza.original.firstChildElement()
        self.not_found(message)

        # send ack only for chat messages
        if message.getAttribute('type') == 'chat':
            self.send_ack(message, 'sent')

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
                        receipt = xmlstream2.extract_receipt(stanza, ('request')) or \
                            xmlstream2.extract_receipt(stanza, ('received'))
                        try:
                            """
                            We are deliberately ignoring messages with sent
                            receipt because they are assumed to be volatile.
                            """
                            if receipt:
                                # send message to offline storage just to be safe
                                stanza['id'] = self.message_offline(stanza)
                            # send message to sm
                            self.parent.sfactory.dispatch(stanza)

                            """
                            If message is a received receipt, we have just delivered it.
                            It's not really a big deal if a receipt is lost...
                            """
                            received = xmlstream2.extract_receipt(stanza, 'received')
                            if received:
                                # delete the receipt
                                self.parent.stanzadb.delete(stanza['id'])
                                # delete the received message
                                self.parent.stanzadb.delete(received['id'])
                        except:
                            # manager not found - send error or send to offline storage
                            log.debug("c2s manager for %s not found" % (stanza['to'], ))
                            # receipt not present - send to offline storage
                            if not receipt and stanza.body:
                                stanza['id'] = self.message_offline(stanza)
                            if self.parent.push_manager and (stanza.body and (not receipt or receipt.name == 'request')):
                                self.parent.push_manager.notify(to)

                        stamp = time.time()

                        # sent receipt will be sent only if message is not coming from storage
                        if not xmlstream2.has_element(stanza, xmlstream2.NS_XMPP_STORAGE, 'storage'):
                            # send ack only for chat messages (if requested)
                            if stanza.getAttribute('type') == 'chat' and xmlstream2.extract_receipt(stanza, 'request'):
                                self.send_ack(stanza, 'sent', stamp)
                            # send receipt to originating server, if requested
                            try:
                                origin = stanza.request.getAttribute['origin']
                                stanza['to'] = origin
                                self.send_ack(stanza, 'sent', stamp)
                            except:
                                pass

                    else:
                        # deliver local stanza
                        self.parent.local(stanza)

                    """
                    If message is a receipt coming from a remote server, delete
                    the message from our storage.
                    """
                    r_sent = xmlstream2.extract_receipt(stanza, 'sent')
                    r_received = xmlstream2.extract_receipt(stanza, 'received')
                    receipt = r_sent if r_sent else r_received
                    if receipt is not None:
                        sender = jid.JID(stanza['from'])
                        """
                        We are receiving a sent receipt from another server,
                        meaning that the server has now responsibility for the
                        message - we can delete it now.
                        """
                        if sender.host != self.parent.servername:
                            self.parent.stanzadb.delete(receipt['id'])

                else:
                    log.debug("stanza is not our concern or is an error")

    def send_ack(self, stanza, status, stamp=None):
        request = xmlstream2.extract_receipt(stanza, 'request')
        ack = xmlstream2.toResponse(stanza, stanza.getAttribute('type'))
        rec = ack.addElement((xmlstream2.NS_XMPP_SERVER_RECEIPTS, status))
        rec['id'] = request['id']
        if stamp:
            rec['stamp'] = time.strftime(xmlstream2.XMPP_STAMP_FORMAT, time.gmtime(stamp))
        self.send(ack)

    def message_offline(self, stanza):
        """Stores a message stanza to the storage."""

        # TEST using deepcopy is not safe
        from copy import deepcopy
        stanza = deepcopy(stanza)

        # check if an id is present in the receipt, otherwise generate a new one
        receipt = xmlstream2.extract_receipt(stanza, 'request')
        if not receipt:
            stanza['id'] = util.rand_str(30, util.CHARSBOX_AZN_LOWERCASE)

        # store message for bare network JID
        jid_to = jid.JID(stanza['to'])
        jid_to.host = self.parent.network
        stanza['to'] = jid_to.userhost()

        # sender JID should be a network JID
        jid_from = jid.JID(stanza['from'])
        jid_from.host = self.parent.network
        stanza['from'] = jid_from.full()

        try:
            del stanza['origin']
        except KeyError:
            pass

        # safe uri for persistance
        stanza.uri = stanza.defaultUri = sm.C2SManager.namespace

        log.debug("storing offline message for %s" % (stanza['to'], ))
        try:
            self.parent.stanzadb.store(stanza)
        except:
            traceback.print_exc()

        return stanza['id']


class C2SComponent(component.Component):
    """
    Kontalk c2s component.
    L{StreamManager} is for the connection with the router.
    """

    protocolHandlers = (
        InitialPresenceHandler,
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
        self.registration = None
        self.push_manager = None

        # protocol handlers here!!
        for handler in self.protocolHandlers:
            handler().setHandlerParent(self)

    def setup(self):
        # initialize storage
        # doing it here because it's needed by the c2s server factory
        storage.init(self.config['database'])
        self.stanzadb = storage.MySQLStanzaStorage()
        self.presencedb = storage.MySQLPresenceStorage()
        self.validationdb = storage.MySQLUserValidationStorage()

        self.keyring = keyring.Keyring(storage.MySQLNetworkStorage(), self.config['fingerprint'], self.servername)
        authrealm = auth.SASLRealm("Kontalk")
        authportal = portal.Portal(authrealm, [auth.AuthKontalkToken(self.config['fingerprint'], self.keyring)])

        self.sfactory = XMPPServerFactory(authportal, self, self.network, self.servername)
        self.sfactory.logTraffic = self.config['debug']
        if 'ssl_key' in self.config and 'ssl_cert' in self.config:
            self.sfactory.loadPEM(self.config['ssl_cert'], self.config['ssl_key'])

        return strports.service('tcp:' + str(self.config['bind'][1]) +
            ':interface=' + str(self.config['bind'][0]), self.sfactory)

    def startService(self):
        component.Component.startService(self)

        # register the registration provider if configured
        if 'registration' in self.config:
            from kontalk.xmppserver import register
            provider = self.config['registration']['provider']
            try:
                prov_class = register.providers[provider]
                self.registration = prov_class(self, self.config['registration'])
            except:
                log.warn(traceback.format_exc())

        if self.registration:
            log.info("using registration provider %s (type=%s)" % (self.registration.name, self.registration.type))
        else:
            log.info("disabling registration")

        # register push notifications providers if configured
        if 'push' in self.config:
            from kontalk.xmppserver import push
            self.push_manager = push.PushManager(self, self.config['push'])

        if self.push_manager:
            log.info("using push notifications providers: %s" % (', '.join(self.push_manager.providers.keys())))
        else:
            log.info("disabling push notifictions")

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
        self.xmlstream.addObserver("/presence", self.dispatch)
        self.xmlstream.addObserver("/iq", self.dispatch)
        # <message/> has its own handler

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

    def local(self, stanza):
        """Handle stanzas delivered to this component."""
        pass

    def not_found(self, stanza):
        """Handle stanzas for unavailable resources."""
        # TODO if stanza.name == ...
        pass

    def local_presence(self, user, stanza):
        """
        Called by sm after receiving a local initial presence.
        """

        # initial presence - deliver offline storage
        def output(data):
            log.debug("data: %r" % (data, ))
            for msgId, msg in data.iteritems():
                log.debug("msg[%s]=%s" % (msgId, msg['stanza'].toXml().encode('utf-8'), ))
                try:
                    """
                    Mark the stanza with our server name, so we'll receive a
                    copy of the receipt
                    """
                    if msg['stanza'].request:
                        msg['stanza'].request['origin'] = self.servername

                    """
                    We use direct delivery here: it's faster and does not
                    involve JID resolution
                    """
                    msg['stanza']['to'] = self.resolveJID(jid.JID(msg['stanza']['to'])).full()
                    self.dispatch(msg['stanza'])

                    """
                    If a receipt is requested, we won't delete the message from
                    storage now; we must be sure client has received it.
                    Otherwise just delete the message.
                    """
                    if not xmlstream2.extract_receipt(msg['stanza'], 'request'):
                        self.stanzadb.delete(msgId)
                except:
                    traceback.print_exc()
                    log.debug("offline message delivery failed (%s)" % (msgId, ))

        d = self.stanzadb.get_by_recipient(user)
        d.addCallback(output)

    def resolveJID(self, _jid):
        """Transform host attribute of JID from network name to server name."""
        if isinstance(_jid, jid.JID):
            return jid.JID(tuple=(_jid.user, self.servername, _jid.resource))
        else:
            _jid = jid.JID(_jid)
            _jid.host = self.servername
            return _jid
