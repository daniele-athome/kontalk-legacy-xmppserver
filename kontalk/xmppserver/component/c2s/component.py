# -*- coding: utf-8 -*-
"""Kontalk XMPP c2s component."""
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


import time
import base64
import traceback

from twisted.internet import reactor, defer
from twisted.application import strports, internet
from twisted.application.internet import StreamServerEndpointService
from twisted.cred import portal
from twisted.internet.protocol import ServerFactory

from twisted.words.protocols.jabber import xmlstream, jid, error
from twisted.words.xish import domish, xmlstream as xish_xmlstream

from gnutls.crypto import OpenPGPCertificate, OpenPGPPrivateKey

try:
    from OpenSSL import crypto
    from twisted.internet import ssl
except ImportError:
    ssl = None
if ssl and not ssl.supported:
    ssl = None

from wokkel import component

from kontalk.xmppserver import log, auth, keyring, util, storage, xmlstream2, tls
from kontalk.xmppserver.component.sm import component as sm
import handlers


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
        self.tls_ctx = None

    def loadPEM(self, certfile, keyfile):
        if ssl is None:
            raise xmlstream.TLSNotSupported()

        self.tls_ctx = xmlstream2.MyOpenSSLCertificateOptions(keyfile, certfile, self._sslVerify)

    def getSSLContext(self):
        return self.tls_ctx

    def _sslVerify(self, conn, cert, errno, depth, preverify_ok):
        # TODO is this safe?
        return True

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

        if resource in self.streams[userid]:
            log.debug("resource conflict for %s" % (xs.otherEntity, ))
            self.streams[userid][resource].conflict()
        self.streams[userid][resource] = xs.manager

    def connectionLost(self, xs, reason):
        """Called from the handler when connection to a client is lost."""
        if xs.otherEntity is not None:
            userid, resource = util.jid_to_userid(xs.otherEntity, True)
            if userid in self.streams and resource in self.streams[userid] and self.streams[userid][resource] == xs.manager:
                del self.streams[userid][resource]
                if len(self.streams[userid]) == 0:
                    del self.streams[userid]

    def check_conflict(self, _jid):
        """Checks for local conflict and disconnects the conflicting local resource."""
        if _jid.user and _jid.host in self.router.keyring.hostlist():
            if _jid.user in self.streams and _jid.resource in self.streams[_jid.user]:
                log.debug("network resource conflict for %s" % (_jid.full(), ))
                self.streams[_jid.user][_jid.resource].conflict()

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
        userid, unused, resource = jid.parse(stanza['to'])

        util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)

        if resource is not None:
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
            (xmlstream2.TLSReceivingInitializer, True, False),
            (xmlstream2.SASLReceivingInitializer, True, True),
            (xmlstream2.RegistrationInitializer, True, True),
            # doesn't work yet -- (compression.CompressReceivingInitializer, False, False),
            (xmlstream2.BindInitializer, True, False),
            (xmlstream2.SessionInitializer, False, False),
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
            init.deinitialize()
            self.xmlstream.initializers.remove(init)

        log.debug("initializers=%r" % (self.xmlstream.initializers, ))
        if not required:
            self.xmlstream.dispatch(self.xmlstream, xmlstream.STREAM_AUTHD_EVENT)


class C2SComponent(xmlstream2.SocketComponent):
    """
    Kontalk c2s component.
    L{StreamManager} is for the connection with the router.
    """

    """
    How many seconds to wait for a receipt before a message goes to offline
    storage.
    """
    OFFLINE_STORE_DELAY = 10

    protocolHandlers = (
        handlers.InitialPresenceHandler,
        handlers.PresenceProbeHandler,
        handlers.LastActivityHandler,
        handlers.PresenceSubscriptionHandler,
        handlers.MessageHandler,
    )

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
        self.start_time = time.time()
        self.registration = None
        self.push_manager = None
        self.stanzadb = None
        self.presencedb = None
        self.validationdb = None
        self.keyring = None
        self.sfactory = None

        # protocol handlers here!!
        for handler in self.protocolHandlers:
            handler().setHandlerParent(self)

    def setup(self):
        # initialize storage
        # doing it here because it's needed by the c2s server factory
        storage.init(self.config['database'])
        self.presencedb = storage.MySQLPresenceStorage()

        try:
            stanza_expire = self.config['stanza_expire']
        except KeyError:
            stanza_expire = 0
        self.stanzadb = storage.MySQLStanzaStorage(stanza_expire)

        try:
            validation_expire = self.config['registration']['expire']
        except KeyError:
            validation_expire = 0
        self.validationdb = storage.MySQLUserValidationStorage(validation_expire)

        self.keyring = keyring.Keyring(storage.MySQLNetworkStorage(), self.config['fingerprint'], self.network, self.servername)
        authrealm = auth.SASLRealm("Kontalk")
        authportal = portal.Portal(authrealm, [auth.AuthKontalkChecker(self.config['fingerprint'], self.keyring, self._verify_fingerprint)])

        self.sfactory = XMPPServerFactory(authportal, self, self.network, self.servername)
        self.sfactory.logTraffic = self.config['debug']
        if 'ssl_key' in self.config and 'ssl_cert' in self.config:
            self.sfactory.loadPEM(self.config['ssl_cert'], self.config['ssl_key'])

        services = []

        if 'plain' in self.config['bind']:
            plain_svc = strports.service('tcp:' + str(self.config['bind']['plain'][1]) +
                ':interface=' + str(self.config['bind']['plain'][0]), self.sfactory)
            services.append(plain_svc)

        if 'ssl' in self.config['bind']:
            ssl_svc = internet.SSLServer(port=int(self.config['bind']['ssl'][1]),
                interface=str(self.config['bind']['ssl'][0]),
                factory=self.sfactory,
                contextFactory=self.sfactory.getSSLContext())

            services.append(ssl_svc)

        if 'tls' in self.config['bind']:
            cert = OpenPGPCertificate(open(self.config['pgp_cert']).read())
            key = OpenPGPPrivateKey(open(self.config['pgp_key']).read())

            cred = auth.OpenPGPKontalkCredentials(cert, key, str(self.config['pgp_keyring']))
            cred.verify_peer = True
            tls_svc = StreamServerEndpointService(
                tls.TLSServerEndpoint(reactor=reactor,
                    port=int(self.config['bind']['tls'][1]),
                    interface=str(self.config['bind']['tls'][0]),
                    credentials=cred),
                self.sfactory)
            tls_svc._raiseSynchronously = True

            services.append(tls_svc)

        return services

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

    def upload_enabled(self):
        return 'upload' in self.config and 'enabled' in self.config['upload'] and self.config['upload']['enabled']

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
        self.xmlstream.addObserver("/iq", self.iq, 50)
        self.xmlstream.addObserver("/iq", self.dispatch)
        # <message/> has its own handler

        # bind to servername route
        """
        bind = domish.Element((None, 'bind'))
        bind['name'] = self.servername
        xs.send(bind)
        """

    def _disconnected(self, reason):
        component.Component._disconnected(self, reason)
        log.debug("lost connection to router (%s)" % (reason, ))

    def iq(self, stanza):
        """
        Removes the from attribute if it matches the c2s JID.
        This was actually done to "fake" IQ stanzas coming from
        remote c2s that should appear to the client as coming from nowhere.
        """

        sender = stanza.getAttribute('from')
        if sender and not ('@' in sender):
            # receiving iq from remote c2s, remove from attribute
            unused, host = util.jid_component(sender, util.COMPONENT_C2S)

            if host in self.keyring.hostlist():
                del stanza['from']

    def send_wrapped(self, stanza, sender, destination=None):
        """
        Wraps the given stanza in a <stanza/> stanza intended to the given
        recipient. If recipient is None, the "to" of the original stanza is used.
        """

        envelope = domish.Element((None, 'stanza'))
        envelope['from'] = sender
        envelope['to'] = destination if destination else stanza['to']
        envelope.addChild(stanza)
        self.send(envelope)

    def send(self, stanza):
        # TODO
        pass

    def dispatch(self, stanza):
        """Dispatches stanzas from the router."""

        if not stanza.consumed:
            stanza.consumed = True

            util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)

            if stanza.hasAttribute('to'):
                to = jid.JID(stanza['to'])
                # process only our JIDs
                if util.jid_local(util.COMPONENT_C2S, self, to):
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

                # TODO stanzas from s2s will be network domain!! They must be resolved!

    def local(self, stanza):
        """Handle stanzas delivered to this component."""
        # nothing here yet...
        pass

    def not_found(self, stanza):
        """Handle stanzas for unavailable resources."""
        # TODO if stanza.name == ...
        pass

    def consume(self, stanza):
        stanza.consumed = True

    def _verify_fingerprint(self, userjid, fingerprint):
        """Check if the given fingerprint matches with the currently cached one."""
        if self.keyring.get_fingerprint(userjid.user) == fingerprint:
            return defer.succeed(userjid)
        else:
            return defer.fail(Exception())

    def _local_presence_output(self, data, user):
        log.debug("data: %r" % (data, ))
        # this will be used to set a safe recipient
        # WARNING this will create a JID anyway :(
        to = self.resolveJID(user).full()
        for msg in data:
            log.debug("msg[%s]=%s" % (msg['id'], msg['stanza'].toXml().encode('utf-8'), ))
            try:
                """
                Mark the stanza with our server name, so we'll receive a
                copy of the receipt
                """
                if msg['stanza'].request:
                    msg['stanza'].request['from'] = self.xmlstream.thisEntity.full()
                elif msg['stanza'].received:
                    msg['stanza'].received['from'] = self.xmlstream.thisEntity.full()

                # mark delayed delivery
                if 'timestamp' in msg:
                    delay = msg['stanza'].addElement((xmlstream2.NS_XMPP_DELAY, 'delay'))
                    delay['stamp'] = msg['timestamp'].strftime(xmlstream2.XMPP_STAMP_FORMAT)

                """
                We use direct delivery here: it's faster and does not
                involve JID resolution
                """
                msg['stanza']['to'] = to
                self.dispatch(msg['stanza'])

                """
                If a receipt is requested, we won't delete the message from
                storage now; we must be sure client has received it.
                Otherwise just delete the message immediately.
                """
                if not xmlstream2.extract_receipt(msg['stanza'], 'request'):
                    self.message_offline_delete(msg['id'], msg['stanza'].name)
            except:
                log.debug("offline message delivery failed (%s)" % (msg['id'], ))
                traceback.print_exc()

    def local_presence(self, user, stanza):
        """
        Called by sm after receiving a local presence.
        """

        available = not stanza.hasAttribute('type')

        # send presence to storage
        if user.user:
            if stanza.getAttribute('type') == 'unavailable':
                self.presencedb.touch(user.user)
            else:
                self.presencedb.presence(stanza)

        if available:
            # initial presence - deliver offline storage
            d = self.stanzadb.get_by_recipient(user)
            d.addCallback(self._local_presence_output, user)

    def local_vcard(self, user, stanza):
        """
        Called by SM when receiving a vCard from a local client.
        It checks vcard info (including public key) and if positive, sends the
        vCard to all remote c2s.
        @return: iq result or error stanza for the client
        """
        if self.logTraffic:
            log.debug("client sent vcard: %s" % (stanza.toXml(), ))
        else:
            log.debug("client sent vcard: %s" % (stanza['to'], ))
        stanza.consumed = True

        stanza_to = stanza.getAttribute('to')
        if stanza_to:
            entity = jid.JID(stanza_to)
        else:
            entity = None

        # setting our own vcard
        if not entity or (entity.userhost() == user.userhost()):
            # TODO parse vcard for interesting sections

            if stanza.vcard.key is not None:
                # we do this because of the uri member in domish.Element
                keydata = stanza.vcard.key.firstChildElement()
                if keydata and keydata.name == 'uri':
                    keydata = str(keydata)

                    if keydata.startswith(xmlstream2.DATA_PGP_PREFIX):
                        try:
                            keydata = base64.b64decode(keydata[len(xmlstream2.DATA_PGP_PREFIX):])
                        except:
                            log.debug("invalid base64 data")
                            e = xmlstream.error.StanzaError('bad-request', text='Invalid public key.')
                            iq = xmlstream.toResponse(stanza, 'error')
                            iq.addChild(e.getElement())
                            return iq

                        # check key
                        fp = self.keyring.check_user_key(keydata, user.user)
                        if fp:
                            # generate response beforing tampering with the stanza
                            response = xmlstream.toResponse(stanza, 'result')
                            # update presencedb
                            self.presencedb.public_key(user.user, fp)

                            # send vcard to all remote c2s
                            for server in self.keyring.hostlist():
                                if server != self.servername:
                                    stanza['id'] = util.rand_str(8)
                                    stanza['to'] = util.component_jid(server, util.COMPONENT_C2S)
                                    # consume any response (very high priority)
                                    self.xmlstream.addOnetimeObserver("/iq[@id='%s']" % stanza['id'], self.consume, 500)

                                    # wrap stanza in an envelope because we want errors to return to us
                                    self.send_wrapped(stanza, self.xmlstream.thisEntity.full())

                            # send response
                            return response
                        else:
                            log.debug("invalid key - authorization to vCard denied")
                            e = xmlstream.error.StanzaError('bad-request', text='Invalid public key.')
                            iq = xmlstream.toResponse(stanza, 'error')
                            iq.addChild(e.getElement())
                            return iq
        else:
            log.debug("authorization to vCard denied")
            e = xmlstream.error.StanzaError('not-allowed', text='Not authorized.')
            iq = xmlstream.toResponse(stanza, 'error')
            iq.addChild(e.getElement())
            return iq

    def broadcast_public_key(self, userid, keydata):
        """Broadcasts to all remote c2s the given public key."""
        # create vcard
        iq_vcard = domish.Element((None, 'iq'))
        iq_vcard['type'] = 'set'
        iq_vcard['from'] = util.userid_to_jid(userid, self.xmlstream.thisEntity.host).full()

        # add vcard
        vcard = iq_vcard.addElement((xmlstream2.NS_XMPP_VCARD4, 'vcard'))
        if keydata:
            vcard_key = vcard.addElement((None, 'key'))
            vcard_data = vcard_key.addElement((None, 'uri'))
            vcard_data.addContent(xmlstream2.DATA_PGP_PREFIX + base64.b64encode(keydata))

        # send vcard to remote c2s
        for server in self.keyring.hostlist():
            if server != self.servername:
                iq_vcard['id'] = util.rand_str(8)
                # remote server
                iq_vcard['to'] = util.component_jid(server, util.COMPONENT_C2S)
                # consume any response (very high priority)
                self.xmlstream.addOnetimeObserver("/iq[@id='%s']" % iq_vcard['id'], self.consume, 500)
                # send!
                self.send_wrapped(iq_vcard, self.xmlstream.thisEntity.full())

    def resolveJID(self, _jid):
        """Transform host attribute of JID from network name to server name."""
        if isinstance(_jid, jid.JID):
            return jid.JID(tuple=(_jid.user, self.xmlstream.thisEntity.host, _jid.resource))
        else:
            _jid = jid.JID(_jid)
            _jid.host = self.xmlstream.thisEntity.host
            return _jid

    def message_offline_delete(self, stanzaId, stanzaName, sender=None, recipient=None):
        """
        Deletes a message from offline storage.
        """
        return self.stanzadb.delete(stanzaId, stanzaName, sender, recipient)

    def message_offline_store(self, stanza, delayed=False, reuseId=None):
        """
        Stores a message stanza to the offline storage.
        @param delayed: True to delay the actual store action; this is useful
        when waiting for a confirmation receipt, in order to avoid storing the
        message before sending it. If confirmation is not received after a
        defined time, message will be stored.
        @param reuseId: string to reuse an existing stanza id if present;
        None to generate a random id.
        """
        return self.stanzadb.store(stanza, self.network, delayed, reuseId)
