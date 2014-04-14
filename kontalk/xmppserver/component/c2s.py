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
from twisted.application import strports
from twisted.application.internet import StreamServerEndpointService
from twisted.cred import portal
from twisted.internet.protocol import ServerFactory

from twisted.words.protocols.jabber import xmlstream, jid, error
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
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
        self.tls_ctx = None

    def loadPEM(self, certfile, keyfile):
        if ssl is None:
            raise xmlstream.TLSNotSupported()

        self.tls_ctx = xmlstream2.MyOpenSSLCertificateOptions(keyfile, certfile, self._sslVerify)

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
                # already on TLS
                if tls.isTLS(self.xmlstream) and isinstance(initializer, xmlstream2.TLSReceivingInitializer):
                    log.debug("already on TLS, skipping %r" % (initializer, ))
                    continue

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


class InitialPresenceHandler(XMPPHandler):
    """
    Handle presence stanzas and client disconnection.
    @type parent: L{C2SManager}
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence[not(@type)][@to='%s']" % (self.xmlstream.thisEntity.full(), ), self.presence)

    def send_presence(self, to):
        """
        Sends all local presence data (available and unavailable) to the given
        entity.
        """

        def _db(presence, to):
            from copy import deepcopy
            log.debug("presence: %r" % (presence, ))
            if type(presence) == list and len(presence) > 0:

                for user in presence:
                    response_from = util.userid_to_jid(user['userid'], self.parent.xmlstream.thisEntity.host).full()

                    num_avail = 0
                    try:
                        streams = self.parent.sfactory.streams[user['userid']]
                        for x in streams.itervalues():
                            presence = x._presence
                            if presence and not presence.hasAttribute('type'):
                                response = domish.Element((None, 'presence'))
                                response['to'] = to
                                response['from'] = presence['from']

                                # copy stuff
                                for child in ('status', 'show', 'priority'):
                                    e = getattr(presence, child)
                                    if e:
                                        response.addChild(deepcopy(e))

                                self.send(response)

                                num_avail += 1
                    except KeyError:
                        pass

                    # no available resources - send unavailable presence
                    if not num_avail:
                        response = domish.Element((None, 'presence'))
                        response['to'] = to
                        response['from'] = response_from

                        if user['status'] is not None:
                            response.addElement((None, 'status'), content=user['status'])
                        if user['show'] is not None:
                            response.addElement((None, 'show'), content=user['show'])

                        response['type'] = 'unavailable'
                        delay = domish.Element(('urn:xmpp:delay', 'delay'))
                        delay['stamp'] = user['timestamp'].strftime(xmlstream2.XMPP_STAMP_FORMAT)
                        response.addChild(delay)

                        self.send(response)

                    if self.parent.logTraffic:
                        log.debug("presence sent: %s" % (response.toXml().encode('utf-8'), ))
                    else:
                        log.debug("presence sent: %s" % (response['from'], ))

                    # send vcard
                    iq_vcard = domish.Element((None, 'iq'))
                    iq_vcard['type'] = 'set'
                    iq_vcard['from'] = response_from
                    iq_vcard['to'] = to

                    # add vcard
                    vcard = iq_vcard.addElement((xmlstream2.NS_XMPP_VCARD4, 'vcard'))
                    if user['fingerprint']:
                        pub_key = self.parent.keyring.get_key(user['userid'], user['fingerprint'])
                        if pub_key:
                            vcard_key = vcard.addElement((None, 'key'))
                            vcard_data = vcard_key.addElement((None, 'uri'))
                            vcard_data.addContent("data:application/pgp-keys;base64," + base64.b64encode(pub_key))

                    self.send(iq_vcard)
                    if self.parent.logTraffic:
                        log.debug("vCard sent: %s" % (iq_vcard.toXml().encode('utf-8'), ))
                    else:
                        log.debug("vCard sent: %s" % (iq_vcard['from'], ))

        d = self.parent.presencedb.get_all()
        d.addCallback(_db, to)

    def presence(self, stanza):
        """
        This initial presence is from a broadcast sent by external entities
        (e.g. not the sm); sm wouldn't see it because it has no observer.
        Here we are sending offline messages directly to the connected user.
        """

        log.debug("initial presence from router by %s" % (stanza['from'], ))

        try:
            # receiving initial presence from remote or local resolver, send all presence data
            component, host = util.jid_component(stanza['from'], util.COMPONENT_RESOLVER)

            if host in self.parent.keyring.hostlist():
                log.debug("resolver appeared, sending all local presence and vCards to %s" % (stanza['from'], ))
                self.send_presence(stanza['from'])

        except:
            pass

        sender = jid.JID(stanza['from'])

        # check for external conflict
        self.parent.sfactory.check_conflict(sender)

        if sender.user:
            try:
                component, host = util.jid_component(sender.host, util.COMPONENT_C2S)

                # initial presence from a client connected to another server, clear it from our presence table
                if host != self.parent.servername and host in self.parent.keyring.hostlist():
                    log.debug("deleting %s from presence table" % (sender.user, ))
                    self.parent.presencedb.delete(sender.user)

            except:
                pass

        # initial presence - deliver offline storage
        def output(data, user):
            log.debug("data: %r" % (data, ))
            to = user.full()

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

                    msg['to'] = to
                    self.send(msg['stanza'])
                    """
                    We don't delete the message from storage now; we must be
                    sure remote sm has received it.
                    """
                except:
                    log.debug("offline message delivery failed (%s)" % (msg['id'], ))
                    traceback.print_exc()

        d = self.parent.stanzadb.get_by_recipient(sender)
        d.addCallback(output, sender)


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
            log.debug("presence: %r" % (presence, ))
            if type(presence) == list and len(presence) > 0:
                chain = domish.Element((xmlstream2.NS_XMPP_STANZA_GROUP, 'group'))
                chain['id'] = stanza['id']
                chain['count'] = str(len(presence))

                for user in presence:
                    response = xmlstream2.toResponse(stanza)
                    response['id'] = util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
                    response_from = util.userid_to_jid(user['userid'], self.xmlstream.thisEntity.host)
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

                    if self.parent.logTraffic:
                        log.debug("probe result sent: %s" % (response.toXml().encode('utf-8'), ))
                    else:
                        log.debug("probe result sent: %s" % (response['from'], ))

            elif presence is not None and type(presence) != list:
                chain = domish.Element((xmlstream2.NS_XMPP_STANZA_GROUP, 'group'))
                chain['id'] = stanza['id']
                chain['count'] = '1'

                response = xmlstream2.toResponse(stanza)

                if presence['status'] is not None:
                    response.addElement((None, 'status'), content=presence['status'])
                if presence['show'] is not None:
                    response.addElement((None, 'show'), content=presence['show'])

                response_from = util.userid_to_jid(presence['userid'], self.parent.servername)
                if not self.parent.sfactory.client_connected(response_from):
                    response['type'] = 'unavailable'
                    delay = domish.Element(('urn:xmpp:delay', 'delay'))
                    delay['stamp'] = presence['timestamp'].strftime(xmlstream2.XMPP_STAMP_FORMAT)
                    response.addChild(delay)

                response.addChild(chain)
                self.send(response)

                if self.parent.logTraffic:
                    log.debug("probe result sent: %s" % (response.toXml().encode('utf-8'), ))
                else:
                    log.debug("probe result sent: %s" % (response['from'], ))
            else:
                log.debug("probe: user not found")
                # TODO return error?
                response = xmlstream2.toResponse(stanza, 'error')

                chain = domish.Element((xmlstream2.NS_XMPP_STANZA_GROUP, 'group'))
                chain['id'] = stanza['id']
                chain['count'] = '1'
                response.addChild(chain)

                self.send(response)

        userid = util.jid_user(stanza['to'])
        d = self.parent.presencedb.get(userid)
        d.addCallback(_db, stanza)


class LastActivityHandler(XMPPHandler):
    """
    XEP-0012: Last activity
    http://xmpp.org/extensions/xep-0012.html
    TODO this needs serious fixing
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
                response_from = util.userid_to_jid(user['userid'], self.xmlstream.thisEntity.host)
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

        userid = util.jid_user(stanza['to'])
        d = self.parent.presencedb.get(userid)
        d.addCallback(_db, stanza)


class PresenceSubscriptionHandler(XMPPHandler):
    """Presence subscription handler."""

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence[@type='subscribe']", self.dispatch)
        self.xmlstream.addObserver("/presence[@type='subscribed']", self.subscribed)
        self.xmlstream.addObserver("/presence[@type='unsubscribed']", self.unsubscribed)

    def features(self):
        return tuple()

    def subscribed(self, stanza):
        log.debug("user has accepted subscription")
        # TODO
        pass

    def unsubscribed(self, stanza):
        log.debug("user has refused subscription")
        # TODO
        pass

    def dispatch(self, stanza):
        if not stanza.consumed:
            if self.parent.logTraffic:
                log.debug("incoming subscription request: %s" % (stanza.toXml().encode('utf-8')))

            stanza.consumed = True

            util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)

            if stanza.hasAttribute('to'):
                to = jid.JID(stanza['to'])
                # process only our JIDs
                if util.jid_local(util.COMPONENT_C2S, self.parent, to):
                    if to.user is not None:
                        try:
                            # send stanza to sm only to non-negative resources
                            self.parent.sfactory.dispatch(stanza)
                        except:
                            # manager not found - send error or send to offline storage
                            log.debug("c2s manager for %s not found" % (stanza['to'], ))
                            self.parent.message_offline_store(stanza)
                            # push notify client
                            if self.parent.push_manager:
                                self.parent.push_manager.notify(to)

                    else:
                        # deliver local stanza
                        self.parent.local(stanza)

                else:
                    log.debug("stanza is not our concern or is an error")


class MessageHandler(XMPPHandler):
    """Message stanzas handler."""

    def connectionInitialized(self):
        self.xmlstream.addObserver("/message", self.dispatch)
        self.xmlstream.addObserver("/message/ack[@xmlns='%s']" % (xmlstream2.NS_XMPP_SERVER_RECEIPTS), self.ack, 100)
        self.xmlstream.addObserver("/message[@type='error']/error/network-server-timeout", self.network_timeout, 100)

    def features(self):
        return tuple()

    def ack(self, stanza):
        stanza.consumed = True
        msgId = stanza['id']
        if msgId:
            try:
                if stanza['to'] == self.xmlstream.thisEntity.full():
                    self.parent.message_offline_delete(msgId, stanza.name)
            except:
                traceback.print_exc()

    def network_timeout(self, stanza):
        """
        Handles errors from the net component (e.g. kontalk server not responding).
        """
        stanza.consumed = True
        util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)
        message = stanza.original.firstChildElement()
        self.parent.not_found(message)

        # send ack only for chat messages
        if message.getAttribute('type') == 'chat':
            self.send_ack(message, 'sent')

    def dispatch(self, stanza):
        """
        Incoming message from router.
        A message may come from any party:
        1. local resolver
        2. remote c2s
        3. remote resolver
        """
        if not stanza.consumed:
            if self.parent.logTraffic:
                log.debug("incoming message: %s" % (stanza.toXml().encode('utf-8')))

            stanza.consumed = True

            util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)

            if stanza.hasAttribute('to'):
                to = jid.JID(stanza['to'])
                # process only our JIDs
                if util.jid_local(util.COMPONENT_C2S, self.parent, to):
                    chat_msg = (stanza.getAttribute('type') == 'chat')
                    if to.user is not None:
                        keepId = None
                        receipt = xmlstream2.extract_receipt(stanza, 'request')
                        received = xmlstream2.extract_receipt(stanza, 'received')
                        try:
                            """
                            We are deliberately ignoring messages with sent
                            receipt because they are supposed to be volatile.
                            """
                            if chat_msg and not xmlstream2.has_element(stanza, xmlstream2.NS_XMPP_STORAGE, 'storage') and (receipt or received):
                                """
                                Apply generated id if we are getting a received receipt.
                                This way stanza is received by the client with the
                                correct id to cancel preemptive storage.
                                """
                                if received:
                                    keepId = stanza['id'] = util.rand_str(30, util.CHARSBOX_AZN_LOWERCASE)

                                # send message to offline storage just to be safe (delayed)
                                keepId = self.parent.message_offline_store(stanza, delayed=True, reuseId=keepId)


                            # send message to sm only to non-negative resources
                            log.debug("sending message %s" % (stanza['id'], ))
                            self.parent.sfactory.dispatch(stanza)

                        except:
                            # manager not found - send error or send to offline storage
                            log.debug("c2s manager for %s not found" % (stanza['to'], ))
                            """
                            Since our previous call to message_offline_store()
                            was with delayed parameter, we need to store for
                            real now.
                            """
                            if chat_msg and (stanza.body or stanza.e2e or received):
                                self.parent.message_offline_store(stanza, delayed=False, reuseId=keepId)
                            if self.parent.push_manager and chat_msg and (stanza.body or stanza.e2e) and (not receipt or receipt.name == 'request'):
                                self.parent.push_manager.notify(to)

                        # if message is a received receipt, we can delete the original message
                        if chat_msg and received:
                            # delete the received message
                            # TODO safe delete with sender/recipient
                            self.parent.message_offline_delete(received['id'], stanza.name)

                        stamp = time.time()

                        """
                        Receipts will be sent only if message is not coming from
                        storage or message is from a remote server.
                        This is because if the message is coming from storage,
                        it means that it's a user collecting its offline
                        messages, so we don't need to send a <sent/> again.
                        If a message is coming from a remote server, it means
                        that is being delivered by a remote c2s by either:
                         * sm request (direct message from client)
                         * offline delivery (triggered by an initial presence from this server)
                        """
                        host = util.jid_host(stanza['from'])

                        from_storage = xmlstream2.has_element(stanza, xmlstream2.NS_XMPP_STORAGE, 'storage')

                        try:
                            log.debug("host(unparsed): %s" % (host, ))
                            unused, host = util.jid_component(host, util.COMPONENT_C2S)
                            log.debug("host(parsed): %s" % (host, ))
                            from_remote = host != self.parent.servername
                        except:
                            from_remote = False

                        if chat_msg and (not from_storage or from_remote):

                            # send ack only for chat messages (if requested)
                            # do not send if coming from remote storage
                            if chat_msg and receipt and not from_storage:
                                self.send_ack(stanza, 'sent', stamp)

                            # send receipt to originating server, if requested
                            receipt = None
                            # receipt request: send <sent/>
                            if stanza.request:
                                receipt = stanza.request
                                request = 'request'
                                delivery = 'sent'
                            # received receipt: send <ack/>
                            elif stanza.received:
                                receipt = stanza.received
                                request = 'received'
                                delivery = 'ack'

                            # now send what we prepared
                            if receipt:
                                try:
                                    from_server = receipt['from']
                                    if util.hostjid_local(util.COMPONENT_C2S, self.parent, from_server):
                                        stanza['from'] = from_server
                                        self.send_ack(stanza, delivery, stamp, request)
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
                    if chat_msg and r_sent:
                        sender_host = util.jid_host(stanza['from'])
                        """
                        We are receiving a sent receipt from another server,
                        meaning that the server has now responsibility for the
                        message - we can delete it now.
                        Special case is the sender domain being the network
                        domain, meaning the resolver rejected the message.
                        """
                        unused, sender_host = util.jid_component(sender_host)
                        if sender_host != self.parent.servername:
                            log.debug("remote server now has responsibility for message %s - deleting" % (r_sent['id'], ))
                            # TODO safe delete with sender/recipient
                            self.parent.message_offline_delete(r_sent['id'], stanza.name)

                else:
                    log.debug("stanza is not our concern or is an error")

    def send_ack(self, stanza, status, stamp=None, receipt='request'):
        request = xmlstream2.extract_receipt(stanza, receipt)
        ack = xmlstream2.toResponse(stanza, stanza.getAttribute('type'))
        rec = ack.addElement((xmlstream2.NS_XMPP_SERVER_RECEIPTS, status))
        rec['id'] = request['id']
        if stamp:
            rec['stamp'] = time.strftime(xmlstream2.XMPP_STAMP_FORMAT, time.gmtime(stamp))
        self.send(ack)


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
        InitialPresenceHandler,
        PresenceProbeHandler,
        LastActivityHandler,
        PresenceSubscriptionHandler,
        MessageHandler,
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

        # protocol handlers here!!
        for handler in self.protocolHandlers:
            handler().setHandlerParent(self)

    def setup(self):
        # initialize storage
        # doing it here because it's needed by the c2s server factory
        storage.init(self.config['database'])
        self.stanzadb = storage.MySQLStanzaStorage()
        self.presencedb = storage.MySQLPresenceStorage()

        try:
            validation_expire = self.config['registration']['expire']
        except:
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
        """Removes from attribute if it's from network name."""
        if stanza.getAttribute('from') == self.network:
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

    def dispatch(self, stanza):
        """
        Stanzas from router must be intended to a server JID (e.g.
        prime.kontalk.net), since the resolver should already have resolved it.
        Otherwise it is an error.
        Sender host has already been translated to network JID by the resolver
        at this point - if it's from our network.
        """

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
        """Requests a vCard to the resolver for fingerprint matching on login."""

        def _response(d, fingerprint, stanza):
            stanza.consumed = True
            # TODO ugly stuff

            if stanza.vcard:
                # error (TODO check if is actually vcard not found)
                if stanza.error:
                    d.callback(userjid)

                # got vcard, check if fingerprint matches
                elif stanza.vcard.key:
                    # extract key data from vcard and retrieve fingerprint
                    # we do this because of the uri member in domish.Element
                    keydata = stanza.vcard.key.firstChildElement()
                    if keydata.name == 'uri':
                        keydata = str(keydata)

                        if keydata.startswith(xmlstream2.DATA_PGP_PREFIX):
                            keydata = base64.b64decode(keydata[len(xmlstream2.DATA_PGP_PREFIX):])
                            # import into keyring
                            fpr, unused = self.keyring.import_key(keydata)
                            if fpr == fingerprint:
                                d.callback(userjid)
                            else:
                                d.errback(Exception())

        # request vcard to the resolver for fingerprint matching
        stanzaId = util.rand_str(10)
        d = defer.Deferred()
        self.xmlstream.addOnetimeObserver("/iq[@id='%s']" % (stanzaId, ), _response, 0, d, fingerprint)

        iq = domish.Element((None, 'iq'))
        iq['id'] = stanzaId
        iq['type'] = 'get'
        iq['from'] = self.xmlstream.thisEntity.full()
        iq['to'] = userjid.userhost()
        iq.addElement((xmlstream2.NS_XMPP_VCARD4, 'vcard'))
        self.send(iq)

        return d

    def local_presence(self, user, stanza):
        """
        Called by sm after receiving a local initial presence.
        """

        # send presence to storage
        if user.user:
            if stanza.getAttribute('type') == 'unavailable':
                self.presencedb.touch(user.user)
            else:
                self.presencedb.presence(stanza)

        # initial presence - deliver offline storage
        def output(data, user):
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

        d = self.stanzadb.get_by_recipient(user)
        d.addCallback(output, user)

    def local_vcard(self, user, stanza):
        """
        Called by SM when receiving a vCard from a local client.
        It checks vcard info (including public key) and if positive, sends the
        vCard to all resolvers.
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

                            # send vcard to resolvers
                            for server in self.keyring.hostlist():
                                stanza['id'] = util.rand_str(8)
                                stanza['to'] = util.component_jid(server, util.COMPONENT_RESOLVER)
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
        """Broadcasts to all resolvers the given public key."""
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

        # send vcard to resolvers
        for server in self.keyring.hostlist():
            iq_vcard['id'] = util.rand_str(8)
            # remote server
            iq_vcard['to'] = util.component_jid(server, util.COMPONENT_RESOLVER)
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
