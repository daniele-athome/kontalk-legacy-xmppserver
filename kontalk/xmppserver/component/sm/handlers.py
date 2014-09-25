# -*- coding: utf-8 -*-
"""sm protocol handlers."""
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


import base64

from twisted.internet import reactor
from twisted.words.protocols.jabber import error, jid, xmlstream
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish

from wokkel import xmppim

from kontalk.xmppserver import log, xmlstream2, version, util, push, upload, tls


class PresenceHandler(XMPPHandler):
    """
    Handle presence stanzas and client disconnection.
    @type parent: L{C2SManager}
    """

    def connectionInitialized(self):
        # initial presence is... well, initial :)
        self.xmlstream.addOnetimeObserver("/presence[not(@type)]", self.initialPresence)
        self.xmlstream.addObserver("/presence[not(@type)]", self.presence)
        self.xmlstream.addObserver("/presence[@type='unavailable']", self.unavailablePresence)
        self.xmlstream.addObserver("/presence[@type='subscribe']", self.onSubscribe, 100)
        self.xmlstream.addObserver("/presence[@type='unsubscribe']", self.onUnsubscribe, 100)
        self.xmlstream.addObserver("/presence[@type='subscribed']", self.onSubscribed, 600)

    def connectionLost(self, reason):
        if self.xmlstream and self.xmlstream.otherEntity is not None and self.parent._presence is not None:
            # void the current presence
            self.presence(None)
            # send unavailable presence
            stanza = xmppim.UnavailablePresence()
            stanza['from'] = self.xmlstream.otherEntity.full()
            self.parent.forward(stanza, True)
            # notify c2s
            stanza.consumed = False
            self.parent.router.local_presence(self.xmlstream.otherEntity, stanza)

    def features(self):
        pass

    def items(self):
        pass

    def unavailablePresence(self, stanza):
        # notify c2s about unavailable presence
        if not stanza.hasAttribute('to'):
            self.parent.router.local_presence(self.xmlstream.otherEntity, stanza)
            # void the current presence
            self.presence(None)
            # set the initial presence listener again
            self.xmlstream.addOnetimeObserver("/presence[not(@type)]", self.initialPresence)

    def presence(self, stanza):
        # store presence stanza in the stream manager
        self.parent._presence = stanza

    def initialPresence(self, stanza):
        """
        This initial presence is from the client connection. We just notify c2s
        which will do the rest.
        """
        if not stanza.hasAttribute('to'):
            self.parent.router.local_presence(self.xmlstream.otherEntity, stanza)

            # this will do the necessary checks with public key
            self.parent.public_key_presence(self.xmlstream)

    def onSubscribe(self, stanza):
        """Handle subscription requests."""

        if stanza.consumed:
            return

        if self.parent.logTraffic:
            log.debug("subscription request: %s" % (stanza.toXml(), ))
        else:
            log.debug("subscription request to %s from %s" % (stanza['to'], self.xmlstream.otherEntity))

        # extract jid the user wants to subscribe to
        jid_to = jid.JID(stanza['to']).userhostJID()
        jid_from = self.xmlstream.otherEntity

        # are we subscribing to a user we have blocked?
        if self.parent.router.is_presence_allowed(jid_to, jid_from) == -1:
            log.debug("subscribing to blocked user, bouncing error")
            e = error.StanzaError('not-acceptable', 'cancel')
            errstanza = e.toResponse(stanza)
            errstanza.error.addElement((xmlstream2.NS_IQ_BLOCKING_ERRORS, 'blocked'))
            self.send(errstanza)

        else:
            if not self.parent.router.subscribe(self.parent.router.translateJID(jid_from),
                    self.parent.router.translateJID(jid_to), stanza.getAttribute('id')):
                e = error.StanzaError('item-not-found')
                self.send(e.toResponse(stanza))

    def onUnsubscribe(self, stanza):
        """Handle unsubscription requests."""

        if stanza.consumed:
            return

        if self.parent.logTraffic:
            log.debug("unsubscription request: %s" % (stanza.toXml(), ))
        else:
            log.debug("unsubscription request to %s from %s" % (stanza['to'], self.xmlstream.otherEntity))

        # extract jid the user wants to unsubscribe from
        jid_to = jid.JID(stanza['to']).userhostJID()
        jid_from = self.xmlstream.otherEntity

        self.parent.router.unsubscribe(self.parent.router.translateJID(jid_to),
            self.parent.router.translateJID(jid_from))

    def onSubscribed(self, stanza):
        if stanza.consumed:
            return

        log.debug("user %s accepted subscription by %s" % (self.xmlstream.otherEntity, stanza['to']))
        stanza.consumed = True
        jid_to = jid.JID(stanza['to'])

        jid_from = self.xmlstream.otherEntity.userhostJID()

        # add "to" user to whitelist of "from" user
        self.parent.router.add_whitelist(jid_from, jid_to)

        log.debug("SUBSCRIPTION SUCCESSFUL")

        if self.parent.router.cache.jid_available(jid_from):
            # send subscription accepted immediately and subscribe
            # TODO this is wrong, but do it for the moment until we find a way to handle this case
            self.parent.router.doSubscribe(jid_from, jid_to, stanza.getAttribute('id'), response_only=False)


class PingHandler(XMPPHandler):
    """
    XEP-0199: XMPP Ping
    http://xmpp.org/extensions/xep-0199.html
    """

    PING_DELAY = 240
    PING_TIMEOUT = 240

    def __init__(self):
        XMPPHandler.__init__(self)
        self.ping_timeout = None
        self.pinger = None

    def connectionInitialized(self):
        """
        This is a special case: ping to network is handled by us because it's
        a local issue, no need to forward to resolver.
        """
        self.xmlstream.addObserver("/iq[@type='get']/ping[@xmlns='%s']" % (xmlstream2.NS_XMPP_PING, ), self.ping, 600)
        # first ping request
        self.pinger = reactor.callLater(self.PING_DELAY, self._ping)

    def connectionLost(self, reason):
        XMPPHandler.connectionLost(self, reason)
        # stop pinger
        if self.pinger:
            self.pinger.cancel()
            self.pinger = None
        # stop ping timeout
        if self.ping_timeout:
            self.ping_timeout.cancel()
            self.ping_timeout = None

    def _ping(self):
        """Sends a ping request to client."""
        ping = domish.Element((None, 'iq'))
        ping['from'] = self.parent.network
        ping['type'] = 'get'
        ping['id'] = util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
        ping.addElement((xmlstream2.NS_XMPP_PING, 'ping'))
        self.send(ping)
        # setup ping timeout
        self.pinger = None
        self.ping_timeout = reactor.callLater(self.PING_TIMEOUT, self._timeout)
        # observe pong
        self.xmlstream.addObserver("/iq[@type='result'][@id='%s']" % (ping['id'], ), self.pong, 600)

    def _timeout(self):
        self.ping_timeout = None
        # send stream error
        self.xmlstream.sendStreamError(error.StreamError('connection-timeout'))
        # refuse to process any more stanzas
        self.xmlstream.setDispatchFn(None)
        # broadcast unavailable presence
        if self.xmlstream.otherEntity is not None:
            stanza = xmppim.UnavailablePresence()
            stanza['from'] = self.xmlstream.otherEntity.full()
            self.parent.forward(stanza, True)

    def ping(self, stanza):
        if not stanza.hasAttribute('to') or stanza['to'] == self.parent.network:
            # reply with same stanza
            self.parent.bounce(stanza)
        else:
            self.parent.forward(stanza)

    def pong(self, stanza):
        """Client replied to ping: abort timeout."""
        if self.ping_timeout:
            self.ping_timeout.cancel()
            self.ping_timeout = None
        # unobserve pong
        self.xmlstream.removeObserver("/iq[@type='result'][@id='%s']" % (stanza['id'], ), self.pong)
        # consume stanza
        stanza.consumed = True
        # restart pinger
        self.pinger = reactor.callLater(self.PING_DELAY, self._ping)

    def features(self):
        return (xmlstream2.NS_XMPP_PING, )

    def items(self):
        pass


class ServerListCommand():
    def __init__(self, handler):
        self.handler = handler

    def connectionLost(self, reason):
        self.handler = None

    def commands(self):
        return ({
            'jid': self.handler.parent.network,
            'node': 'serverlist',
            'name': 'Retrieve server list',
        }, )

    def execute(self, stanza):
        stanza.consumed = True
        res = xmlstream.toResponse(stanza, 'result')
        cmd = res.addElement((xmlstream2.NS_PROTO_COMMANDS, 'command'))
        cmd['node'] = stanza.command['node']
        cmd['status'] = 'completed'

        slist = cmd.addElement(('http://kontalk.org/extensions/serverlist', 'serverlist'))
        for host in self.handler.parent.router.keyring.hostlist():
            item = slist.addElement((None, 'item'))
            item['node'] = host

        return res


class PushNotificationsHandler(XMPPHandler):
    """Support for push notifications."""

    pushHandlers = (
        push.GCMPushNotifications,
    )

    def __init__(self):
        XMPPHandler.__init__(self)
        # push handler for items quick access
        self.handler_items = []
        # push handlers
        self.push_handlers = {}

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence/c[@xmlns='%s']" % (xmlstream2.NS_PRESENCE_PUSH), self.push_regid, 100)

        for h in self.pushHandlers:
            inst = h(self)
            nodes = inst.supports()
            self.handler_items.extend(nodes)
            for c in nodes:
                self.push_handlers[c['node']] = inst

    def connectionLost(self, reason):
        XMPPHandler.connectionLost(self, reason)

        # cleanup
        self.push_handlers = None

    def push_regid(self, stanza):
        for child in stanza.children:
            if child.name == 'c' and child.uri == xmlstream2.NS_PRESENCE_PUSH:
                regid = str(child)
                provider = child.getAttribute('provider')
                if regid and provider:
                    log.debug("registering %s using %s with %s" % (self.xmlstream.otherEntity, provider, regid))
                    self.parent.router.push_manager.register(self.xmlstream.otherEntity, provider, regid)

    def features(self):
        return (xmlstream2.NS_PRESENCE_PUSH, )

    def items(self):
        return ({'node': xmlstream2.NS_PRESENCE_PUSH, 'items': self.handler_items }, )


class CommandsHandler(xmlstream2.CommandsHandler):
    """Ad-Hoc Commands for clients."""

    commandHandlers = (
        ServerListCommand,
    )

    def __init__(self):
        xmlstream2.CommandsHandler.__init__(self, self.commandHandlers)

    def setHandlerParent(self, parent):
        xmlstream2.CommandsHandler.setHandlerParent(self, parent, parent.network)


class UploadHandler(XMPPHandler):
    """
    Upload media extension.
    """

    uploadHandlers = (
        upload.KontalkBoxUploadService,
    )

    def __init__(self):
        XMPPHandler.__init__(self)
        self.services = []
        self.serv_handlers = {}

    def connectionInitialized(self):
        for h in self.uploadHandlers:
            name = h.name
            try:
                config = self.parent.router.config['upload'][name]
            except:
                return

            if config['enabled']:
                serv = h(self, config)
                servinfo = serv.info()
                self.services.append(servinfo)
                self.serv_handlers[servinfo['node']] = serv

        # add observer only if at least one service is enabled
        if len(self.services):
            self.xmlstream.addObserver("/iq[@type='get'][@to='%s']/upload[@xmlns='%s']" % (self.parent.network, xmlstream2.NS_MESSAGE_UPLOAD), self.upload, 100)

    def connectionLost(self, reason):
        XMPPHandler.connectionLost(self, reason)

        # cleanup
        self.serv_handlers = None

    def upload(self, stanza):
        node = stanza.upload.getAttribute('node')
        log.debug("upload request received: %s" % (node, ))
        if node and node in self.serv_handlers:
            try:
                return self.serv_handlers[node].upload(stanza)
            except:
                import traceback
                traceback.print_exc()

        self.parent.error(stanza)

    def features(self):
        return (xmlstream2.NS_MESSAGE_UPLOAD, )

    def items(self):
        return ({'node': xmlstream2.NS_MESSAGE_UPLOAD, 'items': self.services }, )


class PrivacyListHandler(XMPPHandler):
    """Handles IQ urn:xmpp:blocking stanzas."""

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='set']/allow[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.forward, 100)
        self.xmlstream.addObserver("/iq[@type='set']/unallow[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.forward, 100)
        self.xmlstream.addObserver("/iq[@type='set']/block[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.forward, 100)
        self.xmlstream.addObserver("/iq[@type='set']/unblock[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.forward, 100)
        self.xmlstream.addObserver("/iq[@type='get']/blocklist[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.forward, 100)

    def forward(self, stanza):
        # enforce destination (resolver)
        stanza['to'] = self.parent.network

        # forward to resolver
        self.parent.forward(stanza)

    def features(self):
        return (xmlstream2.NS_IQ_BLOCKING, )

    def items(self):
        pass


class RosterHandler(XMPPHandler):
    """Handles the roster and XMPP compatibility mode."""

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='get']/query[@xmlns='%s']" % (xmlstream2.NS_IQ_ROSTER), self.roster, 100)

    def roster(self, stanza):
        # enforce destination (resolver)
        stanza['to'] = self.parent.network

        if not xmlstream2.has_element(stanza.query, uri=xmlstream2.NS_IQ_ROSTER, name='item'):
            # requesting initial roster - enter XMPP compatibility mode
            self.parent.compatibility_mode = True

        # forward to resolver
        self.parent.forward(stanza)

    def features(self):
        return (xmlstream2.NS_IQ_ROSTER, )

    def items(self):
        pass


class IQHandler(XMPPHandler):
    """Handles various iq stanzas."""

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq/query[@xmlns='%s']" % (xmlstream2.NS_IQ_LAST), self.forward_check, 100,
            fn=self.parent.forward, componentfn=self.last_activity)
        self.xmlstream.addObserver("/iq/query[@xmlns='%s']" % (xmlstream2.NS_IQ_VERSION), self.forward_check, 100,
            fn=self.parent.forward, componentfn=self.version)
        self.xmlstream.addObserver("/iq[@type='set']/query[@xmlns='%s']" % (xmlstream2.NS_IQ_REGISTER), self.register, 100)
        self.xmlstream.addObserver("/iq[@type='result']", self.parent.forward, 100)
        self.xmlstream.addObserver("/iq[@type='set']/vcard[@xmlns='%s']" % (xmlstream2.NS_XMPP_VCARD4, ), self.vcard_set, 100)
        self.xmlstream.addObserver("/iq[@type='get']/vcard[@xmlns='%s']" % (xmlstream2.NS_XMPP_VCARD4, ), self.vcard_get, 100)

        # fallback: service unavailable
        self.xmlstream.addObserver("/iq", self.parent.error, 50)

    def forward_check(self, stanza, fn, componentfn):
        if not stanza.consumed:
            if stanza['to'] == util.component_jid(self.parent.servername, util.COMPONENT_C2S):
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

    def register(self, stanza):
        """This is actually used for key regeneration."""
        log.debug("client requested key regeneration: %s" % (stanza.toXml(), ))
        stanza.consumed = True
        fields = stanza.query.x.elements(uri='jabber:x:data', name='field')
        var_pkey = None
        var_revoked = None

        for f in fields:
            if f['var'] == 'publickey':
                var_pkey = f
            elif f['var'] == 'revoked':
                var_revoked = f

        # FIXME maybe some stuff here should go to c2s?

        if var_pkey:
            userid = self.parent.xmlstream.otherEntity.user

            # check if user has already a key
            # this is used for users coming from version 2.x (no key back then)
            d = self.parent.router.presencedb.get(userid)
            d.addCallback(self._register_continue, userid, var_pkey, var_revoked, stanza)

        else:
            # bad request
            stanza.consumed = False
            self.parent.error(stanza, 'bad-request')

    def _register_success(self, userid, var_pkey, stanza):
        # verify and link key
        pkey = base64.b64decode(var_pkey.value.__str__().encode('utf-8'))
        signed_pkey = self.parent.link_public_key(pkey, userid)
        if signed_pkey:
            iq = xmlstream.toResponse(stanza, 'result')
            query = iq.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))

            form = query.addElement(('jabber:x:data', 'x'))
            form['type'] = 'form'

            hidden = form.addElement((None, 'field'))
            hidden['type'] = 'hidden'
            hidden['var'] = 'FORM_TYPE'
            hidden.addElement((None, 'value'), content='http://kontalk.org/protocol/register#key')

            signed = form.addElement((None, 'field'))
            signed['type'] = 'text-single'
            signed['label'] = 'Signed public key'
            signed['var'] = 'publickey'
            signed.addElement((None, 'value'), content=base64.b64encode(signed_pkey))

            self.parent.send(iq, True)

        else:
            # key not signed or verified
            stanza.consumed = False
            self.parent.error(stanza, 'forbidden', text='Invalid public key.')

    def _register_continue(self, presence, userid, var_pkey, var_revoked, stanza):
        # we also check if user has logged in through a certificate
        allowed_ssl = tls.isTLS(self.xmlstream) and self.xmlstream.transport.getPeerCertificate()
        if allowed_ssl and presence and presence['fingerprint']:
            # user already has a key, check if fingerprint matches and
            # check the revocation certificate
            rkeydata = base64.b64decode(var_revoked.value.__str__().encode('utf-8'))
            # import key and verify revocation certificate
            rkey_fpr, rkey = self.parent.router.keyring.import_key(rkeydata)

            if rkey_fpr == presence['fingerprint']:

                if rkey and rkey.revoked:
                    log.debug("old key has been revoked, accepting new key")
                    # old key has been revoked, ok to accept new one
                    self._register_success(userid, var_pkey, stanza)

                else:
                    # key not valid or not revoked
                    log.debug("old key is not revoked, refusing to proceed")
                    stanza.consumed = False
                    self.parent.error(stanza, 'forbidden', text='Old key has not been revoked.')

            else:
                # old key fingerprint not matching
                log.debug("old key does not match current fingerprint, refusing to proceed")
                stanza.consumed = False
                self.parent.error(stanza, 'forbidden', text='Revoked key does not match.')

        else:
            # user has no key, accept it
            self._register_success(userid, var_pkey, stanza)

    def vcard_set(self, stanza):
        # let c2s handle this
        self.send(self.parent.router.local_vcard(self.xmlstream.otherEntity, stanza))

    def vcard_get(self, stanza):
        if not stanza.hasAttribute('to'):
            stanza['to'] = self.xmlstream.otherEntity.userhost()
        self.parent.forward(stanza)

    def features(self):
        ft = [
            xmlstream2.NS_DISCO_INFO,
            xmlstream2.NS_DISCO_ITEMS,
            xmlstream2.NS_IQ_VERSION,
            xmlstream2.NS_IQ_LAST,
        ]
        if self.parent.router.registration:
            ft.append(xmlstream2.NS_IQ_REGISTER)

        return ft

    def items(self):
        pass


class MessageHandler(XMPPHandler):
    """Message stanzas handler."""

    def connectionInitialized(self):
        # messages for the server
        #self.xmlstream.addObserver("/message[@to='%s']" % (self.parent.servername), self.parent.error, 100)
        # ack is above stanza processing rules
        self.xmlstream.addObserver("/message/ack[@xmlns='%s']" % (xmlstream2.NS_XMPP_SERVER_RECEIPTS), self.ack, 600)
        # this is for replying with <ack/> immediately
        self.xmlstream.addObserver("/message/received[@xmlns='%s']" % (xmlstream2.NS_XMPP_SERVER_RECEIPTS), self.received, 600)

    def received(self, stanza):
        ack = xmlstream.toResponse(stanza, stanza['type'])
        ack.addElement((xmlstream2.NS_XMPP_SERVER_RECEIPTS, 'ack'))
        self.send(ack)
        # proceed with processing

    def ack(self, stanza):
        stanza.consumed = True
        msgId = stanza.ack.getAttribute('id')
        if msgId:
            try:
                to = jid.JID(stanza['to'])
                sender = self.xmlstream.otherEntity
                if to.host == self.parent.network and sender.host == self.parent.network:
                    self.parent.router.message_offline_delete(msgId, stanza.name, to.user, sender.user)
            except:
                pass

    def features(self):
        pass

    def items(self):
        pass


class DiscoveryHandler(XMPPHandler):
    """Handle iq stanzas for discovery."""

    def __init__(self):
        self.post_handlers = []
        self.supportedFeatures = []
        # key is node attribute of <query/>
        self.items = {}

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='get'][@to='%s']/query[@xmlns='%s']" % (self.parent.network, xmlstream2.NS_DISCO_ITEMS), self.onDiscoItems, 100)
        self.xmlstream.addObserver("/iq[@type='get'][@to='%s']/query[@xmlns='%s']" % (self.parent.network, xmlstream2.NS_DISCO_INFO), self.onDiscoInfo, 100)
        # add items now
        for h in self.post_handlers:
            items = h.items()
            if items:
                for i in items:
                    node = i['node']
                    if node not in self.items:
                        self.items[node] = []
                    self.items[node].extend(i['items'])

    def connectionLost(self, reason):
        XMPPHandler.connectionLost(self, reason)

        # cleanup
        self.post_handlers = None

    def onDiscoItems(self, stanza):
        if not stanza.consumed:
            stanza.consumed = True
            response = xmlstream.toResponse(stanza, 'result')
            query = response.addElement((xmlstream2.NS_DISCO_ITEMS, 'query'))
            node = stanza.query.getAttribute('node')
            if node:
                query['node'] = node
                if node in self.items:
                    for item in self.items[node]:
                        n = query.addElement((None, 'item'))
                        n['jid'] = item['jid']
                        n['node'] = item['node']
                        n['name'] = item['name']

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


