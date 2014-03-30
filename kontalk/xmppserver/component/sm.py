# -*- coding: utf-8 -*-
"""Kontalk XMPP sm component (part of c2s)."""
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
from twisted.words.protocols.jabber import error, jid, component
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish

from wokkel import xmppim

from gnutls.constants import OPENPGP_FMT_RAW, OPENPGP_FMT_BASE64

from kontalk.xmppserver import log, xmlstream2, version, util, push, upload, keyring


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

    def connectionLost(self, reason):
        if self.xmlstream and self.xmlstream.otherEntity is not None:
            stanza = xmppim.UnavailablePresence()
            stanza['from'] = self.xmlstream.otherEntity.full()
            self.parent.forward(stanza, True)

    def features(self):
        pass

    def items(self):
        pass

    def unavailablePresence(self, stanza):
        # notify c2s about unavailable presence
        if not stanza.hasAttribute('to'):
            self.parent.router.local_presence(self.xmlstream.otherEntity, stanza)
            # TODO disconnection should be triggered immediately

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
        # stop ping timeout
        if self.ping_timeout:
            self.ping_timeout.cancel()

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

    def commands(self):
        return ({
            'jid': self.handler.parent.network,
            'node': 'serverlist',
            'name': 'Retrieve server list',
        }, )

    def execute(self, stanza):
        # TODO actually implement the command :)
        stanza.consumed = True
        res = xmlstream2.toResponse(stanza, 'result')
        cmd = res.addElement((xmlstream2.NS_PROTO_COMMANDS, 'command'))
        cmd['node'] = stanza.command['node']
        cmd['status'] = 'completed'
        self.handler.send(res)


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


class CommandsHandler(XMPPHandler):
    """
    XEP-0050: Ad-Hoc Commands
    http://xmpp.org/extensions/xep-0050.html
    """

    commandHandlers = (
        ServerListCommand,
    )

    def __init__(self):
        XMPPHandler.__init__(self)
        # command list for quick access
        self.commands = []
        # command handlers for execution
        self.cmd_handlers = {}

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='set'][@to='%s']/command[@xmlns='%s']" % (self.parent.network, xmlstream2.NS_PROTO_COMMANDS), self.command, 100)

        for h in self.commandHandlers:
            cmd = h(self)
            cmdlist = cmd.commands()
            self.commands.extend(cmdlist)
            for c in cmdlist:
                self.cmd_handlers[c['node']] = cmd

    def command(self, stanza):
        node = stanza.command.getAttribute('node')
        action = stanza.command.getAttribute('action')
        log.debug("command received: %s/%s" % (node, action))
        if action and node and node in self.cmd_handlers:
            try:
                func = getattr(self.cmd_handlers[node], action)
                log.debug("found command handler %s" % (func, ))
                func(stanza)
            except:
                self.parent.error(stanza)
        else:
            self.parent.error(stanza)

    def features(self):
        return (xmlstream2.NS_PROTO_COMMANDS, )

    def items(self):
        return ({'node': xmlstream2.NS_PROTO_COMMANDS, 'items': self.commands }, )


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
            if stanza['to'] == self.parent.servername:
                return componentfn(stanza)
            else:
                return fn(stanza)

    def last_activity(self, stanza):
        stanza.consumed = True
        seconds = self.parent.router.uptime()
        response = xmlstream2.toResponse(stanza, 'result')
        response.addChild(domish.Element((xmlstream2.NS_IQ_LAST, 'query'), attribs={'seconds': str(int(seconds))}))
        self.send(response)

    def version(self, stanza):
        stanza.consumed = True
        response = xmlstream2.toResponse(stanza, 'result')
        query = domish.Element((xmlstream2.NS_IQ_VERSION, 'query'))
        query.addElement((None, 'name'), content=version.NAME + '-c2s')
        query.addElement((None, 'version'), content=version.VERSION)
        response.addChild(query)
        self.send(response)

    def register(self, stanza):
        """This is actually used for key regeneration."""
        if not self.parent.router.registration:
            return self.parent.error(stanza, text='Registration not available.')

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

            def _send_signed(userid, var_pkey):
                # verify and link key
                pkey = base64.b64decode(var_pkey.value.__str__().encode('utf-8'))
                signed_pkey = self.parent.link_public_key(pkey, userid)
                if signed_pkey:
                    iq = xmlstream2.toResponse(stanza, 'result')
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
                    self.parent.error(stanza, 'forbidden', 'Invalid public key.')

            def _continue(presence, userid, var_pkey, var_revoked, stanza):
                if presence and presence['fingerprint']:
                    # user already has a key, check if fingerprint matches and
                    # check the revocation certificate
                    rkeydata = base64.b64decode(var_revoked.value.__str__().encode('utf-8'))
                    # import key and verify revocation certificate
                    rkey_fpr, rkey = self.parent.router.keyring.import_key(rkeydata)

                    if rkey_fpr == presence['fingerprint']:

                        if rkey and rkey.revoked:
                            log.debug("old key has been revoked, accepting new key")
                            # old key has been revoked, ok to accept new one
                            _send_signed(userid, var_pkey)

                        else:
                            # key not valid or not revoked
                            log.debug("old key is not revoked, refusing to proceed")
                            self.parent.error(stanza, 'forbidden', 'Old key has not been revoked.')

                    else:
                        # old key fingerprint not matching
                        log.debug("old key does not match current fingerprint, refusing to proceed")
                        self.parent.error(stanza, 'forbidden', 'Revoked key does not match.')

                else:
                    # user has no key, accept it
                    _send_signed(userid, var_pkey)

            userid = self.parent.xmlstream.otherEntity.user

            # check if user has already a key
            # this is used for users coming from version 2.x (no key back then)
            d = self.parent.router.presencedb.get(userid)
            d.addCallback(_continue, userid, var_pkey, var_revoked, stanza)

        else:
            # bad request
            self.parent.error(stanza, 'bad-request')

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
        ack = xmlstream2.toResponse(stanza, stanza['type'])
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

    def onDiscoItems(self, stanza):
        if not stanza.consumed:
            stanza.consumed = True
            response = xmlstream2.toResponse(stanza, 'result')
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
            response = xmlstream2.toResponse(stanza, 'result')
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
        CommandsHandler,
        PushNotificationsHandler,
        UploadHandler,
        IQHandler,
        PrivacyListHandler,
        RosterHandler,
        MessageHandler,
    )

    def __init__(self, xs, factory, router, network, servername):
        self.factory = factory
        self.router = router
        self.network = network
        self.servername = servername
        self._presence = None
        self.compatibility_mode = False
        xmlstream2.StreamManager.__init__(self, xs)

        """
        Register the discovery handler first so it can process features from
        the other handlers.
        """
        disco = self.disco_handler()

        for handler in self.init_handlers:
            # skip push notifications handler if no push manager is registered
            if handler == PushNotificationsHandler and not self.router.push_manager:
                continue
            # skip upload handler if disabled
            if handler == UploadHandler and not self.router.upload_enabled():
                continue

            h = handler()
            h.setHandlerParent(self)
            info = h.features()
            if info:
                disco.supportedFeatures.extend(info)
            # we will use this later
            disco.post_handlers.append(h)

        # disco is added at last element so onConnectionInitialized will be called last
        disco.setHandlerParent(self)

    def _connected(self, xs):
        xmlstream2.StreamManager._connected(self, xs)
        # add observers for unauthorized stanzas
        xs.addObserver("/iq", self._unauthorized)
        xs.addObserver("/presence", self._unauthorized)
        xs.addObserver("/message", self._unauthorized)
        # everything else is handled by initializers

    def conflict(self):
        if self.xmlstream:
            self.xmlstream.sendStreamError(error.StreamError('conflict'))
            # refuse to process any more stanzas
            self.xmlstream.setDispatchFn(None)

    def _unauthorized(self, stanza):
        if not stanza.consumed and (not stanza.hasAttribute('to') or stanza['to'] != self.network):
            stanza.consumed = True
            self.xmlstream.sendStreamError(error.StreamError('not-authorized'))
            # refuse to process any more stanzas
            self.xmlstream.setDispatchFn(None)

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
            try:
                to = jid.JID(to)
            except:
                # invalid destination, consume stanza and return error
                stanza.consumed = True
                log.debug("invalid address: %s" % (to, ))
                e = error.StanzaError('jid-malformed', 'modify')
                self.send(e.toResponse(stanza))
                return

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
        # generate message id if receipt is requested by client
        if xmlstream2.extract_receipt(stanza, 'request'):
            stanza.request['id'] = util.rand_str(30, util.CHARSBOX_AZN_LOWERCASE)

        # no to address, presume sender bare JID
        if not stanza.hasAttribute('to'):
            stanza['to'] = self.xmlstream.otherEntity.userhost()

        # if message is a received receipt, we can delete the original message
        # TODO move this to MessageHandler
        if stanza.getAttribute('type') == 'chat':
            received = xmlstream2.extract_receipt(stanza, 'received')
            if stanza.received:
                # delete the received message
                # TODO safe delete with sender/recipient
                self.router.message_offline_delete(received['id'], stanza.name)

        self.handle(stanza)

    def _disconnected(self, reason):
        self.factory.connectionLost(self.xmlstream, reason)
        xmlstream2.StreamManager._disconnected(self, reason)

    def error(self, stanza, condition='service-unavailable', errtype='cancel', text=None):
        if not stanza.consumed:
            log.debug("error %s" % (stanza.toXml(), ))
            stanza.consumed = True
            util.resetNamespace(stanza, self.namespace)
            e = error.StanzaError(condition, errtype, text)
            self.send(e.toResponse(stanza), True)

    def bounce(self, stanza):
        """Bounce stanzas as results."""
        if not stanza.consumed:
            util.resetNamespace(stanza, self.namespace)

            if self.router.logTraffic:
                log.debug("bouncing %s" % (stanza.toXml(), ))

            stanza.consumed = True
            self.send(xmlstream2.toResponse(stanza, 'result'))

    def send(self, stanza, force=False):
        """Send stanza to client, setting to and id attributes if not present."""

        if stanza.hasAttribute('original-to'):
            origTo = stanza.getAttribute('original-to')
            del stanza['original-to']

            """
            Extract original recipient from stanza.
            If original-to is not present, we will assume that
            stanza was intended to the full JID.
            """
            origTo = jid.JID(origTo)

            if self.router.logTraffic:
                log.debug("sending message to client %s (original was %s)" % (self.xmlstream.otherEntity, origTo))
                if self._presence:
                    log.debug("_presence: %s" % (self._presence.toXml(), ))

            # sending to bare JID
            # initial presence found
            # negative resource
            # => DROP STANZA
            try:
                if not origTo.resource and int(str(self._presence.priority)) < 0:
                    return None
            except:
                pass

        # FIXME using deepcopy is not safe
        from copy import deepcopy
        stanza = deepcopy(stanza)

        util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT, self.namespace)

        # translate sender to network JID
        sender = stanza.getAttribute('from')
        if sender and sender != self.network:
            sender = jid.JID(stanza['from'])
            sender.host = self.network
            stanza['from'] = sender.full()
        # TODO should we force self.network if no sender?

        # remove reserved elements
        if stanza.name in ('presence', 'message'):
            # storage child
            if stanza.storage and stanza.storage.uri == xmlstream2.NS_XMPP_STORAGE:
                stanza.children.remove(stanza.storage)
            # origin in receipt
            if stanza.request and stanza.request.hasAttribute('origin'):
                del stanza.request['origin']
            elif stanza.received and stanza.received.hasAttribute('origin'):
                del stanza.received['origin']
        if stanza.name == 'presence':
            # push device id
            for c in stanza.elements(name='c', uri=xmlstream2.NS_PRESENCE_PUSH):
                stanza.children.remove(c)
                break

        # force destination address
        if self.xmlstream.otherEntity:
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

            if self.router.logTraffic:
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

    def link_public_key(self, publickey, userid):
        """
        Link the provided public key to a userid.
        @param publickey: public key in DER format
        @return: the signed public key, in DER binary format.
        """
        # import public key and sign it
        fp, keydata = self.router.keyring.sign_public_key(publickey, userid)

        if fp and keydata:
            # signed public key to presence table
            self.router.presencedb.public_key(userid, fp)

            # broadcast public key
            self.router.broadcast_public_key(userid, keydata)

            # return signed public key
            return keydata

    def public_key_presence(self, xs):
        """
        Calls C2SComponent.broadcast_public_key from the data found in the
        provided client certificate. It also saves the public key in the local
        presence cache.
        This also checks if the key fingerprint matches the one found in our
        local presence cache.
        """

        userid = xs.otherEntity.user
        cert = xs.transport.getPeerCertificate()
        pkey = keyring.extract_public_key(cert)

        if pkey:
            # export raw key data
            keydata = pkey.export(OPENPGP_FMT_RAW)

            # TODO workaround for GnuTLS bug (?)
            # public key block less than 50 bytes? Impossible.
            if len(keydata) < 50:
                keydata = keyring.convert_openpgp_from_base64(pkey.export(OPENPGP_FMT_BASE64))

            # store in local presence cache
            self.router.presencedb.public_key(userid, pkey.fingerprint)

            # broadcast the key
            self.router.broadcast_public_key(userid, keydata)
