# -*- coding: utf-8 -*-
"""Kontalk XMPP sm component (part of c2s)."""
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
from twisted.words.protocols.jabber import error, jid, component
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish

from wokkel import xmppim

from kontalk.xmppserver import log, xmlstream2, version, util, push, upload


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


class PingHandler(XMPPHandler):
    """
    XEP-0199: XMPP Ping
    http://xmpp.org/extensions/xep-0199.html
    """

    PING_DELAY = 120
    PING_TIMEOUT = 120

    def __init__(self):
        XMPPHandler.__init__(self)
        self.ping_timeout = None
        self.pinger = None

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='get'][@to='%s']/ping[@xmlns='%s']" % (self.parent.network, xmlstream2.NS_XMPP_PING, ), self.ping, 100)
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
        self.xmlstream.addObserver("/iq[@type='result'][@id='%s']" % (ping['id'], ), self.pong, 100)

    def _timeout(self):
        self.ping_timeout = None
        # send stream error
        e = error.StreamError('connection-timeout')
        self.xmlstream.sendStreamError(e)

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



class IQHandler(XMPPHandler):
    """Handle various iq stanzas."""

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='get']/query[@xmlns='%s']" % (xmlstream2.NS_IQ_ROSTER), self.roster, 100)
        self.xmlstream.addObserver("/iq/query[@xmlns='%s']" % (xmlstream2.NS_IQ_LAST), self.forward_check, 100,
            fn=self.parent.forward, componentfn=self.last_activity)
        self.xmlstream.addObserver("/iq/query[@xmlns='%s']" % (xmlstream2.NS_IQ_VERSION), self.forward_check, 100,
            fn=self.parent.forward, componentfn=self.version)
        self.xmlstream.addObserver("/iq/query[@xmlns='%s']" % (xmlstream2.NS_IQ_REGISTER), self.register, 100)
        self.xmlstream.addObserver("/iq[@type='result']", self.parent.forward, 100)

        # fallback: service unavailable
        self.xmlstream.addObserver("/iq", self.parent.error, 50)

    def forward_check(self, stanza, fn, componentfn):
        if not stanza.consumed:
            if stanza['to'] == self.parent.servername:
                return componentfn(stanza)
            else:
                return fn(stanza)

    def roster(self, stanza):
        # enforce destination (resolver)
        stanza['to'] = self.parent.network

        # requesting items lookup, forward to resolver
        if xmlstream2.has_element(stanza.query, uri=xmlstream2.NS_IQ_ROSTER, name='item'):
            self.parent.forward(stanza)
        # requesting initial roster - no action
        else:
            self.parent.bounce(stanza)

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

    # TODO this should be an initializer
    def register(self, stanza):
        if not self.parent.router.registration:
            return self.parent.error(stanza)

        log.debug("client requested registration: %s" % (stanza.toXml(), ))
        stanza.consumed = True
        if stanza['type'] == 'get':
            self.parent.router.registration.request(self.parent, stanza)
        elif stanza['type'] == 'set':
            self.parent.router.registration.register(self.parent, stanza)

    def features(self):
        ft = [
            xmlstream2.NS_DISCO_INFO,
            xmlstream2.NS_DISCO_ITEMS,
            xmlstream2.NS_IQ_VERSION,
            xmlstream2.NS_IQ_ROSTER,
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
                    self.parent.router.message_offline_delete(msgId, to.user, sender.user)
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
        MessageHandler,
    )

    def __init__(self, xs, factory, router, network, servername):
        self.factory = factory
        self.router = router
        self.network = network
        self.servername = servername
        self._presence = None
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
        if stanza.name == 'message' and stanza.storage and stanza.storage.uri == xmlstream2.NS_XMPP_STORAGE:
            stanza.children.remove(stanza.storage)
        if stanza.name == 'presence':
            for c in stanza.elements(name='c', uri=xmlstream2.NS_PRESENCE_PUSH):
                stanza.children.remove(c)
                break

        # force destination address
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
