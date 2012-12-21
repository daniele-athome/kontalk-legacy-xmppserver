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


import time

from twisted.words.protocols.jabber import error, jid, component
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish

from wokkel import xmppim

from kontalk.xmppserver import log, xmlstream2, version, util


class PresenceHandler(XMPPHandler):
    """
    Handle presence stanzas and client disconnection.
    @type parent: L{C2SManager}
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence[not(@type)]", self.presence)

    def connectionLost(self, reason):
        if self.xmlstream.otherEntity is not None:
            stanza = xmppim.UnavailablePresence()
            stanza['from'] = self.xmlstream.otherEntity.full()
            self.parent.forward(stanza, True)

    def features(self):
        return tuple()

    def send_ack(self, stanza, status, stamp=None):
        request = xmlstream2.extract_receipt(stanza, 'request')
        ack = xmlstream2.toResponse(stanza, stanza.getAttribute('type'))
        rec = ack.addElement((xmlstream2.NS_XMPP_SERVER_RECEIPTS, status))
        rec['id'] = request['id']
        if stamp:
            rec['stamp'] = time.strftime(xmlstream2.XMPP_STAMP_FORMAT, time.gmtime(stamp))
        self.parent.forward(ack)

    def presence(self, stanza):
        """
        This initial presence is from the client connection. We just notify c2s
        which will do the rest.
        """

        # initial presence - tell c2s about it
        if not stanza.hasAttribute('to'):
            self.parent.router.local_presence(self.xmlstream.otherEntity, stanza)


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
        self.xmlstream.addObserver("/iq[@type='get']/query[@xmlns='%s']" % (xmlstream2.NS_IQ_ROSTER), self.roster, 100)
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

    def roster(self, stanza):
        # requesting items lookup, forward to resolver
        if xmlstream2.has_element(stanza.query, name='item'):
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
            response = xmlstream2.toResponse(stanza, 'result')
            response.addElement((xmlstream2.NS_DISCO_ITEMS, 'query'))
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

    def conflict(self):
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
            self.send(xmlstream2.toResponse(stanza, 'result'))

    def send(self, stanza, force=False):
        """Send stanza to client, setting to and id attributes if not present."""
        # FIXME using deepcopy is not safe
        from copy import deepcopy
        stanza = deepcopy(stanza)

        util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT, self.namespace)

        # translate sender to network JID
        sender = stanza.getAttribute('from')
        if sender:
            sender = jid.JID(stanza['from'])
            sender.host = self.network
            stanza['from'] = sender.full()

        # remove reserved elements
        if stanza.name == 'message' and stanza.storage and stanza.storage.uri == xmlstream2.NS_XMPP_STORAGE:
            stanza.children.remove(stanza.storage)

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
