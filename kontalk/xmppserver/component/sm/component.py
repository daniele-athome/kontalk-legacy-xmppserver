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


from twisted.words.protocols.jabber import error, jid, component, xmlstream

from gnutls.constants import OPENPGP_FMT_RAW, OPENPGP_FMT_BASE64

from kontalk.xmppserver import log, xmlstream2, util, keyring
import handlers


class C2SManager(xmlstream2.StreamManager):
    """
    Handles communication with a client. Note that this is the L{StreamManager}
    towards the client, not the router!!

    @param router: the connection with the router
    @type router: L{xmlstream.StreamManager}
    """

    namespace = 'jabber:client'

    disco_handler = handlers.DiscoveryHandler
    init_handlers = (
        handlers.PresenceHandler,
        handlers.PingHandler,
        handlers.CommandsHandler,
        handlers.PushNotificationsHandler,
        handlers.UploadHandler,
        handlers.IQHandler,
        handlers.PrivacyListHandler,
        handlers.RosterHandler,
        handlers.MessageHandler,
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
            if handler == handlers.PushNotificationsHandler and not self.router.push_manager:
                continue
            # skip upload handler if disabled
            if handler == handlers.UploadHandler and not self.router.upload_enabled():
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
        #xs.addObserver('/*', self.forward)

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
            elif to.host != util.component_jid(self.servername, util.COMPONENT_C2S):
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

        # disown handlers
        for h in list(self):
            h.disownHandlerParent(self)

        # cleanup
        self.factory = None
        self.router = None

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
            self.send(xmlstream.toResponse(stanza, 'result'))

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
            if stanza.request and stanza.request.hasAttribute('from'):
                del stanza.request['from']
            elif stanza.received and stanza.received.hasAttribute('from'):
                del stanza.received['from']
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
        """Transform host attribute of JID from network name to component name."""
        host = util.component_jid(self.servername, util.COMPONENT_C2S)
        if isinstance(_jid, jid.JID):
            return jid.JID(tuple=(_jid.user, host, _jid.resource))
        else:
            _jid = jid.JID(_jid)
            _jid.host = host
            return _jid

    def link_public_key(self, publickey, userid):
        """
        Link the provided public key to a userid.
        @param publickey: public key in DER format
        @return: the signed public key, in DER binary format.
        """

        # check if key is already valid
        fp = self.router.keyring.check_user_key(publickey, userid)
        if not fp:
            # import public key and sign it
            try:
                fp, keydata = self.router.keyring.sign_public_key(publickey, userid)
            except:
                import traceback
                traceback.print_exc()
                return None

        else:
            # use given key
            keydata = publickey

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
