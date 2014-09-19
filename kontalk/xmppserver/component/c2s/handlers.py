# -*- coding: utf-8 -*-
"""c2s protocol handlers."""
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

from twisted.words.protocols.jabber import xmlstream, jid
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish

from wokkel import component

from kontalk.xmppserver import log, util, xmlstream2


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
                unused, host = util.jid_component(sender.host, util.COMPONENT_C2S)

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
                    If a receipt is requested, we won't delete the message from
                    storage now; we must be sure client has received it.
                    Otherwise just delete the message immediately.
                    """
                    if not xmlstream2.extract_receipt(msg['stanza'], 'request'):
                        self.parent.message_offline_delete(msg['id'], msg['stanza'].name)
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
                    response = xmlstream.toResponse(stanza)
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

                response = xmlstream.toResponse(stanza)

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
                response = xmlstream.toResponse(stanza, 'error')

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

                response = xmlstream.toResponse(stanza, 'result')
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
                            if receipt and not from_storage:
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
                                    if not util.hostjid_local(util.COMPONENT_C2S, self.parent, from_server):
                                        stanza['from'] = from_server
                                        self.send_ack(stanza, delivery, stamp, request)
                                except KeyError:
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
        ack = xmlstream.toResponse(stanza, stanza.getAttribute('type'))
        rec = ack.addElement((xmlstream2.NS_XMPP_SERVER_RECEIPTS, status))
        rec['id'] = request['id']
        if stamp:
            rec['stamp'] = time.strftime(xmlstream2.XMPP_STAMP_FORMAT, time.gmtime(stamp))
        self.send(ack)
