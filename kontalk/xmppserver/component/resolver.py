# -*- coding: utf-8 -*-
"""Kontalk XMPP resolver component."""
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
from datetime import datetime
from copy import deepcopy

from twisted.python import failure
from twisted.internet import defer, reactor, task, threads
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish
from twisted.words.protocols.jabber import jid, error, xmlstream

from wokkel import component

from kontalk.xmppserver import log, storage, util, xmlstream2, version, keyring


class RosterHandler(XMPPHandler):
    """
    Handles the roster and XMPP compatibility mode.
    @ivar parent: resolver instance
    @type parent: L{Resolver}
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='get']/query[@xmlns='%s']" % (xmlstream2.NS_IQ_ROSTER), self.roster, 100)

    def roster(self, stanza):
        _items = stanza.query.elements(uri=xmlstream2.NS_IQ_ROSTER, name='item')
        requester = jid.JID(stanza['from'])
        stanza.consumed = True

        # items present, requesting roster lookup
        response = xmlstream.toResponse(stanza, 'result')
        roster = response.addElement((xmlstream2.NS_IQ_ROSTER, 'query'))

        probes = []
        # this will be true if roster lookup is requested
        roster_lookup = False
        for item in _items:
            # items present, meaning roster lookup
            roster_lookup = True

            itemJid = jid.internJID(item['jid'])

            # include the entry in the roster reply anyway
            entry = self.parent.cache.lookup(itemJid)
            if entry:
                allowed = self.parent.is_presence_allowed(requester, itemJid)
                if allowed != -1:
                    item = roster.addElement((None, 'item'))
                    item['jid'] = self.parent.translateJID(entry.jid).userhost()

                if allowed == 1:
                    probes.append(entry.presence())

        # roster lookup, send presence data and vcards
        if roster_lookup:

            # lookup response
            self.send(response)

            # simulate a presence probe and send vcards
            # we'll use one group ID so the client knows when to stop waiting
            gid = stanza.getAttribute('id')
            if not gid:
                gid = util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)

            i = sum([len(x) for x in probes])
            for presence_list in probes:
                for presence in presence_list:
                    presence = deepcopy(presence)
                    presence['to'] = stanza['from']
                    group = presence.addElement((xmlstream2.NS_XMPP_STANZA_GROUP, 'group'))
                    group['id'] = gid
                    group['count'] = str(i)
                    i -= 1
                    self.send(presence)

                # send vcard for this user
                jid_from = jid.JID(presence_list[0]['from'])
                iq = domish.Element((None, 'iq'))
                iq['type'] = 'set'
                iq['from'] = jid_from.userhost()
                iq['to'] = stanza['from']
                self.parent.build_vcard(jid_from.user, iq)
                self.send(iq)

        # no roster lookup, XMPP standard roster instead
        else:

            # include items from the user's whitelist
            wl = self.parent.get_whitelist(requester)
            probes = None
            if wl:
                subscriptions = []
                for e in wl:
                    item = roster.addElement((None, 'item'))
                    item['jid'] = e

                    itemJid = jid.JID(e)

                    # check if subscription status is 'both' or just 'from'
                    allowed = self.parent.is_presence_allowed(requester, itemJid)
                    if allowed == 1:
                        status = 'both'
                    else:
                        status = 'from'

                    # TODO include name from PGP key?
                    item['subscription'] = status

                    # add to subscription list
                    subscriptions.append(itemJid)

            # send the roster
            self.send(response)

            # subscribe to all users (without sending subscribed stanza of course)
            if wl:
                for itemJid in subscriptions:
                    self.parent.subscribe(requester, itemJid, send_subscribed=False)


class IQHandler(XMPPHandler):
    """
    Handles IQ stanzas.
    @type parent: L{Resolver}
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='get']/query[@xmlns='%s']" % (xmlstream2.NS_IQ_LAST, ), self.last_activity, 100)
        self.xmlstream.addObserver("/iq[@type='get']/query[@xmlns='%s']" % (xmlstream2.NS_IQ_VERSION, ), self.version, 100)
        self.xmlstream.addObserver("/iq[@type='result']", self.parent.bounce, 100)
        self.xmlstream.addObserver("/iq/query", self.parent.error, 80)

    def version(self, stanza):
        if not stanza.consumed:
            stanza.consumed = True

            if stanza['to'] == self.parent.network:
                response = xmlstream.toResponse(stanza, 'result')
                query = domish.Element((xmlstream2.NS_IQ_VERSION, 'query'))
                query.addElement((None, 'name'), content=version.NAME)
                query.addElement((None, 'version'), content=version.VERSION)
                response.addChild(query)
                self.send(response)
            else:
                # send resolved stanza to router
                self.send(stanza)

    def last_activity(self, stanza):
        if not stanza.consumed:
            stanza.consumed = True

            if stanza['to'] == self.parent.network:
                # server uptime
                seconds = self.parent.uptime()
                response = xmlstream.toResponse(stanza, 'result')
                response.addChild(domish.Element((xmlstream2.NS_IQ_LAST, 'query'), attribs={'seconds': str(int(seconds))}))
                self.send(response)
            else:
                # seconds ago user was last seen
                to = jid.JID(stanza['to'])

                def found_latest(latest, stanza):
                    if latest:
                        log.debug("found latest! %r" % (latest, ))
                        response = xmlstream.toResponse(stanza, 'result')
                        query = domish.Element((xmlstream2.NS_IQ_LAST, 'query'), attribs={ 'seconds' : str(latest[1]) })
                        response.addChild(query)
                        self.send(response)
                        log.debug("response sent: %s" % (response.toXml(), ))
                    else:
                        log.debug("no latest found! sending back error")
                        # TODO send error

                def _abort(stanzaId, callback, data):
                    log.debug("iq/last broadcast request timed out!")
                    self.xmlstream.removeObserver("/iq[@id='%s']" % stanza['id'], find_latest)
                    if not callback.called:
                        #callback.errback(failure.Failure(internet_error.TimeoutError()))
                        callback.callback(data['latest'])

                def find_latest(stanza, data, callback, timeout):
                    log.debug("iq/last: %s" % (stanza.toXml(), ))
                    data['count'] += 1
                    seconds = int(stanza.query['seconds'])
                    if not data['latest'] or seconds < data['latest'][1]:
                        # no need to parse JID here
                        data['latest'] = (stanza['from'], seconds)

                    if int(stanza.query['seconds']) == 0 or data['count'] >= data['max']:
                        log.debug("all replies received, stop watching iq %s" % (stanza['id'], ))
                        timeout.cancel()
                        self.xmlstream.removeObserver("/iq[@id='%s']" % stanza['id'], find_latest)
                        if not callback.called:
                            callback.callback(data['latest'])

                tmpTo = jid.JID(tuple=(to.user, to.host, to.resource))
                lastIq = domish.Element((None, 'iq'))
                lastIq['id'] = stanza['id']
                lastIq['type'] = 'get'
                lastIq['from'] = self.parent.network
                lastIq.addElement((xmlstream2.NS_IQ_LAST, 'query'))

                # data
                data = {
                    # max replies that can be received
                    'max': len(self.parent.keyring.hostlist()),
                    # number of replies received so far
                    'count': 0,
                    # contains a tuple with JID and timestamp of latest seen user
                    'latest': None,
                }
                # final callback
                callback = defer.Deferred()
                callback.addCallback(found_latest, stanza)
                # timeout of request
                timeout = reactor.callLater(self.parent.cache.MAX_LOOKUP_TIMEOUT, _abort, stanzaId=lastIq['id'], data=data, callback=callback)
                # request observer
                self.xmlstream.addObserver("/iq[@id='%s']" % lastIq['id'], find_latest, 100, data=data, callback=callback, timeout=timeout)

                # send iq last activity to the network
                for server in self.parent.keyring.hostlist():
                    tmpTo.host = server
                    lastIq['to'] = tmpTo.full()
                    self.send(lastIq)


class MessageHandler(XMPPHandler):
    """
    Handle message stanzas.
    @type parent: L{Resolver}
    """

    def connectionInitialized(self):
        # messages for the network
        #self.xmlstream.addObserver("/message[@to='%s']" % (self.parent.network), self.parent.error, 100)
        self.xmlstream.addObserver("/message", self.message, 90)

    def message(self, stanza):
        if not stanza.consumed:
            jid_from = jid.JID(stanza['from'])

            # no destination - use sender bare JID
            if not stanza.hasAttribute('to'):
                jid_to = jid.JID(stanza['from'])
                stanza['to'] = jid_to.userhost()
            else:
                jid_to = jid.JID(stanza['to'])

            # are we sending a message to a user we have blocked?
            if self.parent.is_presence_allowed(jid_to, jid_from) == -1:
                log.debug("sending message to blocked user, bouncing error")
                e = error.StanzaError('not-acceptable', 'cancel')
                errstanza = e.toResponse(stanza)
                errstanza.error.addElement((xmlstream2.NS_IQ_BLOCKING_ERRORS, 'blocked'))
                self.parent.send(errstanza)

            else:

                # check for permission
                if self.parent.is_presence_allowed(jid_from, jid_to) == 1:
                    # send to router (without implicitly consuming)
                    self.parent.send(stanza, force_delivery=True)
                else:
                    log.debug("not allowed to send messages, sending fake response to %s" % (stanza['from'], ))
                    if stanza.getAttribute('type') == 'chat' and xmlstream2.extract_receipt(stanza, 'request'):
                        self.send_fake_receipt(stanza)

    def send_fake_receipt(self, stanza):
        """Sends back a fake sent receipt, while silently discard the message."""
        msg = xmlstream.toResponse(stanza, stanza['type'])
        r = msg.addElement((xmlstream2.NS_XMPP_SERVER_RECEIPTS, 'sent'))
        r['id'] = util.rand_str(30, util.CHARSBOX_AZN_LOWERCASE)
        self.parent.send(msg)


class Resolver(xmlstream2.SocketComponent):
    """
    Kontalk resolver XMPP handler.
    This component resolves network JIDs in stanzas (kontalk.net) into server
    JIDs (prime.kontalk.net), altering the "to" attribute, then it bounces the
    stanza back to the router.

    @ivar subscriptions: a map of active user subscriptions (key=watched, value=subscribers)
    @type subscriptions: L{dict}

    @ivar whitelists: a map of user whitelists (key=user, value=list(allowed_users))
    @type whitelists: L{dict}

    @ivar blacklists: a map of user blacklists (key=user, value=list(blocked_users))
    @type blacklists: L{dict}

    @ivar cache: a local JID cache
    @type cache: L{JIDCache}
    """

    protocolHandlers = (
        JIDCache,
        PresenceHandler,
        RosterHandler,
        IQHandler,
        PrivacyListHandler,
        MessageHandler,
    )

    WHITELIST = 1
    BLACKLIST = 2

    def __init__(self, config):
        router_cfg = config['router']
        for key in ('socket', 'host', 'port'):
            if key not in router_cfg:
                router_cfg[key] = None

        router_jid = '%s.%s' % (router_cfg['jid'], config['host'])
        xmlstream2.SocketComponent.__init__(self, router_cfg['socket'], router_cfg['host'], router_cfg['port'], router_jid, router_cfg['secret'])
        self.config = config

        # this is for queueing keyring thread requests
        reactor.suggestThreadPoolSize(1)

        self.logTraffic = config['debug']
        self.network = config['network']
        self.servername = config['host']
        self.start_time = time.time()

        storage.init(config['database'])
        self.keyring = keyring.Keyring(storage.MySQLNetworkStorage(), config['fingerprint'], self.network, self.servername, True)
        self.presencedb = storage.MySQLPresenceStorage()

        self.subscriptions = {}
        self.whitelists = {}
        self.blacklists = {}

        # protocol handlers here!!
        for handler in self.protocolHandlers:
            inst = handler()
            if handler == JIDCache:
                self.cache = inst
            inst.setHandlerParent(self)

    def uptime(self):
        return time.time() - self.start_time

    def _authd(self, xs):
        component.Component._authd(self, xs)
        log.debug("connected to router")
        xs.addObserver("/iq", self.iq, 500)
        xs.addObserver("/presence", self.presence, 500)

        # bind to network route
        bind = domish.Element((None, 'bind'))
        bind['name'] = self.network
        bind.addElement((None, 'private'))
        xs.send(bind)

    def _disconnected(self, reason):
        component.Component._disconnected(self, reason)
        log.debug("lost connection to router (%s)" % (reason, ))

    def iq(self, stanza):
        to = stanza.getAttribute('to')

        if to is not None:
            to = jid.JID(to)
            # sending to full JID, forward to router
            if to.resource is not None:
                self.bounce(stanza)

            # sending to bare JID: handled by handlers

    def presence(self, stanza):
        to = stanza.getAttribute('to')

        if to is not None:
            to = jid.JID(to)
            # sending to full JID, forward to router
            if to.resource is not None:
                self.bounce(stanza)

            # sending to bare JID: handled by handlers

    def error(self, stanza, condition='service-unavailable'):
        if not stanza.consumed:
            log.debug("error %s" % (stanza.toXml(), ))
            stanza.consumed = True
            e = error.StanzaError(condition, 'cancel')
            self.send(e.toResponse(stanza))

    def bounce(self, stanza, *args, **kwargs):
        """Send the stanza to the router."""
        if not stanza.consumed:
            stanza.consumed = True
            self.send(stanza, *args, **kwargs)

    def result(self, stanza):
        """Sends back a result response stanza. Used for IQ stanzas."""
        stanza = xmlstream.toResponse(stanza, 'result')
        self.send(stanza)

    def build_vcard(self, userid, iq):
        """Adds a vCard to the given iq stanza."""
        fpr = self.keyring.get_fingerprint(userid)
        keydata = self.keyring.get_key(userid, fpr)
        # add vcard
        vcard = iq.addElement((xmlstream2.NS_XMPP_VCARD4, 'vcard'))
        vcard_key = vcard.addElement((None, 'key'))
        vcard_data = vcard_key.addElement((None, 'uri'))
        vcard_data.addContent(xmlstream2.DATA_PGP_PREFIX + base64.b64encode(keydata))
        return iq
