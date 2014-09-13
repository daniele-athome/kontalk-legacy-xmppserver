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
from twisted.internet import defer, reactor, task
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish
from twisted.words.protocols.jabber import jid, error, xmlstream

from wokkel import component

from kontalk.xmppserver import log, storage, util, xmlstream2, version, keyring


class PresenceHandler(XMPPHandler):
    """
    Handle presence stanzas.
    @ivar parent: resolver instance
    @type parent: L{Resolver}
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence[not(@type)]", self.onPresenceAvailable, 100)
        self.xmlstream.addObserver("/presence[@type='unavailable']", self.onPresenceUnavailable, 100)
        self.xmlstream.addObserver("/presence[@type='subscribe']", self.onSubscribe, 100)
        self.xmlstream.addObserver("/presence[@type='unsubscribe']", self.onUnsubscribe, 100)
        self.xmlstream.addObserver("/presence[@type='subscribed']", self.onSubscribed, 600)

    def onPresenceAvailable(self, stanza):
        """Handle available presence stanzas."""

        if stanza.consumed:
            return

        try:
            # initial presence from a remote resolver
            component, host = util.jid_component(stanza['from'], util.COMPONENT_RESOLVER)

            if host != self.parent.servername and host in self.parent.keyring.hostlist():
                self.send_privacy_lists('blocklist', self.parent.blacklists, stanza['from'])
                self.send_privacy_lists('whitelist', self.parent.whitelists, stanza['from'])

        except:
            pass

        self.parent.broadcastSubscribers(stanza)

    def send_privacy_lists(self, pname, plist, addr_from):
        for user, wl in plist.iteritems():
            iq = domish.Element((None, 'iq'))
            iq['from'] = '%s@%s' % (user, self.parent.network)
            iq['type'] = 'set'
            iq['id'] = util.rand_str(8)
            iq['to'] = addr_from
            allow = iq.addElement((xmlstream2.NS_IQ_BLOCKING, pname))

            for item in wl:
                elem = allow.addElement((None, 'item'))
                elem['jid'] = item

            self.parent.send(iq)

    def onPresenceUnavailable(self, stanza):
        """Handle unavailable presence stanzas."""

        if stanza.consumed:
            return

        user = jid.JID(stanza['from'])
        # forget any subscription requested by this user
        self.parent.cancelSubscriptions(self.parent.translateJID(user))
        # broadcast presence
        self.parent.broadcastSubscribers(stanza)

    def onSubscribe(self, stanza):
        """Handle subscription requests."""

        if stanza.consumed:
            return

        if self.parent.logTraffic:
            log.debug("subscription request: %s" % (stanza.toXml(), ))
        else:
            log.debug("subscription request to %s from %s" % (stanza['to'], stanza['from']))

        # extract jid the user wants to subscribe to
        jid_to = jid.JID(stanza['to'])
        jid_from = jid.JID(stanza['from'])

        # are we subscribing to a user we have blocked?
        if self.parent.is_presence_allowed(jid_to, jid_from) == -1:
            log.debug("subscribing to blocked user, bouncing error")
            e = error.StanzaError('not-acceptable', 'cancel')
            errstanza = e.toResponse(stanza)
            errstanza.error.addElement((xmlstream2.NS_IQ_BLOCKING_ERRORS, 'blocked'))
            self.send(errstanza)

        else:
            if not self.parent.subscribe(self.parent.translateJID(jid_from),
                    self.parent.translateJID(jid_to), stanza.getAttribute('id')):
                e = error.StanzaError('item-not-found')
                self.send(e.toResponse(stanza))

    def onUnsubscribe(self, stanza):
        """Handle unsubscription requests."""

        if stanza.consumed:
            return

        if self.parent.logTraffic:
            log.debug("unsubscription request: %s" % (stanza.toXml(), ))
        else:
            log.debug("unsubscription request to %s from %s" % (stanza['to'], stanza['from']))

        # extract jid the user wants to unsubscribe from
        jid_to = jid.JID(stanza['to'])
        jid_from = jid.JID(stanza['from'])

        self.parent.unsubscribe(self.parent.translateJID(jid_to),
            self.parent.translateJID(jid_from))

    def onSubscribed(self, stanza):
        if stanza.consumed:
            return

        log.debug("user %s accepted subscription by %s" % (stanza['from'], stanza['to']))
        stanza.consumed = True
        jid_to = jid.JID(stanza['to'])

        jid_from = jid.JID(stanza['from'])

        # add "to" user to whitelist of "from" user
        self.parent.add_whitelist(jid_from, jid_to)

        log.debug("SUBSCRIPTION SUCCESSFUL")

        if self.parent.cache.jid_available(jid_from):
            # send subscription accepted immediately and subscribe
            # TODO this is wrong, but do it for the moment until we find a way to handle this case
            self.parent.doSubscribe(jid_from, jid_to, stanza.getAttribute('id'), response_only=False)


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


class PrivacyListHandler(XMPPHandler):
    """
    Handle IQ urn:xmpp:blocking stanzas.
    @type parent: L{Resolver}
    """

    """
    TODO this needs some versioning or timestamping. When receiving a new privacy
    list, it will have a timestamp to indicate its versioning. The most recent
    will take precedence.
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='set']/blocklist[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.blacklist, 100)
        self.xmlstream.addObserver("/iq[@type='set']/whitelist[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.whitelist, 100)
        self.xmlstream.addObserver("/iq[@type='set']/allow[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.allow, 100)
        self.xmlstream.addObserver("/iq[@type='set']/unallow[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.unallow, 100)
        self.xmlstream.addObserver("/iq[@type='set']/block[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.block, 100)
        self.xmlstream.addObserver("/iq[@type='set']/unblock[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.unblock, 100)
        self.xmlstream.addObserver("/iq[@type='get']/blocklist[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.get_blacklist, 100)

    def get_blacklist(self, stanza):
        iq = xmlstream.toResponse(stanza, 'result')
        iq['to'] = stanza['from']
        blocklist = iq.addElement((xmlstream2.NS_IQ_BLOCKING, 'blocklist'))

        wl = self.parent.get_blacklist(jid.JID(stanza['from']))
        if wl:
            for item in wl:
                elem = blocklist.addElement((None, 'item'))
                elem['jid'] = item

        self.send(iq)

    def _blacklist(self, jid_from, items, remove=False, broadcast=True):
        if remove:
            fn = self.parent.remove_blacklist
        else:
            fn = self.parent.add_blacklist

        for it in items:
            jid_to = jid.JID(it['jid'])
            fn(jid_from, jid_to, broadcast)

    def _whitelist(self, jid_from, items, remove=False, broadcast=True):
        if remove:
            fn = self.parent.remove_whitelist
        else:
            fn = self.parent.add_whitelist

        for it in items:
            jid_to = jid.JID(it['jid'])
            fn(jid_from, jid_to, broadcast)

    def blacklist(self, stanza):
        jid_from = jid.JID(stanza['from'])
        items = stanza.blocklist.elements(uri=xmlstream2.NS_IQ_BLOCKING, name='item')
        if items:
            # FIXME shouldn't we replace instead of just adding?
            self._blacklist(jid_from, items, broadcast=False)

        self.parent.result(stanza)

    def whitelist(self, stanza):
        jid_from = jid.JID(stanza['from'])
        items = stanza.whitelist.elements(uri=xmlstream2.NS_IQ_BLOCKING, name='item')
        if items:
            # FIXME shouldn't we replace instead of just adding?
            self._whitelist(jid_from, items, broadcast=False)

        self.parent.result(stanza)

    def allow(self, stanza):
        jid_from = jid.JID(stanza['from'])
        broadcast = (jid_from.host == util.component_jid(self.parent.servername, util.COMPONENT_C2S))
        items = stanza.allow.elements(uri=xmlstream2.NS_IQ_BLOCKING, name='item')
        if items:
            self._whitelist(jid_from, items, broadcast=broadcast)

        if broadcast:
            self.parent.result(stanza)

    def unallow(self, stanza):
        jid_from = jid.JID(stanza['from'])
        broadcast = (jid_from.host == util.component_jid(self.parent.servername, util.COMPONENT_C2S))
        items = stanza.unallow.elements(uri=xmlstream2.NS_IQ_BLOCKING, name='item')
        if items:
            self._whitelist(jid_from, items, True, broadcast=broadcast)

        if broadcast:
            self.parent.result(stanza)

    def block(self, stanza):
        jid_from = jid.JID(stanza['from'])
        broadcast = (jid_from.host == util.component_jid(self.parent.servername, util.COMPONENT_C2S))
        items = stanza.block.elements(uri=xmlstream2.NS_IQ_BLOCKING, name='item')
        if items:
            self._blacklist(jid_from, items, broadcast=broadcast)

        if broadcast:
            self.parent.result(stanza)

    def unblock(self, stanza):
        jid_from = jid.JID(stanza['from'])
        broadcast = (jid_from.host == util.component_jid(self.parent.servername, util.COMPONENT_C2S))
        items = stanza.unblock.elements(uri=xmlstream2.NS_IQ_BLOCKING, name='item')
        if items:
            self._blacklist(jid_from, items, True, broadcast=broadcast)

        if broadcast:
            self.parent.result(stanza)


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


class PresenceStub(object):
    """VERY UNOPTIMIZED CLASS"""

    def __init__(self, _jid):
        """Creates a presence stub for a bare JID."""
        if _jid.resource:
            raise ValueError('not a bare JID.')
        self._avail = {}
        self.jid = _jid

    def __set__(self, name, value):
        if name == 'type':
            self.type = value
        elif name == 'show':
            if value in ['away', 'xa', 'chat', 'dnd']:
                self.show = value
            else:
                self.show = None
        elif name == 'status':
            if value:
                self.status = value.encode('utf-8')
            else:
                self.status = None
        elif name == 'priority':
            try:
                self.priority = int(value)
            except:
                self.priority = 0
        elif name == 'delay':
            try:
                self.delay = datetime.strptime(value, xmlstream2.XMPP_STAMP_FORMAT)
            except:
                self.delay = None
        else:
            raise AttributeError(name)

    def update(self, stanza):
        """
        Update this stub with data from the given unavailable presence.
        Presence data is updated only if delay is more recent than the old one.
        """
        ptype = stanza.getAttribute('type')
        if ptype != 'unavailable':
            raise ValueError('only unavailable presences are allowed.')

        delay = stanza.delay
        if delay:
            delay = datetime.strptime(delay['stamp'], xmlstream2.XMPP_STAMP_FORMAT)
            if self.delay:
                diff = delay - self.delay
                try:
                    diff_seconds = diff.total_seconds()
                except AttributeError:
                    diff_seconds = (diff.microseconds + (diff.seconds + diff.days * 24 * 3600) * 10**6) / 10**6
            else:
                # no delay :)
                diff_seconds = 1

            if diff_seconds >= 0:
                ujid = jid.JID(stanza['from'])
                # update local jid
                self.jid = ujid.userhostJID()

                if stanza.hasAttribute('type'):
                    self.type = stanza['type']
                else:
                    self.type = None

                # delay already parsed
                self.delay = delay

                for child in ('status', 'show', 'priority'):
                    e = getattr(stanza, child)
                    if e:
                        self.__set__(child, e.__str__())

    def push(self, stanza):
        """Push a presence to this stub."""
        ptype = stanza.getAttribute('type')
        if ptype == 'unavailable':
            raise ValueError('only available presences are allowed.')

        ujid = jid.JID(stanza['from'])
        # update local jid
        self.jid = ujid.userhostJID()

        # recreate presence stanza for local use
        presence = domish.Element((None, 'presence'))
        for attr in ('type', 'from'):
            if stanza.hasAttribute(attr):
                presence[attr] = stanza[attr]

        if stanza.hasAttribute('type'):
            self.type = stanza['type']
        else:
            self.type = None

        for child in ('status', 'show', 'priority', 'delay'):
            e = getattr(stanza, child)
            if e:
                self.__set__(child, e.__str__())
                presence.addChild(e)

        self._avail[ujid.resource] = presence

    def pop(self, resource):
        """Pop the presence for the given resource from this stub."""
        try:
            presence = self._avail[resource]
            del self._avail[resource]

            # no more presences - resource is now unavailable
            if len(self._avail) == 0:
                self.type = 'unavailable'
                # update delay with now
                self.delay = datetime.utcnow()

            return presence
        except:
            pass

    def presence(self):
        if self.available():
            return self._avail.values()
        else:
            return (self.toElement(), )

    def jids(self):
        """Returns a list of available resources from this JID."""
        users = []
        for avail in self._avail.itervalues():
            users.append(jid.JID(avail['from']))
        return users

    def available(self):
        """Returns true if available presence count is greater than 0."""
        return len(self._avail) > 0

    def __str__(self, *args, **kwargs):
        return self.__repr__(*args, **kwargs)

    def __repr__(self, *args, **kwargs):
        return '<PresenceStub jid=%s, avail=%r>' % (self.jid.full(), self._avail)

    @classmethod
    def fromElement(klass, e, from_host=None):
        p_type = e.getAttribute('type')
        if e.show:
            show = str(e.show)
        else:
            show = None
        if e.status:
            status = e.status.__str__()
        else:
            status = None
        try:
            priority = int(e.priority.__str__())
        except:
            priority = 0

        try:
            delay = e.delay['stamp']
        except:
            delay = None

        sender = jid.JID(e['from']).userhostJID()
        if from_host is not None:
            sender.host = from_host

        p = klass(sender)
        p.__set__('type', p_type)
        p.__set__('show', show)
        p.__set__('status', status)
        p.__set__('priority', priority)
        p.__set__('delay', delay)
        if not p_type:
            p.push(e)
        return p

    def toElement(self, attr='from'):
        p = domish.Element((None, 'presence'))
        p[attr] = self.jid.full()
        if self.type:
            p['type'] = self.type

        if self.show:
            p.addElement((None, 'show'), content=self.show)
        if self.priority != 0:
            p.addElement((None, 'priority'), content=str(self.priority))
        if self.status:
            p.addElement((None, 'status'), content=self.status)
        if self.delay:
            d = p.addElement((xmlstream2.NS_XMPP_DELAY, 'delay'))
            d['stamp'] = self.delay.strftime(xmlstream2.XMPP_STAMP_FORMAT)

        return p


class JIDCache(XMPPHandler):
    """
    Cache maintaining JID distributed in this Kontalk network.
    An instance is kept by the L{Resolver} component.
    @ivar presence_cache: cache of presence stanzas
    @type presence_cache: C{dict} [userid]=PresenceStub
    """

    """Seconds to wait for presence probe response from servers."""
    MAX_LOOKUP_TIMEOUT = 5

    def __init__(self):
        XMPPHandler.__init__(self)
        self.lookups = {}
        self.presence_cache = {}
        self._last_lookup = 0

        """ TEST TEST TEST
        def _print_cache():
            log.debug("CACHE(%d): %r" % (len(self.presence_cache), self.presence_cache, ))
        task.LoopingCall(_print_cache).start(5)
        """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence[not(@type)]", self.onPresenceAvailable, 200)
        self.xmlstream.addObserver("/presence[@type='unavailable']", self.onPresenceUnavailable, 200)
        # presence probes MUST be handled by server so the high priority
        self.xmlstream.addObserver("/presence[@type='probe']", self.onProbe, 600)
        # vCards MUST be handled by server so the high priority
        self.xmlstream.addObserver("/iq[@type='set']/vcard[@xmlns='%s']" % (xmlstream2.NS_XMPP_VCARD4, ), self.onVCardSet, 600)
        self.xmlstream.addObserver("/stanza/iq[@type='set']/vcard[@xmlns='%s']" % (xmlstream2.NS_XMPP_VCARD4, ), self.wrapped, 600, fn=self.onVCardSet)
        self.xmlstream.addObserver("/iq[@type='get']/vcard[@xmlns='%s']" % (xmlstream2.NS_XMPP_VCARD4, ), self.onVCardGet, 600)

    def wrapped(self, stanza, fn):
        fn(stanza.firstChildElement())

    def onPresenceAvailable(self, stanza):
        """Handle availability presence stanzas."""
        if self.parent.logTraffic:
            log.debug("presence: %s" % (stanza.toXml().encode('utf-8'), ))
        else:
            log.debug("presence available from %s" % (stanza['from'], ))

        # update usercache with last seen and status
        user = jid.JID(stanza['from'])
        if user.user:
            self.user_available(stanza)

    def onPresenceUnavailable(self, stanza):
        """Handle unavailable presence stanzas."""
        if self.parent.logTraffic:
            log.debug("user unavailable: %s" % (stanza.toXml().encode('utf-8'), ))
        else:
            log.debug("user unavailable from %s" % (stanza['from'], ))

        # local c2s or remote server has disconnected, remove presences from cache
        try:
            unused, host = util.jid_component(stanza['from'], util.COMPONENT_C2S)
            if host == self.parent.servername:
                log.debug("local c2s disconnecting, removing data from presence cache" % (host, ))
                keys = self.presence_cache.keys()
                for key in keys:
                    stub = self.presence_cache[key]
                    if stub.jid.host == stanza['from']:
                        del self.presence_cache[key]

            elif host in self.parent.keyring.hostlist():
                log.debug("server %s is disconnecting, taking over presence data" % (host, ))
                ordered_presence = []
                for stub in self.presence_cache.itervalues():
                    if stub.jid.host == stanza['from']:
                        ordered_presence.append(stub)

                # TEST TEST TEST
                # TODO this needs serious re-design from scratch (I mean the whole presence sharing architecture)
                from operator import attrgetter
                ordered_presence.sort(key=attrgetter('jid'))
                # take the N-th part
                index = 1
                for s in self.parent.keyring.hostlist():
                    # skip missing server
                    if s == host:
                        continue
                    # we found ourselves
                    if s == self.parent.servername:
                        break
                    index += 1

                if index > len(self.parent.keyring.hostlist()):
                    log.warn("we can't find ourselves on the servers table! WTF!?!?")

                else:
                    network_len = len(self.parent.keyring.hostlist())
                    presence_len = len(ordered_presence)
                    slice_start = presence_len / (network_len-1) * (index - 1)
                    slice_end = presence_len / (network_len-1) * ((index+1) - 1)
                    log.debug("slice_start = %d, slice_end = %d" % (slice_start, slice_end))
                    for i in range(slice_start, slice_end):
                        e = ordered_presence[i]
                        rewrite = None
                        presence = e.presence()
                        for p in presence:
                            # do not consider available presence stanzas
                            if p['type'] == 'unavailable':
                                rewrite = PresenceStub.fromElement(p, util
                                    .component_jid(self.parent.servername, util.COMPONENT_C2S))
                                self.presence_cache[e.jid.user] = rewrite
                                break

                        # simulate presence broadcast so resolvers will insert it into their cache
                        if rewrite:
                            p = rewrite.presence()
                            try:
                                fpr = self.parent.keyring.get_fingerprint(e.jid.user)
                                self.parent.presencedb.presence(p[0])
                                self.parent.presencedb.public_key(e.jid.user, fpr)
                            except keyring.KeyNotFoundException:
                                pass
                            self.send(p[0].toXml().encode('utf-8'))
            return

        except TypeError:
            pass
        except:
            import traceback
            traceback.print_exc()

        # normal user unavailable
        user = jid.JID(stanza['from'])

        if user.user:
            self.user_unavailable(stanza)

    def onVCardGet(self, stanza):
        log.debug("%s requested vCard for %s" % (stanza['from'], stanza['to']))
        jid_from = jid.JID(stanza['from'])
        jid_to = jid.JID(stanza['to'])
        try:
            # are we requesting vCard for a user we have blocked?
            if self.parent.is_presence_allowed(jid_to, jid_from) == -1:
                log.debug("requesting vCard for a blocked user, bouncing error")
                e = error.StanzaError('not-acceptable', 'cancel')
                errstanza = e.toResponse(stanza)
                errstanza.error.addElement((xmlstream2.NS_IQ_BLOCKING_ERRORS, 'blocked'))
                self.send(errstanza)

            else:
                fpr = self.parent.is_presence_allowed(jid_from, jid_to)
                log.debug("is_presence_allowed: %d" % (fpr, ))
                if fpr != 1:
                    raise Exception()

                fpr = self.parent.keyring.get_fingerprint(jid_to.user)
                keydata = self.parent.keyring.get_key(jid_to.user, fpr)

                iq = xmlstream.toResponse(stanza, 'result')
                # add vcard
                vcard = iq.addElement((xmlstream2.NS_XMPP_VCARD4, 'vcard'))
                vcard_key = vcard.addElement((None, 'key'))
                vcard_data = vcard_key.addElement((None, 'uri'))
                vcard_data.addContent(xmlstream2.DATA_PGP_PREFIX + base64.b64encode(keydata))
                self.send(iq)

        except:
            self.parent.error(stanza)

    def onVCardSet(self, stanza):
        """
        Handle vCards set IQs.
        This simply takes care of importing the key in the keyring for future
        signature verification. Actual key verification is done by c2s when
        accepting vCards coming from clients.
        WARNING/1 does this mean that we bindly accept keys from components? --
         YES blindly :P c2s will filter invalid requests
        WARNING/2 importing the key means that keys coming from local c2s are
        imported twice because the keyring is the same. Unless we want to make
        a separated keyring only for resolver? -- YES USING .gnupg-cache
        """
        # TODO parse vcard for interesting sections

        if stanza.vcard.key is not None:
            # we do this because of the uri member in domish.Element
            keydata = stanza.vcard.key.firstChildElement()
            if keydata.name == 'uri':
                keydata = str(keydata)

                if keydata.startswith(xmlstream2.DATA_PGP_PREFIX):
                    keydata = base64.b64decode(keydata[len(xmlstream2.DATA_PGP_PREFIX):])
                    # import into cache keyring
                    userid = util.jid_user(stanza['from'])
                    fpr = self.parent.keyring.check_user_key(keydata, userid)
                    if fpr:
                        log.debug("key cached successfully")
                    else:
                        log.warn("invalid key")

        # TODO send response!!!

    def send_user_presence(self, gid, sender, recipient):
        stub = self.lookup(recipient)
        log.debug("onProbe(%s): found %r" % (gid, stub, ))
        if stub:
            data = stub.presence()
            i = len(data)
            for x in data:
                presence = deepcopy(x)
                presence['to'] = sender.full()

                try:
                    # add fingerprint
                    fpr = self.parent.keyring.get_fingerprint(recipient.user)
                    if fpr:
                        pubkey = presence.addElement(('urn:xmpp:pubkey:2', 'pubkey'))
                        fprint = pubkey.addElement((None, 'print'))
                        fprint.addContent(fpr)
                except keyring.KeyNotFoundException:
                    log.warn("key not found for user %s" % (recipient, ))

                if gid:
                    # FIXME this will duplicate group elements - actually in storage there should be no group element!!!
                    group = presence.addElement((xmlstream2.NS_XMPP_STANZA_GROUP, 'group'))
                    group['id'] = gid
                    group['count'] = str(i)
                    i -= 1

                self.send(presence)
                return True

        # no such user
        return False

    def onProbe(self, stanza):
        """Handle presence probes."""

        if stanza.consumed:
            return

        log.debug("probe request: %s" % (stanza.toXml(), ))
        stanza.consumed = True
        to = jid.JID(stanza['to'])
        sender = jid.JID(stanza['from'])

        # are we probing a user we have blocked?
        if self.parent.is_presence_allowed(to, sender) == -1:
            log.debug("probing blocked user, bouncing error")
            e = error.StanzaError('not-acceptable', 'cancel')
            errstanza = e.toResponse(stanza)
            errstanza.error.addElement((xmlstream2.NS_IQ_BLOCKING_ERRORS, 'blocked'))
            self.send(errstanza)

        elif self.parent.is_presence_allowed(sender, to) == 1:
            gid = stanza.getAttribute('id')
            if not self.send_user_presence(gid, sender, to):
                response = xmlstream.toResponse(stanza, 'error')
                # TODO include error cause?
                self.send(response)

    def user_available(self, stanza):
        """Called when receiving a presence stanza."""
        userid = util.jid_user(stanza['from'])

        try:
            stub = self.presence_cache[userid]
            stub.push(stanza)
        except KeyError:
            stub = PresenceStub.fromElement(stanza)
            self.presence_cache[userid] = stub

    def user_unavailable(self, stanza):
        """Called when receiving a presence unavailable stanza."""
        ujid = jid.JID(stanza['from'])

        try:
            stub = self.presence_cache[ujid.user]
            if ujid.resource:
                stub.pop(ujid.resource)
            else:
                # update stub data if stanza is more recent
                stub.update(stanza)
        except KeyError:
            # user not found in cache -- shouldn't happen!!
            stub = PresenceStub.fromElement(stanza)
            self.presence_cache[ujid.user] = stub

    def network_presence_probe(self, to):
        """
        Broadcast a presence probe to find the given L{JID}.
        @return: a list of stanza IDs sent to the network that can be watched to
        for responses
        """
        """
        presence = domish.Element((None, 'presence'))
        presence['type'] = 'probe'
        presence['from'] = self.parent.network
        idList = []
        #to = jid.JID(tuple=(to.user, to.host, to.resource))
        for server in self.parent.keyring.hostlist():
            #to.host = server
            presence['to'] = to.user + '@' + server
            if to.resource:
                presence['to'] += '/' + to.resource
            presence.addUniqueId()
            #presence['id'] = util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
            self.send(presence)
            idList.append(presence['id'])
        """
        # we need to be fast here
        idList = []
        presence = "<presence type='probe' from='%s' to='%%s' id='%%s'/>" % (self.parent.network, )
        for server in self.parent.keyring.hostlist():
            packetId = util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
            dest = to.user + '@' + server
            if to.resource:
                dest += '/' + to.resource
            self.send(presence % (dest, packetId))
            idList.append(packetId)

        return idList

    def find(self, _jid, wait_factor=1.0):
        """
        Send a presence probe to the network and wait for responses.
        @return a L{Deferred} which will be fired with the JID of the probed
        entity.
        """
        idList = self.network_presence_probe(_jid)
        def _presence(stanza, callback, timeout, buf):
            # presence probe error - finish here
            if stanza.getAttribute('type') == 'error':
                # TODO duplicated code
                self.xmlstream.removeObserver("/presence/group[@id='%s']" % (stanza['id'], ), _presence)
                self.xmlstream.removeObserver("/presence[@type='error'][@id='%s']" % (stanza['id'], ), _presence)
                if not callback.called:
                    # cancel timeout
                    timeout.cancel()
                    # fire deferred
                    callback.callback(buf)
                return

            sender = jid.JID(stanza['from'])
            log.debug("JID %s found!" % (sender.full(), ))
            stanza.consumed = True
            buf.append(sender)

            chain = stanza.group
            # end of presence chain!!!
            if not chain or int(chain['count']) == len(buf):
                # TODO duplicated code
                self.xmlstream.removeObserver("/presence/group[@id='%s']" % (stanza['id'], ), _presence)
                self.xmlstream.removeObserver("/presence[@type='error'][@id='%s']" % (stanza['id'], ), _presence)
                if not callback.called:
                    # cancel timeout
                    timeout.cancel()
                    # fire deferred
                    callback.callback(buf)

        def _abort(stanzaId, callback, buf):
            #log.debug("presence broadcast request timed out!")
            self.xmlstream.removeObserver("/presence/group[@id='%s']" % (stanzaId, ), _presence)
            self.xmlstream.removeObserver("/presence[@type='error'][@id='%s']" % (stanzaId, ), _presence)
            if not callback.called:
                #callback.errback(failure.Failure(internet_error.TimeoutError()))
                callback.callback(buf if len(buf) > 0 else None)

        deferList = []
        for stanzaId in idList:
            d = defer.Deferred()
            deferList.append(d)
            # this will contain presence probe hits for this JID
            buf = []

            # timeout of request
            timeout = reactor.callLater(self.MAX_LOOKUP_TIMEOUT*wait_factor*len(idList), _abort, stanzaId=stanzaId, callback=d, buf=buf)

            # add stanza group observer
            self.xmlstream.addObserver("/presence/group[@id='%s']" % (stanzaId, ), _presence, 150, callback=d, timeout=timeout, buf=buf)
            # routing error observer
            self.xmlstream.addObserver("/presence[@type='error'][@id='%s']" % (stanzaId, ), _presence, 150, callback=d, timeout=timeout, buf=buf)

        # gather all returned presence from the network
        return defer.gatherResults(deferList, True)

    def jid_available(self, _jid):
        """Return true if L{JID} has an available resource."""
        try:
            return self.presence_cache[_jid.user].available()
        except:
            pass

        return False

    def lookup(self, _jid):
        try:
            return self.presence_cache[_jid.user]
        except:
            pass


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

    def send(self, stanza, force_delivery=False, force_bare=False):
        """
        Resolves stanza recipient and send the stanza to the router.
        @todo document parameters
        """

        # send raw xml if you really know what you are doing
        if not domish.IElement.providedBy(stanza):
            return component.Component.send(self, stanza)

        util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)

        # save original recipient for later
        stanza['original-to'] = stanza['to']
        to = jid.JID(stanza['to'])

        # force host in sender
        component_jid = util.component_jid(self.servername, util.COMPONENT_RESOLVER)
        sender = jid.JID(stanza['from'])
        if sender.host == self.network:
            sender.host = component_jid
            stanza['from'] = sender.full()

        # stanza is intended to the network
        if to.full() == self.network or to.host == component_jid:
            # TODO
            log.debug("stanza for the network: %s" % (stanza.toXml(), ))
            return

        # network JID - resolve and send to router
        elif to.host == self.network:
            rcpts = self.cache.lookup(to)
            log.debug("rcpts = %r" % (rcpts, ))

            if not rcpts:
                if not stanza.consumed:
                    stanza.consumed = True
                    log.debug("JID %s not found" % (to.full(), ))
                    e = error.StanzaError('item-not-found', 'cancel')
                    component.Component.send(self, e.toResponse(stanza))
                else:
                    log.debug("JID %s not found (stanza has been consumed)" % (to.full(), ))
                    return
            else:
                """
                Stanza delivery rules
                1. deliver to all available resources
                2. destination was a bare JID
                  a. if all resources are unavailable, deliver to the first network bare JID (then return)
                3. destination was a full JID:
                  a. deliver to full JID
                """
                log.debug("JID found: %r" % (rcpts, ))
                stanza.consumed = True

                jids = rcpts.jids()

                # destination was a full JID
                if to.resource and not force_bare:
                    # no available resources, deliver to bare JID if force delivery
                    if len(jids) == 0 and force_delivery:
                        stanza['to'] = rcpts.jid.userhost()
                        component.Component.send(self, stanza)
                    # deliver if resource is available
                    else:
                        sent = False
                        for _to in jids:
                            if _to.resource == to.resource:
                                stanza['to'] = _to.full()
                                component.Component.send(self, stanza)
                                sent = True
                                break

                        # if sent=False it means that the intended resource has vanished
                        # if force delivery is enabled, deliver to the first available resource
                        if not sent and len(jids) > 0 and force_delivery:
                            stanza['to'] = jids[0].full()
                            component.Component.send(self, stanza)

                # destination was a bare JID
                else:
                    log.debug("destination was a bare JID (force_bare=%s)" % (force_bare, ))
                    # no available resources, send to first network bare JID
                    if len(jids) == 0 or force_bare:
                        stanza['to'] = rcpts.jid.userhost()
                        component.Component.send(self, stanza)
                    else:
                        for _to in jids:
                            stanza['to'] = _to.full()
                            component.Component.send(self, stanza)

        # otherwise send to router
        else:
            component.Component.send(self, stanza)

    def cancelSubscriptions(self, user):
        """Cancel all subscriptions requested by the given user."""
        for rlist in self.subscriptions.itervalues():
            for sub in list(rlist):
                if sub == user:
                    rlist.remove(sub)

    def subscribe(self, jid_from, jid_to, gid=None, send_subscribed=True):
        if jid_to.host == self.network and not self.cache.lookup(jid_to):
            log.debug("user %s not found, rejecting subscription request" % (jid_to, ))
            # no point in proceeding if user does not exists
            return False

        allowed = self.is_presence_allowed(jid_from, jid_to)

        if allowed == 1:
            self.doSubscribe(jid_to, jid_from, gid, send_subscribed=send_subscribed)
        elif allowed == -1:
            log.debug("user is blacklisted, ignoring request")
        else:
            log.debug("not authorized to subscribe to user's presence, sending request")
            try:
                stanza = domish.Element((None, 'presence'))
                stanza['type'] = 'subscribe'
                stanza['from'] = jid_from.full()
                stanza['to'] = jid_to.full()

                fpr = self.keyring.get_fingerprint(jid_from.user)
                keydata = self.keyring.get_key(jid_from.user, fpr)
                pubkey = stanza.addElement(('urn:xmpp:pubkey:2', 'pubkey'))

                # key data
                key = pubkey.addElement((None, 'key'))
                key.addContent(base64.b64encode(keydata))

                # fingerprint
                fprint = pubkey.addElement((None, 'print'))
                fprint.addContent(fpr)

                self.send(stanza)
            except:
                import traceback
                traceback.print_exc()
                return False

        return True


    def doSubscribe(self, to, subscriber, gid=None, response_only=False, send_subscribed=True):
        """Subscribe a given user to events from another one."""

        if not response_only:
            try:
                if subscriber not in self.subscriptions[to]:
                    self.subscriptions[to].append(subscriber)
            except:
                self.subscriptions[to] = [subscriber]

            log.debug("subscriptions: %r" % (self.subscriptions, ))

        if send_subscribed:
            # send subscription accepted immediately
            pres = domish.Element((None, "presence"))
            if gid:
                pres['id'] = gid
            pres['to'] = subscriber.full()
            pres['from'] = to.userhost()
            pres['type'] = 'subscribed'
            self.send(pres)

        if not response_only:
            # simulate a presence probe response
            if not gid:
                gid = util.rand_str(8)
            self.cache.send_user_presence(gid, subscriber, to)

        """
        # send a fake roster entry
        roster = domish.Element((None, 'iq'))
        roster['type'] = 'set'
        roster['to'] = subscriber.full()
        query = domish.Element((xmlstream2.NS_IQ_ROSTER, 'query'))
        query.addChild(domish.Element((None, 'item'), attribs={
            'jid'           : to.userhost(),
            'subscription'  : 'both',
        }))
        roster.addChild(query)
        self.send(roster)
        """

    def unsubscribe(self, to, subscriber):
        """Unsubscribe a given user from events from another one."""
        try:
            self.subscriptions[to].remove(subscriber)

            # clean up
            if len(self.subscriptions[to]) == 0:
                del self.subscriptions[to]
        except:
            pass

    def broadcastSubscribers(self, stanza):
        """Broadcast stanza to JID subscribers."""

        user = jid.JID(stanza['from'])

        try:
            unused, host = util.jid_component(user.host)

            # FIXME wrong host check (this is a one of the causes of the invalid-from bug)
            if host == self.servername or host in self.keyring.hostlist():
                # local or network user: translate host name
                watched = jid.JID(tuple=(user.user, self.network, user.resource))
            else:
                # other JIDs, use unchanged
                watched = user

        except ValueError:
            # other JIDs, use unchanged
            watched = user

        #log.debug("checking subscriptions to %s" % (watched.full(), ))
        bareWatched = watched.userhostJID()
        if bareWatched in self.subscriptions:
            #stanza['from'] = watched.full()

            removed = []
            for sub in self.subscriptions[bareWatched]:
                if self.is_presence_allowed(sub, watched) == 1:
                    log.debug("notifying subscriber %s" % (sub, ))
                    stanza['to'] = sub.userhost()
                    self.send(stanza)
                else:
                    log.debug("%s is not allowed to see presence" % (sub, ))
                    removed.append(sub)

            # remove unauthorized users
            for e in removed:
                self.subscriptions[bareWatched].remove(e)

    def translateJID(self, _jid, resource=True):
        """
        Translate a server JID (user@component.prime.kontalk.net) into a network JID
        (user@kontalk.net).
        """
        # TODO ehm :D
        try:
            unused, host = util.jid_component(_jid.host)
            if host in self.keyring.hostlist():
                return jid.JID(tuple=(_jid.user, self.network, _jid.resource if resource else None))
        except ValueError:
            pass

        return _jid if resource else _jid.userhostJID()

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

    def _broadcast_privacy_list_change(self, dest, src, node):
        # broadcast to all resolvers
        iq = domish.Element((None, 'iq'))
        iq['from'] = dest
        iq['type'] = 'set'
        iq['id'] = util.rand_str(8)
        nodeElement = iq.addElement((xmlstream2.NS_IQ_BLOCKING, node))
        elem = nodeElement.addElement((None, 'item'))
        elem['jid'] = src

        for server in self.keyring.hostlist():
            if server != self.servername:
                iq['to'] = util.component_jid(server, util.COMPONENT_RESOLVER)
                self.send(iq)

    def _privacy_list_add(self, jid_to, jid_from, list_type, broadcast=True):
        if list_type == self.WHITELIST:
            node = 'allow'
            data = self.whitelists
        elif list_type == self.BLACKLIST:
            node = 'block'
            data = self.blacklists

        try:
            wl = data[jid_to.user]
        except KeyError:
            wl = data[jid_to.user] = set()

        src = self.translateJID(jid_to, False).userhost()
        dest = self.translateJID(jid_from, False).userhost()

        wl.add(dest)

        # broadcast to all resolvers
        if broadcast:
            self._broadcast_privacy_list_change(src, dest, node)

    def _privacy_list_remove(self, jid_to, jid_from, list_type, broadcast=True):
        if list_type == self.WHITELIST:
            node = 'unallow'
            data = self.whitelists
        elif list_type == self.BLACKLIST:
            node = 'unblock'
            data = self.blacklists

        if jid_to.user in data:
            wl = data[jid_to.user]

            src = self.translateJID(jid_to, False).userhost()
            dest = self.translateJID(jid_from, False).userhost()

            wl.discard(dest)

            # broadcast to all resolvers
            if broadcast:
                self._broadcast_privacy_list_change(src, dest, node)

    def add_blacklist(self, jid_to, jid_from, broadcast=True):
        """Adds jid_from to jid_to's blacklist."""
        self._privacy_list_add(jid_to, jid_from, self.BLACKLIST, broadcast)

    def add_whitelist(self, jid_to, jid_from, broadcast=True):
        """Adds jid_from to jid_to's whitelist."""
        self._privacy_list_add(jid_to, jid_from, self.WHITELIST, broadcast)

    def remove_blacklist(self, jid_to, jid_from, broadcast=True):
        """Removes jid_from from jid_to's blacklist."""
        self._privacy_list_remove(jid_to, jid_from, self.BLACKLIST, broadcast)

    def remove_whitelist(self, jid_to, jid_from, broadcast=True):
        """Removes jid_from from jid_to's whitelist."""
        self._privacy_list_remove(jid_to, jid_from, self.WHITELIST, broadcast)

    def get_whitelist(self, _jid):
        try:
            return self.whitelists[_jid.user]
        except KeyError:
            return None

    def get_blacklist(self, _jid):
        try:
            return self.blacklists[_jid.user]
        except KeyError:
            return None

    def is_presence_allowed(self, jid_from, jid_to):
        """
        Checks if requester (from) is allowed to see a user's (to) presence.
        @return 1 if allowed, 0 if not allowed, -1 if blacklisted, -2 if user not found
        """

        if not self.cache.lookup(jid_to):
            return -2

        # servers are allowed to subscribe to user presence
        if not jid_from.user:
            return 1

        # translate to network JID first
        jid_from = self.translateJID(jid_from, False)
        translated_to = self.translateJID(jid_to, False)

        # talking to ourselves :)
        if jid_from == translated_to:
            return 1

        # blacklist has priority
        try:
            bl = self.blacklists[jid_to.user]
            if jid_from.userhost() in bl:
                return -1

        except KeyError:
            # blacklist not present for user - go ahead
            pass

        try:
            wl = self.whitelists[jid_to.user]
            if jid_from.userhost() in wl:
                return 1

        except KeyError:
            # whitelist not present for the user - not authorized
            pass

        return 0
