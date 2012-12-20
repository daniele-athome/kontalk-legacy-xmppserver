# -*- coding: utf-8 -*-
"""Kontalk XMPP resolver component."""
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
from datetime import datetime

from twisted.python import failure
from twisted.internet import defer, reactor
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish
from twisted.words.protocols.jabber import jid, error, xmlstream, client

from wokkel import component

from kontalk.xmppserver import log, storage, util, xmlstream2, version, keyring


class PresenceHandler(XMPPHandler):
    """Handle presence stanzas."""

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence[not(@type)]", self.onPresenceAvailable, 100)
        self.xmlstream.addObserver("/presence[@type='unavailable']", self.onPresenceUnavailable, 100)
        self.xmlstream.addObserver("/presence[@type='subscribe']", self.onSubscribe, 100)

    def onPresenceAvailable(self, stanza):
        """Handle availability presence stanzas."""

        if stanza.consumed:
            return

        self.parent.broadcastSubscribers(stanza)

    def onPresenceUnavailable(self, stanza):
        """Handle unavailable presence stanzas."""

        if stanza.consumed:
            return

        user = jid.JID(stanza['from'])
        # forget any subscription requested by this user
        self.parent.cancelSubscriptions(user)
        # broadcast presence
        self.parent.broadcastSubscribers(stanza)

    def onSubscribe(self, stanza):
        """Handle subscription requests."""

        if stanza.consumed:
            return

        log.debug("subscription request: %s" % (stanza.toXml(), ))

        # extract jid the user wants to subscribe to
        jid_to = jid.JID(stanza['to'])
        jid_from = jid.JID(stanza['from'])

        self.parent.subscribe(jid_to, jid_from)


class IQHandler(XMPPHandler):
    """
    Handle IQ stanzas.
    @type parent: L{Resolver}
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='get']/query[@xmlns='%s']" % (xmlstream2.NS_IQ_ROSTER), self.roster, 100)
        self.xmlstream.addObserver("/iq[@type='get']/query[@xmlns='%s']" % (xmlstream2.NS_IQ_LAST, ), self.last_activity, 100)
        self.xmlstream.addObserver("/iq[@type='get']/query[@xmlns='%s']" % (xmlstream2.NS_IQ_VERSION, ), self.version, 100)
        self.xmlstream.addObserver("/iq[@type='result']", self.parent.bounce, 100)
        self.xmlstream.addObserver("/iq/query", self.parent.error, 80)

    def roster(self, stanza):
        items = stanza.query.elements(uri=xmlstream2.NS_IQ_ROSTER, name='item')
        if items:
            stanza.consumed = True
            dlist = []
            for item in items:
                log.debug("checking for roster: %s" % (item['jid'], ))
                dlist.append(self.parent.cache.lookup(jid.JID(item['jid']), refresh=True))

            def _roster(data, stanza):
                log.debug("roster result: %r" % (data, ))
                response = xmlstream2.toResponse(stanza, 'result')
                unique = set([e.userhostJID() for entry in data for e in entry])
                if len(unique) > 0:
                    log.debug("roster output: %r" % (unique, ))
                    roster = response.addElement((xmlstream2.NS_IQ_ROSTER, 'query'))
                    for e in unique:
                        item = roster.addElement((None, 'item'))
                        item['jid'] = self.parent.translateJID(e).userhost()

                self.send(response)

                if len(unique) > 0:
                    # simulate a presence probe
                    from copy import deepcopy
                    for entry in data:
                        gid = util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
                        i = len(entry)
                        for e in entry:
                            presence = deepcopy(self.parent.cache.presence_cache[e])
                            presence['to'] = stanza['from']
                            # FIXME this will duplicate group elements - actually in storage there should be no group element!!!
                            group = presence.addElement((xmlstream2.NS_XMPP_STANZA_GROUP, 'group'))
                            group['id'] = gid
                            group['count'] = str(i)
                            i -= 1
                            self.send(presence)

            d = defer.gatherResults(dlist)
            d.addCallback(_roster, stanza)

    def version(self, stanza):
        if not stanza.consumed:
            stanza.consumed = True

            if stanza['to'] == self.parent.network:
                response = xmlstream2.toResponse(stanza, 'result')
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
                response = xmlstream2.toResponse(stanza, 'result')
                response.addChild(domish.Element((xmlstream2.NS_IQ_LAST, 'query'), attribs={'seconds': str(int(seconds))}))
                self.send(response)
            else:
                # seconds ago user was last seen
                to = jid.JID(stanza['to'])

                def found_latest(latest, stanza):
                    if latest:
                        log.debug("found latest! %r" % (latest, ))
                        response = xmlstream2.toResponse(stanza, 'result')
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
            # no destination - use sender bare JID
            if not stanza.hasAttribute('to'):
                stanza['to'] = jid.JID(stanza['from']).userhost()

            # generate message id if client is requesting server receipts
            """
            FIXME it is safe here to check if request has already been generated?
            It could be forged by client!!!
            """
            if xmlstream2.extract_receipt(stanza, 'request') and not stanza.request.hasAttribute('id'):
                stanza.request['id'] = util.rand_str(30, util.CHARSBOX_AZN_LOWERCASE)

            # send to router (without implicitly consuming)
            self.parent.send(stanza, force_unavailable=False, force_delivery=(stanza.sent is not None or stanza.received is not None))


class JIDCache(XMPPHandler):
    """
    Cache maintaining JID distributed in this Kontalk network.
    An instance is kept by the L{Resolver} component.
    @ivar jid_cache: cache of JIDs location [userid][resource]=host
    @type jid_cache: C{dict}
    @ivar presence_cache: cache of presence stanzas
    @type presence_cache: C{dict} [JID]=<presence/>
    """

    """Seconds should pass to consider the cache to be old."""
    MAX_CACHE_REFRESH_DELAY = 60
    """Seconds to wait for presence probe response from servers."""
    MAX_LOOKUP_TIMEOUT = 5

    def __init__(self):
        XMPPHandler.__init__(self)
        self.jid_cache = {}
        self.presence_cache = {}
        self._last_lookup = 0

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence[not(@type)]", self.onPresenceAvailable, 200)
        self.xmlstream.addObserver("/presence[@type='unavailable']", self.onPresenceUnavailable, 200)
        # presence probes MUST be handled by server so the high priority
        self.xmlstream.addObserver("/presence[@type='probe']", self.onProbe, 600)

    def onPresenceAvailable(self, stanza):
        """Handle availability presence stanzas."""
        log.debug("presence: %s" % (stanza.toXml().encode('utf-8'), ))

        # update usercache with last seen and status
        user = jid.JID(stanza['from'])
        if user.user:
            if user.host == self.parent.servername:
                self.parent.presencedb.presence(stanza)

            self.user_available(stanza)

    def onPresenceUnavailable(self, stanza):
        """Handle unavailable presence stanzas."""
        log.debug("user unavailable: %s" % (stanza.toXml().encode('utf-8'), ))
        user = jid.JID(stanza['from'])

        if user.user:
            if user.host == self.parent.servername:
                # consider only stanzas without delay (that is, sent by client or on behalf of it)
                if not stanza.delay:
                    if stanza.status is not None:
                        # update last seen and status
                        self.parent.presencedb.presence(stanza)
                    else:
                        # update last seen only
                        self.parent.presencedb.touch(user)

            self.user_unavailable(stanza)

    def onProbe(self, stanza):
        """Handle presence probes."""

        if stanza.consumed:
            return

        log.debug("probe request: %s" % (stanza.toXml(), ))
        stanza.consumed = True
        sender = jid.JID(stanza['from'])
        to = jid.JID(stanza['to'])

        def _lookup(data, gid):
            log.debug("onProbe(%s): found %r" % (gid, data, ))
            if data:
                # TEST using deepcopy is not safe
                from copy import deepcopy
                i = len(data)
                for user in data:
                    presence = deepcopy(self.presence_cache[user])
                    presence['to'] = sender.full()
                    if gid:
                        # FIXME this will duplicate group elements - actually in storage there should be no group element!!!
                        group = presence.addElement((xmlstream2.NS_XMPP_STANZA_GROUP, 'group'))
                        group['id'] = gid
                        group['count'] = str(i)
                        i -= 1

                    self.send(presence)

        d = self.lookup(to, refresh=True)
        d.addCallback(_lookup, gid=stanza.getAttribute('id'))

    def user_available(self, stanza):
        """Called when receiving a presence stanza."""
        ujid = jid.JID(stanza['from'])
        userid, resource = util.jid_to_userid(ujid, True)
        if userid not in self.jid_cache:
            self.jid_cache[userid] = dict()

        now = time.time()
        # recreate presence stanza for local use
        presence = domish.Element((None, 'presence'))
        for attr in ('type', 'to', 'from'):
            if stanza.hasAttribute(attr):
                presence[attr] = stanza[attr]
        for child in ('status', 'show', 'priority', 'delay'):
            e = getattr(stanza, child)
            if e:
                presence.addChild(e)

        self.presence_cache[ujid] = presence
        self.jid_cache[userid][resource] = (now, ujid.host)
        #self._last_lookup = time.time()

    def user_unavailable(self, stanza):
        """Called when receiving a presence unavailable stanza."""
        self.user_available(stanza)
        """
        ujid = jid.JID(stanza['from'])
        userid, resource = util.jid_to_userid(ujid, True)
        if userid in self.jid_cache and resource in self.jid_cache[userid]:
            del self.jid_cache[userid][resource]
            if len(self.jid_cache[userid]) == 0:
                del self.jid_cache[userid]

        self.presence_cache[ujid] = stanza
        #self._last_lookup = time.time()
        """

    def network_presence_probe(self, to):
        """
        Broadcast a presence probe to find the given L{JID}.
        @return: a list of stanza IDs sent to the network that can be watched to
        for responses
        """
        presence = domish.Element((None, 'presence'))
        presence['type'] = 'probe'
        presence['from'] = self.parent.network
        idList = []
        to = jid.JID(tuple=(to.user, to.host, to.resource))
        for server in self.parent.keyring.hostlist():
            to.host = server
            presence['to'] = to.full()
            presence['id'] = util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
            self.send(presence)
            idList.append(presence['id'])

        return idList

    def find(self, _jid):
        """
        Send a presence probe to the network and wait for responses.
        @return a L{Deferred} which will be fired with the JID of the probed
        entity.
        """
        idList = self.network_presence_probe(_jid)
        def _presence(stanza, callback, timeout, buf):
            # check if stanza is for the requested user
            sender = jid.JID(stanza['from'])
            log.debug("JID %s found!" % (sender.full(), ))
            stanza.consumed = True
            buf.append(sender)

            chain = stanza.group
            # end of presence chain!!!
            if not chain or int(chain['count']) == len(buf):
                self.xmlstream.removeObserver("/presence/group[@id='%s']" % (stanza['id'], ), _presence)
                if not callback.called:
                    # cancel timeout
                    timeout.cancel()
                    # fire deferred
                    callback.callback(buf)

        def _abort(stanzaId, callback, buf):
            log.debug("presence broadcast request timed out!")
            self.xmlstream.removeObserver("/presence/group[@id='%s']" % (stanzaId, ), _presence)
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
            timeout = reactor.callLater(self.MAX_LOOKUP_TIMEOUT, _abort, stanzaId=stanzaId, callback=d, buf=buf)

            self.xmlstream.addObserver("/presence/group[@id='%s']" % (stanzaId, ), _presence, callback=d, timeout=timeout, buf=buf)

        # gather all returned presence from the network
        return defer.gatherResults(deferList, True)

    def jid_available(self, _jid):
        """Return true if full L{JID} is an available resource."""
        try:
            # no type attribute - assume available
            if not self.presence_cache[_jid].getAttribute('type'):
                return True
        except:
            pass

        return False

    def cache_lookup(self, _jid, unavailable=True):
        """
        Search a JID in the server caches. If jid is a bare JID, all matches
        are returned.
        @return a list of translated server JIDs if found.
        """

        if _jid.resource is not None:
            # full JID
            try:
                stamp, host = self.jid_cache[_jid.user][_jid.resource]
                hit = jid.JID(tuple=(_jid.user, host, _jid.resource))
                # FIXME redundant condition
                if not unavailable and self.jid_available(hit):
                    return set((hit, ))
                else:
                    return set((hit, ))
            except:
                pass
        else:
            # bare JID
            try:
                resources = self.jid_cache[_jid.user]
                out = set([jid.JID(tuple=(_jid.user, host, resource)) for resource, (stamp, host) in resources.iteritems()])
                if not unavailable:
                    tmp = set()
                    for u in out:
                        if self.jid_available(u): tmp.add(u)
                    out = tmp
                return out
            except:
                pass

        return None

    def lookup(self, _jid, refresh=False):
        """
        Lookup a L{JID} in the network.
        @param refresh: if true lookup is started over the whole network
        immediately; otherwise, just cached results are returned if cache is not
        so old; in that case, a lookup is started anyway. A lookup is started
        also if refresh is false and no results are found in cache - just to be
        sure the requested L{JID} doesn't exist.
        @rtype: L{Deferred}
        """

        log.debug("[%s] looking up" % (_jid.full(), ))

        # force refresh is cache is too old
        now = time.time()
        diff = now - self._last_lookup
        log.debug("[%s] now=%d, last=%d, diff=%.2f" % (_jid.full(), now, self._last_lookup, diff))
        if diff > self.MAX_CACHE_REFRESH_DELAY:
            refresh = True

        if not refresh:
            hits = self.cache_lookup(_jid)
            log.debug("[%s] local cache hits: %r (%r)" % (_jid.full(), hits, self.jid_cache))

            if hits:
                log.debug("[%s] found: %r" % (_jid.full(), hits))
                return defer.succeed(hits)
            else:
                refresh = True

        # evaluate refresh again
        if refresh:
            # refreshing, lookup the network
            d = self.find(_jid)

            self._last_lookup = now

            # cumulative response
            clientDeferred = defer.Deferred()
            def _cb(result):
                log.debug("result = %r" % (result, ))
                out = set()
                # TODO this is always true since errbacks are not really used
                if not isinstance(result, failure.Failure):
                    # FIXME this is really a messy algorithm
                    for hit in result:
                        if hit:
                            for x in hit:
                                added = False
                                for cur in out:
                                    if cur.user == x.user and cur.resource == x.resource and cur.host != x.host:
                                        log.debug("duplicate found: %r/%r" % (cur, x))
                                        """
                                        Take the most recent presence:
                                        1. available presence is always the most recent (without type)
                                        2. difference between <delay/> extensions
                                        2. unavailable presences without <delay/> are considered
                                           only if 1 and 2 are not a match
                                        """
                                        def _presencecmp(p1, p2):
                                            """
                                            strcmp for presence stanzas :)
                                            """

                                            # available presence is always the most recent (without type)
                                            if not p1.getAttribute('type'):
                                                return 1
                                            elif not p2.getAttribute('type'):
                                                return -1

                                            # difference between <delay/> extensions
                                            if p1.delay and p2.delay:
                                                # both delay present, compare them
                                                p1_time = datetime.strptime(p1.delay['stamp'], xmlstream2.XMPP_STAMP_FORMAT)
                                                p2_time = datetime.strptime(p2.delay['stamp'], xmlstream2.XMPP_STAMP_FORMAT)
                                                if p1_time > p2_time:
                                                    return 1
                                                elif p1_time < p2_time:
                                                    return -1
                                                return 0

                                            # only p1 has <delay/>
                                            if p1.delay:
                                                return 1
                                            # only p2 has <delay/>
                                            elif p2.delay:
                                                return -1

                                            # no <delay/> found on both stanzas
                                            # no way to compare stanzas
                                            return 0

                                        # already found, discard obsolete value
                                        if _presencecmp(self.presence_cache[cur], self.presence_cache[x]) < 0:
                                            log.debug("discarding %s and adding %s" % (cur.full(), x.full()))
                                            out.discard(cur)
                                            out.add(x)
                                        added = True

                                if not added:
                                    out.add(x)

                clientDeferred.callback(out)

            d.addBoth(_cb)
            return clientDeferred


class Resolver(component.Component):
    """
    Kontalk resolver XMPP handler.
    This component resolves network JIDs in stanzas (kontalk.net) into server
    JIDs (prime.kontalk.net), altering the "to" attribute, then it bounces the
    stanza back to the router.

    @ivar presencedb: database connection to the usercache table
    @type presencedb: L{PresenceStorage}

    @ivar subscriptions: a map of user subscriptions (key=watched, value=subscribers)
    @type subscriptions: L{dict}

    @ivar cache: a local JID cache
    @type cache: L{JIDCache}
    """

    protocolHandlers = (
        JIDCache,
        PresenceHandler,
        IQHandler,
        MessageHandler,
    )

    def __init__(self, config):
        router_cfg = config['router']
        print router_cfg
        component.Component.__init__(self, router_cfg['host'], router_cfg['port'], router_cfg['jid'], router_cfg['secret'])
        self.config = config

        self.logTraffic = config['debug']
        self.network = config['network']
        self.servername = config['host']
        self.start_time = time.time()

        storage.init(config['database'])
        self.presencedb = storage.MySQLPresenceStorage()
        self.keyring = keyring.Keyring(storage.MySQLNetworkStorage(), config['fingerprint'], self.servername)

        self.subscriptions = {}

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

    def send(self, stanza, force_unavailable=False, force_delivery=False):
        """
        Resolves stanza recipient and send the stanza to the router.
        @todo document parameters
        """

        util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)

        to = jid.JID(stanza['to'])

        # stanza is intended to the network
        if to.full() == self.network:
            # TODO
            log.debug("stanza for the network: %s" % (stanza.toXml(), ))
            return

        # network JID - resolve and send to router
        elif to.host == self.network:
            def _lookup(rcpts, stanza, sent):
                log.debug("rcpts = %r" % (rcpts, ))
                if rcpts is None or len(rcpts) == 0:
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
                    Stanza delivery rules (force_unavailable=False):
                    1. deliver to all available resources
                    2. destination was a bare JID
                      a. if all resources are unavailable, deliver to the first network bare JID (then return)
                    3. destination was a full JID:
                      a. deliver to full JID if force_delivery=True

                    Stanza delivery rules (force_unavailable=True):
                    1. deliver to all resources found
                    2. if no resource is available, silently drop stanza
                    """
                    log.debug("JID found: %r" % (rcpts, ))
                    stanza.consumed = True

                    if not force_unavailable:
                        # destination was a full JID
                        if to.resource:
                            # deliver anyway
                            if force_delivery:
                                for _to in rcpts:
                                    stanza['to'] = _to.full()
                                    component.Component.send(self, stanza)

                        # destination was a bare JID
                        else:
                            avail = 0
                            for _to in rcpts:
                                if self.cache.jid_available(_to):
                                    avail += 1
                                    stanza['to'] = _to.full()
                                    component.Component.send(self, stanza)

                            # no available resources, send to first network bare JID
                            if avail == 0:
                                for _to in rcpts:
                                    stanza['to'] = _to.userhost()
                                    component.Component.send(self, stanza)
                                    break

                    else:
                        for _to in rcpts:
                            if self.cache.jid_available(_to):
                                stanza['to'] = _to.full()
                                component.Component.send(self, stanza)

            sent = set()
            d = self.cache.lookup(to, refresh=False)
            d.addCallback(_lookup, stanza=stanza, sent=sent)

        # otherwise send to router
        else:
            component.Component.send(self, stanza)

    def cancelSubscriptions(self, user):
        """Cancel all subscriptions requested by the given user."""
        for rlist in self.subscriptions.itervalues():
            for sub in rlist:
                if sub == user:
                    rlist.remove(sub)

    def subscribe(self, to, subscriber):
        """Subscribe a given user to events from another one."""
        try:
            if subscriber not in self.subscriptions[to]:
                self.subscriptions[to].append(subscriber)
        except:
            self.subscriptions[to] = [subscriber]

        log.debug("subscriptions: %r" % (self.subscriptions, ))

        # send subscription accepted immediately
        pres = domish.Element((None, "presence"))
        pres['to'] = subscriber.full()
        pres['from'] = to.userhost()
        pres['type'] = 'subscribed'
        self.send(pres)

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

    def broadcastSubscribers(self, stanza):
        """Broadcast stanza to JID subscribers."""

        user = jid.JID(stanza['from'])

        if user.host == self.servername:
            # local user: translate host name
            watched = jid.JID(tuple=(user.user, self.network, user.resource))
        else:
            # other JIDs, use unchaged
            watched = user

        log.debug("checking subscriptions to %s" % (watched.full(), ))
        bareWatched = watched.userhostJID()
        if bareWatched in self.subscriptions:
            #stanza['from'] = watched.full()

            for sub in self.subscriptions[bareWatched]:
                log.debug("notifying subscriber %s" % (sub, ))
                stanza['to'] = sub.userhost()
                self.send(stanza)

    def translateJID(self, _jid):
        """
        Translate a server JID (user@prime.kontalk.net) into a network JID
        (user@kontalk.net).
        """
        # TODO ehm :D
        if _jid.host == self.servername:
            return jid.JID(tuple=(_jid.user, self.network, _jid.resource))
        return _jid
