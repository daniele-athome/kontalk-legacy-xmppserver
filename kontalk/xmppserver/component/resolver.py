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


import time, datetime

from twisted.python import failure
from twisted.internet import defer, reactor
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish
from twisted.words.protocols.jabber import jid, error, xmlstream

from wokkel import component

from kontalk.xmppserver import log, storage, util, xmlstream2, version, keyring


class PresenceHandler(XMPPHandler):
    """Handle presence stanzas."""

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence[not(@type)]", self.onPresenceAvailable, 100)
        self.xmlstream.addObserver("/presence[@type='unavailable']", self.onPresenceUnavailable, 100)
        self.xmlstream.addObserver("/presence[@type='subscribe']", self.onSubscribe, 100)
        # presence probes MUST be handled by server so the high priority
        self.xmlstream.addObserver("/presence[@type='probe']", self.onProbe, 600)

    def onPresenceAvailable(self, stanza):
        """Handle availability presence stanzas."""

        if stanza.consumed:
            return

        log.debug("presence: %s" % (stanza.toXml().encode('utf-8'), ))

        # update usercache with last seen and status
        user = jid.JID(stanza['from'])
        if user.user:
            # TODO handle push notifications ID as capability
            # http://xmpp.org/extensions/xep-0115.html

            if user.host == self.parent.servername:
                self.parent.presencedb.presence(stanza)

            self.parent.user_available(user)

        self.parent.broadcastSubscribers(stanza)

    def onPresenceUnavailable(self, stanza):
        """Handle unavailable presence stanzas."""

        if stanza.consumed:
            return

        log.debug("user unavailable: %s" % (stanza.toXml(), ))
        user = jid.JID(stanza['from'])
        # forget any subscription requested by this user
        self.parent.cancelSubscriptions(user)

        if user.user:
            if user.host == self.parent.servername:
                # update usercache with last seen
                self.parent.presencedb.touch(user)

            self.parent.user_unavailable(user)

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

    def onProbe(self, stanza):
        """Handle presence probes."""

        if stanza.consumed:
            return

        log.debug("probe request: %s" % (stanza.toXml(), ))
        stanza.consumed = True
        sender = jid.JID(stanza['from'])
        to = jid.JID(stanza['to'])

        # TODO for now we handle only requests from the network
        if sender.full() in self.parent.keyring.hostlist():
            def userdata(presence, stanza, found):
                log.debug("presence: %r/%r" % (presence, found))
                if type(presence) == list:
                    response = domish.Element((None, 'presence'))
                    response['to'] = sender.full()

                    if len(presence) > 1:
                        chain = domish.Element((xmlstream2.NS_XMPP_STANZA_GROUP, 'group'))
                        chain['id'] = stanza['id']
                        chain['count'] = str(len(presence))
                    else:
                        chain = None

                    for user in presence:
                        response_from = util.userid_to_jid(user['userid'], self.parent.servername)
                        response['from'] = response_from.full()

                        if user['status'] is not None:
                            response.addElement((None, 'status'), content=user['status'])
                        if user['show'] is not None:
                            response.addElement((None, 'show'), content=user['show'])

                        if not found or response_from not in found:
                            response['type'] = 'unavailable'
                            delay = domish.Element(('urn:xmpp:delay', 'delay'))
                            delay['stamp'] = user['timestamp'].strftime('%Y-%m-%dT%H:%M:%SZ')
                            response.addChild(delay)

                        if chain:
                            response.addChild(chain)

                        self.send(response)
                        log.debug("probe result sent: %s" % (response.toXml().encode('utf-8'), ))
                else:
                    response = domish.Element((None, 'presence'))
                    response['to'] = sender.full()
                    response['from'] = to.full()

                    if presence['status'] is not None:
                        response.addElement((None, 'status'), content=presence['status'])
                    if presence['show'] is not None:
                        response.addElement((None, 'show'), content=presence['show'])

                    self.send(response)
                    log.debug("probe result sent: %s" % (response.toXml().encode('utf-8'), ))

            found = self.parent.cacheLookupJID(to)
            d = self.parent.presencedb.get(to)
            d.addCallback(userdata, stanza, found)


class IQHandler(XMPPHandler):
    """
    Handle IQ stanzas.
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
                def userdata(data, stanza):
                    presence = data[0]
                    lookup = data[1]

                    log.debug("presence/lookup: %r/%r" % (presence, lookup))
                    if type(presence) == list and len(presence) > 0:
                        presence = presence[0]

                    if presence:
                        response = xmlstream2.toResponse(stanza, 'result')
                        if lookup is not None:
                            seconds = 0
                        else:
                            now = datetime.datetime.today()
                            delta = now - presence['timestamp']
                            seconds = int(delta.total_seconds())

                        query = domish.Element((xmlstream2.NS_IQ_LAST, 'query'), attribs={ 'seconds' : str(seconds) })
                        response.addChild(query)
                        self.send(response)
                        log.debug("response sent: %s" % (response.toXml(), ))

                to = jid.JID(stanza['to'])
                d1 = self.parent.presencedb.get(to)
                d2 = self.parent.lookupJID(to)
                d = defer.gatherResults((d1, d2))
                d.addCallback(userdata, stanza)


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

            self.parent.bounce(stanza)


class Resolver(component.Component):
    """
    Kontalk resolver XMPP handler.
    This component resolves network JIDs in <route> stanzas (kontalk.net) into
    server JIDs (prime.kontalk.net), altering the "to" attribute and bouncing
    the stanza back to the router.

    @ivar presencedb: database connection to the usercache table
    @type presencedb: L{PresenceStorage}
    @ivar subscriptions: a map of user subscriptions (key=watched, value=subscribers)
    @type subscriptions: C{dict}
    @ivar jid_cache: cache of JIDs location
    @type jid_cache: C{dict}
    """

    protocolHandlers = (
        PresenceHandler,
        IQHandler,
        MessageHandler,
    )

    def __init__(self, config):
        router_cfg = config['router']
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
        self.jid_cache = {}

        # protocol handlers here!!
        for handler in self.protocolHandlers:
            handler().setHandlerParent(self)

    def uptime(self):
        return time.time() - self.start_time

    def _authd(self, xs):
        component.Component._authd(self, xs)
        log.debug("connected to router")
        xs.addObserver("/error", self.onError)
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

    def onError(self, stanza):
        log.debug("routing error: %s" % (stanza.toXml(), ))

    def error(self, stanza, condition='service-unavailable'):
        if not stanza.consumed:
            log.debug("error %s" % (stanza.toXml(), ))
            stanza.consumed = True
            e = error.StanzaError(condition, 'cancel')
            self.send(e.toResponse(stanza))

    def bounce(self, stanza):
        """Send the stanza to the router."""
        if not stanza.consumed:
            stanza.consumed = True
            self.send(stanza)

    def send(self, stanza):
        """Resolves stanza recipient and send the stanza to the router."""

        util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)
        #if stanza.hasAttribute('from'):
        #    stanza['from'] = self.translateJID(jid.JID(stanza['from'])).full()

        to = jid.JID(stanza['to'])

        # stanza is intended to the network
        if to.full() == self.network:
            # TODO
            log.debug("stanza for the network: %s" % (stanza.toXml(), ))
            return

        # network JID - resolve and send to router
        elif to.host == self.network:
            def _lookup(rcpts, stanza):
                log.debug("rcpts = %r" % (rcpts, ))
                if rcpts is None:
                    if not stanza.consumed:
                        stanza.consumed = True
                        log.debug("JID %s not found" % (to.full(), ))
                        e = error.StanzaError('item-not-found', 'cancel')
                        stanza = e.toResponse(stanza)
                    else:
                        log.debug("JID %s not found (stanza has been consumed)" % (to.full(), ))
                        return
                else:
                    log.debug("JID found: %r" % (rcpts, ))
                    stanza.consumed = True
                    if type(rcpts) == list:
                        for _to in rcpts:
                            stanza['to'] = _to.full()
                            component.Component.send(self, stanza)
                        return
                    else:
                        stanza['to'] = rcpts.full()
                component.Component.send(self, stanza)

            d = self.lookupJID(to, progressive=True)
            for cb in d:
                cb.addCallback(_lookup, stanza=stanza)

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

    def user_available(self, _jid):
        """Called when receiving a presence stanza."""
        userid, resource = util.jid_to_userid(_jid, True)
        if userid not in self.jid_cache:
            self.jid_cache[userid] = dict()
        self.jid_cache[userid][resource] = _jid.host

    def user_unavailable(self, _jid):
        """Called when receiving a presence unavailable stanza."""
        userid, resource = util.jid_to_userid(_jid, True)
        if userid in self.jid_cache and resource in self.jid_cache[userid]:
            del self.jid_cache[userid][resource]
            if len(self.jid_cache[userid]) == 0:
                del self.jid_cache[userid]

    def translateJID(self, _jid):
        """
        Translate a server JID (user@prime.kontalk.net) into a network JID
        (user@kontalk.net).
        """
        # TODO ehm :D
        if _jid.host == self.servername:
            return jid.JID(tuple=(_jid.user, self.network, _jid.resource))
        return _jid

    def network_presence_probe(self, to):
        """
        Broadcast a presence probe to find the given jid.
        @return: a list of stanza IDs sent to the network that can be watched to
        for responses
        """
        presence = domish.Element((None, 'presence'))
        presence['type'] = 'probe'
        presence['from'] = self.network
        idList = []
        for server in self.keyring.hostlist():
            to.host = server
            presence['to'] = to.full()
            presence['id'] = util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
            self.send(presence)
            idList.append(presence['id'])

        return idList

    def find_jid(self, _jid, progressive=False):
        """
        Send a presence probe to the network and wait for the first response.
        """
        idList = self.network_presence_probe(_jid)
        def _presence(stanza, callback, timeout, buf):
            # check if stanza is for the requested user
            sender = jid.JID(stanza['from'])
            log.debug("full JID %s found!" % (sender.full(), ))
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
            timeout = reactor.callLater(5, _abort, stanzaId=stanzaId, callback=d, buf=buf)

            self.xmlstream.addObserver("/presence[@id='%s']" % (stanzaId, ), _presence, 1000, callback=d, timeout=timeout, buf=buf)

        if progressive:
            return deferList
        else:
            # gather all returned presence from the network
            return defer.gatherResults(deferList, True)

    def cacheLookupJID(self, _jid):
        """
        Search a JID in the server caches. If jid is a bare JID, all matches
        are returned.
        @return one or a list of translated server JIDs if found.
        """

        out = []

        # lookup in JID cache first
        if _jid.resource is not None:
            try:
                host = self.jid_cache[_jid.user][_jid.resource]
                return jid.JID(tuple=(_jid.user, host, _jid.resource))
            except:
                pass
        else:
            # bare JID
            try:
                resources = self.jid_cache[_jid.user]
                out.extend([jid.JID(tuple=(_jid.user, host, resource)) for resource, host in resources.iteritems()])
            except:
                pass

        if len(out) > 0:
            return out

    def lookupJID(self, _jid, progressive=False, refresh=False):
        """
        Lookup a jid in the network.
        @param progressive: see @return
        @param refresh: if true lookup is forced over the whole network;
        otherwise, just cached results are returned if found. In the latter
        case, if no results are found, a lookup over the network will be started.
        @return if progresive is false, a L{Deferred} which will be fired for
        lookups. Otherwise a list of L{Deferred} is returned, the first one for
        cache lookup, and then one for each remote lookup request. Useful for
        getting JID lookup as soon as a server responds to presence probes.
        @rtype: L{Deferred}
        @rtype: C{list}
        """

        log.debug("[%s] looking up" % (_jid.full(), ))

        hits = self.cacheLookupJID(_jid)
        log.debug("[%s] found: %r" % (_jid.full(), hits))

        # not found in caches or refreshing, lookup the network
        if hits is None or refresh:
            d = self.find_jid(_jid, progressive)
            # return hits + remote deferred
            if progressive:
                out = []
                if hits: out.append(defer.succeed(hits))
                out.extend(d)
                return out

            clientDeferred = defer.Deferred()
            def _cb(result):
                log.debug("result = %r, hits = %r" % (result, hits))
                if isinstance(result, failure.Failure):
                    out = hits
                else:
                    out = []
                    if hits:
                        out.extend(hits)
                    for hit in result:
                        if hit: out.append(hit)

                clientDeferred.callback(out)

            d.addBoth(_cb)
            return clientDeferred

        return defer.succeed(hits)
