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

from twisted.internet import defer
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish
from twisted.words.protocols.jabber import jid, xmlstream, error

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
        log.debug("presence: %s" % (stanza.toXml().encode('utf-8'), ))

        # update usercache with last seen and status
        user = jid.JID(stanza['from'])
        if user.user:
            # TODO handle push notifications ID as capability
            # http://xmpp.org/extensions/xep-0115.html

            self.parent.presencedb.presence(stanza)
            self.parent.local_user_available(user)

        self.parent.broadcastSubscribers(stanza)

    def onPresenceUnavailable(self, stanza):
        """Handle unavailable presence stanzas."""
        log.debug("user unavailable: %s" % (stanza.toXml(), ))
        user = jid.JID(stanza['from'])
        # forget any subscription requested by this user
        self.parent.cancelSubscriptions(user)

        if user.user:
            # update usercache with last seen
            self.parent.presencedb.touch(user)
            self.parent.local_user_unavailable(user)

        self.parent.broadcastSubscribers(stanza)

    def onSubscribe(self, stanza):
        """Handle subscription requests."""
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
                def userdata(data, stanza):
                    presence = data[0]
                    lookup = data[1]

                    log.debug("presence/lookup: %r/%r" % (presence, lookup))
                    if type(presence) == list and len(presence) > 0:
                        presence = presence[0]

                    response = xmlstream.toResponse(stanza, 'result')
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
                stanza['origTo'] = ''
            else:
                stanza['origTo'] = stanza['to']

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
        self.keyring = keyring.Keyring(storage.MySQLNetworkStorage(), config['fingerprint'])

        self.subscriptions = {}
        self.local_users = {}

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

    def send(self, stanza, to=None):
        """Resolves stanza recipient and send the stanza to the router."""

        util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)
        if stanza.hasAttribute('from'):
            stanza['from'] = self.translateJID(jid.JID(stanza['from'])).full()

        if to is None:
            to = jid.JID(stanza['to'])

        # stanza is intended to the network
        if to.full() == self.network:
            # TODO
            log.debug("stanza for the network: %s" % (stanza.toXml(), ))
            return

        # network JID - resolve and send to router
        elif to.host == self.network:
            # no local users - drop silently to avoid loops
            if len(self.local_users) == 0:
                return

            def _lookup(rcpts, stanza):
                if rcpts is None:
                    e = error.StanzaError('item-not-found', 'cancel')
                    stanza = e.toResponse(stanza)
                else:
                    if type(rcpts) == list:
                        for to in rcpts:
                            stanza['to'] = to.full()
                            component.Component.send(self, stanza)
                            return
                    else:
                        stanza['to'] = rcpts.full()
                component.Component.send(self, stanza)

            d = self.lookupJID(to)
            d.addCallback(_lookup, stanza=stanza)

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
        self.send(pres, subscriber)

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

    def local_user_available(self, _jid):
        """Called when a user locally connects to this server."""
        userid, resource = util.jid_to_userid(_jid, True)
        if userid not in self.local_users:
            self.local_users[userid] = set()
        self.local_users[userid].add(resource)

    def local_user_unavailable(self, _jid):
        """Called when a local user disconnects from this server."""
        userid, resource = util.jid_to_userid(_jid, True)
        if userid in self.local_users:
            self.local_users[userid].discard(resource)
            if len(self.local_users[userid]) == 0:
                del self.local_users[userid]

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
        @return: a list of JID attempts to the network that can be watched to
        for responses
        """
        presence = domish.Element((None, 'presence'))
        presence['type'] = 'probe'
        presence['from'] = self.network
        toList = []
        for server in self.keyring.itervalues():
            to.host = server['host']
            presence['to'] = to.full()
            presence['id'] = util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
            self.send(presence)
            toList.append(to)

        return toList

    def find_jid(self, _jid):
        """
        Send a presence probe to the network and wait for the first response.
        """
        toList = self.network_presence_probe(_jid)
        def presence(stanza, probes):
            # check if stanza is for the requested user
            sender = jid.JID(stanza['from'])
            # TODO AAAAHHHHHH
            self.xmlstream.removeObserver("/presence[to='%s']" % (self.network, ), presence)

        self.xmlstream.addObserver("/presence[to='%s']" % (self.network, ), presence, 1000, probes=toList)

    def lookupJID(self, _jid):
        """
        Lookup a jid in the network.
        If jid is a bare JID, a list of matching server JIDs is returned.
        Otherwise single server JID is returned.
        """

        log.debug("looking up JIDs (local=%r)" % (self.local_users, ))
        # FIXME we are not really looking up the user yet
        if _jid.host == self.network:
            result = None
            log.debug("[%s] network JID" % (_jid.full(), ))
            if _jid.resource is not None:
                log.debug("[%s] full JID" % (_jid.full(), ))
                if _jid.user in self.local_users and _jid.resource in self.local_users[_jid.user]:
                    result = jid.JID(tuple=(_jid.user, self.servername, _jid.resource))
                else:
                    self.network_presence_probe(_jid)
            else:
                log.debug("[%s] bare JID" % (_jid.full(), ))
                if _jid.user in self.local_users:
                    result = [jid.JID(tuple=(_jid.user, self.servername, x)) for x in self.local_users[_jid.user]]
                # lookup in the network too
                self.network_presence_probe(_jid)

            if result is None:
                log.debug("[%s] unknown JID" % (_jid.full(), ))
        else:
            # not our network, return unchanged
            log.debug("[%s] not our network" % (_jid.full(), ))
            result = _jid

        return defer.succeed(result)
