# -*- coding: utf-8 -*-
'''Kontalk XMPP resolver component.'''
'''
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
'''


import base64

from twisted.application import service
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish
from twisted.words.protocols.jabber import jid, xmlstream, error

from wokkel import xmppim, component

from kontalk.xmppserver import log, database, util, xmlstream2


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
            userid = util.jid_to_userid(user)

            # TODO handle multiple statuses with xml:lang
            if stanza.status:
                status = base64.b64encode(stanza.status.__str__().encode('utf-8'))
            else:
                status = None

            # TODO handle push notifications ID as capability
            # http://xmpp.org/extensions/xep-0115.html

            self.parent.usercache.update(userid, status=status)

        self.parent.broadcastSubscribers(stanza)

    def onPresenceUnavailable(self, stanza):
        """Handle unavailable presence stanzas."""
        log.debug("user unavailable: %s" % (stanza.toXml(), ))
        user = jid.JID(stanza['from'])
        # forget any subscription requested by this user
        self.parent.cancelSubscriptions(user)

        if user.user:
            userid = util.jid_to_userid(user)

            # update usercache with last seen
            self.parent.usercache.update(userid)

        self.parent.broadcastSubscribers(stanza)

    def onSubscribe(self, stanza):
        """Handle subscription requests."""
        log.debug("subscription request: %s" % (stanza.toXml(), ))

        # extract jid the user wants to subscribe to
        jid_to = jid.JID(stanza['to'])
        jid_from = jid.JID(stanza['from'])

        self.parent.subscribe(jid_to, jid_from)

class IQQueryHandler(XMPPHandler):
    """
    Handle IQ query stanzas.
    @type parent: L{Resolver}
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='get']/query[@xmlns='%s']" % (xmlstream2.NS_IQ_LAST), self.lastActivity, 100)
        self.xmlstream.addObserver("/iq/query", self.parent.error, 80)

    def lastActivity(self, stanza):
        if not stanza.consumed:
            stanza.consumed = True
            response = xmlstream.toResponse(stanza, 'result')

            if stanza['to'] == self.parent.network:
                # TODO server uptime
                seconds = 123456
            else:
                # TODO seconds ago user was last seen
                seconds = 10

            response.addChild(domish.Element((xmlstream2.NS_IQ_LAST, 'query'), attribs={'seconds': str(seconds)}))
            self.send(response)

class Resolver(component.Component):
    """
    Kontalk resolver XMPP handler.
    This component resolves network JIDs in <route> stanzas (kontalk.net) into
    server JIDs (prime.kontalk.net), altering the "to" attribute and bouncing
    the stanza back to the router.

    @ivar usercache: database connection to the usercache table
    @type usercache: L{UsercacheDb}
    @ivar subscriptions: a map of user subscriptions (key=watched, value=subscribers)
    @type subscriptions: C{dict}
    """

    def __init__(self, config):
        router_cfg = config['router']
        component.Component.__init__(self, router_cfg['host'], router_cfg['port'], router_cfg['jid'], router_cfg['secret'])
        self.config = config

        self.logTraffic = config['debug']
        self.network = config['network']
        self.servername = config['host']

        self.db = database.connect_config(self.config)
        self.usercache = database.usercache(self.db)
        self.subscriptions = {}

        # protocol handlers here!!
        PresenceHandler().setHandlerParent(self)
        IQQueryHandler().setHandlerParent(self)

    def connectionInitialized(self):
        log.debug("connected to router")
        self.xmlstream.addObserver("/error", self.onError)

    def connectionLost(self, reason):
        XMPPHandler.connectionLost(self, reason)
        log.debug("lost connection to router (%s)" % (reason, ))

    def onError(self, stanza):
        log.debug("routing error: %s" % (stanza.toXml(), ))

    def error(self, stanza):
        if not stanza.consumed:
            log.debug("error %s" % (stanza.toXml(), ))
            stanza.consumed = True
            e = error.StanzaError('service-unavailable', 'cancel')
            self.send(e.toResponse(stanza))

    def send(self, stanza, to=None):
        """Resolves stanza recipient and send the route to the stanza."""
        if to is None:
            to = jid.JID(stanza['to'])
        if to.host == self.network:
            rcpts = self.lookupJID(to)
            if type(rcpts) == list:
                # TODO
                log.debug("multiple routing is not supported yet.")
            else:
                to = rcpts
                stanza['to'] = to.full()

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
        pres['to'] = subscriber.userhost()
        pres['from'] = to.userhost()
        pres['type'] = 'subscribed'
        self.send(pres, subscriber.full())

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
            stanza.defaultUri = stanza.uri = None
            stanza['from'] = watched.full()

            for sub in self.subscriptions[bareWatched]:
                log.debug("notifying subscriber %s" % (sub, ))
                stanza['to'] = sub.userhost()
                self.send(stanza)

    def lookupJID(self, _jid):
        """
        Lookup a jid in the network.
        If jid is a bare JID, a list of matching server JIDs is returned.
        Otherwise single server JID is returned.
        FIXME one day this will return a deferred
        """

        # FIXME we are not really looking up the user yet
        if _jid.host == self.network:
            if _jid.resource is not None:
                return jid.JID(tuple=(_jid.user, self.servername, _jid.resource))
            else:
                # TODO don't know how to handle this right now
                return []

        # not our network, return unchanged
        return _jid


class ResolverService(service.Service):
    def __init__(self, config, comp):
        self.config = config
        self.logTraffic = config['debug']
        self.component = comp

    def startService(self):
        self.resolver = Resolver(self.config, self.component)
        self.resolver.setHandlerParent(self.component)

    def stopService(self):
        pass
