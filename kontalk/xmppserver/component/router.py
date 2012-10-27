# -*- coding: utf-8 -*-
"""Kontalk XMPP router component."""
from wokkel.xmppim import Presence, UnavailablePresence
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

from kontalk.xmppserver import log
from twisted.words.protocols.jabber.component import XMPPComponentServerFactory
from wokkel import component
from twisted.words.xish import domish
from copy import deepcopy


class Router(component.Router):
    '''Kontalk router.'''

    def __init__(self):
        component.Router.__init__(self)

    def addRoute(self, destination, xs):
        """
        Add a new route.

        The passed XML Stream C{xs} will have an observer for all stanzas
        added to route its outgoing traffic. In turn, traffic for
        C{destination} will be passed to this stream.

        @param destination: Destination of the route to be added as a host name
                            or C{None} for the default route.
        @type destination: C{str} or C{NoneType}.
        @param xs: XML Stream to register the route for.
        @type xs: L{EventDispatcher<utility.EventDispatcher>}.
        """

        stanza = Presence()
        stanza['from'] = destination

        log.debug("adversiting component %s" % (stanza.toXml()))
        self.broadcast(stanza)

        # advertise this component about the others
        for host in self.routes.iterkeys():
            stanza = Presence()
            stanza['from'] = host
            xs.send(stanza)

        self.routes[destination] = xs
        xs.addObserver('/bind', self.onBind)
        xs.addObserver('/unbind', self.onUnbind)
        xs.addObserver('/route', self.route)

    def removeRoute(self, destination, xs):
        component.Router.removeRoute(self, destination, xs)

        stanza = UnavailablePresence()
        stanza['from'] = destination
        log.debug("unadvertising component %s" % (stanza.toXml(),))
        self.broadcast(stanza)

    def route(self, stanza):
        """
        Route a stanza.

        @param stanza: The stanza to be routed.
        @type stanza: L{domish.Element}.
        """

        if stanza.getAttribute('type') == 'broadcast':
            log.debug("broadcasting stanza %s" % (stanza.toXml()))
            self.broadcast(stanza)
        else:
            log.debug("routing stanza %s" % (stanza.toXml()))
            component.Router.route(self, stanza)

    def broadcast(self, stanza, same=False):
        """Broadcast a stanza to every component."""
        stanza = deepcopy(stanza)
        for host, xs in self.routes.iteritems():
            # do not send to the original sender
            if host != stanza['from'] or same:
                log.debug("sending to %s" % (host, ))
                stanza['to'] = host
                xs.send(stanza)

    def onBind(self, stanza):
        log.debug("binding component %s" % (stanza.toXml(), ))
        # TODO

    def onUnbind(self, stanza):
        log.debug("unbinding component %s" % (stanza.toXml(), ))
        # TODO


class XMPPRouterFactory(XMPPComponentServerFactory):
    """
    XMPP Component Server factory implementing a routing protocol.
    """

    def __init__(self, router, secret='secret'):
        XMPPComponentServerFactory.__init__(self, router, secret)

