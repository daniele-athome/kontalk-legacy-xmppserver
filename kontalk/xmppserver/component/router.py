# -*- coding: utf-8 -*-
"""Kontalk XMPP router component."""
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


from twisted.words.protocols.jabber.component import XMPPComponentServerFactory
from twisted.words.protocols.jabber import error
from twisted.words.xish import domish

from wokkel import component
from wokkel.xmppim import Presence, UnavailablePresence

from kontalk.xmppserver import log, util, xmlstream2


class Router(component.Router):
    """Kontalk router."""

    def __init__(self):
        component.Router.__init__(self)
        self.logs = set()
        # private names: binding with those names will not be advertised
        self.private = {}

    def advertise(self, host, xs=None):
        stanza = Presence()
        stanza['from'] = host

        log.info("advertising component %s" % (host, ))
        self.broadcast(stanza, xs=xs)

    def unadvertise(self, host, xs=None):
        stanza = UnavailablePresence()
        stanza['from'] = host
        log.info("unadvertising component %s" % (host,))
        self.broadcast(stanza, xs=xs)

    def send_routes(self, host, xs):
        stanza = Presence()
        stanza['to'] = host
        for h, stream in self.routes.iteritems():
            # ignore default route and do not send back to requesting stream
            if h is not None and stream != xs:
                stanza['from'] = h
                xs.send(stanza)

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

        # advertise presence
        self.advertise(destination, xs)

        # advertise this component about the others
        self.send_routes(destination, xs)

        # add route and observers
        self.routes[destination] = xs
        xs.addObserver('/bind', self.bind, 100, xs = xs)
        xs.addObserver('/unbind', self.unbind, 100, xs = xs)
        xs.addObserver('/*', self.route, xs = xs)

    def removeRoute(self, destination, xs):
        # remove route immediately
        # we assume component is disconnecting so we don't remove observers
        component.Router.removeRoute(self, destination, xs)

        # remove other bound names
        for host in list(self.routes.keys()):
            if self.routes[host] == xs:
                del self.routes[host]

        # remove any private name
        for name, stream in self.private.items():
            if stream == xs:
                del self.private[name]

        # remove log route if any
        self.logs.discard(xs)

        # unadvertise component
        self.unadvertise(destination, xs)

    def route(self, stanza, xs):
        """
        Route a stanza.

        @param stanza: The stanza to be routed.
        @type stanza: L{domish.Element}.
        """

        if stanza.consumed:
            return

        """"
        TEST check sender host is component
        stanzaFrom = jid.JID(stanza['from'])
        if stanzaFrom.host != xs.thisEntity.host:
            log.error("stanza is not from component - dropping")
            return
        """

        # reset namespace
        util.resetNamespace(stanza, component.NS_COMPONENT_ACCEPT)

        # send stanza to logging entities
        for lg in self.logs:
            lg.send(stanza)

        if not stanza.hasAttribute('to'):
            if self.logTraffic:
                log.debug("broadcasting stanza %s" % (stanza.toXml().encode('utf-8'), ))
            self.broadcast(stanza)
        else:
            """
            FIXME we have encoding problems here... (why not in other components?!?!?)
            """

            # check for stanza loops
            errors = 0
            for child in stanza.children:
                if domish.IElement.providedBy(child) and child.name == 'error':
                    errors += 1
                    if errors > 1:
                        if self.logTraffic:
                            log.debug("error loop, dropping stanza %s" % (stanza.toXml().encode('utf-8'), ))
                        else:
                            log.debug("error loop, dropping stanza")

                        return

            if self.logTraffic:
                log.debug("routing stanza %s" % (stanza.toXml().encode('utf-8'), ))
            try:
                destination_host = util.jid_host(stanza['to'])

                if destination_host in self.routes:
                    self.routes[destination_host].send(stanza)
                else:
                    self.routes[None].send(stanza)

            except KeyError:
                log.warn("unroutable stanza, bouncing back to component")
                e = error.StanzaError('service-unavailable')
                xs.send(xmlstream2.errorResponse(e, stanza))

    def broadcast(self, stanza, same=False, xs=None):
        """
        Broadcast a stanza to every component.
        This alters the to attribute in outgoing stanza for each component.
        """
        from_host = util.jid_host(stanza['from'])

        try:
            sender_xs = self.routes[from_host]
        except KeyError:
            sender_xs = xs

        for host, xs in self.routes.iteritems():
            # do not send to the original sender
            if host is not None and ((host != from_host and sender_xs != xs) or same):
                log.debug("sending to %s" % (host, ))
                stanza['to'] = host
                xs.send(stanza)

    def bind(self, stanza, xs):
        log.debug("binding name %s" % (stanza['name'], ))
        stanza.consumed = True

        if stanza.default:
            route = None
        else:
            try:
                route = stanza['name']
            except:
                xs.send(domish.Element((None, 'bind'), attribs={'error': 'bad-request'}))
                #xs.transport.loseConnection()

        if route not in self.routes and route not in self.private:

            if stanza.private:
                self.private[route] = xs
            else:
                self.routes[route] = xs

            xs.send(domish.Element((None, 'bind')))

            if stanza.log:
                self.logs.add(xs)

            # advertise new binding if not private
            if not stanza.private:
                # advertise presence
                self.advertise(route, xs)
                # advertise this component about the others
                self.send_routes(route, xs)

        else:
            xs.send(domish.Element((None, 'bind'), attribs={'error': 'conflict'}))
            #xs.transport.loseConnection()

    def unbind(self, stanza, xs):
        log.debug("unbinding name %s" % (stanza['name'], ))
        stanza.consumed = True

        # TODO security checks

        route = stanza['name']

        # remove any normal route
        if route in self.routes:
            del self.routes[route]

        if route in self.private:
            del self.private[route]

        else:
            # remove any private name
            for name, stream in self.private.items():
                if stream == xs:
                    del self.private[name]

            # unadvertise binding
            self.unadvertise(route, xs)


class XMPPRouterFactory(XMPPComponentServerFactory):
    """
    XMPP Component Server factory implementing a routing protocol.
    """

    def __init__(self, router, secret='secret'):
        XMPPComponentServerFactory.__init__(self, router, secret)

