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


from twisted.words.protocols.jabber.xmlstream import XMPPHandler

from kontalk.xmppserver import log


class Resolver(XMPPHandler):
    """
    Kontalk resolver XMPP handler.
    This component resolves network JIDs (user@kontalk.net) into server JIDs
    (user@prime.kontalk.net), altering the "to" attribute and bouncing the
    stanza back to the router.
    """

    def __init__(self, config):
        XMPPHandler.__init__(self)
        self.config = config
        self.logTraffic = config['debug']

    def connectionInitialized(self):
        log.debug("connected to router")
        self.xmlstream.addObserver('/presence', self.onPresence)
        self.xmlstream.addObserver('/route', self.onRoute)

    def onPresence(self, stanza):
        log.debug("component presence %s" % (stanza.toXml(), ))

    def onRoute(self, stanza):
        log.debug("route stanza %s" % (stanza.toXml(), ))
