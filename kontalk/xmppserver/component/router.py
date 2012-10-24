# -*- coding: utf-8 -*-
'''Kontalk XMPP router.'''
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


import kontalk.util.logging as log

from twisted.application import service, internet
from wokkel import component


class Router(service.Service, component.Router):
    '''
    Kontalk stanza router.
    This router is not a standard XMPP stanza router; if a stanza has our domain
    it is internally handled
    '''

    def __init__(self, application, config):
        self.setServiceParent(application)
        component.Router.__init__(self)
        self.config = config

    def startService(self):
        service.Service.startService(self)
        log.debug("starting router")

        factory = component.XMPPComponentServerFactory(self, self.config['secret'])
        factory.logTraffic = self.config['debug']

        router = internet.TCPServer(port=self.config['bind'][1],
            factory=factory, interface=self.config['bind'][0])
        router.setServiceParent(self.parent)
