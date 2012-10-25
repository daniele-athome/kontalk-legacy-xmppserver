# -*- coding: utf-8 -*-
'''twistd plugin for XMPP resolver.'''
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


import json

from zope.interface import implements

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker

class Options(usage.Options):
    optParameters = [["config", "c", "resolver.conf", "Configuration file."]]


class KontalkResolverServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "kontalk-resolver"
    description = "Kontalk XMPP resolver component."
    options = Options

    def makeService(self, options):
        from wokkel import component
        from kontalk.xmppserver.component.resolver import Resolver
        import kontalklib.logging as log

        # load configuration
        fp = open(options['config'], 'r')
        config = json.load(fp)
        fp.close()
        
        log.init(config)

        router_cfg = config['router']
        comp = component.Component(router_cfg['host'], router_cfg['port'], router_cfg['jid'], router_cfg['secret'])
        comp.logTraffic = config['debug']
        
        resolver = Resolver(config)
        resolver.setHandlerParent(comp)

        return comp

serviceMaker = KontalkResolverServiceMaker()
