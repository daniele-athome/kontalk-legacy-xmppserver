# -*- coding: utf-8 -*-
'''twistd plugin for XMPP router.'''
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

from twisted.application import strports
from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker

class Options(usage.Options):
    optParameters = [["config", "c", "router.conf", "Configuration file."]]


class KontalkRouterServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "kontalk-router"
    description = "Kontalk XMPP router."
    options = Options

    def makeService(self, options):
        from twisted.words.protocols.jabber import component
        from kontalk.xmppserver import log

        # load configuration
        fp = open(options['config'], 'r')
        config = json.load(fp)
        fp.close()

        log.init(config)

        router = component.Router()
        factory = component.XMPPComponentServerFactory(router, config['secret'])
        factory.logTraffic = config['debug']

        return strports.service('tcp:' + str(config['bind'][1]) + ':interface=' + str(config['bind'][0]), factory)


serviceMaker = KontalkRouterServiceMaker()
