# -*- coding: utf-8 -*-
'''twistd plugin for XMPP c2s.'''
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
from twisted.application.service import IServiceMaker, MultiService

class Options(usage.Options):
    optParameters = [["config", "c", "c2s.conf", "Configuration file."]]


class KontalkC2SServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "kontalk-c2s"
    description = "Kontalk XMPP C2S component."
    options = Options

    def makeService(self, options):
        from kontalk.xmppserver.component.c2s import C2SComponent
        from kontalk.xmppserver import log

        # load configuration
        fp = open(options['config'], 'r')
        config = json.load(fp)
        fp.close()

        log.init(config)

        appl = MultiService()
        comp = C2SComponent(config)
        comp.setServiceParent(appl)
        comp.setup().setServiceParent(appl)
        return appl

serviceMaker = KontalkC2SServiceMaker()
