# -*- coding: utf-8 -*-
"""Upload services modules."""
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


from twisted.words.protocols.jabber import xmlstream

import xmlstream2


class UploadService():
    """Interface for upload service classes."""

    def upload(self, stanza):
        """Process an incoming upload info request."""
        pass

    def info(self):
        """Returns the discovery item for this handler."""
        pass


class KontalkBoxUploadService(UploadService):
    """Internal Kontalk Box upload service."""

    name = 'kontalkbox'

    def __init__(self, handler, config):
        self.handler = handler
        self.config = config

    def upload(self, stanza):
        stanza.consumed = True
        # TODO check for <media/> tag and supported MIME types
        iq = xmlstream.toResponse(stanza, 'result')
        upload = iq.addElement((xmlstream2.NS_MESSAGE_UPLOAD, 'upload'))
        upload['node'] = self.name
        upload.addElement((None, 'uri'), content=self.config['uri'])
        self.handler.send(iq)

    def info(self):
        return {
            'jid': self.handler.parent.network,
            'node': self.name,
            'name': 'Kontalk dropbox service',
        }
