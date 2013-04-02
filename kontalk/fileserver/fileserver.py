# -*- coding: utf-8 -*-
"""Kontalk Dropbox file server."""
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


from zope.interface import implements

from twisted.application import strports, service
from twisted.web import server, resource
from twisted.cred.portal import IRealm, Portal
from twisted.web.guard import HTTPAuthSessionWrapper

from kontalk.xmppserver import log, storage, keyring, auth


class FileUploadRealm(object):
    implements(IRealm)

    def __init__(self, fileserver):
        self.fileserver = fileserver

    def requestAvatar(self, avatarId, mind, *interfaces):
        #log.debug("[upload] requestAvatar: %s" % avatarId)
        uploader = FileUpload(self.fileserver, avatarId)
        return interfaces[0], uploader, uploader.logout

class FileDownloadRealm(object):
    implements(IRealm)

    def __init__(self, fileserver):
        self.fileserver = fileserver

    def requestAvatar(self, avatarId, mind, *interfaces):
        #log.debug("[download] requestAvatar: %s" % avatarId)
        downloader = FileDownload(self.fileserver, avatarId)
        return interfaces[0], downloader, downloader.logout


class Fileserver(resource.Resource, service.Service):
    '''Fileserver connection manager.'''

    def __init__(self, config):
        resource.Resource.__init__(self)
        self.config = config
        self.logTraffic = config['debug']
        self.network = config['network']
        self.servername = config['host']

    def setup(self):
        # initialize storage
        # doing it here because it's needed by the server factory
        storage.init(self.config['database'])

        self.keyring = keyring.Keyring(storage.MySQLNetworkStorage(), self.config['fingerprint'], self.servername)

        credFactory = auth.AuthKontalkTokenFactory(str(self.config['fingerprint']), self.keyring)
        token_auth = auth.AuthKontalkToken(self.config['fingerprint'], self.keyring)

        # upload endpoint
        portal = Portal(FileUploadRealm(self), [token_auth])
        resource = HTTPAuthSessionWrapper(portal, [credFactory])
        self.putChild('upload', resource)

        # download endpoint
        portal = Portal(FileDownloadRealm(self), [token_auth])
        resource = HTTPAuthSessionWrapper(portal, [credFactory])
        self.putChild('download', resource)

        # http service
        self.factory = server.Site(self)
        return strports.service('tcp:' + str(self.config['bind'][1]) +
            ':interface=' + str(self.config['bind'][0]), self.factory)

    def startService(self):
        service.Service.startService(self)
        # nothing for now :)
