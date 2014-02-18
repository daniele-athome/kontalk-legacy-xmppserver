# -*- coding: utf-8 -*-
"""Kontalk Dropbox file server."""
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


import os

from zope.interface import implements

from twisted.application import service
from twisted.application.internet import StreamServerEndpointService
from twisted.internet import reactor
from twisted.internet.endpoints import SSL4ServerEndpoint
from twisted.web import server, resource
from twisted.cred.portal import IRealm, Portal
from twisted.protocols.basic import FileSender

from httpauth import HTTPSAuthSessionWrapper
from kontalk.xmppserver import log, storage, keyring, auth, util, xmlstream2


class FileDownload(resource.Resource):
    def __init__(self, fileserver, userid):
        resource.Resource.__init__(self)
        self.fileserver = fileserver
        self.userid = userid

    def _quick_response(self, request, code, text):
        request.setResponseCode(code)
        request.setHeader('content-type', 'text/plain')
        return text

    def render_GET(self, request):
        log.debug("request from %s: %s" % (self.userid, request.args))
        if 'f' in request.args:
            fn = request.args['f'][0]
            info = self.fileserver.storage.get(fn, False)
            if info:
                filename, mime, md5sum = info
                log.debug("sending file type %s, path %s, md5sum %s" % (mime, filename, md5sum))
                genfilename = util.generate_filename(mime)
                request.setHeader('content-type', mime)
                request.setHeader('content-length', os.path.getsize(filename))
                request.setHeader('content-disposition', 'attachment; filename="%s"' % (genfilename))
                request.setHeader('x-md5sum', md5sum)

                # stream file to the client
                fp = open(filename, 'rb')
                d = FileSender().beginFileTransfer(fp, request)
                def finished(ignored):
                    fp.close()
                    request.finish()
                d.addErrback(log.error).addCallback(finished)
                return server.NOT_DONE_YET

            # file not found in extra storage
            else:
                return self._quick_response(request, 404, 'not found')

        return self._quick_response(request, 400, 'bad request')

    def logout(self):
        # TODO
        pass


class FileUpload(resource.Resource):
    def __init__(self, fileserver, userid):
        resource.Resource.__init__(self)
        self.fileserver = fileserver
        self.config = fileserver.config
        self.userid = userid

    def _quick_response(self, request, code, text):
        request.setResponseCode(code)
        request.setHeader('content-type', 'text/plain')
        return text

    def render_POST(self, request):
        #log.debug("request from %s: %s" % (self.userid, request.requestHeaders))

        # check mime type
        mime = request.getHeader('content-type')
        if mime not in self.config['upload']['accept_content']:
            return self._quick_response(request, 406, 'unacceptable content type')

        # check length
        length = request.getHeader('content-length')
        if length != None:
            length = long(length)
            if length <= self.config['upload']['max_size']:
                # store file to storage
                # TODO convert to file-object management for less memory consumption
                data = request.content.read()
                if len(data) == length:
                    fileid = util.rand_str(40)
                    filename = self.fileserver.storage.store_data(fileid, mime, data)
                    if filename:
                        log.debug("file stored to disk (filename=%s, fileid=%s)" % (filename, fileid))
                        request.setHeader('content-type', 'text/url')
                        return str(self.config['upload']['url']) % (fileid, )
                    else:
                        log.error("error storing file")
                        return self._quick_response(request, 500, 'unable to store file')

                else:
                    log.warn("file length not matching content-length header (%d/%d)" % (len(data), length))
                    return self._quick_response(request, 400, 'bad request')
            else:
                log.warn("file too big (%d bytes)" % length)
                return self._quick_response(request, 413, 'request too large')
        else:
            log.warn("content-length header not found")
            return self._quick_response(request, 411, 'content length not declared')

    def logout(self):
        # TODO
        pass


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
        log.debug("[download] requestAvatar: %s" % avatarId)
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
        self.presencedb = storage.MySQLPresenceStorage()

        # TODO from configuration
        stor_class = self.config['storage']['class']
        klass = getattr(storage, stor_class)
        self.storage = klass(*self.config['storage']['params'])

        self.keyring = keyring.Keyring(storage.MySQLNetworkStorage(), self.config['fingerprint'], self.network, self.servername)

        token_auth = auth.AuthKontalkChecker(self.config['fingerprint'], self.keyring, self.presencedb)

        # upload endpoint
        portal = Portal(FileUploadRealm(self), [token_auth])
        resource = HTTPSAuthSessionWrapper(portal)
        self.putChild('upload', resource)

        # download endpoint
        portal = Portal(FileDownloadRealm(self), [token_auth])
        resource = HTTPSAuthSessionWrapper(portal)
        self.putChild('download', resource)

        # http service
        self.factory = server.Site(self)
        sslFactory = xmlstream2.MyOpenSSLCertificateOptions(self.config['ssl_key'], self.config['ssl_cert'], self._sslVerify)
        endpoint = SSL4ServerEndpoint(reactor, self.config['bind'][1], sslFactory, interface=str(self.config['bind'][0]))
        svc = StreamServerEndpointService(endpoint, self.factory)
        svc._raiseSynchronously = True
        return svc


    def _sslVerify(self, conn, cert, errno, depth, preverify_ok):
        # TODO is this safe?
        return True

    def startService(self):
        service.Service.startService(self)
        self.storage.init()
