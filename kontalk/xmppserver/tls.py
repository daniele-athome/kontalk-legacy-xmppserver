# -*- coding: utf-8 -*-
"""TLS powered by GnuTLS."""
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


from twisted.internet import defer, interfaces

from zope.interface import implements

from gnutls.connection import OpenPGPCredentials as _OpenPGPCredentials
from gnutls.interfaces import twisted


def isTLS(xmlstream):
    return isinstance(xmlstream.transport, twisted.TLSMixin)


class OpenPGPCredentials(_OpenPGPCredentials):
    """A Twisted enhanced OpenPGPCredentials"""
    verify_peer = False
    verify_period = None

    def verify_callback(self, peer_cert, preverify_status=None):
        """Verifies the peer certificate and raises an exception if it cannot be accepted"""
        if isinstance(preverify_status, Exception):
            raise preverify_status
        self.check_certificate(peer_cert, cert_name='peer certificate')


class TLSServerEndpoint(object):
    """
    TCP server endpoint with an IPv4 configuration

    @ivar _reactor: An L{IReactorTCP} provider.

    @type _port: int
    @ivar _port: The port number on which to listen for incoming connections.

    @type _backlog: int
    @ivar _backlog: size of the listen queue

    @type _interface: str
    @ivar _interface: the hostname to bind to, defaults to '' (all)
    """
    implements(interfaces.IStreamServerEndpoint)

    def __init__(self, reactor, port, credentials=None, backlog=50, interface=''):
        self._reactor = reactor
        self._port = port
        self._backlog = backlog
        self._interface = interface
        self._credentials = credentials

    def listen(self, protocolFactory):
        return defer.execute(twisted.listenTLS,
                             self._reactor,
                             self._port,
                             protocolFactory,
                             self._credentials,
                             backlog=self._backlog,
                             interface=self._interface)
