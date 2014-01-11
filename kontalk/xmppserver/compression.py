# -*- coding: utf-8 -*-
"""XMPP stream compression."""
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

"""
This code is based on patches submitted to Twisted:
http://twistedmatrix.com/trac/ticket/4849
"""


import zlib

from zope.interface import directlyProvides, providedBy

# twisted imports
from twisted.internet.protocol import ServerFactory, Protocol
from twisted.words.xish import domish

from xmlstream2 import BaseFeatureReceivingInitializer


NS_XMPP_FEATURE_COMPRESS = "http://jabber.org/features/compress"
NS_XMPP_COMPRESS = "http://jabber.org/protocol/compress"


class CompressReceivingInitializer(BaseFeatureReceivingInitializer):
    """
    Compressing stream initializer for the receiving entity.

    If it is included in the list of initializers for an XMPP stream, it must
    be after the TLS initializer. The spec allows stream compression after
    TLS if TLS negotiation failed, or if it is not desired.

    The only supported compression method at the moment is C{zlib}.

    @cvar wanted: indicates if stream compression negotiation is wanted.
    @type wanted: C{bool}
    @ivar withTLS: if set to C{True}, allows negociating compression when TLS
        is already used.
    @type withTLS: C{bool}

    @since: 11.1
    """

    withTLS = False

    def feature(self):
        compr = domish.Element((NS_XMPP_FEATURE_COMPRESS, 'compression'))
        compr.addElement((None, 'method'), content='zlib')
        return compr

    def initialize(self):
        self.xmlstream.addOnetimeObserver('/compress', self.onCompress)

    def deinitialize(self):
        self.xmlstream.removeObserver('/compress', self.onCompress)

    def onCompress(self, stanza):
        # only zlib supported
        if stanza.method and str(stanza.method) != 'zlib':
            response = domish.Element((NS_XMPP_COMPRESS, 'failure'))
            response.addElement((None, 'unsupported-method'))
            self.xmlstream.send(response)

        else:
            response = domish.Element((NS_XMPP_COMPRESS, 'compressed'))
            self.xmlstream.send(response)
            # TODO should we flush data or something like that?

            # now starting compressed stream
            compressingProtocol = XmppCompressingProtocol(self.xmlstream)
            compressingProtocol.makeConnection(self.xmlstream.transport)
            self.xmlstream.reset()
            self.xmlstream.sendHeader()


class ProtocolWrapper(Protocol):
    """
    Wraps protocol instances and acts as their transport as well.

    @ivar wrappedProtocol: An L{IProtocol} provider to which L{IProtocol}
        method calls onto this L{ProtocolWrapper} will be proxied.

    @ivar factory: The L{WrappingFactory} which created this
        L{ProtocolWrapper}.
    """

    disconnecting = 0

    def __init__(self, factory, wrappedProtocol):
        self.wrappedProtocol = wrappedProtocol
        self.factory = factory

    def makeConnection(self, transport):
        """
        When a connection is made, register this wrapper with its factory,
        save the real transport, and connect the wrapped protocol to this
        L{ProtocolWrapper} to intercept any transport calls it makes.
        """
        directlyProvides(self, providedBy(transport))
        Protocol.makeConnection(self, transport)
        self.factory.registerProtocol(self)
        self.wrappedProtocol.makeConnection(self)

    # Transport relaying

    def write(self, data):
        self.transport.write(data)

    def writeSequence(self, data):
        self.transport.writeSequence(data)

    def loseConnection(self):
        self.disconnecting = 1
        self.transport.loseConnection()

    def getPeer(self):
        return self.transport.getPeer()

    def getHost(self):
        return self.transport.getHost()

    def registerProducer(self, producer, streaming):
        self.transport.registerProducer(producer, streaming)

    def unregisterProducer(self):
        self.transport.unregisterProducer()

    def stopConsuming(self):
        self.transport.stopConsuming()

    def __getattr__(self, name):
        return getattr(self.transport, name)

    # Protocol relaying

    def dataReceived(self, data):
        self.wrappedProtocol.dataReceived(data)

    def connectionLost(self, reason):
        self.factory.unregisterProtocol(self)
        self.wrappedProtocol.connectionLost(reason)


class WrappingFactory(ServerFactory):
    """Wraps a factory and its protocols, and keeps track of them."""

    protocol = ProtocolWrapper

    def __init__(self, wrappedFactory):
        self.wrappedFactory = wrappedFactory
        self.protocols = {}

    def doStart(self):
        self.wrappedFactory.doStart()
        ServerFactory.doStart(self)

    def doStop(self):
        self.wrappedFactory.doStop()
        ServerFactory.doStop(self)

    def buildProtocol(self, addr):
        return self.protocol(self, self.wrappedFactory.buildProtocol(addr))

    def registerProtocol(self, p):
        """Called by protocol to register itself."""
        self.protocols[p] = 1

    def unregisterProtocol(self, p):
        """Called by protocols when they go away."""
        del self.protocols[p]


class CompressingProtocol(ProtocolWrapper):
    """
    Wraps a transport with zlib compression.

    @ivar _compressor: Zlib object to compress the data stream
    @type _compressor: C{zlib.compressobj}
    @ivar _decompressor: Zlib object to decompress the data stream
    @type _decompressor: C{zlib.decompressobj}

    @since: 11.1
    """

    def __init__(self, factory, wrappedProtocol):
        ProtocolWrapper.__init__(self, factory, wrappedProtocol)
        self._compressor = zlib.compressobj()
        self._decompressor = zlib.decompressobj()


    def write(self, data):
        if not data:
            return
        compressed = self._compressor.compress(data)
        compressed += self._compressor.flush(zlib.Z_SYNC_FLUSH)
        self.transport.write(compressed)


    def writeSequence(self, dataSequence):
        if not dataSequence:
            return
        compressed = [ self._compressor.compress(data)
                       for data in dataSequence if data ]
        if not compressed:
            return
        compressed.append(self._compressor.flush(zlib.Z_SYNC_FLUSH))
        self.transport.writeSequence(compressed)


    def dataReceived(self, data):
        toDecompress = self._decompressor.unconsumed_tail + data
        decompressed = self._decompressor.decompress(toDecompress, 1024)
        self.wrappedProtocol.dataReceived(decompressed)


    def connectionLost(self, reason):
        try:
            self.wrappedProtocol.dataReceived(self._decompressor.flush())
        finally:
            ProtocolWrapper.connectionLost(self, reason)


class XmppCompressingProtocol(CompressingProtocol):
    """
    Wraps a transport with zlib compression, to implement XEP-0138 (stream
    compression). Used by L{CompressInitiatingInitializer}.

    @since: 11.1
    """

    def __init__(self, wrappedProtocol):
        CompressingProtocol.__init__(self, WrappingFactory(None), wrappedProtocol)


    def makeConnection(self, transport):
        """
        Connects the factory to us and us to the underlying transport.

        L{CompressingProtocol.makeConnection}() can't be used because it calls
        makeConnection on the wrapped protocol, which causes a second full
        initialization, while the stream just needs a reset (done by
        L{CompressInitiatingInitializer}).
        """
        directlyProvides(self, providedBy(transport))
        Protocol.makeConnection(self, transport)
        self.factory.registerProtocol(self)
        self.wrappedProtocol.transport = self
        transport.protocol = self
