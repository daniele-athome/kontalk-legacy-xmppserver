#!/usr/bin/env python
# SSL bridge for XMPP STARTTLS

from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from twisted.internet import ssl, reactor

HOST = 'beta.kontalk.net'
PORT = 5222
INIT = '<stream:stream to="kontalk.net" xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" version="1.0"><starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>'

class XMPPClient(Protocol):

    def __init__(self, client):
        self.client = client
        self._buf = ''

    def write(self, data):
        """Writes data to the XMPP server."""
        if self.transport and self.transport.TLS:
            print 'SEND: %s' % (data, )
            self.transport.write(data)
        else:
            self._buf += data

    def connectionMade(self):
        """Connected to XMPP server."""
        print 'SEND: %s' % (INIT, )
        self.transport.write(INIT)

    def dataReceived(self, data):
        print 'RECV: %s' % (data, )
        if self.transport.TLS:
            self.client.transport.write(data)
        elif data.endswith("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"):
            print 'starting TLS'

            with open("kontalk-login.key") as keyFile:
                    with open("kontalk-login.crt") as certFile:
                        clientCert = ssl.PrivateCertificate.loadPEM(
                            keyFile.read() + certFile.read())

            ctx = clientCert.options()
            self.transport.startTLS(ctx)
            if self._buf:
                print 'SEND: %s' % (INIT, )
                self.transport.write(self._buf)
                self._buf = None


class BridgeProtocol(Protocol):

    def __init__(self, addr):
        self.addr = addr
        self._conn = None
        self._buf = ''

    def _connected(self, p):
        self._conn = p

    def dataReceived(self, data):
        # <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>=</auth>
        if '<auth' in data and 'mechanism' in data and 'PLAIN' in data:
            data = data.replace('PLAIN', 'EXTERNAL')

        self.client.write(data)
        if '</stream:stream>' in data:
            self.client.transport.loseConnection()
            self.transport.loseConnection()

    def connectionMade(self):
        print 'got connection from %s' % (self.addr, )
        print 'connecting to %s:%d' % (HOST, PORT)
        point = TCP4ClientEndpoint(reactor, HOST, PORT)
        self.client = XMPPClient(self)
        d = connectProtocol(point, self.client)
        d.addCallback(self._connected)

    def connectionLost(self, reason):
        pass


class BridgeFactory(Factory):

    def buildProtocol(self, addr):
        return BridgeProtocol(addr)


reactor.listenTCP(5224, BridgeFactory())
reactor.run()
