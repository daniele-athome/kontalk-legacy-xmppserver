# -*- coding: utf-8 -*-
"""XML stream utilities."""
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


import copy

from twisted.cred import error as cred_error
from twisted.internet import reactor, defer
from twisted.words.protocols.jabber import client, ijabber, xmlstream, sasl, error
from twisted.words.protocols.jabber.error import NS_XMPP_STANZAS
from twisted.words.xish import domish

from wokkel import component

from OpenSSL import SSL

from zope.interface.declarations import implements
from zope.interface.interface import Attribute, Interface

import auth, log, tls

INIT_SUCCESS_EVENT = intern("//event/xmpp/initsuccess")

NS_DISCO_INFO = 'http://jabber.org/protocol/disco#info'
NS_DISCO_ITEMS = 'http://jabber.org/protocol/disco#items'

NS_IQ_REGISTER = 'jabber:iq:register'
NS_IQ_VERSION = 'jabber:iq:version'
NS_IQ_ROSTER = 'jabber:iq:roster'
NS_IQ_LAST = 'jabber:iq:last'
NS_IQ_BLOCKING = 'urn:xmpp:blocking'
NS_IQ_BLOCKING_ERRORS = 'urn:xmpp:blocking:errors'

NS_XMPP_DELAY = 'urn:xmpp:delay'
NS_XMPP_PING = 'urn:xmpp:ping'
NS_PROTO_COMMANDS = 'http://jabber.org/protocol/commands'
NS_XMPP_VCARD4 = 'urn:ietf:params:xml:ns:vcard-4.0'

NS_XMPP_STANZA_GROUP = 'urn:xmpp:stanza-group'
NS_XMPP_SERVER_RECEIPTS = 'urn:xmpp:server-receipts'
NS_XMPP_STORAGE = 'urn:xmpp:storage'
# <presence/> direct delivery: no notification to subscribers
NS_XMPP_DIRECT = 'urn:xmpp:direct'

NS_PRESENCE_PUSH = 'http://kontalk.org/extensions/presence#push'
NS_MESSAGE_UPLOAD = 'http://kontalk.org/extensions/message#upload'

XMPP_STAMP_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

DATA_PGP_PREFIX = 'data:application/pgp-keys;base64,'


def strip_server_receipt(stanza):
    """
    Strips server receipt elements from the given stanza.
    """
    if stanza.request and stanza.request.uri == NS_XMPP_SERVER_RECEIPTS:
        stanza.children.remove(stanza.request)
    if stanza.sent and stanza.sent.uri == NS_XMPP_SERVER_RECEIPTS:
        stanza.children.remove(stanza.sent)
    if stanza.received and stanza.received.uri == NS_XMPP_SERVER_RECEIPTS:
        stanza.children.remove(stanza.received)


def extract_receipt(stanza, rtype):
    """
    Extract the requested type of server receipt.
    """
    for receipt in stanza.elements(uri=NS_XMPP_SERVER_RECEIPTS, name=rtype):
        return receipt

def has_element(stanza, uri, name):
    for elem in stanza.elements(uri, name):
        return elem
    return None


class IXMPPUser(Interface):
    """
    An interface for users
    """

    jid = Attribute("""The JID of the user""")

    def logout():
        """
        Do cleanup here
        """

class XMPPUser:
    """
    A regular JID user
    """

    implements(IXMPPUser)

    def __init__(self, jid):
        self.jid = jid

    def logout(self):
        pass


class IReceivingInitializer(ijabber.IInitializer):
    """
    Interface for XML stream initializers for the initiating entity.
    """

    xmlstream = Attribute("""The associated XML stream""")
    required = Attribute("""Whether this initialization step is required""")

    def feature():
        """
        return a domish element that represents the feature, or None
        """

    def initialize():
        """
        Initiate the initialization step. Unlike IInitializingInitializer
        this should not return a deferred. All initialize should do
        is add some observers and see what the client does next.
        """

    def deinitialize():
        """
        Clean up initialize if this initializer is skipped
        """

class MyOpenSSLCertificateOptions(object):

    _context = None
    # Older versions of PyOpenSSL didn't provide OP_ALL.  Fudge it here, just in case.
    _OP_ALL = getattr(SSL, 'OP_ALL', 0x0000FFFF)
    method = SSL.SSLv23_METHOD
    options = SSL.OP_NO_SSLv3 | SSL.OP_NO_SSLv2

    def __init__(self, privateKeyFile=None, certificateFile=None, verifyCallback=None, enableSingleUseKeys=True):
        self.privateKeyFile = privateKeyFile
        self.certificateFile = certificateFile
        self._verifyCallback = verifyCallback
        self.enableSingleUseKeys = enableSingleUseKeys

    def getContext(self):
        """Return a SSL.Context object.
        """
        if self._context is None:
            self._context = self._makeContext()
        return self._context


    def _makeContext(self):
        ctx = SSL.Context(self.method)
        ctx.set_options(self.options)

        if self.certificateFile is not None and self.privateKeyFile is not None:
            ctx.use_certificate_chain_file(self.certificateFile)
            ctx.use_privatekey_file(self.privateKeyFile)
            # Sanity check
            ctx.check_privatekey()

        verifyFlags = SSL.VERIFY_NONE
        if self._verifyCallback:
            verifyFlags = SSL.VERIFY_PEER

            ctx.set_verify(verifyFlags, self._verifyCallback)

        if self.enableSingleUseKeys:
            ctx.set_options(SSL.OP_SINGLE_DH_USE)

        return ctx


class BaseFeatureReceivingInitializer(object):
    """
    Base class for receivers with a stream feature.

    This assumes the associated XmlStream represents the receiving entity
    of the connection. After adding hooks in initialize(), you should call
    the canInitialize callback with self as a parameter. The callback will
    return True if you can continue or False if you should abort.

    This is to catch clients trying to initialize out-of-order, e.g. a client
    trying SASL authentication when the server requires TLS encryption first.
    """

    implements(IReceivingInitializer)

    def __init__(self, xs, canInitialize):
        self.xmlstream = xs
        self.canInitialize = canInitialize


class TLSReceivingInitializer(BaseFeatureReceivingInitializer):
    """
    TLS stream initializer for the receiving entity.
    """

    def feature(self):
        if self.xmlstream.factory.getSSLContext() is None:
            log.warn("TLS not supported")
            return None

        if not tls.isTLS(self.xmlstream):
            feature = domish.Element((xmlstream.NS_XMPP_TLS, 'starttls'), defaultUri=xmlstream.NS_XMPP_TLS)
            if self.required:
                feature.addElement((xmlstream.NS_XMPP_TLS, 'required'))
            return feature

        return None

    def initialize(self):
        self.xmlstream.addOnetimeObserver('/starttls', self.onStartTLS)

    def deinitialize(self):
        self.xmlstream.removeObserver('/starttls', self.onStartTLS)

    def onStartTLS(self, element):
        # TLS not supported or already negotiated
        if self.xmlstream.factory.getSSLContext() is None or tls.isTLS(self.xmlstream):
            failure = domish.Element((sasl.NS_XMPP_SASL, 'failure'), defaultUri=xmlstream.NS_XMPP_TLS)
            self.xmlstream.send(failure)
            self.xmlstream.sendFooter()
            self.xmlstream.transport.loseConnection()

        elif self.canInitialize(self):
            self.xmlstream.dispatch(self, INIT_SUCCESS_EVENT)
            self.xmlstream.send(domish.Element((xmlstream.NS_XMPP_TLS, 'proceed')))
            self.xmlstream.transport.startTLS(self.xmlstream.factory.getSSLContext())
            self.xmlstream.reset()


class BindInitializer(BaseFeatureReceivingInitializer):
    """
    Initializer that implements Resource Binding for the receiving entity.

    This protocol is documented in U{RFC 3920, section
    7<http://www.xmpp.org/specs/rfc3920.html#bind>}.
    """

    def feature(self):
        if self.required:
            return domish.Element((client.NS_XMPP_BIND, 'bind'))

    def initialize(self):
        self.xmlstream.addOnetimeObserver('/iq/bind', self.onBind, 100)

    def deinitialize(self):
        self.xmlstream.removeObserver('/iq/bind', self.onBind)

    def _sendError(self, stanza, error_type, error_condition, error_message=None):
        """ Send an error in response to a stanza
        """
        response = xmlstream.toResponse(stanza, 'error')

        error = domish.Element((None, 'error'))
        error['type'] = error_type
        error.addElement((NS_XMPP_STANZAS, error_condition))

        if error_message:
            error.addElement((NS_XMPP_STANZAS, 'text'), content=error_message.encode('UTF-8'))

        response.addChild(error)
        self.xmlstream.send(response)

    def onBind(self, stanza):
        if not self.canInitialize(self):
            return

        stanza.consumed = True
        # resource has already been extracted by realm (avatarId)
        response = xmlstream.toResponse(stanza, 'result')
        bind = response.addElement((client.NS_XMPP_BIND, 'bind'))
        bind.addElement((None, 'jid'), content=self.xmlstream.otherEntity.full().encode('UTF-8'))
        self.xmlstream.send(response)
        self.xmlstream.dispatch(self, INIT_SUCCESS_EVENT)


class SessionInitializer(BaseFeatureReceivingInitializer):
    """
    Initializer that implements session establishment for the receiving entity.

    This protocol is defined in U{RFC 3921, section
    3<http://www.xmpp.org/specs/rfc3921.html#session>}.
    """

    def feature(self):
        feature = domish.Element((client.NS_XMPP_SESSION, 'session'))
        if self.required:
            feature.addElement((client.NS_XMPP_SESSION, 'required'))
        return feature

    def initialize(self):
        self.xmlstream.addOnetimeObserver('/iq/session', self.onSession, 100)

    def deinitialize(self):
        self.xmlstream.removeObserver('/iq/session', self.onSession)

    def onSession(self, stanza):
        if not self.canInitialize(self):
            return

        stanza.consumed = True
        iq = xmlstream.toResponse(stanza, 'result')
        iq.addElement((client.NS_XMPP_SESSION, 'session'))
        self.xmlstream.send(iq)

        if self.required:
            self.xmlstream.dispatch(self, INIT_SUCCESS_EVENT)


class RegistrationInitializer(BaseFeatureReceivingInitializer):
    """
    Initializer that implements in-band registration for the receiving entity.

    This protocol is defined in U{XEP-0077<http://xmpp.org/extensions/xep-0077.html>}.
    """

    def feature(self):
        return domish.Element(('http://jabber.org/features/iq-register', 'register'))

    def initialize(self):
        self.xmlstream.addObserver("/iq[@type='get']/query[@xmlns='%s']" % (NS_IQ_REGISTER), self.onRequest, 100)
        self.xmlstream.addObserver("/iq[@type='set']/query[@xmlns='%s']" % (NS_IQ_REGISTER), self.onRegister, 100)

    def deinitialize(self):
        self.xmlstream.removeObserver("/iq[@type='get']/query[@xmlns='%s']" % (NS_IQ_REGISTER), self.onRequest)
        self.xmlstream.removeObserver("/iq[@type='set']/query[@xmlns='%s']" % (NS_IQ_REGISTER), self.onRegister)

    def _error(self, stanza):
        e = error.StanzaError('service-unavailable', 'cancel', 'Registration not available.')
        self.xmlstream.send(e.toResponse(stanza))

    def onRequest(self, stanza):
        if not self.canInitialize(self):
            return

        stanza.consumed = True

        if not self.xmlstream.manager.router.registration:
            return self._error(stanza)

        self.xmlstream.manager.router.registration.request(self.xmlstream.manager, stanza)

    def onRegister(self, stanza):
        if not self.canInitialize(self):
            return

        stanza.consumed = True

        if not self.xmlstream.manager.router.registration:
            return self._error(stanza)

        self.xmlstream.manager.router.registration.register(self.xmlstream.manager, stanza)


class ISASLServerMechanism(Interface):
    """
    The server-side of ISASLMechanism. Could perhaps be integrated into
    twisted.words.protocols.jabber.sasl_mechanisms.ISSASLMechanism
    """

    portal = Attribute("""A twisted.cred portal to authenticate through""")

    def getInitialChallenge():
        """
        Create an initial challenge. Used by e.g. DIGEST-MD5
        """

    def parseInitialResponse(response):
        """
        Parse the initial resonse from the client, if any and return a deferred.
        The deferred's callback returns either an instance of IXMPPUser or a string
        that should be used as a subsequent challenge to be sent to the client.
        Raises SASLAuthError as errback on failure
        """

    def parseResponse(response):
        """
        Parse a response from the client and return a deferred.
        The deferred's callback returns either an instance of IXMPPUser or a string
        that should be used as a subsequent challenge to be sent to the client.
        Raises SASLAuthError as errback on failure
        """


class ExternalMechanism(object):
    """
    Implements the EXTERNAL SASL authentication mechanism.

    @type portal: L{Portal}
    """
    implements(ISASLServerMechanism)

    name = 'EXTERNAL'

    def __init__(self, portal=None, peer_certificate=None):
        self.portal = portal
        self.peer_certificate = peer_certificate

    def getInitialChallenge(self):
        return defer.Deferred().errback(SASLMechanismError())

    def parseInitialResponse(self, response):
        self.deferred = defer.Deferred()
        login = self.portal.login(auth.KontalkCertificate(self.peer_certificate), None, IXMPPUser)
        login.addCallbacks(self.onSuccess, self.onFailure)
        return self.deferred

    def parseResponse(self, response):
        return defer.Deferred().errback(SASLMechanismError())

    def onSuccess(self, (interface, avatar, logout)):
        self.deferred.callback(avatar)

    def onFailure(self, failure):
        failure.trap(cred_error.UnauthorizedLogin)
        self.deferred.errback(sasl.SASLAuthError())


class PlainMechanism(object):
    """
    Implements the PLAIN SASL authentication mechanism.

    The PLAIN SASL authentication mechanism is defined in RFC 2595.
    This should be folded into twisted.words.protocols.jabber.sasl_mechanisms.Plain
    @type portal: L{Portal}
    """
    implements(ISASLServerMechanism)

    name = 'PLAIN'

    def __init__(self, portal=None):
        self.portal = portal

    def getInitialChallenge(self):
        return defer.Deferred().errback(SASLMechanismError())

    def parseInitialResponse(self, response):
        self.deferred = defer.Deferred()
        authzid, authcid, password = response.split('\x00')
        log.debug("using password %s" % (password, ))
        login = self.portal.login(auth.KontalkToken(password, True), None, IXMPPUser)
        login.addCallbacks(self.onSuccess, self.onFailure)
        return self.deferred

    def parseResponse(self, response):
        return defer.Deferred().errback(SASLMechanismError())

    def onSuccess(self, (interface, avatar, logout)):
        self.deferred.callback(avatar)

    def onFailure(self, failure):
        failure.trap(cred_error.UnauthorizedLogin)
        self.deferred.errback(sasl.SASLAuthError())


class KontalkTokenMechanism(object):
    """
    Implements the Kontalk token SASL authentication mechanism.
    """
    implements(ISASLServerMechanism)

    name = 'KONTALK-TOKEN'

    def __init__(self, portal=None):
        self.portal = portal

    def getInitialChallenge(self):
        return defer.Deferred().errback(SASLMechanismError())

    def parseInitialResponse(self, response):
        self.deferred = defer.Deferred()
        login = self.portal.login(auth.KontalkToken(response), None, IXMPPUser)
        login.addCallbacks(self.onSuccess, self.onFailure)
        return self.deferred

    def parseResponse(self, response):
        return defer.Deferred().errback(SASLMechanismError())

    def onSuccess(self, (interface, avatar, logout)):
        self.deferred.callback(avatar)

    def onFailure(self, failure):
        failure.trap(cred_error.UnauthorizedLogin)
        self.deferred.errback(sasl.SASLAuthError())


class SASLReceivingInitializer(BaseFeatureReceivingInitializer):
    """Stream initializer that performs SASL authentication."""

    external = False

    def feature(self):
        self.external = tls.isTLS(self.xmlstream)

        feature = domish.Element((sasl.NS_XMPP_SASL, 'mechanisms'), defaultUri=sasl.NS_XMPP_SASL)
        if self.external:
            feature.addElement('mechanism', content='EXTERNAL')

        feature.addElement('mechanism', content='KONTALK-TOKEN')
        feature.addElement('mechanism', content='PLAIN')
        return feature

    def initialize(self):
        self.xmlstream.addOnetimeObserver('/auth', self.onAuth)

    def deinitialize(self):
        self.xmlstream.removeObserver('/auth', self.onAuth)

    def _sendChallenge(self, content):
        self.xmlstream.addOnetimeObserver('/response', self.onResponse)
        challenge = domish.Element((sasl.NS_XMPP_SASL, 'challenge'))
        challenge.addContent(sasl.b64encode(content))
        self.xmlstream.send(challenge)

    def _sendFailure(self, error):
        failure = domish.Element((sasl.NS_XMPP_SASL, 'failure'), defaultUri=sasl.NS_XMPP_SASL)
        failure.addElement(error)
        self.xmlstream.send(failure)
        self.xmlstream.sendFooter()

    def onAuth(self, element):
        if not self.canInitialize(self):
            return

        mechanism = element.getAttribute('mechanism')
        if self.external and mechanism == 'EXTERNAL':
            self.mechanism = ExternalMechanism(self.xmlstream.portal, self.xmlstream.transport.getPeerCertificate())
        elif mechanism == 'KONTALK-TOKEN':
            self.mechanism = KontalkTokenMechanism(self.xmlstream.portal)
        elif mechanism == 'PLAIN':
            self.mechanism = PlainMechanism(self.xmlstream.portal)
        else:
            self._sendFailure('invalid-mechanism')
            return

        response = str(element)

        # HACK this a workaround for naughty clients
        if mechanism == 'EXTERNAL' and not response:
            response = '='

        if response:
            # TODO base64 might fail - UNHANDLED ERROR
            deferred = self.mechanism.parseInitialResponse(sasl.fromBase64(response))
            deferred.addCallbacks(self.onSuccess, self.onFailure)
        else:
            self._sendChallenge(self.mechanism.getInitialChallenge())

    def onResponse(self, element):
        response = sasl.fromBase64(str(element))
        deferred = self.mechanism.parseResponse(response)
        deferred.addCallbacks(self.onSuccess, self.onFailure)

    def onSuccess(self, result):
        if IXMPPUser.providedBy(result):
            self.xmlstream.otherEntity = result.jid
            self.xmlstream.otherEntity.host = self.xmlstream.thisEntity.host
            self.xmlstream.dispatch(self, INIT_SUCCESS_EVENT)

            succes = domish.Element((sasl.NS_XMPP_SASL, 'success'))
            self.xmlstream.send(succes)
            self.xmlstream.reset()
        elif type(result) == str:
            self._sendChallenge(result)
        else:
            self._sendFailure('temporary-auth-failure')
            print "No vaild result in onSuccess: %s" % (type(result))

    def onFailure(self, fail):
        fail.trap(sasl.SASLAuthError, SASLMechanismError)

        if fail.type == sasl.SASLAuthError:
            self._sendFailure('not-authorized')
        else:
            self._sendFailure('temporary-auth-failure')

class SASLMechanismError(sasl.SASLError):
    """
    Something went wrong in the mechanism. Could be caused by user (e.g. sending
    an initial response for DIGEST-MD5) or by the server.
    """


class StreamManager(xmlstream.XMPPHandlerCollection):
    """
    Business logic representing a managed XMPP connection.
    Adapted for server factories.

    This maintains a single XMPP connection and provides facilities for packet
    routing and transmission. Business logic modules are objects providing
    L{ijabber.IXMPPHandler} (like subclasses of L{XMPPHandler}), and added
    using L{addHandler}.

    @ivar xmlstream: currently managed XML stream
    @type xmlstream: L{XmlStream}
    @ivar logTraffic: if true, log all traffic.
    @type logTraffic: C{bool}
    @ivar _initialized: Whether the stream represented by L{xmlstream} has
                        been initialized. This is used when caching outgoing
                        stanzas.
    @type _initialized: C{bool}
    @ivar _packetQueue: internal buffer of unsent data. See L{send} for details.
    @type _packetQueue: C{list}
    """

    logTraffic = False

    def __init__(self, xs):
        xmlstream.XMPPHandlerCollection.__init__(self)
        self.xmlstream = None
        self._packetQueue = []
        self._initialized = False

        xs.addObserver(xmlstream.STREAM_CONNECTED_EVENT, self._connected)
        xs.addObserver(xmlstream.STREAM_AUTHD_EVENT, self._authd)
        xs.addObserver(xmlstream.INIT_FAILED_EVENT, self.initializationFailed)
        xs.addObserver(xmlstream.STREAM_END_EVENT, self._disconnected)
        self._connected(xs)

    def addHandler(self, handler):
        """
        Add protocol handler.

        When an XML stream has already been established, the handler's
        C{connectionInitialized} will be called to get it up to speed.
        """
        xmlstream.XMPPHandlerCollection.addHandler(self, handler)

        # get protocol handler up to speed when a connection has already
        # been established
        if self.xmlstream and self._initialized:
            handler.makeConnection(self.xmlstream)
            handler.connectionInitialized()


    def _connected(self, xs):
        """
        Called when the transport connection has been established.

        Here we optionally set up traffic logging (depending on L{logTraffic})
        and call each handler's C{makeConnection} method with the L{XmlStream}
        instance.
        """
        def logDataIn(buf):
            log.debug("RECV: %s" % unicode(buf, 'utf-8').encode('utf-8'))

        def logDataOut(buf):
            log.debug("SEND: %s" % unicode(buf, 'utf-8').encode('utf-8'))

        if self.logTraffic:
            xs.rawDataInFn = logDataIn
            xs.rawDataOutFn = logDataOut

        self.xmlstream = xs
        self.xmlstream.namespace = self.namespace

        for e in self:
            e.makeConnection(xs)


    def _authd(self, xs):
        """
        Called when the stream has been initialized.

        Send out cached stanzas and call each handler's
        C{connectionInitialized} method.
        """
        # Flush all pending packets
        for p in self._packetQueue:
            xs.send(p)
        self._packetQueue = []
        self._initialized = True

        # Notify all child services which implement
        # the IService interface
        for e in self:
            e.connectionInitialized()


    def initializationFailed(self, reason):
        """
        Called when stream initialization has failed.

        Stream initialization has halted, with the reason indicated by
        C{reason}. It may be retried by calling the authenticator's
        C{initializeStream}. See the respective authenticators for details.

        @param reason: A failure instance indicating why stream initialization
                       failed.
        @type reason: L{failure.Failure}
        """


    def _disconnected(self, reason):
        """
        Called when the stream has been closed.

        From this point on, the manager doesn't interact with the
        L{XmlStream} anymore and notifies each handler that the connection
        was lost by calling its C{connectionLost} method.
        """
        self.xmlstream = None
        self._initialized = False

        # Notify all child services which implement
        # the IService interface
        for e in self:
            e.connectionLost(reason)


    def send(self, obj, force=False):
        """
        Send data over the XML stream.

        When there is no established XML stream, the data is queued and sent
        out when a new XML stream has been established and initialized.

        @param obj: data to be sent over the XML stream. See
                    L{xmlstream.XmlStream.send} for details.
        """
        if self._initialized or (force and self.xmlstream is not None):
            self.xmlstream.send(obj)
        else:
            self._packetQueue.append(obj)


class SocketComponent(component.Component):
    def __init__(self, socket, host, port, jid, password):
        component.Component.__init__(self, host, port, jid, password)
        self.socket = socket

    def _getConnection(self):
        if self.socket:
            return reactor.connectUNIX(self.socket, self.factory)
        else:
            return reactor.connectTCP(self.host, self.port, self.factory)


class CommandsHandler(xmlstream.XMPPHandler):
    """
    XEP-0050: Ad-Hoc Commands
    http://xmpp.org/extensions/xep-0050.html
    """

    def __init__(self, handlers):
        xmlstream.XMPPHandler.__init__(self)
        self._init_handlers = handlers
        self._component_name = None
        # command list for quick access
        self.commands = []
        # command handlers for execution
        self.cmd_handlers = {}

    def setHandlerParent(self, parent, component_name):
        xmlstream.XMPPHandler.setHandlerParent(self, parent)
        self._component_name = component_name

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='set'][@to='%s']/command[@xmlns='%s']" % (self._component_name, NS_PROTO_COMMANDS), self.command, 100)

        for h in self._init_handlers:
            cmd = h(self)
            cmdlist = cmd.commands()
            self.commands.extend(cmdlist)
            for c in cmdlist:
                self.cmd_handlers[c['node']] = cmd

    def connectionLost(self, reason):
        xmlstream.XMPPHandler.connectionLost(self, reason)

        # cleanup
        for c in self.cmd_handlers.itervalues():
            c.connectionLost(reason)
        self.cmd_handlers = None

    def command(self, stanza):
        node = stanza.command.getAttribute('node')
        action = stanza.command.getAttribute('action')
        log.debug("command received: %s/%s" % (node, action))
        if action and node and node in self.cmd_handlers:
            try:
                func = getattr(self.cmd_handlers[node], action)
                response = func(stanza)
                if response:
                    self.send(response)
            except:
                self.parent.error(stanza)
        else:
            self.parent.error(stanza)

    def features(self):
        return (NS_PROTO_COMMANDS, )

    def items(self):
        return ({'node': NS_PROTO_COMMANDS, 'items': self.commands }, )
