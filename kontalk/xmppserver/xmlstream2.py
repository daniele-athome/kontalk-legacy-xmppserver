
from twisted.cred import error as cred_error
from twisted.internet import defer
from twisted.words.protocols.jabber import client, ijabber, xmlstream, sasl
from twisted.words.protocols.jabber.error import NS_XMPP_STANZAS
from twisted.words.xish import domish

from zope.interface.declarations import implements
from zope.interface.interface import Attribute, Interface

import auth, log

INIT_SUCCESS_EVENT = intern("//event/xmpp/initsuccess")

NS_DISCO_INFO = 'http://jabber.org/protocol/disco#info'
NS_DISCO_ITEMS = 'http://jabber.org/protocol/disco#items'

NS_IQ_REGISTER = 'jabber:iq:register'
NS_IQ_VERSION = 'jabber:iq:version'
NS_IQ_ROSTER = 'jabber:iq:roster'
NS_IQ_LAST = 'jabber:iq:last'

NS_XMPP_PING = 'urn:xmpp:ping'

NS_XMPP_STANZA_GROUP = 'urn:xmpp:stanza-group'


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
        if self.required:
            return domish.Element((client.NS_XMPP_SESSION, 'session'))

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
        self.xmlstream.dispatch(self, INIT_SUCCESS_EVENT)


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


class PlainMechanism(object):
    """
    Implements the PLAIN SASL authentication mechanism.

    The PLAIN SASL authentication mechanism is defined in RFC 2595.
    This should be folded into twisted.words.protocols.jabber.sasl_mechanisms.Plain
    @type portal: L{Portal}
    """
    implements(ISASLServerMechanism)

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
    """
    Stream initializer that performs SASL authentication.

    The supported mechanisms by this initializer are C{DIGEST-MD5} and C{PLAIN}
    """

    def feature(self):
        feature = domish.Element((sasl.NS_XMPP_SASL, 'mechanisms'), defaultUri=sasl.NS_XMPP_SASL)
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
        if mechanism == 'KONTALK-TOKEN':
            self.mechanism = KontalkTokenMechanism(self.xmlstream.portal)
        elif mechanism == 'PLAIN':
            self.mechanism = PlainMechanism(self.xmlstream.portal)
        else:
            self._sendFailure('invalid-mechanism')
            return

        response = str(element)

        if response:
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

def toResponse(stanza, stanzaType=None):
    """
    Create a response stanza from another stanza.

    This takes the addressing and id attributes from a stanza to create a (new,
    empty) response stanza. The addressing attributes are swapped and the id
    copied. Optionally, the stanza type of the response can be specified.
    This takes care also of handling origin and destination attributes

    @param stanza: the original stanza
    @type stanza: L{domish.Element}
    @param stanzaType: optional response stanza type
    @type stanzaType: C{str}
    @return: the response stanza.
    @rtype: L{domish.Element}
    """

    toAddr = stanza.getAttribute('from')
    destinationAddr = stanza.getAttribute('origin')
    fromAddr = stanza.getAttribute('to')
    originAddr = stanza.getAttribute('destination')
    stanzaID = stanza.getAttribute('id')

    response = domish.Element((None, stanza.name))
    if toAddr:
        response['to'] = toAddr
    if destinationAddr:
        response['destination'] = destinationAddr
    if fromAddr:
        response['from'] = fromAddr
    if originAddr:
        response['origin'] = originAddr
    if stanzaID:
        response['id'] = stanzaID
    if stanzaType:
        response['type'] = stanzaType

    return response
