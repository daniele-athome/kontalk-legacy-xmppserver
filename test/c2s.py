import base64, socket, sys
from twisted.application import service
from twisted.internet import defer, protocol, reactor
from twisted.python import log
from twisted.words.protocols.jabber import client, error, jid, sasl, xmlstream
from twisted.words.xish import domish

XPATH_ALL = "//*"
XPATH_AUTH = "//auth[@xmlns='%s']" % sasl.NS_XMPP_SASL
XPATH_BIND = "//iq[@type='set']/bind[@xmlns='%s']" % client.NS_XMPP_BIND
XPATH_SESSION = "//iq[@type='set']/session[@xmlns='%s']" % \
                client.NS_XMPP_SESSION
XPATH_IQ_GET = "//iq[@type='get']"
XPATH_IQ_SET = "//iq[@type='set']"

NS_ROSTER = 'jabber:iq:roster'
XPATH_ROSTER_GET = "//iq[@type='get']/query[@xmlns='%s']" % NS_ROSTER
XPATH_ROSTER_SET = "//iq[@type='set']/query[@xmlns='%s']" % NS_ROSTER

class XMPPClientListenAuthenticator(xmlstream.Authenticator):
    namespace = 'jabber:client'

    def __init__(self, domain):
        self.domain = domain
        self.failureGrace = 3
        self.state = 'auth'

    def associateWithStream(self, xs):
        xmlstream.Authenticator.associateWithStream(self, xs)
        self.xmlstream.addObserver(XPATH_ALL, self.onElementFallback, -1)

    def onElementFallback(self, element):
        if element.handled:
            return

        exc = error.StreamError('not-authorized')
        self.xmlstream.sendStreamError(exc)

    def streamStarted(self):
        # check namespace
        #if self.xmlstream.namespace != self.namespace:
        #    self.xmlstream.namespace = self.namespace
        #    exc = error.StreamError('invalid-namespace')
        #    self.xmlstream.sendStreamError(exc)
        #    return

        # TODO: check domain

        self.xmlstream.sendHeader()
        
        try:
            stateHandlerName = 'streamStarted' + self.state.capitalize()
            stateHandler = getattr(self, stateHandlerName)
        except AttributeError:
            log.msg('streamStarted handler for', self.state, 'not found')
        else:
            stateHandler()

    def toState(self, state):
        self.state = state
        if state == 'initialized':
            self.xmlstream.removeObserver(XPATH_ALL, self.onElementFallback)
            self.xmlstream.addOnetimeObserver(XPATH_SESSION, self.onSession)
            self.xmlstream.dispatch(self.xmlstream,
                                    xmlstream.STREAM_AUTHD_EVENT)

    def streamStartedAuth(self):
        features = domish.Element((xmlstream.NS_STREAMS, 'features'))
        features.addElement((sasl.NS_XMPP_SASL, 'mechanisms'))
        features.mechanisms.addElement('mechanism', content='PLAIN')
        self.xmlstream.send(features)
        self.xmlstream.addOnetimeObserver(XPATH_AUTH, self.onAuth)
    
    def onAuth(self, auth):
        auth.handled = True

        if auth.getAttribute('mechanism') != 'PLAIN':
            failure = domish.Element((sasl.NS_XMPP_SASL, 'failure'))
            failure.addElement('invalid-mechanism')
            self.xmlstream.send(failure)

            # Close stream on too many failing authentication attempts
            self.failureGrace -= 1
            if self.failureGrace == 0:
                self.xmlstream.sendFooter()
            else:
                self.xmlstream.addOnetimeObserver(XPATH_AUTH, self.onAuth)

            return

        initialResponse = base64.b64decode(unicode(auth))
        authzid, authcid, passwd = initialResponse.split('\x00')

        # TODO: check passwd

        # authenticated

        self.username = authcid

        success = domish.Element((sasl.NS_XMPP_SASL, 'success'))
        self.xmlstream.send(success)
        self.xmlstream.reset()

        self.toState('bind')

    def streamStartedBind(self):
        features = domish.Element((xmlstream.NS_STREAMS, 'features'))
        features.addElement((client.NS_XMPP_BIND, 'bind'))
        features.addElement((client.NS_XMPP_SESSION, 'session'))
        self.xmlstream.send(features)
        self.xmlstream.addOnetimeObserver(XPATH_BIND, self.onBind)

    def doBind(self, iq):
        iq.handled = True
        self.resource = unicode(iq.bind) or 'default'

        # TODO: check for resource conflicts

        newJID = jid.JID(tuple=(self.username, self.domain, self.resource))

        reply = domish.Element((None, 'iq'))
        reply['type'] = 'result'
        if iq.getAttribute('id'):
            reply['id'] = iq['id']
        reply.addElement((client.NS_XMPP_BIND, 'bind'))
        reply.bind.addElement((client.NS_XMPP_BIND, 'jid'),
                              content=newJID.full())
        self.xmlstream.send(reply)
        return defer.succeed(newJID)

    def onBind(self, iq):
        def cb(jid):
            self.xmlstream.clientJID = jid
            self.toState('initialized')

        def eb(failure):
            if not isinstance(failure, error.StanzaError):
                log.msg(failure)
                exc = error.StanzaError('internal-server-error')
            else:
                exc = failure.value
            self.xmlstream.send(exc.toResponse(iq))

        d = defer.maybeDeferred(self.doBind, iq)
        d.addCallbacks(cb, eb)

    def onSession(self, iq):
        iq.handled = True

        reply = domish.Element((None, 'iq'))
        reply['type'] = 'result'
        if iq.getAttribute('id'):
            reply['id'] = iq['id']
        reply.addElement((client.NS_XMPP_SESSION, 'session'))
        self.xmlstream.send(reply)

class XmlStreamServerFactory(protocol.ServerFactory):
    """
    Protocol factory for accepting XML streams.
    """
    protocol = xmlstream.XmlStream

    def __init__(self, authenticatorClass, *args, **kwargs):
        self.bootstraps = []
        self.authenticatorClass = authenticatorClass
        self.args = args
        self.kwargs = kwargs

    def buildProtocol(self, addr):
        """ Create an instance of XmlStream.

        The returned instance will have bootstrap event observers registered
        and will proceed to handle input on an incoming connection.
        """
        authenticator = self.authenticatorClass(*self.args, **self.kwargs)
        xs = self.protocol(authenticator)
        xs.initiating = False
        xs.factory = self
        for event, fn in self.bootstraps:
            xs.addObserver(event, fn)
        return xs

    def addBootstrap(self, event, fn):
        """ Add a bootstrap event handler. """
        self.bootstraps.append((event, fn))

    def removeBootstrap(self, event, fn):
        """ Remove a bootstrap event handler. """
        self.bootstraps.remove((event, fn))

class RosterProtocol(xmlstream.XMPPHandler):
    """
    XMPP subprotocol handler for the roster, server side.
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver(XPATH_ROSTER_GET, self._onRosterGet, -1)
        self.xmlstream.addObserver(XPATH_ROSTER_SET, self._onRosterSet, -1)

    def _toRosterReply(self, items, iq):
        response = xmlstream.toResponse(iq, 'result')
        response.addElement((NS_ROSTER, 'query'))

        for item in items:
            element = response.query.addElement('item')
            element['jid'] = item['jid']
            if item['name']:
                element['name'] = item['name']
            element['subscription'] = item['subscription']
            if item['ask']:
                element['ask'] = item['ask']

            for group in item['groups']:
                element.addElement('group', content=group)

        return response

    def _onRosterGet(self, iq):
        iq.handled = True

        d = self.getRoster(self.xmlstream.clientJID.userhostJID())
        d.addCallback(self._toRosterReply, iq)
        d.addErrback(lambda _: error.ErrorStanza('internal-error').toResponse(iq))
        d.addBoth(self.send)

    def _onRosterSet(self, iq):
        iq.handled = True
        response = error.StanzaError('bad-request').toResponse(iq)
        self.send(response)

    def getRoster(self, entity):
        raise NotImplemented

class StaticRoster(RosterProtocol):

    def __init__(self):
        self.roster = {'ralphm':
                           [{'jid': 'intosi@example.org',
                             'name': 'Intosi',
                             'subscription': 'both',
                             'ask': None,
                             'groups': ['Friends']
                            },
                            {'jid': 'termie@example.org',
                             'name': 'termie',
                             'subscription': 'both',
                             'ask': None,
                             'groups': []
                            }]}

    def getRoster(self, entity):
        return defer.succeed(self.roster[entity.user])

class BasicProtocol(xmlstream.XMPPHandler):
    serial = 0
    
    def __init__(self):
        self.__class__.serial += 1
        self.serial = self.serial
        
    def connectionInitialized(self):
        self.xmlstream.addObserver(XPATH_IQ_GET, self.onIqFallback, -1)
        self.xmlstream.addObserver(XPATH_IQ_SET, self.onIqFallback, -1)

    def onIqFallback(self, iq):
        if iq.handled:
            return

        if iq['type'] in ('result', 'error'):
            return

        iq.handled = True

        if iq.getAttribute('type') in ('get', 'set'):
            exc = error.StanzaError('service-unavailable')
        else:
            exc = error.StanzaError('bad-request')
        self.xmlstream.send(exc.toResponse(iq))

    def connectionMade(self):
        def logDataIn(buf):
            log.msg("RECV(%d): %r" % (self.serial, buf))

        def logDataOut(buf):
            log.msg("SEND(%d): %r" % (self.serial, buf))

        self.xmlstream.rawDataInFn = logDataIn
        self.xmlstream.rawDataOutFn = logDataOut

class ClientService(xmlstream.StreamManager, service.Service):

    def __init__(self, domain, port=5222):
        self.domain = domain
        self.port = port

        factory = XmlStreamServerFactory(XMPPClientListenAuthenticator,
                                         self.domain)
        xmlstream.StreamManager.__init__(self, factory)


    def startService(self):
        service.Service.startService(self)
        reactor.listenTCP(self.port, self.factory)

application = service.Application("Jabber server")
clientService = ClientService(socket.gethostname(), 5224)
clientService.addHandler(BasicProtocol())
clientService.addHandler(StaticRoster())
clientService.setServiceParent(application)
