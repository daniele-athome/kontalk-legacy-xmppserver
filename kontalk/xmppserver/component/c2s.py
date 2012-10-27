# -*- coding: utf-8 -*-
'''Kontalk XMPP c2s component.'''
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


from twisted.application import service, strports
from twisted.cred import portal
from twisted.internet.protocol import ServerFactory
from twisted.words.protocols.jabber import xmlstream, error
from twisted.words.protocols.jabber.error import NS_XMPP_STANZAS
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish, xmlstream as xish_xmlstream
from wokkel.xmppim import UnavailablePresence

from kontalk.xmppserver import log, auth, keyring
import kontalk.xmppserver.xmlstream as xmlstream2



class C2SHandler(XMPPHandler):
    """
    Handles communication with a client.

    @param router: the connection with the router
    @type router: L{xmlstream.StreamManager}
    """

    def __init__(self, router):
        XMPPHandler.__init__(self)
        self.router = router

    def connectionInitialized(self):
        log.debug("[MGR] xml stream authenticated")
        self.xmlstream.addObserver('/presence', self.onPresence)

    def onPresence(self, iq):
        log.debug("[MGR] presence: %s" % (iq.toXml(), ))

        # presence stanza is coming from client
        iq['from'] = self.xmlstream.otherEntity.full()

        stanza = domish.Element((None, 'route'))
        stanza.addChild(iq)

        if not iq.hasAttribute('to'):
            stanza['type'] = 'broadcast'

        self.router.send(stanza)

    def connectionLost(self, reason):
        log.debug("[MGR] xml stream disconnected (%s)" % (reason, ))
        stanza = UnavailablePresence()
        stanza['from'] = self.xmlstream.otherEntity.full()
        self.onPresence(stanza)


class XMPPServerFactory(xish_xmlstream.XmlStreamFactoryMixin, ServerFactory):

    protocol = xmlstream.XmlStream

    def __init__(self, portal, router):
        xish_xmlstream.XmlStreamFactoryMixin.__init__(self)
        self.portal = portal
        self.router = router

    def buildProtocol(self, addr):
        xs = self.protocol(XMPPListenAuthenticator())
        xs.factory = self
        xs.portal = self.portal
        xs.manager = xmlstream2.StreamManager(xs)
        xs.manager.logTraffic = self.logTraffic
        xs.manager.addHandler(C2SHandler(self.router))

        # install bootstrap handlers
        self.installBootstraps(xs)

        return xs

class XMPPListenAuthenticator(xmlstream.ListenAuthenticator):
    """
    Initializes an XmlStream accepted from an XMPP client as a Server.

    This authenticator performs the initialization steps needed to start
    exchanging XML stanzas with an XMPP cient as an XMPP server. It checks if
    the client advertises XML stream version 1.0, performs TLS encryption, SASL
    authentication, and binds a resource. Note: This does not establish a
    session. Sessions are part of XMPP-IM, not XMPP Core.

    Upon successful stream initialization, the L{xmlstream.STREAM_AUTHD_EVENT}
    event will be dispatched through the XML stream object. Otherwise, the
    L{xmlstream.INIT_FAILED_EVENT} event will be dispatched with a failure
    object.
    """

    def associateWithStream(self, xs):
        """
        Perform stream initialization procedures.

        An L{XmlStream} holds a list of initializer objects in its
        C{initializers} attribute. This method calls these initializers in
        order up to the first required initializer. This way, a client
        cannot use an initializer before passing all the previous initializers that
        are marked as required. When a required initializer is successful it is removed,
        and all preceding optional initializers are removed as well.

        It dispatches the C{STREAM_AUTHD_EVENT} event when the list has
        been successfully processed. The initializers themselves are responsible
        for sending an C{INIT_FAILED_EVENT} event on failure.
        """

        xmlstream.ListenAuthenticator.associateWithStream(self, xs)
        xs.addObserver(xmlstream2.INIT_SUCCESS_EVENT, self.onSuccess)

        xs.initializers = []
        inits = [
            #(xmlstream.TLSInitiatingInitializer, False),
            (xmlstream2.SASLReceivingInitializer, True),
            (xmlstream2.BindInitializer, True),
            #(SessionInitializer, False),
        ]
        for initClass, required in inits:
            init = initClass(xs, self.canInitialize)
            init.required = required
            xs.initializers.append(init)
            init.initialize()

    def streamStarted(self, rootElement):
        xmlstream.ListenAuthenticator.streamStarted(self, rootElement)

        if self.xmlstream.version < (1, 0):
            raise error.StreamError('unsupported-version')

        self.xmlstream.sendHeader()

        if self.xmlstream.version >= (1, 0):
            features = domish.Element((xmlstream.NS_STREAMS, 'features'))

            for initializer in self.xmlstream.initializers:
                feature = initializer.feature()
                if feature is not None:
                    features.addChild(feature)
                if hasattr(initializer, 'required') and initializer.required:
                    break

            self.xmlstream.send(features)

    def canInitialize(self, initializer):
        inits = self.xmlstream.initializers[0:self.xmlstream.initializers.index(initializer)]

        # check if there are required inits that should have been run first
        for init in inits:
            if hasattr(init, 'required') and init.required:
                return False

        # remove the skipped inits
        for init in inits:
            init.deinitialize()
            self.xmlstream.initializers.remove(init)

        return True

    def onSuccess(self, initializer):
        self.xmlstream.initializers.remove(initializer)

        required = False
        for init in self.xmlstream.initializers:
            if hasattr(init, 'required') and init.required:
                required = True

        if not required:
            self.xmlstream.dispatch(self.xmlstream, xmlstream.STREAM_AUTHD_EVENT)


class C2SComponent(XMPPHandler, service.Service):
    '''Kontalk c2s component.'''

    def __init__(self, config):
        XMPPHandler.__init__(self)
        self.config = config
        self.logTraffic = config['debug']
        # TODO this will become a dictionary
        self.streams = []

    def setup(self):
        authrealm = auth.SASLRealm("Kontalk")
        ring = keyring.Keyring(None, self.config['fingerprint'])
        authportal = portal.Portal(authrealm, [auth.AuthKontalkToken(self.config['fingerprint'], ring)])

        self.factory = XMPPServerFactory(authportal, self.parent)
        self.factory.logTraffic = self.config['debug']
        self.factory.addBootstrap(xmlstream.STREAM_CONNECTED_EVENT, self.connected)
        self.factory.addBootstrap(xmlstream.STREAM_AUTHD_EVENT, self.authenticated)
        self.factory.addBootstrap(xmlstream.STREAM_END_EVENT, self.disconnected)

        return strports.service('tcp:' + str(self.config['bind'][1]) +
            ':interface=' + str(self.config['bind'][0]), self.factory)

    def sendError(self, stanza, xs, error_type, error_condition, error_message=None):
        """ Send an error in response to a stanza
        """
        response = xmlstream.toResponse(stanza, 'error')

        error = domish.Element((None, 'error'))
        error['type'] = error_type
        error.addElement((NS_XMPP_STANZAS, error_condition))

        if error_message:
            error.addElement((NS_XMPP_STANZAS, 'text'), content=error_message.encode('UTF-8'))

        response.addChild(error)
        xs.send(response)

    def connected(self, xs):
        log.debug("xml stream %s connected" % (xs, ))

    def authenticated(self, xs):
        log.debug("xml stream %s authenticated" % (xs, ))
        self.streams.append(xs)

    def disconnected(self, xs):
        if xs in self.streams:
            self.streams.remove(xs)

    def _verify(self, stanza, xs):
        """ Verify that the stream is authenticated and the stanza is adressed to us
        """
        if not xs in self.streams:
            self.sendError(stanza, xs, 'auth', 'not-authorized')
            return False

        to = stanza.getAttribute('to', 'localhost/jukebox')
        if to != '' and not to.startswith('localhost'):
            self.sendError(stanza, xs, 'cancel', 'item-not-found')
            return False

        return True

    def onIQ(self, iq, xs):
        """ Respond to IQ stanzas sent to the server."""
        if not iq.bind is None or not self._verify(iq, xs):
            return

        # FIXME bounce back response
        xs.send(xmlstream.toResponse(iq, 'result'))
