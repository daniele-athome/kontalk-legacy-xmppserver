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


from twisted.application import strports
from twisted.cred import portal
from twisted.internet.protocol import ServerFactory
from twisted.words.protocols.jabber import xmlstream, error, jid
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish, xmlstream as xish_xmlstream
from wokkel.xmppim import UnavailablePresence

from kontalk.xmppserver import log, auth, keyring, database, util
from kontalk.xmppserver import xmlstream2


class C2SHandler(XMPPHandler):
    """
    Handles communication with a client. Note that this is the L{XMPPHandler}
    towards the client, not the router!!

    @param router: the connection with the router
    @type router: L{xmlstream.StreamManager}
    """

    def __init__(self, factory, router, servername):
        XMPPHandler.__init__(self)
        self.factory = factory
        self.router = router
        self.servername = servername

    def connectionInitialized(self):
        #log.debug("[c2s] xml stream authenticated")
        self.factory.connectionInitialized(self.xmlstream)
        self.xmlstream.addObserver('/presence', self.onPresence)

    def onPresence(self, iq):
        """Process incoming presence stanzas from client."""
        log.debug("[c2s] presence: %s" % (iq.toXml(), ))

        iq['from'] = self.resolveJID(self.xmlstream.otherEntity).full()
        self.router.send(iq)

    def connectionLost(self, reason):
        #log.debug("[c2s] xml stream disconnected (%s)" % (reason, ))
        self.factory.connectionLost(self.xmlstream, reason)

        if self.xmlstream.otherEntity:
            stanza = UnavailablePresence()
            stanza['from'] = self.xmlstream.otherEntity.full()
            self.onPresence(stanza)

    def resolveJID(self, _jid):
        """Transform host attribute of JID from network name to server name."""
        return jid.JID(tuple=(_jid.user, self.servername, _jid.resource))


class XMPPServerFactory(xish_xmlstream.XmlStreamFactoryMixin, ServerFactory):

    protocol = xmlstream.XmlStream
    handler = C2SHandler

    def __init__(self, portal, router, network, servername):
        xish_xmlstream.XmlStreamFactoryMixin.__init__(self)
        self.portal = portal
        self.router = router
        self.network = network
        self.servername = servername
        self.streams = {}

    def buildProtocol(self, addr):
        xs = self.protocol(XMPPListenAuthenticator(self.network))
        xs.factory = self
        xs.portal = self.portal
        xs.manager = xmlstream2.StreamManager(xs)
        xs.manager.logTraffic = self.logTraffic
        xs.manager.addHandler(self.handler(self, self.router, self.servername))

        # install bootstrap handlers
        self.installBootstraps(xs)

        return xs

    def connectionInitialized(self, xs):
        userid, resource = util.jid_to_userid(xs.otherEntity, True)
        if userid not in self.streams:
            self.streams[userid] = {}
        self.streams[userid][resource] = xs

    def connectionLost(self, xs, reason):
        """Called from the handler when connection to a client is lost."""
        userid, resource = util.jid_to_userid(xs.otherEntity, True)
        if userid in self.streams and resource in self.streams[userid]:
            del self.streams[userid][resource]

    def dispatch(self, stanza, to):
        """Dispatch a stanza to a JID all to all available resources found locally."""
        userid, resource = util.jid_to_userid(to, True)
        # deliver to the request jid
        stanza['to'] = to.full()
        stanza.defaultUri = stanza.uri = None
        if to.resource is not None:
            self.streams[userid][resource].send(stanza)
        else:
            for xs in self.streams[userid].itervalues():
                xs.send(stanza)


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

    def __init__(self, network):
        xmlstream.ListenAuthenticator.__init__(self)
        self.network = network

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

        self.xmlstream.sendHeader()

        try:
            if self.xmlstream.version < (1, 0):
                raise error.StreamError('unsupported-version')
            if self.xmlstream.thisEntity.host != self.network:
                raise error.StreamError('not-authorized')
        except error.StreamError, exc:
            self.xmlstream.sendHeader()
            self.xmlstream.sendStreamError(exc)
            return

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


class C2SComponent(XMPPHandler):
    """
    Kontalk c2s component.
    L{XMPPHandler} is for the connection with the router.
    """

    def __init__(self, config):
        XMPPHandler.__init__(self)
        self.config = config
        self.logTraffic = config['debug']
        self.network = config['network']
        self.servername = config['host']

    def setup(self):
        # TODO transform into C2SService/Component like in resolver.py
        self.db = database.connect_config(self.config)

        authrealm = auth.SASLRealm("Kontalk")
        ring = keyring.Keyring(database.servers(self.db), self.config['fingerprint'])
        authportal = portal.Portal(authrealm, [auth.AuthKontalkToken(self.config['fingerprint'], ring)])

        self.factory = XMPPServerFactory(authportal, self.parent, self.network, self.servername)
        self.factory.logTraffic = self.config['debug']

        return strports.service('tcp:' + str(self.config['bind'][1]) +
            ':interface=' + str(self.config['bind'][0]), self.factory)

    """ Connection with router """

    def connectionInitialized(self):
        XMPPHandler.connectionInitialized(self)
        log.debug("connected to router.")
        self.xmlstream.addObserver('/presence', self.onPresence)
        self.xmlstream.addObserver('/error', self.onError)

    def connectionLost(self, reason):
        XMPPHandler.connectionLost(self, reason)
        log.debug("lost connection to router (%s)" % (reason, ))

    def onPresence(self, stanza):
        log.debug("incoming stanza: %s" % (stanza.toXml()))
        """
        incoming stanzas must be intended to a server JID (e.g.
        prime.kontalk.net), since the resolver should already have resolved it.
        Otherwise it is an error.
        """
        if stanza.hasAttribute('to'):
            to = jid.JID(stanza['to'])
            # process only username JIDs
            if to.user and to.host == self.servername:
                self.factory.dispatch(stanza, jid.JID(tuple=(to.user, self.network, to.resource)))
            else:
                log.debug("stanza is not our concern or is an error")

    def onError(self, stanza):
        log.debug("routing error: %s" % (stanza.toXml()))
