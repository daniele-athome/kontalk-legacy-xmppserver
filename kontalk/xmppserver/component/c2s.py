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

from twisted.application import internet
from twisted.cred import portal
from twisted.internet.protocol import ServerFactory
from twisted.words.protocols.jabber import jid, xmlstream, error
from twisted.words.xish import domish, xmlstream as xish_xmlstream
from twisted.words.protocols.jabber.error import NS_XMPP_STANZAS
from wokkel import component

from zope.interface import implements

import kontalk.xmppserver.xmlstream as c2s_xmpp
import kontalklib.logging as log
from kontalklib import utils


class XMPPServerFactory(xish_xmlstream.XmlStreamFactoryMixin, ServerFactory):

    protocol = xmlstream.XmlStream

    def __init__(self, portal):
        xish_xmlstream.XmlStreamFactoryMixin.__init__(self)
        self.streams = []
        self.portal = portal

    def buildProtocol(self, addr):
        xs = self.protocol(XMPPListenAuthenticator())
        xs.factory = self
        xs.portal = self.portal
        xs.logTraffic = self.logTraffic
        
        for event, fn in self.bootstraps:
            xs.addObserver(event, fn)

        self.streams.append(xs)
        return xs


class SASLRealm:
    """
    A twisted.cred Realm for XMPP/SASL authentication
    
    You can subclass this and override the buildAvatar function to return an
    object that implements the IXMPPUser interface.
    """
    
    implements(portal.IRealm)
    
    def __init__(self, name):
        """ @param name: a string identifying the realm
        """
        self.name = name
    
    def requestAvatar(self, avatarId, mind, *interfaces):
        if c2s_xmpp.IXMPPUser in interfaces:
            avatar = self.buildAvatar(avatarId)
            return c2s_xmpp.IXMPPUser, avatar, avatar.logout
        else:
            raise NotImplementedError("Only IXMPPUser interface is supported by this realm")
    
    def buildAvatar(self, avatarId):
        """
        @param avatarId: a string that identifies an avatar, as returned by
        L{ICredentialsChecker.requestAvatarId<twisted.cred.checkers.ICredentialsChecker.requestAvatarId>}
        (via a Deferred).  Alternatively, it may be
        C{twisted.cred.checkers.ANONYMOUS}.
        """
        # The hostname will be overwritten by the SASLReceivingInitializer
        # We put in example.com to keep the JID constructor from complaining
        return c2s_xmpp.XMPPUser(jid.JID(tuple=(avatarId, "kontalk.net", None)))


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
        xs.addObserver(c2s_xmpp.INIT_SUCCESS_EVENT, self.onSuccess)

        xs.initializers = []
        inits = [
            #(xmlstream.TLSInitiatingInitializer, False),
            (c2s_xmpp.SASLReceivingInitializer, True),
            (c2s_xmpp.BindInitializer, True),
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


class C2SComponent(component.Component):
    '''Kontalk c2s component.'''

    def __init__(self, application, config):
        self.setServiceParent(application)
        self.config = config
        self.logTraffic = self.config['debug']
        self.authenticated_streams = []

        router_cfg = config['router']
        component.Component.__init__(self, router_cfg['host'], router_cfg['port'], router_cfg['jid'], router_cfg['secret'])

    def startService(self):
        log.debug("starting c2s")
        component.Component.startService(self)

        #credFactory = utils.AuthKontalkTokenFactory(str(self.config['server']['fingerprint']), self.keyring)
        authrealm = SASLRealm("Kontalk")
        authportal = portal.Portal(authrealm, [utils.AuthKontalkToken()])

        factory = XMPPServerFactory(authportal)
        factory.logTraffic = self.config['debug']
        factory.addBootstrap(xmlstream.STREAM_CONNECTED_EVENT, self.connected)
        factory.addBootstrap(xmlstream.STREAM_AUTHD_EVENT, self.authenticated)
        factory.addBootstrap(xmlstream.STREAM_END_EVENT, self.disconnected)

        c2s = internet.TCPServer(port=self.config['bind'][1],
            factory=factory, interface=self.config['bind'][0])
        c2s.setServiceParent(self.parent)

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
        xs.addObserver('/iq', self.onIQ, xs = xs)
        #xs.addObserver('/presence', self.onPresence, xs = xs)
        #xs.addObserver('/message', self.onMessage, xs = xs)
    
    def authenticated(self, xs):
        log.debug("xml stream authenticated")
        # TODO this should create a specialized StreamManager to handle xs
        self.authenticated_streams.append(xs)

    def disconnected(self, xs):
        if xs in self.authenticated_streams:
            self.authenticated_streams.remove(xs)

    def _verify(self, stanza, xs):
        """ Verify that the stream is authenticated and the stanza is adressed to us
        """
        if not xs in self.authenticated_streams:
            self.sendError(stanza, xs, 'auth', 'not-authorized')
            return False
        
        to = stanza.getAttribute('to', 'localhost/jukebox')
        if to != '' and not to.startswith('localhost'):
            self.sendError(stanza, xs, 'cancel', 'item-not-found')
            return False
        
        return True

    def onIQ(self, iq, xs):
        """ Respond to IQ stanzas sent to the server
        """
        if not iq.bind is None or not self._verify(iq, xs):
            return
        
        xs.send(xmlstream.toResponse(iq, 'result'))
