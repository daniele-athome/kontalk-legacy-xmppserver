
from twisted.cred import error
from twisted.internet import defer
from twisted.words.protocols.jabber import ijabber, xmlstream, xmpp_stringprep, sasl
from twisted.words.protocols.jabber.error import NS_XMPP_STANZAS
from twisted.words.xish import domish

from zope.interface.declarations import implements
from zope.interface.interface import Attribute, Interface

import md5
import os
import random
import time

import auth


INIT_SUCCESS_EVENT = intern("//event/xmpp/initsuccess")


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


NS_XMPP_BIND = 'urn:ietf:params:xml:ns:xmpp-bind'

class BindInitializer(BaseFeatureReceivingInitializer):
    """
    Initializer that implements Resource Binding for the receiving entity.
    
    This protocol is documented in U{RFC 3920, section
    7<http://www.xmpp.org/specs/rfc3920.html#bind>}.
    """
    
    def feature(self):
        if self.required:
            return domish.Element((NS_XMPP_BIND, 'bind'))
    
    def initialize(self):
        self.xmlstream.addOnetimeObserver('/iq', self.onBind)
    
    def deinitialize(self):
        self.xmlstream.removeObserver('/iq', self.onBind)
    
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
        
        if not stanza.bind.resource is None:
            resource = str(stanza.bind.resource)
            if resource == "":
                resource = md5.new("%s:%s:%s" % (str(random.random()) , str(time.gmtime()),str(os.getpid()))).hexdigest()
            
            try:
                resource = xmpp_stringprep.resourceprep.prepare(unicode(resource))
            except UnicodeError:
                self._sendError(stanza, 'modify', 'bad-request')
            
            self.xmlstream.otherEntity.resource = resource
                
            response = xmlstream.toResponse(stanza, 'result')
            bind = response.addElement((NS_XMPP_BIND, 'bind'))
            bind.addElement((None, 'jid'), content=self.xmlstream.otherEntity.full().encode('UTF-8'))
            self.xmlstream.send(response)
            self.xmlstream.dispatch(self, INIT_SUCCESS_EVENT)
        else:
            self._sendError(stanza, 'auth', 'not-authorized')


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
        failure.trap(error.UnauthorizedLogin)
        self.deferred.errback(sasl.SASLAuthError())


class SASLReceivingInitializer(BaseFeatureReceivingInitializer):
    """
    Stream initializer that performs SASL authentication.
    
    The supported mechanisms by this initializer are C{DIGEST-MD5} and C{PLAIN}
    """

    def feature(self):
        feature = domish.Element((sasl.NS_XMPP_SASL, 'mechanisms'), defaultUri=sasl.NS_XMPP_SASL)
        feature.addElement('mechanism', content='KONTALK-TOKEN')
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
        else:
            self._sendFailure('invalid-mechanism')
            return
        
        response = str(element)
        
        if response:
            deferred = self.mechanism.parseInitialResponse(sasl.fromBase64(response))
            deferred.addCallbacks(self.onSucces, self.onFailure)
        else:
            self._sendChallenge(self.mechanism.getInitialChallenge())

    def onResponse(self, element):
        response = sasl.fromBase64(str(element))
        deferred = self.mechanism.parseResponse(response)
        deferred.addCallbacks(self.onSucces, self.onFailure)

    def onSucces(self, result):
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
