# Copyright (c) 2007 Sander Marechal
# See jukebox/trunk/LICENSE for details

"""
A whole bunch of changes and experiments that perhaps one day could go into twisted.
Together the make p support for the serverside of the jabber:client XMPP protocol
"""

from zope.interface import Attribute, Interface, implements

from twisted.internet import defer
from twisted.internet.protocol import ServerFactory

from twisted.words.xish import domish
from twisted.words.xish import xmlstream as xish_xmlstream
from twisted.words.protocols.jabber import ijabber, xmlstream, sasl, sasl_mechanisms, jid, xmpp_stringprep

import md5, binascii

from twisted.cred import error
from twisted.cred import portal
from twisted.cred import credentials

import traceback

try:
    from OpenSSL import crypto
    from twisted.internet import ssl
except ImportError:
    ssl = None
if ssl and not ssl.supported:
    ssl = None

STREAM_AUTHD_EVENT = intern("//event/stream/authd")
INIT_SUCCESS_EVENT = intern("//event/xmpp/initsuccess")
INIT_FAILED_EVENT = intern("//event/xmpp/initfailed")

NS_STREAMS = 'http://etherx.jabber.org/streams'
NS_XMPP_TLS = 'urn:ietf:params:xml:ns:xmpp-tls'

Reset = object()


##
# twisted.cred stuff to do pluggable authentication in the jukebox
# We'll see if this is useful or not
#

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


class UsernamePasswordDigestMD5:
	implements(credentials.IUsernamePassword)

	def __init__(self, charset, username, realm, nonce, cnonce, nc, digest_uri, response):
		self.charset = charset
		self.username = username
		self.realm = realm
		self.nonce = nonce
		self.cnonce = cnonce
		self.nc = nc
		self.digest_uri = digest_uri
		self.response = response
	
	def _gen_response(self, password):
		"""
		Generate response-value.
		
		Creates a response to a challenge according to section 2.1.2.1 of
		RFC 2831 using the L{charset}, L{realm} and L{nonce} directives
		from the challenge.
		
		Lifted from twisted.words.protocols.jabber.sasl_mechanisms.DigestMD5
		Should probably be spun off into twisted.cred somewhere and made
		general enough for both client and server
		"""
		
		def H(s):
			return md5.new(s).digest()
		
		def HEX(n):
			return binascii.b2a_hex(n)
		
		def KD(k, s):
			return H('%s:%s' % (k, s))
		
		try:
			username = self.username.encode(self.charset)
			password = password.encode(self.charset)
		except UnicodeError:
			# TODO - add error checking
			raise
		
		qop = 'auth'
		
		# TODO - add support for authzid
		a1 = "%s:%s:%s" % (H("%s:%s:%s" % (username, self.realm, password)),
			self.nonce,
			self.cnonce)
		a2 = "AUTHENTICATE:%s" % self.digest_uri
		
		response = HEX( KD ( HEX(H(a1)),
			"%s:%s:%s:%s:%s" % (self.nonce, self.nc,
				self.cnonce, "auth", HEX(H(a2)))))
		
		return response
	
	def checkPassword(self, password):
		"""
		Use the password and the stored values to verify the response
		"""
		response = self._gen_response(password)
		return response == self.response


##
# This bit goes into twisted.words.protocols.jabber.ijabber
#

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


##
# Extensions to twisted.words.protocols.jabber.xmlstream
#

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
		if self.xmlstream.factory.tls_ctx is None:
			print "TLS not supported"
			return
		
		feature = domish.Element((xmlstream.NS_XMPP_TLS, 'starttls'), defaultUri=xmlstream.NS_XMPP_TLS)
		if self.required:
			feature.addElement((xmlstream.NS_XMPP_TLS, 'required'))
		return feature
	
	def initialize(self):
		self.xmlstream.addOnetimeObserver('/starttls', self.onStartTLS)
	
	def deinitialize(self):
		self.xmlstream.removeObserver('/starttls', self.onStartTLS)
	
	def onStartTLS(self, element):
		if self.xmlstream.factory.tls_ctx is None:
			failure = domish.Element((sasl.NS_XMPP_SASL, 'failure'), defaultUri=sasl.NS_XMPP_TLS)
			self.xmlstream.send(failure)
			self.xmlstream.sendFooter()
		
		if self.canInitialize(self):
			self.xmlstream.dispatch(self, INIT_SUCCESS_EVENT)
			self.xmlstream.send(domish.Element((xmlstream.NS_XMPP_TLS, 'proceed')))
			self.xmlstream.transport.startTLS(self.xmlstream.factory.tls_ctx)
			self.xmlstream.reset()

##
# Extending twisted.words.protocol.jabber.sasl and sasl_mechanisms with the stuff
# required for the receiving end of a jabber:client stream
#

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
		if IXMPPUser in interfaces:
			avatar = self.buildAvatar(avatarId)
			return IXMPPUser, avatar, avatar.logout
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
		return XMPPUser(jid.JID(tuple=(avatarId, "example.com", None)))



class SASLMechanismError(sasl.SASLError):
	"""
	Something went wrong in the mechanism. Could be caused by user (e.g. sending
	an initial response for DIGEST-MD5) or by the server.
	"""


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


class Plain(object):
	"""
	Implements the PLAIN SASL authentication mechanism.
	
	The PLAIN SASL authentication mechanism is defined in RFC 2595.
	This should be folded into twisted.words.protocols.jabber.sasl_mechanisms.Plain
	"""
	implements(ISASLServerMechanism)
	
	def __init__(self, portal=None):
		self.portal = portal
	
	def getInitialChallenge(self):
		return defer.Deferred().errback(SASLMechanismError())
	
	def parseInitialResponse(self, response):
		self.deferred = defer.Deferred()
		authzid, authcid, password = response.split('\x00')
		login = self.portal.login(credentials.UsernamePassword(authcid, password), None, IXMPPUser)
		login.addCallbacks(self.onSuccess, self.onFailure)
		return self.deferred
	
	def parseResponse(self, response):
		return defer.Deferred().errback(SASLMechanismError())
	
	def onSuccess(self, (interface, avatar, logout)):
		self.deferred.callback(avatar)
	
	def onFailure(self, failure):
		failure.trap(error.UnauthorizedLogin)
		self.deferred.errback(sasl.SASLAuthError())


class DigestMD5(sasl_mechanisms.DigestMD5):
	"""
	Implements the DIGEST-MD5 SASL authentication mechanism.
	
	The DIGEST-MD5 SASL authentication mechanism is defined in RFC 2831.
	This should be folded into twisted.words.protocols.jabber.sasl_mechanisms.DigestMD5
	"""
	implements(ISASLServerMechanism)
	
	#TODO: Is this right when integrated into Twisted?
	def __init__(self, serv_type, host, serv_name, username=None, password=None, portal=None):
		sasl_mechanisms.DigestMD5.__init__(self, serv_type, host, serv_name, username, password)
		self.portal = portal
	
	def getInitialChallenge(self):
		challenge = {
			"realm": self.portal.realm.name,
			"nonce": self._gen_nonce(),
			"qop": "auth",
			"charset": "utf-8",
			"algorithm": "md5-sess"}
		return self._unparse(challenge)
	
	def parseInitialResponse(self, response):
		return defer.Deferred().errback(SASLMechanismError())
	
	def parseResponse(self, response):
		params = self._parse(response)
		self.deferred = defer.Deferred()
		
		cred = UsernamePasswordDigestMD5(
			params['charset'],
			params['username'],
			params['realm'],
			params['nonce'],
			params['cnonce'],
			params['nc'],
			params['digest-uri'],
			params['response'])
		login = self.portal.login(cred, None, IXMPPUser)
		login.addCallbacks(self.onSuccess, self.onFailure)
		return self.deferred
	
	def onSuccess(self, (interface, avatar, logout)):
		# We don't support Subsequent Authentication so no need to send an rspauth challenge
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
		#feature.addElement('mechanism', content='DIGEST-MD5')
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
		if mechanism == 'PLAIN':
			self.mechanism = Plain(self.xmlstream.portal)
		elif mechanism == 'DIGEST-MD5':
			self.mechanism = DigestMD5('xmpp', 'localhost', None, portal=self.xmlstream.portal)  #TODO: Make serv_type configurable
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


##
# Our own implementation of twised.words.protocol.jabber.server
#

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
			response.addElement((None, 'jid'), content=self.xmlstream.otherEntity.full().encode('UTF-8'))
			self.xmlstream.send(response)
			self.xmlstream.dispatch(self, INIT_SUCCESS_EVENT)
		else:
			self._sendError(stanza, 'auth', 'not-authorized')
	

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
		xs.addObserver(INIT_SUCCESS_EVENT, self.onSuccess)
		
		xs.initializers = []
		
		#TODO: Make the inits configurable
		inits = [#(TLSReceivingInitializer, False),
			(SASLReceivingInitializer, True),
			(BindInitializer, True)]
		
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
			self.xmlstream.dispatch(self.xmlstream, STREAM_AUTHD_EVENT)


class XMPPServerFactory(xish_xmlstream.XmlStreamFactoryMixin, ServerFactory):
	
	protocol = xmlstream.XmlStream
	
	def __init__(self, portal):
		xish_xmlstream.XmlStreamFactoryMixin.__init__(self)
		self.streams = []
		self.portal = portal
	
	def loadPEM(self, pemfile, passphrase=""):
		if ssl is None:
			raise xmlstream.TLSNotSupported()
		
		file = open(pemfile, 'rb')
		pem = file.read()
		file.close()
		
		pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, pem, passphrase)
		cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
		self.tls_ctx = ssl.CertificateOptions(privateKey=pkey, certificate=cert)
	
	def buildProtocol(self, addr):
		xs = self.protocol(XMPPListenAuthenticator())
		xs.factory = self
		xs.portal = self.portal
		
		for event, fn in self.bootstraps:
			xs.addObserver(event, fn)
		
		self.streams.append(xs)
		return xs
