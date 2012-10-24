#!/usr/bin/env python

# Copyright (c) 2007 Sander Marechal
# See jukebox/trunk/LICENSE for details

"""
This is a test server build on my twisted.words hacks
"""

from twisted.cred import portal
from twisted.cred import checkers
from twisted.internet import reactor
from twisted.words.xish import domish
from twisted.words.protocols.jabber import xmlstream

from xmppserver import SASLRealm, XMPPServerFactory

NS_XMPP_STANZAS = 'urn:ietf:params:xml:ns:xmpp-stanzas'


class JukeboxServer(object):
	"""
	This is the actual jukebox server, implementing the jukebox XMPP protocol
	"""
	
	def __init__(self):
		authrealm = SASLRealm("Rockbox")
		authportal = portal.Portal(authrealm)
		check = checkers.InMemoryUsernamePasswordDatabaseDontUse()
		check.addUser("admin", "foobar")
		authportal.registerChecker(check)
		
		factory = XMPPServerFactory(authportal)
		factory.addBootstrap(xmlstream.STREAM_CONNECTED_EVENT, self.connected)
		factory.addBootstrap(xmlstream.STREAM_AUTHD_EVENT, self.authenticated)
		factory.addBootstrap(xmlstream.STREAM_END_EVENT, self.disconnected)
		#factory.loadPEM('SSL/server.pem', "serverkey")
		
		self.authenticated_streams = []
		reactor.listenTCP(5222, factory)
	
	def run(self):
		reactor.run()
	
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
		xs.rawDataInFn = self.rawIn
		xs.rawDataOutFn = self.rawOut
		xs.addObserver('/iq', self.onIQ, xs = xs)
		xs.addObserver('/presence', self.onPresence, xs = xs)
		xs.addObserver('/message', self.onMessage, xs = xs)
	
	def authenticated(self, xs):
		print "Autheticated"
		self.authenticated_streams.append(xs)
	
	def disconnected(self, xs):
		if xs in self.authenticated_streams:
			self.authenticated_streams.remove(xs)
	
	def rawIn(self, d):
		print "RECV", repr(d)
	
	def rawOut(self, d):
		print "SEND", repr(d)
	
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

	def onMessage(self, message, xs):
		""" Message stanzas are not implemented by the jukebox
		"""
		if self._verify(message, xs):
			self.sendError(message, xs, 'cancel', 'feature-not-implemented')

	def onPresence(self, presence, xs):
		""" Presence stanzas are not implemented by the jukebox
		"""
		if self._verify(presence, xs):
			self.sendError(presence, xs, 'cancel', 'feature-not-implemented')


server = JukeboxServer()
server.run()

