# -*- coding: utf-8 -*-
"""Handlers and utilities for user presence caching and JID resolution."""
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


import time
import base64
from datetime import datetime
from copy import deepcopy

from twisted.python import failure
from twisted.internet import defer, reactor, task, threads
from twisted.words.protocols.jabber.xmlstream import XMPPHandler
from twisted.words.xish import domish
from twisted.words.protocols.jabber import jid, error, xmlstream

from wokkel import component

from kontalk.xmppserver import log, storage, util, xmlstream2, version, keyring



class PresenceStub(object):
    """VERY UNOPTIMIZED CLASS"""

    def __init__(self, _jid):
        """Creates a presence stub for a bare JID."""
        if _jid.resource:
            raise ValueError('not a bare JID.')
        self._avail = {}
        self.jid = _jid

    def __set__(self, name, value):
        if name == 'type':
            self.type = value
        elif name == 'show':
            if value in ['away', 'xa', 'chat', 'dnd']:
                self.show = value
            else:
                self.show = None
        elif name == 'status':
            if value:
                self.status = value.encode('utf-8')
            else:
                self.status = None
        elif name == 'priority':
            try:
                self.priority = int(value)
            except:
                self.priority = 0
        elif name == 'delay':
            try:
                self.delay = datetime.strptime(value, xmlstream2.XMPP_STAMP_FORMAT)
            except:
                self.delay = None
        else:
            raise AttributeError(name)

    def update(self, stanza):
        """
        Update this stub with data from the given unavailable presence.
        Presence data is updated only if delay is more recent than the old one.
        """
        ptype = stanza.getAttribute('type')
        if ptype != 'unavailable':
            raise ValueError('only unavailable presences are allowed.')

        delay = stanza.delay
        if delay:
            delay = datetime.strptime(delay['stamp'], xmlstream2.XMPP_STAMP_FORMAT)
            if self.delay:
                diff = delay - self.delay
                try:
                    diff_seconds = diff.total_seconds()
                except AttributeError:
                    diff_seconds = (diff.microseconds + (diff.seconds + diff.days * 24 * 3600) * 10**6) / 10**6
            else:
                # no delay :)
                diff_seconds = 1

            if diff_seconds >= 0:
                ujid = jid.JID(stanza['from'])
                # update local jid
                self.jid = ujid.userhostJID()

                if stanza.hasAttribute('type'):
                    self.type = stanza['type']
                else:
                    self.type = None

                # delay already parsed
                self.delay = delay

                for child in ('status', 'show', 'priority'):
                    e = getattr(stanza, child)
                    if e:
                        self.__set__(child, e.__str__())

    def push(self, stanza):
        """Push a presence to this stub."""
        ptype = stanza.getAttribute('type')
        if ptype == 'unavailable':
            raise ValueError('only available presences are allowed.')

        ujid = jid.JID(stanza['from'])
        # update local jid
        self.jid = ujid.userhostJID()

        # recreate presence stanza for local use
        presence = domish.Element((None, 'presence'))
        for attr in ('type', 'from'):
            if stanza.hasAttribute(attr):
                presence[attr] = stanza[attr]

        if stanza.hasAttribute('type'):
            self.type = stanza['type']
        else:
            self.type = None

        for child in ('status', 'show', 'priority', 'delay'):
            e = getattr(stanza, child)
            if e:
                self.__set__(child, e.__str__())
                presence.addChild(e)

        self._avail[ujid.resource] = presence

    def pop(self, resource):
        """Pop the presence for the given resource from this stub."""
        try:
            presence = self._avail[resource]
            del self._avail[resource]

            # no more presences - resource is now unavailable
            if len(self._avail) == 0:
                self.type = 'unavailable'
                # update delay with now
                self.delay = datetime.utcnow()

            return presence
        except:
            pass

    def presence(self):
        if self.available():
            return self._avail.values()
        else:
            return (self.toElement(), )

    def jids(self):
        """Returns a list of available resources from this JID."""
        users = []
        for avail in self._avail.itervalues():
            users.append(jid.JID(avail['from']))
        return users

    def available(self):
        """Returns true if available presence count is greater than 0."""
        return len(self._avail) > 0

    def __str__(self, *args, **kwargs):
        return self.__repr__(*args, **kwargs)

    def __repr__(self, *args, **kwargs):
        return '<PresenceStub jid=%s, avail=%r>' % (self.jid.full(), self._avail)

    @classmethod
    def fromElement(klass, e, from_host=None):
        p_type = e.getAttribute('type')
        if e.show:
            show = str(e.show)
        else:
            show = None
        if e.status:
            status = e.status.__str__()
        else:
            status = None
        try:
            priority = int(e.priority.__str__())
        except:
            priority = 0

        try:
            delay = e.delay['stamp']
        except:
            delay = None

        sender = jid.JID(e['from']).userhostJID()
        if from_host is not None:
            sender.host = from_host

        p = klass(sender)
        p.__set__('type', p_type)
        p.__set__('show', show)
        p.__set__('status', status)
        p.__set__('priority', priority)
        p.__set__('delay', delay)
        if not p_type:
            p.push(e)
        return p

    def toElement(self, attr='from'):
        p = domish.Element((None, 'presence'))
        p[attr] = self.jid.full()
        if self.type:
            p['type'] = self.type

        if self.show:
            p.addElement((None, 'show'), content=self.show)
        if self.priority != 0:
            p.addElement((None, 'priority'), content=str(self.priority))
        if self.status:
            p.addElement((None, 'status'), content=self.status)
        if self.delay:
            d = p.addElement((xmlstream2.NS_XMPP_DELAY, 'delay'))
            d['stamp'] = self.delay.strftime(xmlstream2.XMPP_STAMP_FORMAT)

        return p


class JIDCache(XMPPHandler):
    """
    Cache maintaining JID distributed in this Kontalk network.
    An instance is kept by the L{Resolver} component.
    @ivar presence_cache: cache of presence stanzas
    @type presence_cache: C{dict} [userid]=PresenceStub
    """

    """Seconds to wait for presence probe response from servers."""
    MAX_LOOKUP_TIMEOUT = 5

    def __init__(self):
        XMPPHandler.__init__(self)
        self.lookups = {}
        self.presence_cache = {}
        self._last_lookup = 0

        """
        # TEST TEST TEST
        def _print_cache():
            log.debug("CACHE(%d): %r" % (len(self.presence_cache), self.presence_cache, ))
        task.LoopingCall(_print_cache).start(5)
        """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence[not(@type)]", self.onPresenceAvailable, 200)
        self.xmlstream.addObserver("/presence[@type='unavailable']", self.onPresenceUnavailable, 200)
        # presence probes MUST be handled by server so the high priority
        self.xmlstream.addObserver("/presence[@type='probe']", self.onProbe, 600)
        # vCards MUST be handled by server so the high priority
        self.xmlstream.addObserver("/iq[@type='set']/vcard[@xmlns='%s']" % (xmlstream2.NS_XMPP_VCARD4, ), self.onVCardSet, 600)
        self.xmlstream.addObserver("/stanza/iq[@type='set']/vcard[@xmlns='%s']" % (xmlstream2.NS_XMPP_VCARD4, ), self.parent.wrapped, 600, fn=self.onVCardSet)
        self.xmlstream.addObserver("/iq[@type='get']/vcard[@xmlns='%s']" % (xmlstream2.NS_XMPP_VCARD4, ), self.onVCardGet, 600)

    def onPresenceAvailable(self, stanza):
        """Handle availability presence stanzas."""
        if self.parent.logTraffic:
            log.debug("presence: %s" % (stanza.toXml().encode('utf-8'), ))
        else:
            log.debug("presence available from %s" % (stanza['from'], ))

        # update usercache with last seen and status
        user = jid.JID(stanza['from'])
        if user.user:
            self.user_available(stanza)

    def onPresenceUnavailable(self, stanza):
        """Handle unavailable presence stanzas."""
        if self.parent.logTraffic:
            log.debug("user unavailable: %s" % (stanza.toXml().encode('utf-8'), ))
        else:
            log.debug("user unavailable from %s" % (stanza['from'], ))

        # local c2s or remote server has disconnected, remove presences from cache
        try:
            unused, host = util.jid_component(stanza['from'], util.COMPONENT_C2S)
            if host == self.parent.servername:
                log.debug("local c2s disconnecting, removing data from presence cache" % (host, ))
                keys = self.presence_cache.keys()
                for key in keys:
                    stub = self.presence_cache[key]
                    if stub.jid.host == stanza['from']:
                        del self.presence_cache[key]

            elif host in self.parent.keyring.hostlist():
                log.debug("server %s is disconnecting, taking over presence data" % (host, ))
                ordered_presence = []
                for stub in self.presence_cache.itervalues():
                    if stub.jid.host == stanza['from']:
                        ordered_presence.append(stub)

                # TEST TEST TEST
                # TODO this needs serious re-design from scratch (I mean the whole presence sharing architecture)
                from operator import attrgetter
                ordered_presence.sort(key=attrgetter('jid'))
                # take the N-th part
                index = 1
                for s in self.parent.keyring.hostlist():
                    # skip missing server
                    if s == host:
                        continue
                    # we found ourselves
                    if s == self.parent.servername:
                        break
                    index += 1

                if index > len(self.parent.keyring.hostlist()):
                    log.warn("we can't find ourselves on the servers table! WTF!?!?")

                else:
                    network_len = len(self.parent.keyring.hostlist())
                    presence_len = len(ordered_presence)
                    slice_start = presence_len / (network_len-1) * (index - 1)
                    slice_end = presence_len / (network_len-1) * ((index+1) - 1)
                    log.debug("slice_start = %d, slice_end = %d" % (slice_start, slice_end))
                    for i in range(slice_start, slice_end):
                        e = ordered_presence[i]
                        rewrite = None
                        presence = e.presence()
                        for p in presence:
                            # do not consider available presence stanzas
                            if p.getAttribute('type') == 'unavailable':
                                rewrite = PresenceStub.fromElement(p, util
                                    .component_jid(self.parent.servername, util.COMPONENT_C2S))
                                self.presence_cache[e.jid.user] = rewrite
                                break

                        # simulate presence broadcast so resolvers will insert it into their cache
                        if rewrite:
                            p = rewrite.presence()
                            try:
                                fpr = self.parent.keyring.get_fingerprint(e.jid.user)
                                self.parent.presencedb.presence(p[0])
                                self.parent.presencedb.public_key(e.jid.user, fpr)
                            except keyring.KeyNotFoundException:
                                pass
                            self.send(p[0].toXml().encode('utf-8'))
            return

        except TypeError:
            pass
        except:
            import traceback
            traceback.print_exc()

        # normal user unavailable
        user = jid.JID(stanza['from'])

        if user.user:
            self.user_unavailable(stanza)

    def onVCardGet(self, stanza):
        log.debug("%s requested vCard for %s" % (stanza['from'], stanza['to']))
        jid_from = jid.JID(stanza['from'])
        jid_to = jid.JID(stanza['to'])
        try:
            # are we requesting vCard for a user we have blocked?
            if self.parent.is_presence_allowed(jid_to, jid_from) == -1:
                log.debug("requesting vCard for a blocked user, bouncing error")
                e = error.StanzaError('not-acceptable', 'cancel')
                errstanza = e.toResponse(stanza)
                errstanza.error.addElement((xmlstream2.NS_IQ_BLOCKING_ERRORS, 'blocked'))
                self.send(errstanza)

            else:
                fpr = self.parent.is_presence_allowed(jid_from, jid_to)
                log.debug("is_presence_allowed: %d" % (fpr, ))
                if fpr != 1:
                    raise Exception()

                fpr = self.parent.keyring.get_fingerprint(jid_to.user)
                keydata = self.parent.keyring.get_key(jid_to.user, fpr)

                iq = xmlstream.toResponse(stanza, 'result')
                # add vcard
                vcard = iq.addElement((xmlstream2.NS_XMPP_VCARD4, 'vcard'))
                vcard_key = vcard.addElement((None, 'key'))
                vcard_data = vcard_key.addElement((None, 'uri'))
                vcard_data.addContent(xmlstream2.DATA_PGP_PREFIX + base64.b64encode(keydata))
                self.send(iq)

        except:
            self.parent.error(stanza)

    def onVCardSet(self, stanza, sender=None):
        """
        Handle vCards set IQs.
        This simply takes care of importing the key in the keyring for future
        signature verification. Actual key verification is done by c2s when
        accepting vCards coming from clients.
        WARNING/1 does this mean that we bindly accept keys from components? --
         YES blindly :P c2s will filter invalid requests
        WARNING/2 importing the key means that keys coming from local c2s are
        imported twice because the keyring is the same. Unless we want to make
        a separated keyring only for resolver? -- YES USING .gnupg-cache
        """
        # TODO parse vcard for interesting sections

        if stanza.vcard.key is not None:
            # we do this because of the uri member in domish.Element
            keydata = stanza.vcard.key.firstChildElement()
            if keydata.name == 'uri':
                keydata = str(keydata)

                if keydata.startswith(xmlstream2.DATA_PGP_PREFIX):
                    keydata = base64.b64decode(keydata[len(xmlstream2.DATA_PGP_PREFIX):])
                    # import into cache keyring
                    userid = util.jid_user(stanza['from'])
                    # this chould take a lot of time (up to 500ms)
                    if self.parent.keyring.check_user_key(keydata, userid):
                        log.debug("key cached successfully")
                    else:
                        log.warn("invalid key")
                    # TODO send response!!!

    def send_user_presence(self, gid, sender, recipient):
        stub = self.lookup(recipient)
        log.debug("onProbe(%s): found %r" % (gid, stub, ))
        if stub:
            data = stub.presence()
            i = len(data)
            for x in data:
                presence = deepcopy(x)
                presence['to'] = sender.full()

                try:
                    # add fingerprint
                    fpr = self.parent.keyring.get_fingerprint(recipient.user)
                    if fpr:
                        pubkey = presence.addElement(('urn:xmpp:pubkey:2', 'pubkey'))
                        fprint = pubkey.addElement((None, 'print'))
                        fprint.addContent(fpr)
                except keyring.KeyNotFoundException:
                    log.warn("key not found for user %s" % (recipient, ))

                if gid:
                    # FIXME this will duplicate group elements - actually in storage there should be no group element!!!
                    group = presence.addElement((xmlstream2.NS_XMPP_STANZA_GROUP, 'group'))
                    group['id'] = gid
                    group['count'] = str(i)
                    i -= 1

                self.send(presence)
                return True

        # no such user
        return False

    def onProbe(self, stanza):
        """Handle presence probes."""

        if stanza.consumed:
            return

        log.debug("probe request: %s" % (stanza.toXml(), ))
        stanza.consumed = True
        to = jid.JID(stanza['to'])
        sender = jid.JID(stanza['from'])

        # are we probing a user we have blocked?
        if self.parent.is_presence_allowed(to, sender) == -1:
            log.debug("probing blocked user, bouncing error")
            e = error.StanzaError('not-acceptable', 'cancel')
            errstanza = e.toResponse(stanza)
            errstanza.error.addElement((xmlstream2.NS_IQ_BLOCKING_ERRORS, 'blocked'))
            self.send(errstanza)

        elif self.parent.is_presence_allowed(sender, to) == 1:
            gid = stanza.getAttribute('id')
            if not self.send_user_presence(gid, sender, to):
                response = xmlstream.toResponse(stanza, 'error')
                # TODO include error cause?
                self.send(response)

    def user_available(self, stanza):
        """Called when receiving a presence stanza."""
        userid = util.jid_user(stanza['from'])

        try:
            stub = self.presence_cache[userid]
            stub.push(stanza)
        except KeyError:
            stub = PresenceStub.fromElement(stanza)
            self.presence_cache[userid] = stub

    def user_unavailable(self, stanza):
        """Called when receiving a presence unavailable stanza."""
        ujid = jid.JID(stanza['from'])

        try:
            stub = self.presence_cache[ujid.user]
            if ujid.resource:
                stub.pop(ujid.resource)
            else:
                # update stub data if stanza is more recent
                stub.update(stanza)
        except KeyError:
            # user not found in cache -- shouldn't happen!!
            stub = PresenceStub.fromElement(stanza)
            self.presence_cache[ujid.user] = stub

    def network_presence_probe(self, to):
        """
        Broadcast a presence probe to find the given L{JID}.
        @return: a list of stanza IDs sent to the network that can be watched to
        for responses
        """
        """
        presence = domish.Element((None, 'presence'))
        presence['type'] = 'probe'
        presence['from'] = self.parent.network
        idList = []
        #to = jid.JID(tuple=(to.user, to.host, to.resource))
        for server in self.parent.keyring.hostlist():
            #to.host = server
            presence['to'] = to.user + '@' + server
            if to.resource:
                presence['to'] += '/' + to.resource
            presence.addUniqueId()
            #presence['id'] = util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
            self.send(presence)
            idList.append(presence['id'])
        """
        # we need to be fast here
        idList = []
        presence = "<presence type='probe' from='%s' to='%%s' id='%%s'/>" % (self.parent.network, )
        for server in self.parent.keyring.hostlist():
            packetId = util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
            dest = to.user + '@' + server
            if to.resource:
                dest += '/' + to.resource
            self.send(presence % (dest, packetId))
            idList.append(packetId)

        return idList

    def find(self, _jid, wait_factor=1.0):
        """
        Send a presence probe to the network and wait for responses.
        @return a L{Deferred} which will be fired with the JID of the probed
        entity.
        """
        idList = self.network_presence_probe(_jid)
        def _presence(stanza, callback, timeout, buf):
            # presence probe error - finish here
            if stanza.getAttribute('type') == 'error':
                # TODO duplicated code
                self.xmlstream.removeObserver("/presence/group[@id='%s']" % (stanza['id'], ), _presence)
                self.xmlstream.removeObserver("/presence[@type='error'][@id='%s']" % (stanza['id'], ), _presence)
                if not callback.called:
                    # cancel timeout
                    timeout.cancel()
                    # fire deferred
                    callback.callback(buf)
                return

            sender = jid.JID(stanza['from'])
            log.debug("JID %s found!" % (sender.full(), ))
            stanza.consumed = True
            buf.append(sender)

            chain = stanza.group
            # end of presence chain!!!
            if not chain or int(chain['count']) == len(buf):
                # TODO duplicated code
                self.xmlstream.removeObserver("/presence/group[@id='%s']" % (stanza['id'], ), _presence)
                self.xmlstream.removeObserver("/presence[@type='error'][@id='%s']" % (stanza['id'], ), _presence)
                if not callback.called:
                    # cancel timeout
                    timeout.cancel()
                    # fire deferred
                    callback.callback(buf)

        def _abort(stanzaId, callback, buf):
            #log.debug("presence broadcast request timed out!")
            self.xmlstream.removeObserver("/presence/group[@id='%s']" % (stanzaId, ), _presence)
            self.xmlstream.removeObserver("/presence[@type='error'][@id='%s']" % (stanzaId, ), _presence)
            if not callback.called:
                #callback.errback(failure.Failure(internet_error.TimeoutError()))
                callback.callback(buf if len(buf) > 0 else None)

        deferList = []
        for stanzaId in idList:
            d = defer.Deferred()
            deferList.append(d)
            # this will contain presence probe hits for this JID
            buf = []

            # timeout of request
            timeout = reactor.callLater(self.MAX_LOOKUP_TIMEOUT*wait_factor*len(idList), _abort, stanzaId=stanzaId, callback=d, buf=buf)

            # add stanza group observer
            self.xmlstream.addObserver("/presence/group[@id='%s']" % (stanzaId, ), _presence, 150, callback=d, timeout=timeout, buf=buf)
            # routing error observer
            self.xmlstream.addObserver("/presence[@type='error'][@id='%s']" % (stanzaId, ), _presence, 150, callback=d, timeout=timeout, buf=buf)

        # gather all returned presence from the network
        return defer.gatherResults(deferList, True)

    def jid_available(self, _jid):
        """Return true if L{JID} has an available resource."""
        try:
            return self.presence_cache[_jid.user].available()
        except:
            pass

        return False

    def lookup(self, _jid):
        try:
            return self.presence_cache[_jid.user]
        except:
            pass


class PrivacyListHandler(XMPPHandler):
    """
    Handle IQ urn:xmpp:blocking stanzas.
    @type parent: L{Resolver}
    """

    """
    TODO this needs some versioning or timestamping. When receiving a new privacy
    list, it will have a timestamp to indicate its versioning. The most recent
    will take precedence.
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/iq[@type='set']/blocklist[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.blacklist, 100)
        self.xmlstream.addObserver("/iq[@type='set']/whitelist[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.whitelist, 100)
        self.xmlstream.addObserver("/stanza/iq[@type='set']/whitelist[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING, ), self.parent.wrapped, 600, fn=self.whitelist)
        self.xmlstream.addObserver("/iq[@type='set']/allow[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.allow, 100)
        self.xmlstream.addObserver("/stanza/iq[@type='set']/allow[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING, ), self.parent.wrapped, 600, fn=self.allow)
        self.xmlstream.addObserver("/iq[@type='set']/unallow[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.unallow, 100)
        self.xmlstream.addObserver("/iq[@type='set']/block[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.block, 100)
        self.xmlstream.addObserver("/iq[@type='set']/unblock[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.unblock, 100)
        self.xmlstream.addObserver("/iq[@type='get']/blocklist[@xmlns='%s']" % (xmlstream2.NS_IQ_BLOCKING), self.get_blacklist, 100)

    def get_blacklist(self, stanza):
        iq = xmlstream.toResponse(stanza, 'result')
        iq['to'] = stanza['from']
        blocklist = iq.addElement((xmlstream2.NS_IQ_BLOCKING, 'blocklist'))

        wl = self.parent.get_blacklist(jid.JID(stanza['from']))
        if wl:
            for item in wl:
                elem = blocklist.addElement((None, 'item'))
                elem['jid'] = item

        self.send(iq)

    def _blacklist(self, jid_from, items, remove=False, broadcast=True):
        if remove:
            fn = self.parent.remove_blacklist
        else:
            fn = self.parent.add_blacklist

        for it in items:
            jid_to = jid.JID(it['jid'])
            fn(jid_from, jid_to, broadcast)

    def _whitelist(self, jid_from, items, remove=False, broadcast=True):
        if remove:
            fn = self.parent.remove_whitelist
        else:
            fn = self.parent.add_whitelist

        for it in items:
            jid_to = jid.JID(it['jid'])
            fn(jid_from, jid_to, broadcast)

    def blacklist(self, stanza):
        jid_from = jid.JID(stanza['from'])
        items = stanza.blocklist.elements(uri=xmlstream2.NS_IQ_BLOCKING, name='item')
        if items:
            # FIXME shouldn't we replace instead of just adding?
            self._blacklist(jid_from, items, broadcast=False)

        self.parent.result(stanza)

    def whitelist(self, stanza, sender=None):
        jid_from = jid.JID(stanza['from'])
        items = stanza.whitelist.elements(uri=xmlstream2.NS_IQ_BLOCKING, name='item')
        if items:
            # FIXME shouldn't we replace instead of just adding?
            self._whitelist(jid_from, items, broadcast=False)

        if not sender:
            self.parent.result(stanza)

    def allow(self, stanza, sender=None):
        jid_from = jid.JID(stanza['from'])
        broadcast = (jid_from.host == util.component_jid(self.parent.servername, util.COMPONENT_C2S))
        items = stanza.allow.elements(uri=xmlstream2.NS_IQ_BLOCKING, name='item')
        if items:
            self._whitelist(jid_from, items, broadcast=broadcast)

        if broadcast:
            self.parent.result(stanza)

    def unallow(self, stanza):
        jid_from = jid.JID(stanza['from'])
        broadcast = (jid_from.host == util.component_jid(self.parent.servername, util.COMPONENT_C2S))
        items = stanza.unallow.elements(uri=xmlstream2.NS_IQ_BLOCKING, name='item')
        if items:
            self._whitelist(jid_from, items, True, broadcast=broadcast)

        if broadcast:
            self.parent.result(stanza)

    def block(self, stanza):
        jid_from = jid.JID(stanza['from'])
        broadcast = (jid_from.host == util.component_jid(self.parent.servername, util.COMPONENT_C2S))
        items = stanza.block.elements(uri=xmlstream2.NS_IQ_BLOCKING, name='item')
        if items:
            self._blacklist(jid_from, items, broadcast=broadcast)

        if broadcast:
            self.parent.result(stanza)

    def unblock(self, stanza):
        jid_from = jid.JID(stanza['from'])
        broadcast = (jid_from.host == util.component_jid(self.parent.servername, util.COMPONENT_C2S))
        items = stanza.unblock.elements(uri=xmlstream2.NS_IQ_BLOCKING, name='item')
        if items:
            self._blacklist(jid_from, items, True, broadcast=broadcast)

        if broadcast:
            self.parent.result(stanza)


class PresenceHandler(XMPPHandler):
    """
    Handle presence stanzas.
    @ivar parent: resolver instance
    @type parent: L{Resolver}
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence[not(@type)]", self.onPresenceAvailable, 100)
        self.xmlstream.addObserver("/presence[@type='unavailable']", self.onPresenceUnavailable, 100)

    def onPresenceAvailable(self, stanza):
        """Handle available presence stanzas."""

        if stanza.consumed:
            return

        try:
            # initial presence from a remote resolver
            component, host = util.jid_component(stanza['from'], util.COMPONENT_C2S)

            if host != self.parent.servername and host in self.parent.keyring.hostlist():
                self.send_privacy_lists('blocklist', self.parent.blacklists, stanza['from'])
                self.send_privacy_lists('whitelist', self.parent.whitelists, stanza['from'])

        except:
            pass

        self.parent.broadcastSubscribers(stanza)

    def send_privacy_lists(self, pname, plist, addr_from):
        sender = util.component_jid(self.parent.servername, util.COMPONENT_C2S)
        for user, wl in plist.iteritems():
            iq = domish.Element((None, 'iq'))
            iq['from'] = '%s@%s' % (user, self.parent.network)
            iq['type'] = 'set'
            iq['id'] = util.rand_str(8)
            iq['to'] = addr_from
            allow = iq.addElement((xmlstream2.NS_IQ_BLOCKING, pname))

            for item in wl:
                elem = allow.addElement((None, 'item'))
                elem['jid'] = item

            self.parent.send_wrapped(iq, sender)

    def onPresenceUnavailable(self, stanza):
        """Handle unavailable presence stanzas."""

        if stanza.consumed:
            return

        user = jid.JID(stanza['from'])
        # forget any subscription requested by this user
        self.parent.cancelSubscriptions(self.parent.translateJID(user))
        # broadcast presence
        self.parent.broadcastSubscribers(stanza)


class ResolverMixIn():

    _protocolHandlers = (
        JIDCache,
        PrivacyListHandler,
        PresenceHandler,
    )
    """
    IQHandler,
    """

    WHITELIST = 1
    BLACKLIST = 2

    PERSIST_INTERVAL = 10
    PERSIST_STORAGE = "privacy_lists.db"

    def __init__(self):
        self.servername = None
        self.network = None
        self.keyring = None
        self.cache = None

        # active subscriptions
        self.subscriptions = {}
        # whitelists
        self.whitelists = {}
        # blacklists
        self.blacklists = {}

        # resolver handlers
        for handler in self._protocolHandlers:
            inst = handler()
            if handler == JIDCache:
                self.cache = inst
            inst.setHandlerParent(self)

    def _load_privacy_lists(self):
        try:
            with open(self.PERSIST_STORAGE, 'r') as f:
                import cPickle
                data = cPickle.load(f)
            self.whitelists = data['whitelists']
            self.blacklists = data['blacklists']
        except:
            log.warn("unable to load privacy lists")
            import traceback
            traceback.print_exc()

    def _save_privacy_lists(self):
        try:
            with open(self.PERSIST_STORAGE, 'w+') as f:
                import cPickle
                data = {
                    'whitelists': self.whitelists,
                    'blacklists': self.blacklists,
                }
                cPickle.dump(data, f)
        except:
            # ignore errors
            pass

    def startService(self):
        ### privacy lists persistent storage (very temporary method) ###
        # load privacy lists
        self._load_privacy_lists()
        # schedule save to storage
        task.LoopingCall(self._save_privacy_lists).start(self.PERSIST_INTERVAL, now=False)

    def _authd(self, xs):
        # bind to network route
        bind = domish.Element((None, 'bind'))
        bind['name'] = self.network
        bind.addElement((None, 'private'))
        xs.send(bind)

    def send(self, stanza):
        pass

    def send_wrapped(self, stanza, sender, destination=None):
        """
        Wraps the given stanza in a <stanza/> stanza intended to the given
        recipient. If recipient is None, the "to" of the original stanza is used.
        """
        envelope = domish.Element((None, 'stanza'))
        envelope['from'] = sender
        envelope['to'] = destination if destination else stanza['to']
        envelope.addChild(stanza)
        self.send(envelope)

    def translateJID(self, _jid, resource=True):
        """
        Translate a server JID (user@component.prime.kontalk.net) into a network JID
        (user@kontalk.net).
        """
        # TODO ehm :D
        try:
            unused, host = util.jid_component(_jid.host)
            if host in self.keyring.hostlist():
                return jid.JID(tuple=(_jid.user, self.network, _jid.resource if resource else None))
        except ValueError:
            pass

        return _jid if resource else _jid.userhostJID()

    def cancelSubscriptions(self, user):
        """Cancel all subscriptions requested by the given user."""
        for rlist in self.subscriptions.itervalues():
            for sub in list(rlist):
                if sub == user:
                    rlist.remove(sub)

    def subscribe(self, jid_from, jid_to, gid=None, send_subscribed=True):
        if jid_to.host == self.network and not self.cache.lookup(jid_to):
            log.debug("user %s not found, rejecting subscription request" % (jid_to, ))
            # no point in proceeding if user does not exists
            return False

        allowed = self.is_presence_allowed(jid_from, jid_to)

        if allowed == 1:
            self.doSubscribe(jid_to, jid_from, gid, send_subscribed=send_subscribed)
        elif allowed == -1:
            log.debug("user is blacklisted, ignoring request")
        else:
            log.debug("not authorized to subscribe to user's presence, sending request")
            try:
                stanza = domish.Element((None, 'presence'))
                stanza['type'] = 'subscribe'
                stanza['from'] = jid_from.full()
                stanza['to'] = jid_to.full()

                fpr = self.keyring.get_fingerprint(jid_from.user)
                keydata = self.keyring.get_key(jid_from.user, fpr)
                pubkey = stanza.addElement(('urn:xmpp:pubkey:2', 'pubkey'))

                # key data
                key = pubkey.addElement((None, 'key'))
                key.addContent(base64.b64encode(keydata))

                # fingerprint
                fprint = pubkey.addElement((None, 'print'))
                fprint.addContent(fpr)

                self.send(stanza)
            except:
                import traceback
                traceback.print_exc()
                return False

        return True

    def doSubscribe(self, to, subscriber, gid=None, response_only=False, send_subscribed=True):
        """Subscribe a given user to events from another one."""

        if not response_only:
            try:
                if subscriber not in self.subscriptions[to]:
                    self.subscriptions[to].append(subscriber)
            except:
                self.subscriptions[to] = [subscriber]

        if send_subscribed:
            # send subscription accepted immediately
            pres = domish.Element((None, "presence"))
            if gid:
                pres['id'] = gid
            pres['to'] = subscriber.full()
            pres['from'] = to.userhost()
            pres['type'] = 'subscribed'
            self.send(pres)

        if not response_only:
            # simulate a presence probe response
            if not gid:
                gid = util.rand_str(8)
            self.cache.send_user_presence(gid, subscriber, to)

        """
        # send a fake roster entry
        roster = domish.Element((None, 'iq'))
        roster['type'] = 'set'
        roster['to'] = subscriber.full()
        query = domish.Element((xmlstream2.NS_IQ_ROSTER, 'query'))
        query.addChild(domish.Element((None, 'item'), attribs={
            'jid'           : to.userhost(),
            'subscription'  : 'both',
        }))
        roster.addChild(query)
        self.send(roster)
        """

    def unsubscribe(self, to, subscriber):
        """Unsubscribe a given user from events from another one."""
        try:
            self.subscriptions[to].remove(subscriber)

            # clean up
            if len(self.subscriptions[to]) == 0:
                del self.subscriptions[to]
        except:
            pass

    def broadcastSubscribers(self, stanza):
        """Broadcast stanza to JID subscribers."""

        user = jid.JID(stanza['from'])

        try:
            unused, host = util.jid_component(user.host)

            # FIXME wrong host check (this is a one of the causes of the invalid-from bug)
            if host in self.keyring.hostlist():
                # local or network user: translate host name
                watched = jid.JID(tuple=(user.user, self.network, user.resource))
            else:
                # other JIDs, use unchanged
                watched = user

        except ValueError:
            # other JIDs, use unchanged
            watched = user

        bareWatched = watched.userhostJID()
        if bareWatched in self.subscriptions:
            #stanza['from'] = watched.full()

            removed = []
            for sub in self.subscriptions[bareWatched]:
                if self.is_presence_allowed(sub, watched) == 1:
                    log.debug("notifying subscriber %s" % (sub, ))
                    stanza['to'] = sub.userhost()
                    self.send(stanza)
                else:
                    log.debug("%s is not allowed to see presence" % (sub, ))
                    removed.append(sub)

            # remove unauthorized users
            for e in removed:
                self.subscriptions[bareWatched].remove(e)

    def _broadcast_privacy_list_change(self, dest, src, node):
        # broadcast to all resolvers
        iq = domish.Element((None, 'iq'))
        iq['from'] = dest
        iq['type'] = 'set'
        iq['id'] = util.rand_str(8)
        nodeElement = iq.addElement((xmlstream2.NS_IQ_BLOCKING, node))
        elem = nodeElement.addElement((None, 'item'))
        elem['jid'] = src

        from_component = util.component_jid(self.servername, util.COMPONENT_C2S)
        for server in self.keyring.hostlist():
            if server != self.servername:
                iq['to'] = util.component_jid(server, util.COMPONENT_C2S)
                self.send_wrapped(iq, from_component)

    def _privacy_list_add(self, jid_to, jid_from, list_type, broadcast=True):
        if list_type == self.WHITELIST:
            node = 'allow'
            data = self.whitelists
        elif list_type == self.BLACKLIST:
            node = 'block'
            data = self.blacklists

        try:
            wl = data[jid_to.user]
        except KeyError:
            wl = data[jid_to.user] = set()

        src = self.translateJID(jid_to, False).userhost()
        dest = self.translateJID(jid_from, False).userhost()

        wl.add(dest)

        # broadcast to all resolvers
        if broadcast:
            self._broadcast_privacy_list_change(src, dest, node)

    def _privacy_list_remove(self, jid_to, jid_from, list_type, broadcast=True):
        if list_type == self.WHITELIST:
            node = 'unallow'
            data = self.whitelists
        elif list_type == self.BLACKLIST:
            node = 'unblock'
            data = self.blacklists

        if jid_to.user in data:
            wl = data[jid_to.user]

            src = self.translateJID(jid_to, False).userhost()
            dest = self.translateJID(jid_from, False).userhost()

            wl.discard(dest)

            # broadcast to all resolvers
            if broadcast:
                self._broadcast_privacy_list_change(src, dest, node)

    def add_blacklist(self, jid_to, jid_from, broadcast=True):
        """Adds jid_from to jid_to's blacklist."""
        self._privacy_list_add(jid_to, jid_from, self.BLACKLIST, broadcast)

    def add_whitelist(self, jid_to, jid_from, broadcast=True):
        """Adds jid_from to jid_to's whitelist."""
        self._privacy_list_add(jid_to, jid_from, self.WHITELIST, broadcast)

    def remove_blacklist(self, jid_to, jid_from, broadcast=True):
        """Removes jid_from from jid_to's blacklist."""
        self._privacy_list_remove(jid_to, jid_from, self.BLACKLIST, broadcast)

    def remove_whitelist(self, jid_to, jid_from, broadcast=True):
        """Removes jid_from from jid_to's whitelist."""
        self._privacy_list_remove(jid_to, jid_from, self.WHITELIST, broadcast)

    def get_whitelist(self, _jid):
        try:
            return self.whitelists[_jid.user]
        except KeyError:
            return None

    def get_blacklist(self, _jid):
        try:
            return self.blacklists[_jid.user]
        except KeyError:
            return None

    def is_presence_allowed(self, jid_from, jid_to):
        """
        Checks if requester (from) is allowed to see a user's (to) presence.
        @return 1 if allowed, 0 if not allowed, -1 if blacklisted, -2 if user not found
        """

        if not self.cache.lookup(jid_to):
            return -2

        # servers are allowed to subscribe to user presence
        if not jid_from.user:
            return 1

        # translate to network JID first
        jid_from = self.translateJID(jid_from, False)
        translated_to = self.translateJID(jid_to, False)

        # talking to ourselves :)
        if jid_from == translated_to:
            return 1

        # blacklist has priority
        try:
            bl = self.blacklists[jid_to.user]
            if jid_from.userhost() in bl:
                return -1

        except KeyError:
            # blacklist not present for user - go ahead
            pass

        try:
            wl = self.whitelists[jid_to.user]
            if jid_from.userhost() in wl:
                return 1

        except KeyError:
            # whitelist not present for the user - not authorized
            pass

        return 0

    def local_presence(self, user, stanza):
        if user.user:
            if stanza.getAttribute('type') == 'unavailable':
                self.cache.user_unavailable(stanza)
                # forget any subscription requested by this user
                self.cancelSubscriptions(self.translateJID(user))
                # broadcast presence
                self.broadcastSubscribers(stanza)
            else:
                self.cache.user_available(stanza)
                self.broadcastSubscribers(stanza)

    def wrapped(self, stanza, fn):
        if stanza.getAttribute('type') != 'error':
            fn(stanza.firstChildElement(), stanza['from'])
