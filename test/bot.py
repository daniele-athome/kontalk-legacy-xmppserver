#!/usr/bin/env python
# Testing bot for Kontalk XMPP


from twisted.internet import reactor
from twisted.words.xish import domish
from twisted.words.protocols.jabber import jid, xmlstream, client

from wokkel import xmppim

import sys, time, demjson, base64, gpgme, gpgme.editutil

try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

from kontalk.xmppserver import util, xmlstream2
import bot_utils


class Handler:
    def __init__(self, config):
        self.config = config
        self._stats = {}

    def print_stats(self):
        print
        print "%-30s %5s" % ('key', 'value')
        print '-'*36
        for k, v in self._stats.iteritems():
            print "%-30s %5d" % (k, v)

    def authenticated(self):
        """Server just authenticated us."""
        pass

    def ready(self):
        """Client just sent initial presence."""

        print "Now available."
        """
        TEST conflict stress test
        def dummy():
            self.client.send(domish.Element((None, 'presence')))
            reactor.callLater(0, dummy)
        reactor.callLater(0, dummy)
        """

        for action in self.config['actions']:
            name = action['name']
            del action['name']
            try:
                timeout = action['timeout']
                del action['timeout']
            except:
                timeout = -1
            try:
                fn = getattr(self, name)
                if timeout >= 0:
                    reactor.callLater(timeout, fn, **action)
                else:
                    fn(**action)
            except:
                import traceback
                traceback.print_exc()

    def message(self, stanza):
        """Message stanza received."""

        #print "message from %s" % (stanza['from'], )
        if type(self.config['behavior']['ack']) == int:
            delay = self.config['behavior']['ack']
            if stanza.getAttribute('type') == 'chat':
                if stanza.request and stanza.request.uri == 'urn:xmpp:server-receipts':
                    self.stats('messages:incoming')

                    def sendReceipt(stanza):
                        receipt = domish.Element((None, 'message'))
                        receipt['type'] = 'chat'
                        receipt['to'] = stanza['from']
                        child = receipt.addElement(('urn:xmpp:server-receipts', 'received'))
                        child['id'] = stanza.request['id']
                        self.client.send(receipt)
                        self.stats('messages:confirmed')
                    reactor.callLater(delay, sendReceipt, stanza)

                # received ack
                elif stanza.received and stanza.received.uri == 'urn:xmpp:server-receipts':
                    ack = domish.Element((None, 'message'))
                    ack['to'] = stanza['from']
                    ack['type'] = 'chat'
                    child = ack.addElement(('urn:xmpp:server-receipts', 'ack'))
                    child['id'] = stanza['id']
                    self.client.send(ack)
                    self.stats('messages:delivered')

                elif stanza.sent and stanza.sent.uri == 'urn:xmpp:server-receipts':
                    self.stats('messages:sent')

    def presence(self, stanza):
        """Presence stanza received."""
        ptype = stanza.getAttribute('type')
        if ptype == 'subscribe':
            self.client.send(xmlstream.toResponse(stanza, 'subscribed'))

    def iq(self, stanza):
        """IQ stanza received."""
        pass

    def stats(self, key, inc=1):
        if not key in self._stats:
            self._stats[key] = inc
        else:
            self._stats[key] += inc

    def sendTextMessage(self, peer, content, request=False, delay=0):
        """Sends a text message with an optional receipt request."""

        def _send():
            _jid = self.client.xmlstream.authenticator.jid
            message = domish.Element((None, 'message'))
            message['id'] = 'kontalk' + util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
            message['type'] = 'chat'
            if peer:
                message['to'] = peer
            else:
                message['to'] = _jid.userhost()
            message.addElement((None, 'body'), content=content)
            if request:
                message.addElement(('urn:xmpp:server-receipts', 'request'))
            self.client.send(message)
            self.stats('messages:outgoing')
            if request:
                self.stats('messages:pending')
            else:
                self.stats('messages:sent')
        reactor.callLater(delay, _send)

    def messageLoop(self, peer, contentFmt='%d', request=False, delay=0, count=0):
        self._loopCount = 0
        self._loopAckCount = 0
        self._loopStart = time.time()
        def _stats(stanza):
            self._loopAckCount += 1
            if self._loopAckCount >= count:
                # remove observer
                self.client.xmlstream.removeObserver("/message/received", _stats)
                diff = time.time() - self._loopStart
                self.stats('messages:loopsPerSecond', self._loopAckCount / diff)
                print "%d loops in %.2f seconds" % (self._loopAckCount, diff)
                print "messages: %.2f loops/second" % (self._loopAckCount / diff, )

        def _count():
            self._loopCount += 1
            if self._loopCount < count:
                reactor.callLater(delay, _count)
            self.sendTextMessage(peer, contentFmt % (self._loopCount, ), request)

        # WARNING this is very specific to this method
        self.client.xmlstream.addObserver("/message/received", _stats)
        reactor.callLater(delay, _count)

    def bounceIncrement(self, peer, request=False, begin=False, delay=0, count=0):
        self._bounceIncStart = time.time()
        self._bounceIncAvg = 0
        self._bounceCount = 0
        def _count(stanza):
            try:
                i = int(str(stanza.body))
                if count > 0 and i < count:
                    self._bounceIncAvg += (time.time() - self._bounceIncStart)
                    self._bounceCount += 1
                    reactor.callLater(delay, self.sendTextMessage, peer, str(i+1), request)
                else:
                    self.stats('messages:bouncesPerSecond', self._bounceIncAvg / self._bounceCount)
            except:
                pass
        self.client.xmlstream.addObserver("/message", _count)

        if begin:
            self.sendTextMessage(peer, "1", request)

    def randomRoster(self, delay=0):
        def _count():
            global count, num
            num = 400
            count = 0
            def _presence(stanza):
                global count, num
                count += 1
                if count >= 400:
                    print 'received all presence'
            self.client.xmlstream.addObserver('/presence', _presence)

            _jid = jid.JID(tuple=(None, self.client.network, None))
            r = domish.Element((None, 'iq'))
            r.addUniqueId()
            r['type'] = 'get'
            q = r.addElement((xmppim.NS_ROSTER, 'query'))
            for n in range(num):
                _jid.user = util.rand_str(util.USERID_LENGTH, util.CHARSBOX_HEX_LOWERCASE)
                item = q.addElement((None, 'item'))
                item['jid'] = _jid.userhost()
            self.client.send(r)

        reactor.callLater(delay, _count)

    def roster(self, peers, delay=0):
        def _count():
            r = domish.Element((None, 'iq'))
            r.addUniqueId()
            r['type'] = 'get'
            q = r.addElement((xmppim.NS_ROSTER, 'query'))
            for n in peers:
                _jid = jid.JID(n)
                item = q.addElement((None, 'item'))
                item['jid'] = _jid.userhost()
            self.client.send(r)

        reactor.callLater(delay, _count)

    def probe(self, peer, delay=0):
        def _probe():
            p = xmppim.ProbePresence(jid.JID(peer))
            self.client.send(p.toElement())

        reactor.callLater(delay, _probe)

    def subscribe(self, peer, delay=0):
        def _probe():
            p = xmppim.SubscriptionPresence(jid.JID(peer))
            p.stanzaType = 'subscribe'
            self.client.send(p.toElement())

        reactor.callLater(delay, _probe)

    def registerRequest(self, delay=0):
        reg = client.IQ(self.client.xmlstream, 'get')
        reg.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))
        reg.send(self.client.network)

    def register(self, delay=0):
        reg = client.IQ(self.client.xmlstream, 'set')
        query = reg.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))
        form = query.addElement(('jabber:x:data', 'x'))
        form['type'] = 'submit'

        hidden = form.addElement((None, 'field'))
        hidden['type'] = 'hidden'
        hidden['var'] = 'FORM_TYPE'
        hidden.addElement((None, 'value'), content=xmlstream2.NS_IQ_REGISTER)

        phone = form.addElement((None, 'field'))
        phone['type'] = 'text-single'
        phone['label'] = 'Phone number'
        phone['var'] = 'phone'
        phone.addElement((None, 'value'), content='+39123456')

        reg.send(self.client.network)

    def validate(self, code, publickey, delay=0):
        reg = client.IQ(self.client.xmlstream, 'set')
        query = reg.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))
        form = query.addElement(('jabber:x:data', 'x'))
        form['type'] = 'submit'

        hidden = form.addElement((None, 'field'))
        hidden['type'] = 'hidden'
        hidden['var'] = 'FORM_TYPE'
        hidden.addElement((None, 'value'), content='http://kontalk.org/protocol/register#code')

        vcode = form.addElement((None, 'field'))
        vcode['type'] = 'text-single'
        vcode['label'] = 'Validation code'
        vcode['var'] = 'code'
        vcode.addElement((None, 'value'), content=code)

        pkey = form.addElement((None, 'field'))
        pkey['type'] = 'text-single'
        pkey['label'] = 'Public key'
        pkey['var'] = 'publickey'
        pkey.addElement((None, 'value'), content=publickey)

        reg.send(self.client.network)
        #reactor.callLater(1, xs.reset)

    def vcardSet(self, publickey=None):
        if not publickey:
            publickey = self.config['publickey']['key']

        iq = client.IQ(self.client.xmlstream, 'set')
        vcard = iq.addElement((xmlstream2.NS_XMPP_VCARD4, 'vcard'))
        vcard_key = vcard.addElement((None, 'key'))
        vcard_data = vcard_key.addElement((None, 'uri'))
        vcard_data.addContent("data:application/pgp-keys;base64," + publickey)

        iq.send(self.client.xmlstream.authenticator.jid.userhost())

    def vcardGet(self, peer):
        iq = client.IQ(self.client.xmlstream, 'get')
        iq.addElement((xmlstream2.NS_XMPP_VCARD4, 'vcard'))
        iq.send(peer)

    def blockUser(self, peer, delay=0):
        def _execute():
            iq = client.IQ(self.client.xmlstream, 'set')
            block = iq.addElement((xmlstream2.NS_IQ_BLOCKING, 'block'))
            item = block.addElement((None, 'item'))
            item['jid'] = peer
            iq.send()

        reactor.callLater(delay, _execute)

    def requestBlocklist(self, delay=0):
        def _execute():
            iq = client.IQ(self.client.xmlstream, 'get')
            iq.addElement((xmlstream2.NS_IQ_BLOCKING, 'blocklist'))
            iq.send()

        reactor.callLater(delay, _execute)

    def serverlist(self, delay=0):
        def _execute():
            iq = client.IQ(self.client.xmlstream, 'set')
            cmd = iq.addElement((xmlstream2.NS_PROTO_COMMANDS, 'command'))
            cmd['node'] = 'serverlist'
            cmd['action'] = 'execute'
            iq.send()

        reactor.callLater(delay, _execute)

    def unavailable(self, delay=0):
        def _execute():
            p = domish.Element((None, 'presence'))
            p['type'] = 'unavailable'
            self.client.send(p)
        reactor.callLater(delay, _execute)

    def available(self, delay=0):
        def _execute():
            p = domish.Element((None, 'presence'))
            self.client.send(p)
        reactor.callLater(delay, _execute)

    def discovery(self, delay=0):
        def _execute():
            iq = domish.Element((None, 'iq'))
            iq['to'] = self.client.network
            iq['type'] = 'get'
            iq['id'] = 'disco1'
            iq.addElement((xmlstream2.NS_DISCO_INFO, 'query'))
            self.client.send(iq)
        reactor.callLater(delay, _execute)

    def quit(self):
        self.client.xmlstream.sendFooter()


# load configuration
fp = open(sys.argv[1], 'r')
config = demjson.decode(fp.read(), allow_comments=True)
fp.close()

handler = Handler(config)
c = bot_utils.Client(config, handler)

reactor.run()

# reactor quit, print statistics
handler.print_stats()
