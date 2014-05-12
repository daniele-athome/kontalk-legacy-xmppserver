
import unittest
import demjson

from twisted.words.protocols.jabber import jid

from kontalk.xmppserver.component.resolver import Resolver
from kontalk.xmppserver import log, util

class TestResolverSubscriptions(unittest.TestCase):

    def setUp(self):
        # load configuration
        self.loadConfiguration('../resolver.conf')
        # init logging
        log.init(self.config)
        # create resolver
        self.resolver = Resolver(self.config)
        # override methods
        self.resolver.is_presence_allowed = self._is_presence_allowed

    def _is_presence_allowed(self, jid_from, jid_to):
        return 1

    def loadConfiguration(self, filename):
        # load configuration
        fp = open(filename, 'r')
        self.config = demjson.decode(fp.read(), allow_comments=True)
        fp.close()

    def tearDown(self):
        pass


    def testSubscribe(self):
        jid_from = jid.JID('user1@c2s.prime.kontalk.net/TEST001')
        jid_to = jid.JID('user2@kontalk.net')
        gid = util.rand_str(8)
        self.resolver.subscribe(self.resolver.translateJID(jid_from),
            self.resolver.translateJID(jid_to), gid, False)

        subscriptions = { jid.JID('user2@kontalk.net') : [ jid.JID('user1@kontalk.net/TEST001') ] }
        self.assertDictEqual(self.resolver.subscriptions, subscriptions, 'Subscriptions not maching.')

    def testUnsubscribe(self):
        # execute subscription first
        self.testSubscribe()

        jid_from = jid.JID('user1@c2s.prime.kontalk.net/TEST001')
        jid_to = jid.JID('user2@kontalk.net')
        self.resolver.unsubscribe(self.resolver.translateJID(jid_to),
            self.resolver.translateJID(jid_from))

        self.assertEqual(len(self.resolver.subscriptions), 0, 'Subscriptions not maching.')

    def testCancelSubscriptions(self):
        # execute subscription first
        self.testSubscribe()

        jid_from = jid.JID('user1@c2s.prime.kontalk.net/TEST001')
        jid_to = jid.JID('user2@kontalk.net')
        self.resolver.cancelSubscriptions(self.resolver.translateJID(jid_from))
        self.assertEqual(len(self.resolver.subscriptions[jid_to]), 0, 'Subscriptions not maching.')


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
