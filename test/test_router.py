
import unittest
import demjson

from twisted.words.protocols.jabber import jid, xmlstream

from kontalk.xmppserver.component.router import Router
from kontalk.xmppserver import log, util


class TestRouter(unittest.TestCase):

    def setUp(self):
        # load configuration
        self.loadConfiguration('../router.conf')
        # init logging
        log.init(self.config)
        # create router
        self.router = Router()

    def loadConfiguration(self, filename):
        # load configuration
        fp = open(filename, 'r')
        self.config = demjson.decode(fp.read(), allow_comments=True)
        fp.close()

    def tearDown(self):
        pass


    def testConnect(self):
        """Tests the connection from a component."""
        xs = xmlstream.XmlStream(xmlstream.Authenticator())
        self.router.addRoute("resolver.prime.kontalk.net", xs)

        routes = { "resolver.prime.kontalk.net" : xs }
        self.assertDictEqual(self.router.routes, routes, "Routes not matching.")

    def testRoute(self):
        """Tests stanza routing."""
        pass

    def testBind(self):
        """Tests additional name bindings."""
        pass


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
