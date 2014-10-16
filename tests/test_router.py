
import unittest
import demjson

from twisted.words.protocols.jabber import jid, xmlstream

from kontalk.xmppserver.component.router import Router
from kontalk.xmppserver import log, util


class TestRouter(unittest.TestCase):

    def setUp(self):
        # load configuration
        self.load_configuration('router.conf')
        # init logging
        log.init(self.config)
        # create router
        self.router = Router()

    def load_configuration(self, filename):
        # load configuration
        fp = open(filename, 'r')
        self.config = demjson.decode(fp.read(), allow_comments=True)
        fp.close()

    def tearDown(self):
        pass

    def test_connect(self):
        """Tests the connection from a component."""
        xs = xmlstream.XmlStream(xmlstream.Authenticator())
        self.router.addRoute("resolver.prime.kontalk.net", xs)

        routes = {"resolver.prime.kontalk.net": xs}
        self.assertDictEqual(self.router.routes, routes, "Routes not matching.")

    def test_route(self):
        """Tests stanza routing."""
        pass

    def test_bind(self):
        """Tests additional name bindings."""
        pass


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
