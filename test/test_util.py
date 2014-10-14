
import unittest

from kontalk.xmppserver import util


class TestUtil(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_generate_filename(self):
        mimes = {
            'image/png': 'png',
            'image/jpeg': 'jpg',
            'image/gif': 'gif',
            'text/x-vcard': 'vcf',
            'text/vcard': 'vcf',
            'text/plain': 'txt',
            'audio/3gpp': '3gp',
        }
        for mime, ext in mimes.iteritems():
            filename = util.generate_filename(mime)
            self.assertRegexpMatches(filename, 'att[A-Za-z0-9]+\.' + ext)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
