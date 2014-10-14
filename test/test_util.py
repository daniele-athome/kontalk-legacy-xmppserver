
import unittest
import os
import tempfile

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
            'audio/mpeg': 'mp3',
        }
        for mime, ext in mimes.iteritems():
            filename = util.generate_filename(mime)
            self.assertRegexpMatches(filename, 'att[A-Za-z0-9]+\.' + ext)

    def test_md5sum(self):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write('test data')
        f.close()
        data = util.md5sum(f.name)
        self.assertEqual(data, 'eb733a00c0c9d336e65691a37ab54293')
        os.unlink(f.name)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
