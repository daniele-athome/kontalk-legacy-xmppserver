from twisted.words.protocols.jabber.jid import JID
import unittest
import os
import tempfile

from kontalk.xmppserver import util


class TestUtil(unittest.TestCase):
    def test_split_userid(self):
        userid = '4bdd4f929f3a1062253e4e496bafba0bdfb5db75ABCDEFGH'
        splitted = util.split_userid(userid)
        self.assertTupleEqual(splitted, ('4bdd4f929f3a1062253e4e496bafba0bdfb5db75', 'ABCDEFGH'))

    def test_jid_to_userid(self):
        jid = JID('user@localhost.localdomain/resource')
        userid = util.jid_to_userid(jid, splitted=False)
        self.assertEqual(userid, 'userresource')
        userid = util.jid_to_userid(jid, splitted=True)
        self.assertTupleEqual(userid, ('user', 'resource'))

    def test_userid_to_jid(self):
        jid = util.userid_to_jid('4bdd4f929f3a1062253e4e496bafba0bdfb5db75ABCDEFGH', 'localhost')
        self.assertEqual(jid.user, '4bdd4f929f3a1062253e4e496bafba0bdfb5db75')
        self.assertEqual(jid.host, 'localhost')
        self.assertEqual(jid.resource, 'ABCDEFGH')

    def test_sha1(self):
        text = 'test data'
        data = util.sha1(text)
        self.assertEqual(data, 'f48dd853820860816c75d54d0f584dc863327a7c')

    def test_jid_user(self):
        jidstring = 'user@localhost.localdomain/resource'
        user = util.jid_user(jidstring)
        self.assertEqual(user, 'user')

    def test_jid_host(self):
        jidstring = 'user@localhost.localdomain/resource'
        user = util.jid_host(jidstring)
        self.assertEqual(user, 'localhost.localdomain')

    def test_component_jid(self):
        host = 'localhost.localdomain'
        component = 'c2s'
        data = util.component_jid(host, component)
        self.assertEqual(data, 'c2s.localhost.localdomain')

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
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
