# -*- coding: utf-8 -*-
'''Keyring functions.'''
'''
  Kontalk XMPP server
  Copyright (C) 2011 Kontalk Devteam <devteam@kontalk.org>

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
'''

import base64
import gpgme, gpgme.editutil

from twisted.words.protocols.jabber import jid

try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

import util, log


class Keyring:
    '''Handles all keyring releated functions.'''

    '''Percentages of server signatures needed to obtain privileges.'''
    _privileges = {
        'dht' : (0, 100, 50, 25),
        'token' : (0, 100),
        'messages' : (0, 100)
    }

    def __init__(self, db, fingerprint, network, servername):
        self._db = db
        self.fingerprint = str(fingerprint)
        self.network = network
        self.servername = servername
        self._list = {}

        # gpgme context
        self.ctx = gpgme.Context()
        self.ctx.armor = False
        self.ctx.keylist_mode = gpgme.KEYLIST_MODE_SIGS
        # signing key
        self.ctx.signers = [self.ctx.get_key(self.fingerprint, True)]

        self._reload()

    def itervalues(self):
        '''Wrapper for itervalues() of internal server list.'''
        return self._list.itervalues()

    def _reload(self):
        def done(data):
            self._list = data

        self._db.get_list().addCallback(done)

    def host(self, fingerprint):
        return self._list[fingerprint]

    def get_server_trust(self, fingerprint):
        '''Returns the trust level (ie how many servers trust another) of a given server.'''
        # TODO convert to gpgme
        count = 0
        ctx = core.Context()
        ctx.set_keylist_mode(keymode.SIGS)
        key = ctx.get_key(fingerprint, False)
        for uid in key.uids:
            for sign in uid.signatures:
                skey = ctx.get_key(sign.keyid, False)
                fpr = skey.subkeys[0].fpr
                #print "found signature from %s" % fpr
                #print str(fpr) in self._list.keys()
                #print str(fpr) != fingerprint
                # make sure key is actually in the keyring and the sign is self-made
                if str(fpr) in self._list.keys() and str(fpr) != fingerprint:
                    count += 1

        return count

    def has_privilege(self, fingerprint, priv):
        #print "checking permissions for %s" % fingerprint
        # this is ourself
        if fingerprint == self.fingerprint:
            return True

        # our server isn't in list so it's safe to use this value
        total = len(self._list)
        #print "found %d keys" % total
        # we are alone in the network or we are
        if total <= 0:
            return True

        # key is not in fingerprint
        if fingerprint not in self._list.keys():
            #print "fingerprint not in keyring"
            return False

        privilege = self._privileges[priv]
        if total > len(privilege):
            # take the higher privilege requirement
            need = privilege[-1]
        else:
            need = privilege[total]

        # do not check for signatures
        #print "need %.2f%% signatures" % need
        if need == 0:
            return True

        # get signatures count
        sigs = self.get_server_trust(fingerprint)
        #print "found %d signatures" % (sigs)

        # calculate percentage of signatures on total servers
        perc = sigs/total*100

        # check if percentage is enough
        #print "signatures: %.2f%% out of %.2f%% needed" % (perc, need)
        return perc >= need

    def __len__(self):
        return len(self._list)

    def __iter__(self):
        '''Wrapper for keyring iterator.'''
        return self._list.iterkeys()

    def hostlist(self):
        """List of host servers."""
        return self._list.values()

    def check_token(self, token_data):
        """Checks a Kontalk token. Data must be already base64-decoded."""
        cipher = BytesIO(token_data)
        plain = BytesIO()

        res = self.ctx.verify(cipher, None, plain)
        # check verification result
        if len(res) > 0:
            sign = res[0]
            text = plain.getvalue()
            data = text.split('|', 2)

            # not a valid token
            if len(data) != 2:
                return None

            # length not matching - refused
            userid = data[0]
            if len(userid) != util.USERID_LENGTH_RESOURCE:
                return None

            # compare with own fingerprint
            if sign.fpr.upper() == self.fingerprint.upper():
                return userid

            # no match - compare with keyring
            for rkey in self._list.iterkeys():
                if sign.fpr.upper() == rkey.upper():
                    return userid

    """
    TODO this is not safe. We risk importing unwanted keys and a bunch of other
    security holes. Be sure to use a dedicated GNUPGHOME for this task,
    a copy of the default one to be used as a sandbox.
    """
    def check_key(self, keydata):
        """
        Checks a public key for server signatures.
        @return: JID, fingerprint
        """
        data = BytesIO(keydata)

        result = self.ctx.import_(data)
        # key imported/unchanged, look for our signatures
        if result and (result.imported == 1 or result.unchanged == 1):
            fpr = str(result.imports[0][0])
            key = self.ctx.get_key(fpr, False)
            # take the first uid
            uid = key.uids[0]

            jabberid = jid.JID(uid.email)
            if jabberid.host == self.network:
                jabberid.resource = uid.comment

                for sig in uid.signatures:
                    mkey = self.ctx.get_key(sig.keyid, False)
                    if mkey:
                        fpr = mkey.subkeys[0].fpr.upper()

                        if fpr == self.fingerprint.upper():
                            return (jabberid, key.subkeys[0].fpr)

                        # no direct match - compare with keyring
                        for rkey in self._list.iterkeys():
                            if fpr == rkey.upper():
                                return (jabberid, key.subkeys[0].fpr)

    def check_signature(self, signature, text, fingerprint):
        """
        Checks the given signature against key identified by fingerprint.
        @return: fingerprint
        """
        try:
            cipher = BytesIO(signature)
            plain = BytesIO()

            res = self.ctx.verify(cipher, None, plain)
            # check verification result
            if len(res) > 0:
                sign = res[0]
                cleartext = plain.getvalue()
                if cleartext != text:
                    log.debug("signed text not matching original text")
                    return None

                if sign.fpr != fingerprint:
                    log.debug("fingerprint mismatch")
                    return None

                return fingerprint
        except:
            import traceback
            traceback.print_exc()

        return None

    def sign_public_key(self, keydata, userid):
        try:
            # import key
            result = self.ctx.import_(BytesIO(keydata))
            fp = str(result.imports[0][0])
            keyfp = self.ctx.get_key(fp)

            # check that at least one of the key uids is userid@network
            check = False
            check_email = '%s@%s' % (userid, self.network)
            for uid in keyfp.uids:
                if uid.email == check_email:
                    check = True

            # TODO some other checks?

            if check:
                # sign key
                gpgme.editutil.edit_sign(self.ctx, keyfp, check=0)

                # export signed key
                keydata = BytesIO()
                self.ctx.export(fp, keydata)
                return keydata.getvalue()

        except:
            import traceback
            traceback.print_exc()

    def generate_user_token(self, userid):
        """Generates a user token."""

        """
        A token is made up of the hashed phone number (the user id)
        plus the resource (in one big string, 40+8 characters),
        and the fingerprint of the server he registered to
        """
        fp = str(self.fingerprint)
        string = '%s|%s' % (str(userid), fp)
        plain = BytesIO(string)
        cipher = BytesIO()

        self.ctx.sign(plain, cipher, gpgme.SIG_MODE_NORMAL)
        token = cipher.getvalue()
        return base64.b64encode(token)
