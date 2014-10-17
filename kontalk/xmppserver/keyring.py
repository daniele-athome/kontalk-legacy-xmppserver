# -*- coding: utf-8 -*-
"""Keyring functions."""
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

import base64
import gpgme, gpgme.editutil

from twisted.words.protocols.jabber import jid

from gnutls.crypto import OpenPGPCertificate
from gnutls.constants import OPENPGP_FMT_RAW

from OpenSSL import crypto
from OpenSSL.crypto import X509

from subprocess import Popen, PIPE
from pyasn1.codec.der import decoder

try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

import util, log


def dump_publickey(cert):
    """Ugly hack to extract the public key from a certificate."""
    dump = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    p = Popen(['openssl', 'x509', '-pubkey', '-noout'], stdout=PIPE, stdin=PIPE)
    (stdout, unused) = p.communicate(dump)
    return stdout

def convert_publickey(keydata, keyid=None):
    """Another ugly hack to convert a PGP public key into PEM."""
    cmd = ['openpgp2spki']
    if keyid:
        cmd.append(keyid)

    p = Popen(cmd, stdout=PIPE, stdin=PIPE)
    (stdout, unused) = p.communicate(keydata)
    return stdout

def get_pgp_publickey_extension(cert):
    """Retrieves the custom extension containing the PGP public key block."""
    c = cert.get_extension_count()
    for i in range(c):
        ext = cert.get_extension(i)
        # my god this is really s**t
        if ext.get_short_name() == 'UNDEF':
            data = ext.get_data()
            b = decoder.decode(data)
            return ''.join(util.bitlist_to_chars(b[0]))

def extract_public_key(cert):
    if isinstance(cert, OpenPGPCertificate):
        return cert
    elif isinstance(cert, X509):
        return OpenPGPCertificate(get_pgp_publickey_extension(cert), OPENPGP_FMT_RAW)

def convert_openpgp_from_base64(keydata):
    if keydata.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----'):
        start = keydata.find('\n\n')
        end = keydata.find('-----END PGP PUBLIC KEY BLOCK-----', start + 2)
        if start >= 0 and end > 0:
            return base64.b64decode(keydata[start+2:end])

def get_key_fingerprint(keydata):
    cert = OpenPGPCertificate(keydata, OPENPGP_FMT_RAW)
    if cert:
        return cert.fingerprint

def verify_certificate(cert):
    """
    Verify that a certificate is signed by the same key owning the PGP public
    key block contained in the custom X.509 extension.
    """

    # dump public key from certificate
    pubkey = dump_publickey(cert)

    # dump custom extension from certificate
    pubkey_ext = get_pgp_publickey_extension(cert)

    if pubkey and pubkey_ext:
        # WARNING this goes "internal error" sometimes
        pubkey2 = convert_publickey(pubkey_ext, get_key_fingerprint(pubkey_ext))

        # compare public keys
        return pubkey == pubkey2

    return False


class Keyring:
    '''Handles all keyring releated functions.'''

    '''Percentages of server signatures needed to obtain privileges.'''
    _privileges = {
        'dht' : (0, 100, 50, 25),
        'token' : (0, 100),
        'messages' : (0, 100)
    }

    def __init__(self, db, fingerprint, network, servername, disable_signers=False, disable_cache=False):
        self._db = db
        self.fingerprint = str(fingerprint).upper()
        self.network = network
        self.servername = servername
        self._list = {}
        self._enabled = {}

        # cache of locally discovered fingerprints (userid: fingerprint)
        # TODO find a more efficient way
        if not disable_cache:
            self._fingerprints = {}
        else:
            self._fingerprints = None

        # gpgme context
        self.ctx = gpgme.Context()
        self.ctx.armor = False
        self.ctx.keylist_mode = gpgme.KEYLIST_MODE_SIGS
        # signing key (optional)
        if not disable_signers:
            self.ctx.signers = [self.ctx.get_key(self.fingerprint, True)]

        self._reload()

    def itervalues(self):
        '''Wrapper for itervalues() of internal server list.'''
        return self._list.itervalues()

    def _reload(self):
        slist = self._db.get_list()
        for fpr, data in slist.iteritems():
            self._list[fpr] = data['host']
            if data['enabled']:
                self._enabled[fpr] = data['host']

    def host(self, fingerprint):
        return self._list[fingerprint]

    def get_server_trust(self, fingerprint):
        """
        Verifies signatures on the given server public key and returns the
        list of servers (actually fingerprints) that has signed it.
        """
        trusted_by = []

        key = self.ctx.get_key(fingerprint, False)
        for uid in key.uids:
            for sign in uid.signatures:
                skey = self.ctx.get_key(sign.keyid, False)
                fpr = str(skey.subkeys[0].fpr).upper()
                #print "found signature from %s" % fpr
                #print fpr in self._list.keys()
                #print fpr != fingerprint
                # make sure key is actually in the keyring and the sign is not self-made
                if fpr in self._list.keys() and fpr != fingerprint:
                    trusted_by.append(fpr)

        return trusted_by

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

    def __getitem__(self, key):
        return self._list[key]

    def __iter__(self):
        '''Wrapper for keyring iterator.'''
        return self._list.iterkeys()

    def hostlist(self, full=False):
        """List of host servers."""
        if full:
            return self._list.values()
        else:
            return self._enabled.values()

    def is_enabled(self, fingerprint):
        return fingerprint in self._enabled

    def get_fingerprint(self, userid):
        # TODO find a more efficient way

        if self._fingerprints is None:
            raise AttributeError("fingerprint cache is disabled")

        try:
            return self._fingerprints[userid]
        except KeyError:
            raise KeyNotFoundException(userid)

    def set_fingerprint(self, userid, fpr):
        if self._fingerprints is None:
            raise AttributeError("fingerprint cache is disabled")

        self._fingerprints[userid] = fpr

    def import_key(self, keydata):
        """Imports a key without checking."""
        try:
            # import key
            result = self.ctx.import_(BytesIO(keydata))
            fp = str(result.imports[0][0])
            return fp, self.ctx.get_key(fp)
        except:
            import traceback
            traceback.print_exc()
            return False

    def get_key(self, userid, fingerprint):
        """
        Retrieves a user's key from the cache keyring.
        @return keydata on success, None otherwise
        """
        # retrieve the requested key
        try:
            key = self.ctx.get_key(fingerprint)
            if key:
                keydata = BytesIO()
                self.ctx.export(str(key.subkeys[0].fpr), keydata)
                return keydata.getvalue()
        except:
            import traceback
            traceback.print_exc()

    def check_user_key(self, keydata, userid):
        """
        Does some checks on a user public key, checking for server signatures
        and if uid matches.
        FIXME this method has the side effect of importing the key into the
        keyring and leaving it there.
        @return: key fingerprint on success, None otherwise
        """
        try:
            # TODO this should remove the key from the keyring when it's done

            # import key
            result = self.ctx.import_(BytesIO(keydata))
            #for d in dir(result):
            #    print d, getattr(result, d)
            fp = str(result.imports[0][0]).upper()
            key = self.ctx.get_key(fp)

            # revoked key!
            if key.revoked:
                return None

            # check that at least one of the key uids is userid@network
            check_email = '%s@%s' % (userid, self.network)
            for uid in key.uids:
                # uid found, check signatures
                if uid.email == check_email:

                    # revoked userid
                    if uid.revoked:
                        return None

                    for sig in uid.signatures:
                        try:
                            #log.debug("found signature by [KEYID-%s]" % (sig.keyid, ))
                            mkey = self.ctx.get_key(sig.keyid)
                            if mkey:
                                # signer key revoked!
                                if mkey.revoked:
                                    continue

                                fpr = str(mkey.subkeys[0].fpr).upper()

                                #log.debug("found signature by %s" % (fpr, ))
                                # signature made by us
                                if fpr == self.fingerprint:
                                    if self._fingerprints is not None:
                                        self._fingerprints[userid] = fp
                                    return fp

                                # check against keyring
                                for rkey in self._list.iterkeys():
                                    # fingerprint is a match: check if server is trusted
                                    if fpr == rkey and self.fingerprint in self.get_server_trust(rkey):
                                        if self._fingerprints is not None:
                                            self._fingerprints[userid] = fp
                                        return fp
                        except:
                            pass
        except:
            import traceback
            traceback.print_exc()

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
                    try:
                        mkey = self.ctx.get_key(sig.keyid, False)
                        if mkey:
                            fpr = mkey.subkeys[0].fpr.upper()

                            if fpr == self.fingerprint.upper():
                                return (jabberid, key.subkeys[0].fpr)

                            # no direct match - compare with keyring
                            for rkey in self._list.iterkeys():
                                if fpr == rkey.upper():
                                    return (jabberid, key.subkeys[0].fpr)
                    except:
                        pass

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
        """
        Signs the provided public key with our server private key.
        At least one uid in the public key must match this form: userid@network
        @return: fingerprint, signed_keydata
        """
        try:
            # import key
            result = self.ctx.import_(BytesIO(keydata))
            #for d in dir(result):
            #    print d, getattr(result, d)
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

                if self._fingerprints is not None:
                    # save the key into the fingerprint cache
                    self._fingerprints[userid] = fp

                return fp, keydata.getvalue()

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


class KeyNotFoundException(Exception):

    def __init__(self, uid):
        Exception.__init__(self)
        self.uid = uid
