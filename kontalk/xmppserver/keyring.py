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

# pyme
from pyme import core
from pyme.constants.keylist import mode as keymode
from pyme.constants.sig import mode as sigmode

import log


class Keyring:
    '''Handles all keyring releated functions.'''

    '''Percentages of server signatures needed to obtain privileges.'''
    _privileges = {
        'dht' : (0, 100, 50, 25),
        'token' : (0, 100),
        'messages' : (0, 100)
    }

    def __init__(self, db, fingerprint, servername):
        self._db = db
        self.fingerprint = fingerprint
        self.servername = servername
        self._list = {}

        # pyme context
        self.ctx = core.Context()
        self.ctx.set_armor(0)
        self.ctx.set_keylist_mode(keymode.SIGS)

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

    """
    TODO this is not safe. We risk importing unwanted keys and a bunch of other
    security holes. Be sure to use a dedicated GNUPGHOME for this task,
    a copy of the default one to be used as a sandbox.
    """
    def check_key(self, keydata):
        data = core.Data(keydata)

        result = self.ctx.op_import(data)
        if result:
            log.warn("error! (%s)" % (result, ))
        else:
            result = self.ctx.op_import_result()
            """
            log.debug("-- status: %r" % (result, ))
            log.debug(("%i public keys read\n" +
                                "%i public keys imported\n" +
                                "%i public keys unchanged\n" +
                                "%i secret keys read\n" +
                                "%i secret keys imported\n" +
                                "%i secret keys unchanged") % \
                              (result.considered,
                               result.imported,
                               result.unchanged,
                               result.secret_read,
                               result.secret_imported,
                               result.secret_unchanged))
            """

            # key imported/unchanged, look for our signatures
            if result.imported == 1 or result.unchanged == 1:
                fpr = result.imports[0].fpr
                key = self.ctx.get_key(fpr, False)

                for sig in key.uids[0].signatures:
                    match = False

                    mkey = self.ctx.get_key(sig.keyid, False)
                    if mkey:
                        fpr = mkey.subkeys[0].fpr.upper()

                        if fpr == self.fingerprint.upper():
                            match = True
                        else:
                            # no match - compare with keyring
                            for key in self._list.iterkeys():
                                if fpr == key.upper():
                                    match = True
                                    break

                    if match:
                        return True

        return False


    def generate_user_token(self, userid):
        """Generates a user token."""

        """
        A token is made up of the hashed phone number (the user id)
        plus the resource (in one big string, 40+8 characters),
        and the fingerprint of the server he registered to
        """
        fp = str(self.fingerprint)
        string = '%s|%s' % (str(userid), fp)
        plain = core.Data(string)
        cipher = core.Data()
        ctx = core.Context()
        ctx.set_armor(0)

        # signing key
        ctx.signers_add(ctx.get_key(fp, True))

        ctx.op_sign(plain, cipher, sigmode.NORMAL)
        cipher.seek(0, 0)
        token = cipher.read()
        return base64.b64encode(token)
