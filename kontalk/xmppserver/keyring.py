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

# pyme
from pyme import core
from pyme.constants.sig import mode as sigmode
from pyme.constants.keylist import mode as keymode

from twisted.internet import defer


class Keyring:
    '''Handles all keyring releated functions.'''

    '''Percentages of server signatures needed to obtain privileges.'''
    _privileges = {
        'dht' : (0, 100, 50, 25),
        'token' : (0, 100),
        'messages' : (0, 100)
    }

    def __init__(self, db, fingerprint):
        self._db = db
        self.fingerprint = fingerprint
        self._list = []
        self._reload()

    def itervalues(self):
        '''Wrapper for itervalues() of internal server list.'''
        return self._list.itervalues()

    def _reload(self):
        def done(data):
            self._list = data
            self._keyring = [x for x in self._list.iterkeys()]
            self._keyring.insert(0, self.fingerprint)
        self._db.get_list().addCallback(done)

    def s2s_addr(self, fingerprint):
        d = self._list[fingerprint]
        return d['host'], d['s2s']

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
                #print str(fpr) in self._keyring
                #print str(fpr) != fingerprint
                # make sure key is actually in the keyring and the sign is self-made
                if str(fpr) in self._keyring and str(fpr) != fingerprint:
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
        if fingerprint not in self._keyring:
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
        return len(self._keyring)

    def __iter__(self):
        '''Wrapper for keyring iterator.'''
        return iter(self._keyring)