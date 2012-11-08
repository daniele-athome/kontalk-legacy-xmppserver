# -*- coding: utf-8 -*-
'''Authentication utilities.'''
import GnuPGInterface
'''
  Kontalk Pyserver
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


from zope.interface import implements

from twisted.cred import credentials, checkers, error, portal
from twisted.python import failure
from twisted.internet import defer, ssl
from twisted.words.protocols.jabber import jid, sasl

# pyme
from pyme import core

import xmlstream2, log, util


class IKontalkToken(credentials.ICredentials):

    def checkToken(fingerprint, keyring):
        pass


class KontalkToken(object):
    implements(IKontalkToken)

    def __init__(self, token, decode_b64=False):
        self.token = token
        self.decode_b64 = decode_b64

    def checkToken(self, fingerprint, keyring):
        try:
            # setup pyme
            if self.decode_b64:
                data = sasl.fromBase64(self.token)
            else:
                data = self.token
            cipher = core.Data(data)
            plain = core.Data()
            ctx = core.Context()
            ctx.set_armor(0)

            ctx.op_verify(cipher, None, plain)
            # check verification result
            res = ctx.op_verify_result()
            if len(res.signatures) > 0:
                sign = res.signatures[0]
                plain.seek(0, 0)
                text = plain.read()
                data = text.split('|', 2)

                # not a valid token
                if len(data) != 2:
                    return None

                # length not matching - refused
                userid = data[0]
                if len(userid) != util.USERID_LENGTH_RESOURCE:
                    return None

                # compare with provided fingerprint (if any)
                if fingerprint and (sign.fpr.upper() == fingerprint.upper()):
                    return userid

                # no match - compare with keyring
                for key in keyring:
                    if sign.fpr.upper() == key.upper():
                        return userid

            return None
        except:
            import traceback
            traceback.print_exc()
            log.debug("token verification failed!")


class AuthKontalkToken(object):
    implements(checkers.ICredentialsChecker)

    credentialInterfaces = IKontalkToken,

    def __init__(self, fingerprint, keyring):
        self.fingerprint = str(fingerprint)
        self.keyring = keyring

    def _cbTokenValid(self, userid):
        if userid:
            return userid
        else:
            return failure.Failure(error.UnauthorizedLogin())

    def requestAvatarId(self, credentials):
        return defer.maybeDeferred(
            credentials.checkToken, self.fingerprint, self.keyring).addCallback(
            self._cbTokenValid)

class SASLRealm:
    """
    A twisted.cred Realm for XMPP/SASL authentication

    You can subclass this and override the buildAvatar function to return an
    object that implements the IXMPPUser interface.
    """

    implements(portal.IRealm)

    def __init__(self, name):
        """ @param name: a string identifying the realm
        """
        self.name = name

    def requestAvatar(self, avatarId, mind, *interfaces):
        if xmlstream2.IXMPPUser in interfaces:
            avatar = self.buildAvatar(avatarId)
            return xmlstream2.IXMPPUser, avatar, avatar.logout
        else:
            raise NotImplementedError("Only IXMPPUser interface is supported by this realm")

    def buildAvatar(self, avatarId):
        # The hostname will be overwritten by the SASLReceivingInitializer
        # We put in example.com to keep the JID constructor from complaining
        userid, resource = util.split_userid(avatarId)
        return xmlstream2.XMPPUser(jid.JID(tuple=(userid, "example.com", resource)))


class DefaultGnuPGContextFactory(ssl.ContextFactory):
    """
    L{DefaultGnuPGContextFactory} is a factory for server-side GnuPG context
    objects.  These objects define certain parameters related to SSL
    handshakes and the subsequent connection.

    @ivar _contextFactory: A callable which will be used to create new
        context objects.  This is typically L{SSL.Context}.
    """
    _context = None

    def __init__(self, fingerprint):
        self.fingerprint = str(fingerprint)
        self._contextFactory = core.Context

        # Create a context object right now.  This is to force validation of
        # the given parameters so that errors are detected earlier rather
        # than later.
        self.cacheContext()


    def cacheContext(self):
        if self._context is None:
            ctx = self._contextFactory()
            ctx.set_armor(0)
            ctx.signers_add(ctx.get_key(self.fingerprint, True))
            self._context = ctx


    def __getstate__(self):
        d = self.__dict__.copy()
        del d['_context']
        return d


    def __setstate__(self, state):
        self.__dict__ = state


    def getContext(self):
        """
        Return an SSL context.
        """
        return self._context
