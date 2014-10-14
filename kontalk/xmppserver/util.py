# -*- coding: utf-8 -*-
"""Utilities for everybody."""
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

import random
import hashlib
import mimetypes

from zope.interface import implements

from twisted.internet import protocol, defer
from twisted.web import client
from twisted.web.http import PotentialDataLoss
from twisted.web.iweb import IBodyProducer
from twisted.words.protocols.jabber import jid
from wokkel import generic

USERID_LENGTH = 40
USERID_LENGTH_RESOURCE = 48

CHARSBOX_AZN_CASEINS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890'
CHARSBOX_AZN_LOWERCASE = 'abcdefghijklmnopqrstuvwxyz1234567890'
CHARSBOX_AZN_UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
CHARSBOX_NUMBERS = '1234567890'
CHARSBOX_HEX_LOWERCASE = 'abcdef1234567890'
CHARSBOX_HEX_UPPERCASE = 'ABCDEF1234567890'

COMPONENT_C2S = 'c2s'
COMPONENT_NET = 'net'

DEFAULT_EXTENSION = '.bin'


def split_userid(userid):
    return userid[:USERID_LENGTH], userid[USERID_LENGTH:]


def jid_to_userid(_jid, splitted=False):
    """Converts a L{JID} to a user id."""
    if _jid.resource:
        if splitted:
            return _jid.user, _jid.resource
        return _jid.user + _jid.resource
    else:
        if splitted:
            return _jid.user, None
        return _jid.user


def userid_to_jid(userid, host=None):
    """Converts a user id to a L{JID}."""
    h, r = split_userid(userid)
    return jid.JID(tuple=(h, host, r))


def rand_str(length = 32, chars = CHARSBOX_AZN_CASEINS):
    # Length of character list
    chars_length = (len(chars) - 1)

    # Start our string
    string = chars[random.randrange(chars_length)]

    # Generate random string
    i = 1
    while i < length:
        # Grab a random character from our list
        r = chars[random.randrange(chars_length)]

        # Make sure the same two characters don't appear next to each other
        if r != string[i - 1]:
            string +=  r

        i = len(string)

    # Return the string
    return string


def resetNamespace(node, fromUri = None, toUri = None):
    """
    Reset namespace of the given node and all of its children
    """
    node.defaultUri = node.uri = fromUri
    generic.stripNamespace(node)
    node.defaultUri = node.uri = toUri


def str_none(obj, encoding='utf-8'):
    if obj is not None:
        try:
            data = str(obj)
        except:
            data = obj.__str__().encode(encoding)
        if len(data) > 0:
            return data
    return None


def sha1(text):
    hashed = hashlib.sha1(text)
    return hashed.hexdigest()


def _jid_parse(jidstring, index):
    j = jid.parse(jidstring)
    return j[index]


def jid_user(jidstring):
    return _jid_parse(jidstring, 0)


def jid_host(jidstring):
    return _jid_parse(jidstring, 1)


def component_jid(host, component):
    return component + '.' + host


def jid_component(jidstring, component=None):
    if '@' not in jidstring:
        parsed = jidstring.split('.', 1)
        if component:
            if len(parsed) == 2 and component == parsed[0]:
                return parsed
        else:
            return parsed


def jid_local(component, component_object, _jid):
    return hostjid_local(component, component_object, _jid.host)


def hostjid_server(jidstring, servername):
    try:
        unused, host = jid_component(jidstring)
        return host == servername
    except:
        pass


def hostjid_local(component, component_object, host):
    # depending on the component, one of network or server name must be chosen
    if component == COMPONENT_C2S:
        check = component_object.servername
    else:
        check = None

    if component_object.xmlstream and component_object.xmlstream.thisEntity:
        check2 = component_object.xmlstream.thisEntity.host
    else:
        check2 = None
    return host in (check, check2)


def generate_filename(mime):
    """Generates a random filename for the given MIME type."""
    supported_mimes = {
        'image/png': '.png',
        'image/jpeg': '.jpg',
        'image/gif': '.gif',
        'text/x-vcard': '.vcf',
        'text/vcard': '.vcf',
        'text/plain': '.txt',
        'audio/3gpp': '.3gp',
    }

    try:
        ext = supported_mimes[mime]
    except KeyError:
        ext = mimetypes.guess_extension(mime, strict=False)
        if ext is None:
            ext = DEFAULT_EXTENSION

    return 'att%s%s' % (rand_str(6, CHARSBOX_AZN_LOWERCASE), ext)


def md5sum(filename):
    md5 = hashlib.md5()
    with open(filename,'rb') as f:
        for chunk in iter(lambda: f.read(128*md5.block_size), ''):
            md5.update(chunk)
    return md5.hexdigest()


class SimpleReceiver(protocol.Protocol):
    """A simple string buffer receiver for http clients."""

    def __init__(self, code, d):
        self.buf = ''
        self.code = code
        self.d = d

    def dataReceived(self, data):
        self.buf += data

    def connectionLost(self, reason=protocol.connectionDone):
        if isinstance(reason.value, client.ResponseDone) or isinstance(reason.value, PotentialDataLoss):
            self.d.callback((self.code, self.buf))
        else:
            self.d.errback(reason)


class StringProducer(object):
    implements(IBodyProducer)

    def __init__(self, body):
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass


def bitlist_to_chars(bl):
    """See http://stackoverflow.com/a/10238101/1045199"""
    bi = iter(bl)
    _bytes = zip(*(bi,) * 8)
    shifts = (7, 6, 5, 4, 3, 2, 1, 0)
    for byte in _bytes:
        yield chr(sum(bit << s for bit, s in zip(byte, shifts)))
