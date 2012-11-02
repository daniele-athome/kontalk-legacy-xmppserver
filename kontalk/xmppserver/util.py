# -*- coding: utf-8 -*-
'''Utilities for everybody.'''
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

import random

from wokkel import generic

USERID_LENGTH = 40
USERID_LENGTH_RESOURCE = 48

CHARSBOX_AZN_CASEINS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890'
CHARSBOX_AZN_LOWERCASE = 'abcdefghijklmnopqrstuvwxyz1234567890'
CHARSBOX_AZN_UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
CHARSBOX_NUMBERS = '1234567890'
CHARSBOX_HEX_LOWERCASE = 'abcdef1234567890'
CHARSBOX_HEX_UPPERCASE = 'ABCDEF1234567890'


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
