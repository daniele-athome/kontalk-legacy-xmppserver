# -*- coding: utf-8 -*-
"""Client registration providers."""
"""
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
"""


from twisted.words.protocols.jabber import xmlstream
from twisted.words.xish import domish

from kontalk.xmppserver import log, xmlstream2


class XMPPRegistrationProvider:
    """
    Base class for in-band registration providers.
    """

    def __init__(self, component, config):
        self.component = component
        self.config = config

    def request(self, manager, stanza):
        """
        Requests info about registration (iq get).
        @param manager: session manager
        @param stanza: registration request stanza
        """
        pass

    def register(self, manager, stanza):
        """
        Registers a user (iq set).
        @param manager: session manager
        @param stanza: registration request stanza
        """
        pass


class AndroidEmulatorRegistrationProvider(XMPPRegistrationProvider):
    """
    This provider uses adb to send sms to the Android emulator.
    """

    name = 'android_emu'

    def __init__(self, component, config):
        if config['type'] != 'sms':
            raise NotImplementedError('only sms registration is supported')
        XMPPRegistrationProvider.__init__(self, component, config)

    def request(self, manager, stanza):
        iq = xmlstream.toResponse(stanza, 'result')
        query = iq.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))
        query.addElement((None, 'instructions'), content='Please supply a valid phone number. A SMS will be sent to the Android emulator.')

        form = query.addElement(('jabber:x:data', 'x'))
        form['type'] = 'form'

        hidden = form.addElement((None, 'field'))
        hidden['type'] = 'hidden'
        hidden['var'] = 'FORM_TYPE'
        hidden.addElement((None, 'value'), content=xmlstream2.NS_IQ_REGISTER)

        phone = form.addElement((None, 'field'))
        phone['type'] = 'text-single'
        phone['label'] = 'Phone number'
        phone['var'] = 'phone'
        phone.addElement((None, 'required'))

        manager.send(iq)

    def register(self, manager, stanza):
        # TODO some checking would be nice :)
        fields = stanza.query.x.elements(uri='jabber:x:data', name='field')
        for f in fields:
            if f['var'] == 'phone':
                # TODO generate validation code
                import os
                os.system('adb emu sms send %s %s' % (self.config['from'], 'TODO'))

                # send response with sms sender number
                iq = xmlstream.toResponse(stanza, 'result')
                query = iq.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))
                query.addElement((None, 'instructions'), content='A SMS containing a validation code will be sent to the emulator.')

                form = query.addElement(('jabber:x:data', 'x'))
                form['type'] = 'form'

                hidden = form.addElement((None, 'field'))
                hidden['type'] = 'hidden'
                hidden['var'] = 'FORM_TYPE'
                hidden.addElement((None, 'value'), content=xmlstream2.NS_IQ_REGISTER)

                phone = form.addElement((None, 'field'), content=self.config['from'])
                phone['type'] = 'text-single'
                phone['label'] = 'SMS sender'
                phone['var'] = 'from'

                return manager.send(iq)

            elif f['var'] == 'code':
                # TODO check validation code from database
                iq = xmlstream.toResponse(stanza, 'result')
                query = iq.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))

                form = query.addElement(('jabber:x:data', 'x'))
                form['type'] = 'form'

                hidden = form.addElement((None, 'field'))
                hidden['type'] = 'hidden'
                hidden['var'] = 'FORM_TYPE'
                hidden.addElement((None, 'value'), content='http://kontalk.org/protocol/register#code')

                token = form.addElement((None, 'field'))
                token['type'] = 'text-single'
                token['label'] = 'Authentication token'
                token['var'] = 'token'
                token.addElement((None, 'value'), content='TOKEN-TODO')

                return manager.send(iq)



providers = {
    'android_emu': AndroidEmulatorRegistrationProvider
}
