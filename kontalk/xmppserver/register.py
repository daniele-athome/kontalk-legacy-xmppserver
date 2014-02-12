# -*- coding: utf-8 -*-
"""Client registration providers."""
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

from twisted.internet import reactor
from twisted.words.protocols.jabber import xmlstream, error

from kontalk.xmppserver import log, xmlstream2, util


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
        @param stanza: registration submit stanza
        """
        pass


class SMSRegistrationProvider(XMPPRegistrationProvider):
    """
    Abstract provider for generic SMS-based registration.
    """

    type = 'sms'

    def __init__(self, component, config):
        XMPPRegistrationProvider.__init__(self, component, config)

    def request(self, manager, stanza):
        iq = xmlstream.toResponse(stanza, 'result')
        query = iq.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))
        query.addElement((None, 'instructions'), content=self.request_instructions)

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

        manager.send(iq, True)

    def register(self, manager, stanza):
        # TODO some checking would be nice :)
        fields = stanza.query.x.elements(uri='jabber:x:data', name='field')
        var_phone = None
        var_code = None
        var_pkey = None

        for f in fields:
            if f['var'] == 'phone':
                var_phone = f
            elif f['var'] == 'code':
                var_code = f
            elif f['var'] == 'publickey':
                var_pkey = f

        # validation code request
        if var_phone:
            def _bad_phone():
                e = error.StanzaError('bad-request', 'modify', 'Bad phone number.')
                iq = xmlstream.toResponse(stanza, 'error')
                iq.addChild(e.getElement())
                return manager.send(iq, True)

            n = var_phone.value.__str__().encode('utf-8')

            # validate phone number syntax
            if not n or len(n.strip()) == 0:
                log.debug("number empty - %s" % n)
                return _bad_phone()

            phone = phone_num = n.strip()
            # exclude the initial plus to verify the digits
            if (phone[0] == '+'):
                phone_num = phone[1:]

            # not all digits...
            if not phone_num.isdigit():
                log.debug("number is not all-digits - %s" % phone_num)
                return _bad_phone()

            # replace double-zero with plus
            if phone[0:2] == '00':
                phone = '+' + phone[2:]

            # generate userid
            userid = util.sha1(phone)
            d = self.component.validationdb.register(userid)

            def _continue(code, stanza, phone):
                self.send_sms(phone, code)

                # send response with sms sender number
                iq = xmlstream.toResponse(stanza, 'result')
                query = iq.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))
                query.addElement((None, 'instructions'), content=self.ack_instructions)

                form = query.addElement(('jabber:x:data', 'x'))
                form['type'] = 'form'

                hidden = form.addElement((None, 'field'))
                hidden['type'] = 'hidden'
                hidden['var'] = 'FORM_TYPE'
                hidden.addElement((None, 'value'), content=xmlstream2.NS_IQ_REGISTER)

                phone = form.addElement((None, 'field'))
                phone['type'] = 'text-single'
                phone['label'] = 'SMS sender'
                phone['var'] = 'from'
                phone.addElement((None, 'value'), content=self.config['from'])

                return manager.send(iq, True)

            def _error(failure, stanza):
                log.debug("error: %s" % (failure, ))
                e = error.StanzaError('service-unavailable', 'wait', failure.getErrorMessage())
                iq = xmlstream.toResponse(stanza, 'error')
                iq.addChild(e.getElement())
                manager.send(iq, True)

            d.addCallback(_continue, stanza, phone)
            d.addErrback(_error, stanza)

        # code validation + public key
        elif var_code and var_pkey:
            # check validation code from database
            code = var_code.value.__str__().encode('utf-8')
            d = self.component.validationdb.validate(code)

            def _continue(userid):
                pkey = base64.b64decode(var_pkey.value.__str__().encode('utf-8'))
                signed_pkey = manager.link_public_key(pkey, userid)
                if signed_pkey:
                    iq = xmlstream.toResponse(stanza, 'result')
                    query = iq.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))

                    form = query.addElement(('jabber:x:data', 'x'))
                    form['type'] = 'form'

                    hidden = form.addElement((None, 'field'))
                    hidden['type'] = 'hidden'
                    hidden['var'] = 'FORM_TYPE'
                    hidden.addElement((None, 'value'), content='http://kontalk.org/protocol/register#code')

                    signed = form.addElement((None, 'field'))
                    signed['type'] = 'text-single'
                    signed['label'] = 'Signed public key'
                    signed['var'] = 'publickey'
                    signed.addElement((None, 'value'), content=base64.b64encode(signed_pkey))

                    return manager.send(iq, True)

                else:
                    e = error.StanzaError('bad-request', 'modify', 'Invalid public key.')
                    iq = xmlstream.toResponse(stanza, 'error')
                    iq.addChild(e.getElement())
                    manager.send(iq, True)

            def _error(failure):
                log.debug("error: %s" % (failure, ))
                if isinstance(failure.value, RuntimeError):
                    e = error.StanzaError('bad-request', 'modify', failure.getErrorMessage())
                else:
                    e = error.StanzaError('service-unavailable', 'wait', failure.getErrorMessage())
                iq = xmlstream.toResponse(stanza, 'error')
                iq.addChild(e.getElement())
                manager.send(iq, True)

            d.addCallback(_continue)
            d.addErrback(_error)

        else:
            e = error.StanzaError('bad-request', 'modify', 'Please provider phone number and public key or verification code.')
            iq = xmlstream.toResponse(stanza, 'error')
            iq.addChild(e.getElement())
            manager.send(iq, True)


    def send_sms(self, number, code):
        """Implement this with the actual SMS sending logic."""
        raise NotImplementedError()


class AndroidEmulatorSMSRegistrationProvider(SMSRegistrationProvider):
    """
    This provider uses adb to send sms to the Android emulator.
    """

    name = 'android_emu_sms'
    request_instructions = 'Please supply a valid phone number. A SMS will be sent to the Android emulator.'
    ack_instructions = 'A SMS containing a verification code will be sent to the emulator.'


    def send_sms(self, number, code):
        def _send(code):
            import os
            os.system('adb emu sms send %s %s' % (self.config['from'], code))
        # simulate some delay :)
        reactor.callLater(2, _send, code)


class NexmoSMSRegistrationProvider(SMSRegistrationProvider):
    """
    SMS registration provider using Nexmo API.
    """

    name = 'nexmo'
    request_instructions = 'Please supply a valid phone number. A SMS will be sent to you with a verification code.'
    ack_instructions = 'A SMS containing a verification code will be sent to the phone number you provided.'

    def send_sms(self, number, code):
        from nexmomessage import NexmoMessage
        msg = {
            'reqtype' : 'json',
            'username' : self.config['nx.username'],
            'password': self.config['nx.password'],
            'from': self.config['from'],
            'to': number,
        }
        sms = NexmoMessage(msg)
        # FIXME send just the code for now
        sms.set_text_info(code)
        js = sms.send_request()
        log.debug("sms sent [response=%s]" % js)



providers = {
    'android_emu_sms': AndroidEmulatorSMSRegistrationProvider,
    'nexmo': NexmoSMSRegistrationProvider,
}
