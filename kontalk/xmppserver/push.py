# -*- coding: utf-8 -*-
'''Push notifications support.'''
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


import traceback
import urllib, urllib2

import log, util


class GCMPushNotifications:

    def __init__(self, handler):
        self.handler = handler
        self.sender = handler.parent.router.push_manager.providers['gcm'].sender

    def supports(self):
        return ({
            'jid': 'gcm.push.' + self.handler.parent.network,
            'node': self.sender,
            'name': 'Google Cloud Messaging push notifications',
        }, )


class PushServer:
    '''Push server interface.'''

    def __init__(self):
        pass

    def notify(self, userid):
        raise NotImplementedError()

    def __str__(self):
        return self.name


class GooglePush(PushServer):
    '''Google Cloud Messaging implementation.'''

    name = 'gcm'
    # API entrypoint for GCM requests
    url = 'https://android.googleapis.com/gcm/send'

    def __init__(self, service, config):
        self.service = service
        self.token = config['apikey']
        self.sender = config['projectid']

    def notify(self, userid):
        params = urllib.urlencode({
            'registration_id' : self.regid,
            'collapse_key' : 'new',
            'data.action' : 'org.kontalk.CHECK_MESSAGES'
        })
        headers = {
            'Authorization' : 'key=' + self.token
        }
        req = urllib2.Request(self.url, params, headers)
        fd = urllib2.urlopen(req)
        # TODO what do we do with the output??
        data = fd.read()
        return data


class PushManager:
    providerHandlers = {
        'gcm': GooglePush,
    }

    def __init__(self, service, config):
        # TODO will use database one day
        self._cache = {}
        self.providers = {}
        for push_cfg in config:
            provider = push_cfg['provider']
            try:
                prov_class = self.providerHandlers[provider]
                self.providers[provider] = prov_class(self, push_cfg)
            except:
                log.warn(traceback.format_exc())

    def register(self, _jid, provider, regid):
        userid = util.jid_to_userid(_jid)
        self._cache[userid][provider] = regid

    def notify(self, _jid):
        log.debug("sending push notification to %s" % (_jid.full(), ))
        userid = util.jid_to_userid(_jid)
        if userid in self._cache:
            for prov in self._cache[userid]:
                log.debug("push notifying via %s" % (prov, ))
                self.providers[prov].notify(userid)
