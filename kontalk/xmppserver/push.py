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


from twisted.internet import reactor, defer
from twisted.web.client import Agent, FileBodyProducer
from twisted.web.http_headers import Headers

from StringIO import StringIO
import urllib
import traceback
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
        self.token = str(config['apikey'])
        self.sender = str(config['projectid'])

    def notify(self, regid):
        agent = Agent(reactor)
        params = urllib.urlencode({
            'registration_id' : regid,
            'collapse_key' : 'new',
            'data.action' : 'org.kontalk.CHECK_MESSAGES'
        })
        headers = Headers({
            'Authorization' : ['key=' + self.token],
            'Content-Type' : ['application/x-www-form-urlencoded;charset=UTF-8'],
        })

        d = agent.request('POST', self.url, headers, FileBodyProducer(StringIO(params)))

        def _success(response):
            if response.code == 204:
                d = defer.succeed('')
            else:
                d = defer.Deferred()
                def _debug(data):
                    log.debug("data from gcm(%s): %s" % (data[0], data[1], ))
                d.addCallback(_debug)
                response.deliverBody(util.SimpleReceiver(response.code, d))

            return d

        def _error(response):
            log.warn("error from gcm: %s" % (response, ))

        d.addCallbacks(_success, _error)
        return d


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
        if _jid.user not in self._cache:
            self._cache[_jid.user] = {}
        if _jid.resource not in self._cache[_jid.user]:
            self._cache[_jid.user][_jid.resource] = {}
        self._cache[_jid.user][_jid.resource][provider] = regid

    def notify(self, _jid):
        log.debug("sending push notification to %s" % (_jid.full(), ))
        if _jid.user in self._cache:
            if _jid.resource and _jid.resource in self._cache[_jid.user]:
                for name, regid in self._cache[_jid.user][_jid.resource].iteritems():
                    log.debug("push notifying via %s" % (name, ))
                    self.providers[name].notify(regid)
            else:
                for providers in self._cache[_jid.user].itervalues():
                    for name, regid in providers.iteritems():
                        log.debug("push notifying via %s" % (name, ))
                        self.providers[name].notify(regid)
