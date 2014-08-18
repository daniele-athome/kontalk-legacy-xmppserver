# -*- coding: utf-8 -*-
"""Storage modules."""
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


from twisted.internet import defer, reactor
from twisted.internet.task import LoopingCall
from twisted.enterprise import adbapi
from twisted.words.protocols.jabber import jid

from wokkel import generic

from copy import deepcopy
import os, base64, time, datetime

try:
    from collections import OrderedDict
except:
    from ordereddict import OrderedDict

from kontalk.xmppserver.component import sm
import util, xmlstream2, log

dbpool = None

def init(config):
    global dbpool
    dbpool = adbapi.ConnectionPool(config['dbmodule'], host=config['host'], port=config['port'],
        user=config['user'], passwd=config['password'], db=config['dbname'], autoreconnect=True)


""" interfaces """


class StanzaStorage:
    """Stanza storage system."""

    """Expired timeout call in seconds."""
    EXPIRED_TIMEOUT = 60

    def __init__(self, expire_time=0):
        """
        Creates a new validation storage.
        @var expire_time: expire time in seconds, 0 to disable it
        """
        # register a timeout for expired codes check
        if expire_time > 0:
            self.expire_time = expire_time
            LoopingCall(self.expired).start(self.EXPIRED_TIMEOUT, now=True)

    def expired(self):
        """Called every EXPIRED_TIMEOUT seconds to purge expired entries."""
        pass

    def store(self, stanza, network, delayed=False, reuseId=False):
        """Store a stanza."""
        pass

    def get_by_id(self, stanzaId):
        """Retrieve a stanza by id."""
        pass

    def get_by_sender(self, sender):
        """Retrieve stanzas by sender."""
        pass

    def get_by_recipient(self, recipient):
        """Retrieve stanzas by recipient."""
        pass

    def delete(self, stanzaId, sender=None, recipient=None):
        """Delete a stanza by id."""
        pass


class PresenceStorage:
    """Presence cache storage."""

    def get(self, userid):
        """Retrieve info about a user."""
        pass

    def get_all(self):
        """Retrieve info about all users."""
        pass

    def presence(self, stanza):
        """Persist a presence."""
        pass

    def touch(self, userid):
        """Update last seen timestamp of a user."""
        pass

    def public_key(self, userid, fingerprint):
        """Update a user public key."""
        pass

    def delete(self, userid):
        """Delete a presence."""
        pass


class NetworkStorage:
    """Network info storage."""

    def get_list(self):
        """Retrieve the list of servers in this network."""
        pass


class UserValidationStorage:
    """User validation storage."""

    """Validation code length."""
    VALIDATION_CODE_LENGTH = 6

    """Expired timeout call in seconds."""
    EXPIRED_TIMEOUT = 60

    def __init__(self, expire_time=0):
        """
        Creates a new validation storage.
        @var expire_time: expire time in seconds, 0 to disable it
        """
        # register a timeout for expired codes check
        if expire_time > 0:
            self.expire_time = expire_time
            LoopingCall(self.expired).start(self.EXPIRED_TIMEOUT, now=True)

    def expired(self):
        """Called every EXPIRED_TIMEOUT seconds to purge expired entries."""
        pass

    def register(self, key, code=None):
        """Registers a validation code for a user."""
        pass

    def validate(self, code):
        """Check if code is valid and deletes it."""
        pass


class FileStorage:
    """File storage."""

    def init(self):
        """Initializes this storage driver."""
        pass

    def get(self, name, return_data=True):
        """Retrieves a stored file."""
        pass

    def store_file(self, name, mime, fn):
        """Stores a file reading data from a file-like object."""
        pass

    def store_data(self, name, mime, data):
        """Stores a file reading data from a string."""
        pass


""" implementations """


class MySQLStanzaStorage(StanzaStorage):

    OFFLINE_STORE_DELAY = 10
    tables = ('presence', 'message', 'iq')

    def __init__(self, expire_time=0):
        StanzaStorage.__init__(self, expire_time)
        """
        This dictionary keeps track of messages currently pending for offline
        storage. Keys are message IDs, values are (L{IDelayedCall}, stanza)
        which can be canceled when a message is going to be deleted (also
        avoiding to do the actual database delete).
        """
        self._pending_offline = {}
        self._exiting = False
        # shutdown event trigger for delayed storage
        reactor.addSystemEventTrigger('during', 'shutdown', self._shutdown)

    def _shutdown(self):
        self._exiting = True
        dlist = []
        for cb, stanza, args in self._pending_offline.itervalues():
            if cb.active():
                cb.cancel()
                d = self._store(stanza, *args)
                dlist.append(d)
        return defer.gatherResults(dlist)

    def expired(self):
        for t in ('stanzas_iq', 'stanzas_message', 'stanzas_presence'):
            dbpool.runOperation('DELETE FROM %s WHERE UNIX_TIMESTAMP() > (UNIX_TIMESTAMP(timestamp) + %d)' %
                (t, self.expire_time, ))

    def store(self, stanza, network, delayed=False, reuseId=None, expire=None):
        receipt = xmlstream2.extract_receipt(stanza, 'request')
        if not receipt:
            if reuseId is not None:
                _id = reuseId
            else:
                _id = util.rand_str(30, util.CHARSBOX_AZN_LOWERCASE)
        else:
            _id = receipt['id']

        # cancel any previous delayed call
        self._cancel_pending(_id)

        # WARNING using deepcopy is not safe

        if delayed:
            # delay our call
            self._pending_offline[_id] = (reactor.callLater(self.OFFLINE_STORE_DELAY, self._store,
                stanza=deepcopy(stanza), network=network, _id=_id, expire=expire),
                    stanza, (network, _id, expire))
            return _id
        else:
            return self._store(deepcopy(stanza), network, _id, expire)

    def _store(self, stanza, network, _id, expire):
        # remove ourselves from pending
        if not self._exiting:
            try:
                del self._pending_offline[_id]
            except:
                pass

        # if no receipt request is found, generate a unique id for the message
        receipt = xmlstream2.extract_receipt(stanza, 'request')
        if not receipt:
            if _id:
                stanza['id'] = _id
            else:
                stanza['id'] = util.rand_str(30, util.CHARSBOX_AZN_LOWERCASE)

        # store message for bare network JID
        jid_to = jid.JID(stanza['to'])
        # WARNING this is actually useless
        jid_to.host = network
        stanza['to'] = jid_to.userhost()

        # sender JID should be a network JID
        jid_from = jid.JID(stanza['from'])
        # WARNING this is actually useless
        jid_from.host = network
        stanza['from'] = jid_from.full()

        # safe uri for persistance
        stanza.uri = stanza.defaultUri = sm.C2SManager.namespace

        log.debug("storing offline message for %s" % (stanza['to'], ))
        try:
            d = self._do_store(stanza, expire)
            if self._exiting:
                return d
        except:
            # TODO log this
            import traceback
            traceback.print_exc()

        return stanza['id']

    def _do_store(self, stanza, expire=None):
        global dbpool
        receipt = xmlstream2.extract_receipt(stanza, 'request')
        if receipt:
            # this is indeed generated by server :)
            msgId = receipt['id']
        else:
            # WARNING stanza id must be server generated
            msgId = stanza['id']
        args = (
            msgId,
            util.jid_to_userid(jid.JID(stanza['from'])),
            util.jid_to_userid(jid.JID(stanza['to'])),
            stanza.getAttribute('type'),
            stanza.toXml().encode('utf-8').decode('utf-8'),
            int(time.time()*1e3),
            expire
        )
        # for presence we want to overwrite old requests
        if stanza.name == 'presence':
            op = 'REPLACE'
        else:
            op = 'INSERT'
        return dbpool.runOperation('%s INTO stanzas_%s (id, sender, recipient, type, content, timestamp, expire_timestamp) VALUES(?, ?, ?, ?, ?, ?, ?)'
                                   % (op, stanza.name, ), args)

    def _cancel_pending(self, stanzaId):
        if stanzaId in self._pending_offline:
            if self._pending_offline[stanzaId][0].active():
                self._pending_offline[stanzaId][0].cancel()
                del self._pending_offline[stanzaId]
                return True
        return False

    def get_by_id(self, stanzaId):
        global dbpool
        def _translate(tx, stanzaId):
            # TODO translation to dict
            # TODO stanzas doesn't exist any more
            tx.execute('SELECT content, timestamp FROM stanzas WHERE id = ?', (stanzaId, ))
            return tx.fetchone()
        return dbpool.runInteraction(_translate, stanzaId)

    def get_by_sender(self, sender):
        # TODO
        #global dbpool
        #return dbpool.runQuery('SELECT id, recipient, content, timestamp FROM stanzas WHERE sender = ?', sender)
        raise NotImplementedError()

    def get_by_recipient(self, recipient):
        global dbpool
        def _translate(tx, recipient, out):
            qlist = ['SELECT `id`, `timestamp`, `content`, `expire_timestamp` FROM stanzas_%s WHERE `recipient` = ?' % (t, )
                     for t in self.tables]
            qargs = [recipient.user for t in self.tables]

            tx.execute('SELECT * FROM (' + ' UNION '.join(qlist) + ') a ORDER BY `timestamp`', qargs)
            data = tx.fetchall()
            for row in data:
                stanzaId = str(row[0])
                d = {
                     'id': stanzaId,
                     'timestamp': datetime.datetime.utcfromtimestamp(row[1] / 1e3),
                     'expire': datetime.datetime.utcfromtimestamp(row[3]) if row[3] else None
                }
                d['stanza'] = generic.parseXml(row[2].decode('utf-8').encode('utf-8'))

                """
                Add a <storage/> element to the stanza; this way components have
                a way to know if stanza is coming from storage.
                """
                stor = d['stanza'].addElement((xmlstream2.NS_XMPP_STORAGE, 'storage'))
                stor['id'] = stanzaId

                out.append(d)
            return out

        # include any pending message?
        out = []
        for stanzaId, pend in self._pending_offline.iteritems():
            delayed, stanza, unused = pend
            if util.jid_user(stanza['to']) == recipient.user:
                stanza.consumed = False
                out.append({'id': stanzaId, 'stanza': stanza})
                # reset delayed timer
                delayed.reset(self.OFFLINE_STORE_DELAY)

        return dbpool.runInteraction(_translate, recipient, out)

    def delete(self, stanzaId, stanzaName, sender=None, recipient=None):
        # check if message is pending to offline
        if self._cancel_pending(stanzaId):
            return True

        return self._delete(stanzaId, stanzaName, sender, recipient)

    def _delete(self, stanzaId, stanzaName, sender=None, recipient=None):
        global dbpool
        #import traceback
        #log.debug("deleting stanza %s -- traceback:\n%s" % (stanzaId, ''.join(traceback.format_stack())))
        q = 'DELETE FROM stanzas_%s WHERE id = ?' % (stanzaName, )
        args = [stanzaId]
        if sender:
            q += ' AND sender LIKE ?'
            args.append(sender + '%')
        if recipient:
            q += ' AND recipient LIKE ?'
            args.append(recipient + '%')

        return dbpool.runOperation(q, args)

class MySQLNetworkStorage(NetworkStorage):

    def get_list(self):
        # WARNING accessing Twisted internals and *blocking*
        global dbpool
        conn = dbpool.connectionFactory(dbpool)
        tx = dbpool.transactionFactory(dbpool, conn)
        tx.execute('SELECT fingerprint, host, enabled FROM servers')
        data = tx.fetchall()
        out = {}
        for row in data:
            # { fingerprint: {host, enabled} }
            out[str(row[0]).upper()] = { 'host' : str(row[1]), 'enabled' : int(row[2]) }
        return out

class MySQLPresenceStorage(PresenceStorage):

    def get(self, userid):
        def _fetchone(tx, query, args):
            tx.execute(query, args)
            data = tx.fetchone()
            if data:
                return {
                    'userid': data[0],
                    'timestamp': data[1],
                    'status': base64.b64decode(data[2]).decode('utf-8') if data[2] is not None else '',
                    'show': data[3],
                    'priority': data[4],
                    'fingerprint': data[5]
                }

        query = 'SELECT `userid`, `timestamp`, `status`, `show`, `priority`, `fingerprint` FROM presence WHERE userid = ? AND `timestamp` IS NOT NULL'
        args = (userid[:util.USERID_LENGTH], )
        return dbpool.runInteraction(_fetchone, query, args)

    def get_all(self):
        def _fetchall(tx, query):
            tx.execute(query)
            out = []
            rows = tx.fetchall()
            for data in rows:
                out.append({
                    'userid': data[0],
                    'timestamp': data[1],
                    'status': base64.b64decode(data[2]).decode('utf-8') if data[2] is not None else '',
                    'show': data[3],
                    'priority': data[4],
                    'fingerprint': data[5],
                })
            return out

        query = 'SELECT `userid`, `timestamp`, `status`, `show`, `priority`, `fingerprint` FROM presence WHERE `timestamp` IS NOT NULL'
        return dbpool.runInteraction(_fetchall, query)

    def presence(self, stanza):
        global dbpool
        userid = util.jid_user(stanza['from'])

        def encode_not_empty(val):
            if val is not None:
                data = val.__str__().encode('utf-8')
                if len(data) > 0:
                    return base64.b64encode(val.__str__().encode('utf-8'))
            return None

        try:
            priority = int(stanza.priority.__str__())
        except:
            priority = 0

        status = encode_not_empty(stanza.status)
        show = encode_not_empty(stanza.show)
        values = (userid, status, show, priority, status, show, priority)
        return dbpool.runOperation('INSERT INTO presence (`userid`, `timestamp`, `status`, `show`, `priority`) VALUES(?, UTC_TIMESTAMP(), ?, ?, ?) ON DUPLICATE KEY UPDATE `timestamp` = UTC_TIMESTAMP(), `status` = ?, `show` = ?, `priority` = ?', values)

    def touch(self, userid):
        global dbpool
        return dbpool.runOperation('UPDATE presence SET `timestamp` = UTC_TIMESTAMP() WHERE userid = ?', (userid, ))

    def public_key(self, userid, fingerprint):
        global dbpool
        return dbpool.runOperation('INSERT INTO presence (userid, fingerprint) VALUES(?, ?) ON DUPLICATE KEY UPDATE fingerprint = ?', (userid, fingerprint, fingerprint))

    def delete(self, userid):
        global dbpool
        return dbpool.runOperation('DELETE FROM presence WHERE userid = ?', (userid, ))


class MySQLUserValidationStorage(UserValidationStorage):
    """User validation storage."""

    TEXT_INVALID_CODE = 'Invalid validation code.'

    def expired(self):
        return dbpool.runOperation('DELETE FROM validations WHERE UNIX_TIMESTAMP() > (UNIX_TIMESTAMP(timestamp) + %d)' % (self.expire_time, ))

    def register(self, key, code=None):
        global dbpool

        if not code:
            code = util.rand_str(self.VALIDATION_CODE_LENGTH, util.CHARSBOX_NUMBERS)

        def _callback(result, callback, code):
            callback.callback(code)
        def _errback(failure, callback):
            callback.errback(failure)

        callback = defer.Deferred()
        d = dbpool.runOperation('INSERT INTO validations VALUES (?, ?, sysdate())', (key, code, ))
        d.addCallback(_callback, callback, code)
        d.addErrback(_errback, callback)
        return callback

    def validate(self, code):
        global dbpool

        if len(code) != self.VALIDATION_CODE_LENGTH or not code.isdigit():
            return defer.fail(RuntimeError(self.TEXT_INVALID_CODE))

        def _fetch(tx, code):
            tx.execute('SELECT userid FROM validations WHERE code = ?', (code, ))
            data = tx.fetchone()
            if data:
                # delete code immediately
                tx.execute('DELETE FROM validations WHERE code = ?', (code, ))
                return data[0]
            else:
                raise RuntimeError(self.TEXT_INVALID_CODE)

        return dbpool.runInteraction(_fetch, code)


class DiskFileStorage(FileStorage):
    """File storage."""

    def __init__(self, path):
        self.path = path

    def init(self):
        try:
            os.makedirs(self.path)
        except:
            pass

    def get(self, name, return_data=True):
        if return_data:
            # TODO
            raise NotImplementedError()
        else:
            fn = os.path.join(self.path, name)
            metafn = fn + '.properties'
            if os.path.isfile(fn) and os.path.isfile(metafn):
                # read metadata
                metadata = {}
                f = open(metafn, 'r')
                for line in f:
                    key, value = line.split('=')
                    metadata[key] = value.strip('\n')
                f.close()

                return fn, metadata['mime'], metadata['md5sum']

    def store_file(self, name, mime, fn):
        # TODO
        raise NotImplementedError()

    def store_data(self, name, mime, data):
        filename = os.path.join(self.path, name)
        f = open(filename, 'w')
        f.write(data)
        f.close()

        # calculate md5sum for file
        # this is intentionally done to verify that the file is not corruputed on disk
        # TODO this should be async
        md5sum = util.md5sum(filename)

        # write metadata file (avoid using ConfigParser, it's a simple file)
        f = open(filename + '.properties', 'w')
        f.write("mime=%s\n" % (mime, ))
        f.write("md5sum=%s\n" % (md5sum, ))
        f.close()

        return filename
