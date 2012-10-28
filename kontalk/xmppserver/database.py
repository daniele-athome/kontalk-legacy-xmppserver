# -*- coding: utf-8 -*-
'''Interface to database.'''
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

import time
import oursql

import log, util

def connect_config(servercfg):
    config = servercfg['database']
    return connect(
        config['host'], config['port'],
        config['user'], config['password'],
        config['dbname'], servercfg
    )

def connect(host, port, user, passwd, dbname, servercfg):
    log.debug("connecting to database %s on %s@%s" % (dbname, user, host))
    db = oursql.connect(host=host, port=port, user=user, passwd=passwd, db=dbname)
    return MessengerDb(db, servercfg)

def servers(mdb):
    return ServersDb(mdb._db, mdb._config)

def usercache(mdb):
    return UsercacheDb(mdb._db, mdb._config)


def format_timestamp(ds):
    return ds.strftime('%Y-%m-%d %H:%M:%S')


class MessengerDb:
    '''Generic interface to messenger database.'''
    def __init__(self, db, config):
        self._config = config
        self._db = db

    def execute_update(self, query, args = ()):
        c = self._db.cursor()
        c.execute(query, args)
        n = c.rowcount
        c.close()
        return n

    def execute_query(self, query, args = ()):
        c = self._db.cursor(oursql.DictCursor)
        c.execute(query, args)
        return c

    def get_row(self, query, args = ()):
        c = self.execute_query(query, args)
        data = c.fetchone()
        c.close()
        return data

    def get_rows(self, query, args = ()):
        c = self.execute_query(query, args)
        data = c.fetchall()
        c.close()
        return data

    def get_rows_list(self, query, args = ()):
        c = self.execute_query(query, args)
        data = [row.values()[0] for row in c.fetchall()]
        c.close()
        return data

    def unlock(self):
        return self.execute_update('UNLOCK TABLES')


class ServersDb(MessengerDb):
    '''Interface to the servers table.'''
    def __init__(self, db, config):
        MessengerDb.__init__(self, db, config)

    def get_list(self):
        res = {}
        data = self.get_rows('SELECT * FROM servers')
        for row in data:
            res[row['fingerprint']] = {
                'host' : str(row['host']),
                'c2s' : row['client_port'],
                's2s' : row['serverlink_port'],
                'http' : row['http_port']
            }
        return res

class UsercacheDb(MessengerDb):
    '''Interface to the usercache table.'''
    def __init__(self, db, config):
        MessengerDb.__init__(self, db, config)

    def get(self, userid, exact):
        q = 'SELECT * FROM usercache WHERE userid '
        if exact:
            q += '= ?'
            args = [ userid ]
        else:
            q += 'LIKE ?'
            args = [ userid + '%' ]

        return self.get_row(q + ' ORDER BY timestamp DESC', args)

    def get_generic(self, userid):
        q = 'SELECT * FROM usercache WHERE SUBSTR(userid, 1, ' + str(util.USERID_LENGTH) + ') = ? ORDER BY timestamp DESC'
        return self.get_rows(q, (userid, ))

    def purge_old_entries(self):
        q = 'DELETE FROM usercache WHERE UNIX_TIMESTAMP() > (UNIX_TIMESTAMP(timestamp) + %d)' % (self._config['broker']['usercache.expire'])
        return self.execute_update(q)

    def update(self, userid, timestamp = None, **kwargs):
        args = [ userid ]
        cols = ['userid', 'timestamp']

        if timestamp:
            ts_str = '?'
            args.append(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp)))
        else:
            ts_str = 'sysdate()'

        def add_field(args, cols, data, name):
            if data != None and len(data) == 0:
                data = None
            args.append(data)
            cols.append(name)

        if 'status' in kwargs:
            add_field(args, cols, kwargs['status'], 'status')
        if 'google_registrationid' in kwargs:
            add_field(args, cols, kwargs['google_registrationid'], 'google_registrationid')

        #fmt = [ ts_str, ts_str]
        q = 'INSERT INTO usercache (%s) VALUES (?, %s%s)' % (', '.join(cols), ts_str, ',?' * (len(args) - 1))
        #log.debug('usercache(%s): %s [%s]' % (userid, q, args))
        try:
            return self.execute_update(q, args)
        except:
            fs = [ x + ' = ?' for x in cols[2:] ]
            fs.insert(0, 'timestamp = ' + ts_str)
            q = 'UPDATE usercache SET %s WHERE userid = ?' % ', '.join(fs)
            del args[0]
            args.append(userid)
            #log.debug('usercache(%s): %s [%s]' % (userid, q, args))
            return self.execute_update(q, args)

    def _entry_changed(self, old, new):
        return (
            # timeout expired
            (new['timestamp'] > (old['timestamp'] + self._config['broker']['usercache.validity']))
        )

    def unique_users_count(self):
        q = 'SELECT COUNT(DISTINCT substr(userid,1,40)) CNT FROM usercache'
        rs = self.get_row(q)
        return long(rs['CNT']) if rs else 0
