# -*- coding: utf-8 -*-
'''Twisted logging to Python loggin bridge.'''
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


from twisted.python import log

LEVEL_DEBUG = 1
LEVEL_INFO = 1 << 1
LEVEL_WARN = 1 << 2
LEVEL_ERROR = 1 << 3
# all levels
LEVEL_ALL = LEVEL_DEBUG | LEVEL_INFO | LEVEL_WARN | LEVEL_ERROR

level = 0

def init(cfg):
    '''Initializes logging system.'''
    global level
    l = cfg['log.levels']
    if 'ALL' in l:
        level = LEVEL_ALL
    else:
        if 'DEBUG' in l:
            level |= LEVEL_DEBUG
        if 'INFO' in l:
            level |= LEVEL_INFO
        if 'WARN' in l:
            level |= LEVEL_WARN
        if 'ERROR' in l:
            level |= LEVEL_ERROR

def debug(*args, **kwargs):
    global level
    if level & LEVEL_DEBUG:
        log.msg(*args, **kwargs)

def info(*args, **kwargs):
    global level
    if level & LEVEL_INFO:
        log.msg(*args, **kwargs)

def warn(*args, **kwargs):
    global level
    if level & LEVEL_WARN:
        log.msg(*args, **kwargs)

def error(*args, **kwargs):
    global level
    if level & LEVEL_ERROR:
        log.msg(*args, **kwargs)
