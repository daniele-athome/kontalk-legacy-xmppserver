#!/usr/bin/env python
# Setuptools script for Kontalk XMPP server

from setuptools import setup
from kontalk.xmppserver import version

setup(
    name=version.PACKAGE,
    version=version.VERSION,
    description=version.NAME,
    author=version.AUTHORS[0]['name'],
    author_email=version.AUTHORS[0]['email'],
    url='http://www.kontalk.org',
    packages=[
        'kontalk',
        'kontalk.xmppserver',
        'kontalk.xmppserver.component',
        'kontalk.xmppserver.component.c2s',
        'kontalk.xmppserver.component.sm',
        'kontalk.fileserver',
        'tests',
    ],
    scripts=[],  # TODO: c2s.sh, router.sh, ...
    license='GNU GPL v3',
    requires=['twisted', 'wokkel', 'oursql', 'demjson', 'pyasn1', 'pyopenssl'],
    test_suite='tests'
    #package_data={'': ['data/*.*', 'data/cards/*.jpg']},
)
