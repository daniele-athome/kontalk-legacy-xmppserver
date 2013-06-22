#!/bin/sh
GNUPGHOME=$PWD/.gnupg-cache exec twistd --pidfile resolver.pid -n kontalk-resolver
