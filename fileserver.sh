#!/bin/sh
GNUPGHOME=$PWD/.gnupg exec twistd --pidfile fileserver.pid -n kontalk-fileserver
