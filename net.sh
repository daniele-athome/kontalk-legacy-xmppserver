#!/bin/sh
GNUPGHOME=$PWD/.gnupg exec twistd --pidfile net.pid -n kontalk-net
