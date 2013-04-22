#!/bin/sh
GNUPGHOME=$PWD/.gnupg exec twistd --pidfile c2s.pid -n kontalk-c2s
