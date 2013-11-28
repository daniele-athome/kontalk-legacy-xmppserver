#!/bin/sh
GNUPGHOME=$PWD/.gnupg.beta exec twistd --pidfile resolver.beta.pid -n kontalk-resolver -c resolver.beta.conf
