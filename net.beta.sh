#!/bin/sh
GNUPGHOME=$PWD/.gnupg.beta exec twistd --pidfile net.beta.pid -n kontalk-net -c net.beta.conf
