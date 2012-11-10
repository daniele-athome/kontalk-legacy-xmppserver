#!/bin/sh
exec twistd --pidfile resolver.beta.pid -n kontalk-resolver -c resolver.beta.conf
