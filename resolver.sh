#!/bin/sh
PYTHONPATH=../kontalklib:. exec twistd --pidfile resolver.pid -n kontalk-resolver
