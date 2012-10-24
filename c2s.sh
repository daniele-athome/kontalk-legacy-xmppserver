#!/bin/sh
PYTHONPATH=../kontalklib:. exec twistd --pidfile c2s.pid -n kontalk-c2s
