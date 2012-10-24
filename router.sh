#!/bin/sh
PYTHONPATH=../kontalklib:. exec twistd --pidfile router.pid -n kontalk-router
