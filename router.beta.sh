#!/bin/sh
exec twistd --pidfile router.beta.pid -n kontalk-router -c router.beta.conf
