#!/bin/sh
# W40-01: stand-in for `systemctl reload haproxy` inside a container (see Containerfile.haproxy).
[ "$1" = reload ] && [ "$2" = haproxy ] || { echo "systemctl shim: unsupported: $*" >&2; exit 1; }
kill -USR2 "$(cat /run/haproxy.pid)"
