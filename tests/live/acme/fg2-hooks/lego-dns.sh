#!/bin/sh
# lego --dns exec hook (EXEC_PATH) for the FG2 dns-01 step. lego calls
#   present [--] <fqdn> <value>     and     cleanup [--] <fqdn> <value>
# and the hook talks to pebble-challtestsrv's management API (CHALLTEST_API).
# The goacme/lego image is Alpine-based, so busybox wget is the HTTP client.
set -eu
action="${1:-}"
[ $# -gt 0 ] && shift
[ "${1:-}" = "--" ] && shift
fqdn="${1:-}"
value="${2:-}"
case "$action" in
  present)
    path=/set-txt
    body="{\"host\":\"$fqdn\",\"value\":\"$value\"}"
    ;;
  cleanup)
    path=/clear-txt
    body="{\"host\":\"$fqdn\"}"
    ;;
  *)
    exit 0
    ;;
esac
wget -q -O /dev/null --header 'Content-Type: application/json' --post-data "$body" "${CHALLTEST_API}${path}"
