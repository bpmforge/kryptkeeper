#!/bin/sh
# W27-16 fault injection: fails ONE "-s reload" when /etc/kk-fail-reload
# exists, then removes the marker so the restore's best-effort reload works.
# Every other invocation (e.g. `nginx -t`) is the real nginx.
if [ "$1" = "-s" ] && [ -f /etc/kk-fail-reload ]; then
  rm -f /etc/kk-fail-reload; echo "injected flip failure" >&2; exit 1
fi
exec /usr/sbin/nginx "$@"
