#!/bin/sh
# W19-04 fixture entrypoint: start nginx (the thing the agent discovers and
# renews into), then run kryptkeeper-agent in the foreground so `podman logs`
# captures its registration/inventory/task output for run.sh to assert on.
set -e

nginx -t
nginx

exec /usr/local/bin/kryptkeeper-agent
