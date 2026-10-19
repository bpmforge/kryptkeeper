#!/bin/sh
# certbot --manual-auth-hook for the FG2 dns-01 step: publishes the challenge
# TXT record in pebble-challtestsrv, which the hub's resolver is pointed at.
# certbot sets CERTBOT_DOMAIN and CERTBOT_VALIDATION; CHALLTEST_API is passed in
# by fg2-run.sh. certbot's image is Python-based, so python3 is the HTTP client.
set -eu
python3 - "$CHALLTEST_API" "_acme-challenge.${CERTBOT_DOMAIN}." "$CERTBOT_VALIDATION" <<'PY'
import json, sys, urllib.request
api, host, value = sys.argv[1:4]
req = urllib.request.Request(api + "/set-txt", data=json.dumps({"host": host, "value": value}).encode(),
                             headers={"Content-Type": "application/json"}, method="POST")
urllib.request.urlopen(req, timeout=10).read()
PY
# Give the (stub) resolver a moment; challtestsrv answers immediately.
sleep 2
