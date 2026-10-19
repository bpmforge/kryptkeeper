#!/usr/bin/env bash
# W26-12: mint ONE one-time SCEP challenge (POST /api/v1/scep/challenges).
# The secret is printed to the terminal once and is never written to a file.
set -u
set -o pipefail

usage() {
  cat <<'USAGE'
usage: ./mint-challenge.sh <common_name> [dns_names_comma_separated] [ttl]

  common_name  host name the appliance will request (no wildcards)
  dns_names    default: the common name
  ttl          Go duration; default 1h, max 24h. The API has NO lower bound beyond
               "positive" (internal/bootstrap/handlers_scep_challenges.go), so use
               1m for the expiry test and wait it out; never edit the hub clock.

Reads .state/env.sh written by hub-up.sh (HUB_BASE, HUB_TOKEN, HUB_CA_PEM).
Requires: curl, python3.
USAGE
}
case "${1:-}" in -h|--help|"") usage; [ -z "${1:-}" ] && exit 2; exit 0 ;; esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/.state/env.sh" ] || { echo "no .state/env.sh: run hub-up.sh first" >&2; exit 2; }
# shellcheck disable=SC1091
. "$HERE/.state/env.sh"
CN="$1"; DNS="${2:-$1}"; TTL="${3:-1h}"

BODY="$(CN="$CN" DNS="$DNS" TTL="$TTL" python3 -c '
import json,os
print(json.dumps({"common_name":os.environ["CN"],"dns_names":[d for d in os.environ["DNS"].split(",") if d],"ttl":os.environ["TTL"]}))')"
RESP="$(curl -sS --cacert "$HUB_CA_PEM" -H "Authorization: Bearer $HUB_TOKEN" -H 'Content-Type: application/json' \
  -X POST "$HUB_LOCAL_BASE/api/v1/scep/challenges" -d "$BODY")" || { echo "request failed" >&2; exit 1; }
printf '%s' "$RESP" | python3 -c '
import json,sys
d=json.load(sys.stdin)
if "data" not in d or "challenge" not in d["data"]:
    sys.exit("mint failed: "+json.dumps({k:v for k,v in d.items() if k!="data"}))
x=d["data"]
print("id:        ", x.get("id"))
print("bound CN:  ", x.get("common_name"))
print("expires:   ", x.get("expires_at"))
print("challenge: ", x["challenge"], " <- shown once; not saved anywhere")
'
