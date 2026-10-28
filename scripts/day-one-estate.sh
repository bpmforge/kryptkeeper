#!/usr/bin/env bash
# W12-07 / W24-37: the day-one estate exercise as a script — fresh hub to a
# risk-scored estate report, then a count check. Companion to
# docs/guides/day-one-estate.md.
#
# Usage:
#   BASE_URL=http://localhost:8080 TOKEN=<api-token> \
#   [PEM_BUNDLE=./certs.pem] [SCAN_TARGET=10.0.0.0/24] \
#   [ADCS_EXPORT_PATH=/exports/adcs] \
#   [EXPECT_TOTAL=n EXPECT_MANAGED=n EXPECT_EXTERNAL=n EXPECT_UNMANAGED=n] \
#   [CACERT=./ca.pem] [SCAN_WAIT_SECONDS=600] \
#   bash scripts/day-one-estate.sh
#
# CACERT is the hub's TLS CA (Compose serves https with its own root; see
# getting-started.md for exporting ca.pem). The scan stage waits, up to
# SCAN_WAIT_SECONDS, for its scan job to finish and for every certificate it
# mapped to reach the estate, so verify counts what it found.
#
# Stages and exit codes: hub=10 import=20 scan=30 sync=40 report=50 verify=60.
# Any other failure exits 1 and names CURRENT_STAGE. Set
# KK_DAYONE_INJECT_FAIL=<stage> to force that stage to fail (tests the
# failure path; fires before any network call).
#
# Safe to re-run: imports dedupe by fingerprint, scans are additive,
# sources upsert. No secrets are echoed.
set -Eeuo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
API="$BASE_URL/api/v1"
: "${TOKEN:?set TOKEN to an API token with admin rights}"

auth=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")
if [ -n "${CACERT:-}" ]; then auth+=(--cacert "$CACERT"); fi
CURRENT_STAGE=init

say() { CURRENT_STAGE="$2"; printf '\n== Stage %s — %s: %s\n' "$1" "$2" "$3"; }
fail() { echo "FAILED stage=$1 exit=$2" >&2; exit "$2"; }
# shellcheck disable=SC2154
trap 'rc=$?; echo "FAILED stage=$CURRENT_STAGE exit=$rc" >&2; exit "$rc"' ERR
maybe_inject() {
  if [ "${KK_DAYONE_INJECT_FAIL:-}" = "$1" ]; then
    echo "INJECTED FAILURE at stage=$1" >&2
    fail "$1" "$2"
  fi
}

# Injection preflight: so the failure path is testable with no hub running,
# the named stage fails before any network call is made.
case "${KK_DAYONE_INJECT_FAIL:-}" in
  hub) CURRENT_STAGE=hub; maybe_inject hub 10 ;;
  import) CURRENT_STAGE=import; maybe_inject import 20 ;;
  scan) CURRENT_STAGE=scan; maybe_inject scan 30 ;;
  sync) CURRENT_STAGE=sync; maybe_inject sync 40 ;;
  report) CURRENT_STAGE=report; maybe_inject report 50 ;;
  verify) CURRENT_STAGE=verify; maybe_inject verify 60 ;;
  "") ;;
  *) echo "unknown KK_DAYONE_INJECT_FAIL stage: ${KK_DAYONE_INJECT_FAIL}" >&2; exit 2 ;;
esac

today="$(date -u +%F)"

say 1 hub "hub reachable"
maybe_inject hub 10
curl -fsS "${auth[@]}" "$API/certificates?limit=1" >/dev/null || fail hub 10
echo "   ok: authenticated against $BASE_URL"

say 2 import "bulk import (${PEM_BUNDLE:-skipped})"
maybe_inject import 20
if [ -n "${PEM_BUNDLE:-}" ]; then
  bundle=$(python3 -c 'import json,sys;print(json.dumps(open(sys.argv[1]).read()))' "$PEM_BUNDLE") || fail import 20
  curl -fsS "${auth[@]}" -X POST "$API/certificates/bulk-import" \
    -d "{\"format\":\"pem\",\"bundle\":$bundle}" || fail import 20
  echo
else
  echo "   skipped (set PEM_BUNDLE to a PEM file)"
fi

say 3 scan "network scan (${SCAN_TARGET:-skipped})"
maybe_inject scan 30
if [ -n "${SCAN_TARGET:-}" ]; then
  job=$(curl -fsS "${auth[@]}" -X POST "$API/discovery/scans" \
    -d "{\"scan_type\":\"full\",\"target\":\"$SCAN_TARGET\"}") || fail scan 30
  job_id=$(printf '%s' "$job" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["scan_job"]["id"])') || fail scan 30
  echo "   scan job $job_id started; waiting up to ${SCAN_WAIT_SECONDS:-600}s (progress on the Discovery page)"
  deadline=$(( $(date +%s) + ${SCAN_WAIT_SECONDS:-600} ))
  while :; do
    status=$(curl -fsS "${auth[@]}" "$API/discovery/scan-jobs" | python3 -c '
import json,sys
jobs=json.load(sys.stdin)["data"]["scan_jobs"]
print(next((j["status"] for j in jobs if j["id"]==sys.argv[1]), "missing"))' "$job_id") || fail scan 30
    case "$status" in
      completed) echo "   scan completed"; break ;;
      queued|running) ;;
      *) echo "   scan job ended as $status" >&2; fail scan 30 ;;
    esac
    [ "$(date +%s)" -lt "$deadline" ] || { echo "   scan still $status after ${SCAN_WAIT_SECONDS:-600}s" >&2; fail scan 30; }
    sleep 5
  done
  # A completed job's certificates reach the inventory a few seconds later.
  # Wait until every certificate discovery mapped is an estate row, so the
  # reports below count them.
  # A scan can also map a certificate the estate already holds under another
  # origin (the hub's own, say), so a total that holds still for three reads
  # also ends the wait.
  last=-1; steady=0
  while :; do
    mapped=$(curl -fsS "${auth[@]}" "$API/discovery/summary" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["mapped_certificates"])') || fail scan 30
    read -r found total < <(curl -fsS "${auth[@]}" "$API/reports/estate" | python3 -c 'import json,sys;d=json.load(sys.stdin)["data"];print(d["by_origin"]["discovered"], d["total"])') || fail scan 30
    [ "$found" -ge "$mapped" ] && { echo "   $found discovered certificates in the estate"; break; }
    if [ "$total" = "$last" ]; then steady=$((steady + 1)); else steady=0; last=$total; fi
    [ "$steady" -ge 3 ] && { echo "   $found of $mapped mapped certificates are discovered rows; estate steady at $total"; break; }
    [ "$(date +%s)" -lt "$deadline" ] || { echo "   only $found of $mapped discovered certificates reached the estate" >&2; fail scan 30; }
    sleep 2
  done
else
  echo "   skipped (set SCAN_TARGET to a CIDR or host:port)"
fi

say 4 sync "ADCS export sync (${ADCS_EXPORT_PATH:-skipped})"
maybe_inject sync 40
if [ -n "${ADCS_EXPORT_PATH:-}" ]; then
  src=$(curl -fsS "${auth[@]}" -X POST "$API/inventory-sources" \
    -d "{\"name\":\"day-one-adcs\",\"type\":\"adcs_export\",\"config_json\":\"{\\\"export_path\\\":\\\"$ADCS_EXPORT_PATH\\\"}\"}") || fail sync 40
  id=$(printf '%s' "$src" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["id"])') || fail sync 40
  curl -fsS "${auth[@]}" -X POST "$API/inventory-sources/$id/sync" || fail sync 40
  echo
else
  echo "   skipped (set ADCS_EXPORT_PATH to an export directory on the hub)"
fi

say 6 report "the payoff"
maybe_inject report 50
# Saved first, then shown: piping curl into head would fail under pipefail
# whenever the report is longer than the preview.
pqc="kryptkeeper-pqc-$today.json"
curl -fsS "${auth[@]}" "$API/reports/pqc-migration" -o "$pqc" || fail report 50
head -c 400 "$pqc"
echo
csv="kryptkeeper-estate-$today.csv"
pdf="kryptkeeper-estate-$today.pdf"
estate_json="kryptkeeper-estate-$today.json"
curl -fsS "${auth[@]}" "$API/reports/export/inventory?format=csv" -o "$csv" || fail report 50
curl -fsS "${auth[@]}" "$API/reports/estate?format=pdf" -o "$pdf" || fail report 50
curl -fsS "${auth[@]}" "$API/reports/estate" -o "$estate_json" || fail report 50
echo "   written: $csv $pdf $estate_json"

say 7 verify "estate report equals dashboard (and seeded counts, if EXPECT_* set)"
maybe_inject verify 60
dash=$(curl -fsS "${auth[@]}" "$API/dashboard/summary") || fail verify 60
DASH="$dash" python3 - "$estate_json" <<'PY' || fail verify 60
import json, os, sys
estate = json.load(open(sys.argv[1]))
estate = estate.get("data", estate)
by_state = estate.get("by_state", {})
certs = json.loads(os.environ["DASH"])["data"]["certificates"]
bad = []
for k in ("managed", "external", "unmanaged"):
    if int(by_state.get(k, 0)) != int(certs.get(k, 0)):
        bad.append(f"{k}: estate={by_state.get(k, 0)} dashboard={certs.get(k, 0)}")
actual = {"total": estate.get("total"), "managed": by_state.get("managed", 0),
          "external": by_state.get("external", 0), "unmanaged": by_state.get("unmanaged", 0)}
for k in ("total", "managed", "external", "unmanaged"):
    want = os.environ.get("EXPECT_" + k.upper())
    if want not in (None, "") and int(actual[k] or 0) != int(want):
        bad.append(f"{k}: expected={want} estate={actual[k]}")
print("   estate:", actual)
if bad:
    print("   MISMATCH: " + "; ".join(bad), file=sys.stderr)
    sys.exit(1)
print("   counts verified")
PY
CURRENT_STAGE=complete
echo
echo "Done. Dashboard shows the managed/external/unmanaged split;"
echo "day two: POST $API/estate/takeover to start managing what you found."
