#!/usr/bin/env bash
# W12-07: the day-one estate exercise as a script — fresh hub to a
# risk-scored estate report. Companion to docs/guides/day-one-estate.md.
#
# Usage:
#   BASE_URL=http://localhost:8080 TOKEN=<api-token> \
#   [PEM_BUNDLE=./certs.pem] [SCAN_TARGET=10.0.0.0/24] \
#   [ADCS_EXPORT_PATH=/exports/adcs] \
#   bash scripts/day-one-estate.sh
#
# Safe to re-run: imports dedupe by fingerprint, scans are additive,
# sources upsert. No secrets are echoed.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
API="$BASE_URL/api/v1"
: "${TOKEN:?set TOKEN to an API token with admin rights}"

auth=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")
say() { printf '\n== Stage %s — %s\n' "$1" "$2"; }

say 1 "hub reachable"
curl -fsS "${auth[@]}" "$API/certificates?limit=1" >/dev/null
echo "   ok: authenticated against $BASE_URL"

if [ -n "${PEM_BUNDLE:-}" ]; then
  say 2 "bulk import ($PEM_BUNDLE)"
  bundle=$(python3 -c 'import json,sys;print(json.dumps(open(sys.argv[1]).read()))' "$PEM_BUNDLE")
  curl -fsS "${auth[@]}" -X POST "$API/certificates/bulk-import" \
    -d "{\"format\":\"pem\",\"bundle\":$bundle}"
  echo
else
  say 2 "bulk import — skipped (set PEM_BUNDLE to a PEM file)"
fi

if [ -n "${SCAN_TARGET:-}" ]; then
  say 3 "network scan ($SCAN_TARGET)"
  curl -fsS "${auth[@]}" -X POST "$API/discovery/scans" \
    -d "{\"scan_type\":\"network\",\"target\":\"$SCAN_TARGET\"}"
  echo
  echo "   watch progress on the Discovery page"
else
  say 3 "network scan — skipped (set SCAN_TARGET to a CIDR or host:port)"
fi

if [ -n "${ADCS_EXPORT_PATH:-}" ]; then
  say 4 "ADCS export sync ($ADCS_EXPORT_PATH)"
  src=$(curl -fsS "${auth[@]}" -X POST "$API/inventory-sources" \
    -d "{\"name\":\"day-one-adcs\",\"type\":\"adcs_export\",\"config_json\":\"{\\\"export_path\\\":\\\"$ADCS_EXPORT_PATH\\\"}\"}")
  id=$(printf '%s' "$src" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["id"])')
  curl -fsS "${auth[@]}" -X POST "$API/inventory-sources/$id/sync"
  echo
else
  say 4 "ADCS sync — skipped (set ADCS_EXPORT_PATH to an export directory on the hub)"
fi

say 6 "the payoff"
curl -fsS "${auth[@]}" "$API/reports/pqc-migration" | head -c 400
echo
out="kryptkeeper-estate-$(date -u +%F).csv"
curl -fsS "${auth[@]}" "$API/reports/export/inventory?format=csv" -o "$out"
echo "   estate export written to $out"
echo
echo "Done. Dashboard shows the managed/external/unmanaged split;"
echo "day two: POST $API/estate/takeover to start managing what you found."
