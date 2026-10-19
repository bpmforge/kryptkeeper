#!/usr/bin/env bash
# W28-18: idempotent seed for the posture-pages journey. 1,000 imported
# certificates (900 EC P-256, 100 RSA-2048) plus 5 hub-issued, 3 of them revoked.
# Needs APP_BOOTSTRAP_TOKEN; the token is never printed.
set -euo pipefail

: "${APP_BOOTSTRAP_TOKEN:?set APP_BOOTSTRAP_TOKEN}"
BASE="${KK_E2E_BASE_URL:-http://localhost:3000}"
API="$BASE/api/v1"
AUTH="Authorization: Bearer $APP_BOOTSTRAP_TOKEN"
WORK="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.seed"
mkdir -p "$WORK"

for tool in openssl python3 curl; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done

jget() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }

echo "waiting for $API/cas"
for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" "$API/cas" || true)"
  [ "$code" = "200" ] && break
  sleep 2
done
[ "$code" = "200" ] || { echo "hub not ready (last http $code)" >&2; exit 1; }

total="$(curl -sS -H "$AUTH" "$API/certificates?limit=1" | jget 'd["meta"]["total"]')"
revoked="$(curl -sS -H "$AUTH" "$API/certificates?limit=1&status=revoked" | jget 'd["meta"]["total"]')"
if [ "$total" -ge 1000 ] && [ "$revoked" -ge 3 ]; then
  echo "already seeded (certificates total=$total revoked=$revoked)"
  exit 0
fi

imported=0
if [ "$total" -lt 1000 ]; then
echo "generating 1000 certificates"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ec.key" 2>/dev/null
openssl genrsa -out "$WORK/rsa.key" 2048 2>/dev/null
rm -f "$WORK"/bundle-*.pem
for i in $(seq 1 1000); do
  if [ "$i" -le 900 ]; then key="$WORK/ec.key"; else key="$WORK/rsa.key"; fi
  chunk=$(( (i - 1) / 500 + 1 ))
  openssl req -x509 -new -key "$key" -subj "/CN=e2e-$i.example.test" \
    -set_serial "$i" -days 30 -addext "subjectAltName=DNS:e2e-$i.example.test" \
    >>"$WORK/bundle-$chunk.pem" 2>/dev/null
done

for chunk in 1 2; do
  python3 -c 'import json,sys; print(json.dumps({"format":"pem","bundle":open(sys.argv[1]).read()}))' \
    "$WORK/bundle-$chunk.pem" >"$WORK/bundle-$chunk.json"
  n="$(curl -sS --max-time 300 -H "$AUTH" -H 'Content-Type: application/json' \
    --data-binary "@$WORK/bundle-$chunk.json" "$API/certificates/bulk-import" | jget 'd["data"]["imported"]')"
  imported=$(( imported + n ))
done
[ "$imported" -eq 1000 ] || { echo "imported $imported, expected 1000" >&2; exit 1; }
fi

ca_id="$(curl -sS -H "$AUTH" "$API/cas" | jget 'd["data"][0]["id"]')"
tpl_id="$(curl -sS -H "$AUTH" "$API/templates?active=true" | jget '(d["data"] or [{"id":""}])[0]["id"]')"
if [ -z "$tpl_id" ]; then
  tpl_id="$(curl -sS -H "$AUTH" -H 'Content-Type: application/json' -X POST "$API/templates" \
    -d '{"name":"e2e-posture","display_name":"e2e posture","allowed_algorithms":["ECDSA"],"key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"validity_period":"P30D","active":true}' | jget 'd["data"]["id"]')"
fi

fps=()
for i in 1 2 3 4 5; do
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$WORK/issued-$i.key" -subj "/CN=e2e-issued-$i.example.test" \
    -addext "subjectAltName=DNS:e2e-issued-$i.example.test" -out "$WORK/issued-$i.csr" 2>/dev/null
  python3 -c 'import json,sys; print(json.dumps({"ca_id":sys.argv[1],"template_id":sys.argv[2],"csr_pem":open(sys.argv[3]).read()}))' \
    "$ca_id" "$tpl_id" "$WORK/issued-$i.csr" >"$WORK/issue-$i.json"
  out="$WORK/issue-$i.out"
  code="$(curl -sS -o "$out" -w '%{http_code}' -H "$AUTH" -H 'Content-Type: application/json' \
    --data-binary "@$WORK/issue-$i.json" "$API/certificates")"
  [ "$code" = "201" ] || { echo "issue $i: http $code (template needs no approval gate)" >&2; exit 1; }
  fps+=("$(jget 'd["data"]["fingerprint_sha256"]' <"$out")")
done

for i in 0 1 2; do
  code="$(curl -sS -o /dev/null -w '%{http_code}' -H "$AUTH" -H 'Content-Type: application/json' \
    -d '{"reason_code":1,"reason_text":"e2e"}' "$API/certificates/${fps[$i]}/revoke")"
  [ "$code" = "200" ] || { echo "revoke ${fps[$i]}: http $code" >&2; exit 1; }
done

total="$(curl -sS -H "$AUTH" "$API/certificates?limit=1" | jget 'd["meta"]["total"]')"
echo "seeded: imported=$imported issued=5 revoked=3 certificates_total=$total"
