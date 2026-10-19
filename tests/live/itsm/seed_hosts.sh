#!/usr/bin/env bash
# W32-18: issue N certificates for host-001..host-N.itsm.test through the hub
# and, in stub mode, load a matching N-row CI list into the stand-in's cmdb_ci
# table (fqdn, owned_by, support_group). In real mode the CI rows live in the
# human's ServiceNow instance: this script writes the host list to $OUT/hosts.txt
# and stops, and the operator loads them (see README.md "Real mode").
#
# Usage: seed_hosts.sh <hub_base> <admin_token> <out_dir> [stub_base]
# Env:   N (default 100)
set -u
set -o pipefail

HUB="${1:?hub base url}"; TOKEN="${2:?token}"; OUT="${3:?out dir}"; STUB="${4:-}"
N="${N:-100}"
mkdir -p "$OUT"
api() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }

CA_ID="$(api "$HUB/api/v1/cas" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"][0]["id"])')"
[ -n "$CA_ID" ] || { echo "seed_hosts: no CA" >&2; exit 1; }

TPL="$(api -X POST "$HUB/api/v1/templates" -d '{
  "name": "itsm-live-hosts", "display_name": "W32-18 ITSM live hosts",
  "allowed_algorithms": ["ECDSA"], "key_usage": ["digitalSignature"],
  "extended_key_usage": ["serverAuth"], "validity_period": "720h", "active": true}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
[ -n "$TPL" ] || { echo "seed_hosts: template create failed" >&2; exit 1; }

: > "$OUT/hosts.txt"
issued=0
for i in $(seq 1 "$N"); do
  h="$(printf 'host-%03d.itsm.test' "$i")"
  openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/h.key" 2>/dev/null
  openssl req -new -key "$OUT/h.key" -subj "/CN=$h" -addext "subjectAltName=DNS:$h" -out "$OUT/h.csr" 2>/dev/null
  body="$(python3 -c "import json,sys; print(json.dumps({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}))" "$CA_ID" "$TPL" "$OUT/h.csr")"
  fp="$(api -X POST "$HUB/api/v1/certificates" -d "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["fingerprint_sha256"])' 2>/dev/null)"
  [ -n "$fp" ] && issued=$((issued + 1)) && echo "$h" >> "$OUT/hosts.txt"
done
rm -f "$OUT/h.key" "$OUT/h.csr"
echo "seed_hosts: issued $issued/$N certificates"
[ "$issued" = "$N" ] || exit 1

if [ -n "$STUB" ]; then
  python3 - "$N" <<'PY' > "$OUT/cmdb_ci.json"
import json, sys
n = int(sys.argv[1])
print(json.dumps([{"fqdn": "host-%03d.itsm.test" % i, "name": "host-%03d" % i,
                   "owned_by": "owner-%03d@itsm.test" % i, "support_group": "team-%02d" % (i % 10)}
                  for i in range(1, n + 1)]))
PY
  curl -sS ${STUB_CACERT:+--cacert "$STUB_CACERT"} -X POST "$STUB/_ctl/cmdb" -d @"$OUT/cmdb_ci.json" >/dev/null || { echo "seed_hosts: stand-in cmdb load failed" >&2; exit 1; }
  echo "seed_hosts: loaded $N CI rows into the stand-in"
fi
