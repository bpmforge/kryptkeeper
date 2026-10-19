#!/usr/bin/env bash
# W26-12: start a Kryptkeeper hub an F5 BIG-IP VE / Palo Alto VM-Series can reach
# over SCEP. Pattern: tests/live/protocols/run.sh (sections 1 and 1b).
# Runs in the foreground until Ctrl-C. State (token, CA exports) goes to .state/
# (gitignored, mode 0700). Challenges are NEVER written here; see mint-challenge.sh.
set -u
set -o pipefail

usage() {
  cat <<'USAGE'
usage: KK_SCEP_HUB_ADDR=<ip-or-dns the appliance can reach> [HUB_PORT=8443] ./hub-up.sh

Env:
  KK_SCEP_HUB_ADDR  required. Address the appliance uses to reach the hub; it is
                    added to the hub TLS SANs and printed in the SCEP URL.
  HUB_PORT          optional, default 8443.
  KK_HUB_BIN        optional, a prebuilt kryptkeeper binary (else go build).
Requires: go (unless KK_HUB_BIN), curl, openssl, python3.
USAGE
}
case "${1:-}" in -h|--help) usage; exit 0 ;; esac
[ -n "${KK_SCEP_HUB_ADDR:-}" ] || { usage >&2; echo "KK_SCEP_HUB_ADDR is required" >&2; exit 2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
STATE="$HERE/.state"
HUB_PORT="${HUB_PORT:-8443}"
HUB_BASE="https://127.0.0.1:${HUB_PORT}"
umask 077
mkdir -p "$STATE/hub/data"
chmod 700 "$STATE"
CA_PEM="$STATE/hub-ca.pem"
TOKEN="$(openssl rand -hex 24)"
HUB_PID=""
trap '[ -n "$HUB_PID" ] && kill "$HUB_PID" >/dev/null 2>&1; echo; echo "hub stopped"' EXIT INT TERM

if [ -n "${KK_HUB_BIN:-}" ]; then BIN="$KK_HUB_BIN"; else
  BIN="$STATE/kryptkeeper"
  (cd "$REPO_ROOT" && go build -o "$BIN" ./cmd/kryptkeeper) || { echo "go build failed" >&2; exit 1; }
fi
HUB_COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file
export APP_CREDENTIAL_STORE_PASSPHRASE="$(openssl rand -hex 24)" KRYPTKEEPER_KEYSTORE_PASSPHRASE="$(openssl rand -hex 24)"
D="$STATE/hub/data"
export KRYPTKEEPER_DATA_DIR="$D" APP_CA_FILE="$D/cas.json" APP_TEMPLATE_FILE="$D/templates.json" \
  APP_CERTIFICATE_FILE="$D/certificates.json" APP_AUDIT_FILE="$D/audit.json" APP_CERTS_SUMMARY_FILE="$D/certs_summary.json"
export KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="SCEP Appliance UAT Root"
export APP_BIND_ADDR=0.0.0.0 PORT="$HUB_PORT" KRYPTKEEPER_BASE_URL="https://${KK_SCEP_HUB_ADDR}:${HUB_PORT}"
export KRYPTKEEPER_TLS_SELF_ISSUE=true KRYPTKEEPER_TLS_SANS="${KK_SCEP_HUB_ADDR},localhost,127.0.0.1"
export KRYPTKEEPER_SCEP_ENABLED=true

start_hub() {
  "$BIN" >>"$STATE/hub.log" 2>&1 &
  HUB_PID=$!
  for _ in $(seq 1 40); do curl -sSk -o /dev/null "$HUB_BASE/healthz" && return 0; sleep 0.5; done
  echo "hub did not come up; see $STATE/hub.log" >&2; exit 1
}
curlj() { curl -sS --cacert "$CA_PEM" -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }

echo "starting hub (commit $HUB_COMMIT) on :$HUB_PORT"
start_hub
# Bootstrap the hub's own TLS CA the way protocols/run.sh does (EST cacerts).
curl -sSk --max-time 5 -o "$STATE/cacerts.b64" "$HUB_BASE/.well-known/est/cacerts" \
  && openssl base64 -d -A -in "$STATE/cacerts.b64" -out "$STATE/cacerts.p7" \
  && openssl pkcs7 -inform der -in "$STATE/cacerts.p7" -print_certs -out "$CA_PEM" \
  && [ -s "$CA_PEM" ] || { echo "could not export the hub TLS CA" >&2; exit 1; }

# SCEP needs an RSA issuing CA; the bootstrap root is ECDSA and is refused.
SCEP_CA_ID="$(curlj -X POST "$HUB_BASE/api/v1/cas" \
  -d '{"name":"scep-appliance-rsa-root","type":"root","algorithm":"RSA-2048","validity":"10y","subject_cn":"SCEP Appliance RSA Root"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])')" || true
[ -n "$SCEP_CA_ID" ] || { echo "could not create the RSA CA" >&2; exit 1; }

kill "$HUB_PID" >/dev/null 2>&1; wait "$HUB_PID" 2>/dev/null
export KRYPTKEEPER_SCEP_CA_ID="$SCEP_CA_ID"
start_hub
grep -q "SCEP endpoint: /scep" "$STATE/hub.log" || { echo "SCEP not enabled; see $STATE/hub.log" >&2; exit 1; }

curl -sS --cacert "$CA_PEM" "$HUB_BASE/scep?operation=getcacert" -o "$STATE/scep-ca.der"
openssl x509 -inform der -in "$STATE/scep-ca.der" -out "$STATE/scep-ca.pem"
SCEP_FP256="$(openssl x509 -in "$STATE/scep-ca.pem" -noout -fingerprint -sha256 | cut -d= -f2)"
SCEP_FP1="$(openssl x509 -in "$STATE/scep-ca.pem" -noout -fingerprint -sha1 | cut -d= -f2)"

cat >"$STATE/env.sh" <<ENV
HUB_BASE="https://${KK_SCEP_HUB_ADDR}:${HUB_PORT}"
HUB_LOCAL_BASE="$HUB_BASE"
HUB_TOKEN="$TOKEN"
HUB_CA_PEM="$CA_PEM"
HUB_COMMIT="$HUB_COMMIT"
SCEP_CA_ID="$SCEP_CA_ID"
ENV

cat <<INFO

SCEP URL:               https://${KK_SCEP_HUB_ADDR}:${HUB_PORT}/scep
Hub TLS CA (trust it on the appliance): $CA_PEM
SCEP CA cert (DER/PEM): $STATE/scep-ca.der / scep-ca.pem
SCEP CA fingerprint:    SHA-256 $SCEP_FP256
                        SHA-1   $SCEP_FP1   (Palo Alto 'CA-Cert Fingerprint')
Hub commit:             $HUB_COMMIT
Hub log:                $STATE/hub.log (no challenge secrets are logged)

Next: ./mint-challenge.sh <cn> [dns,...] [ttl]   (in another terminal)
Ctrl-C stops the hub.
INFO
wait "$HUB_PID"
