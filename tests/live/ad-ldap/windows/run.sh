#!/usr/bin/env bash
# filename: tests/live/ad-ldap/windows/run.sh
#
# W24-27: validate the hub's "adcs_live" inventory source against an
# already-provisioned WINDOWS Active Directory DC (no container, no Samba).
# adcs_live binds over LDAP and does a paged search for userCertificate
# (internal/bootstrap/inventory_source_adcs_live.go); K is therefore the number
# of DISTINCT certificates in userCertificate attributes under the search
# base, not the CA's issued-row count. See README.md for the lab setup.
#
# Required env (exit 2 if any is missing; never a silent skip):
#   KK_ADCS_LDAP_URL KK_ADCS_BIND_DN KK_ADCS_BIND_PASSWORD
#   KK_ADCS_SEARCH_BASE KK_ADCS_EXPECTED_K
# Optional: KK_ADCS_FILTER KK_ADCS_PAGE_SIZE (default 1000) KK_ADCS_DC_OS
#   KK_ADCS_DC_COUNT (DC-side count from PowerShell) KK_WRITE_RESULTS=1 KK_KEEP
#
# The bind password is read from the environment only: never echoed, never in
# argv, no `set -x`.
set -u
set -o pipefail

USAGE="usage: KK_ADCS_LDAP_URL=ldaps://dc.<lab>:636 KK_ADCS_BIND_DN=<dn-or-upn> KK_ADCS_BIND_PASSWORD=<pw> KK_ADCS_SEARCH_BASE=<dn> KK_ADCS_EXPECTED_K=<n> [KK_ADCS_FILTER KK_ADCS_PAGE_SIZE KK_ADCS_DC_OS KK_ADCS_DC_COUNT KK_WRITE_RESULTS=1] bash $0"
for v in KK_ADCS_LDAP_URL KK_ADCS_BIND_DN KK_ADCS_BIND_PASSWORD KK_ADCS_SEARCH_BASE KK_ADCS_EXPECTED_K; do
  if [ -z "${!v:-}" ]; then
    echo "missing required env: $v" >&2
    echo "$USAGE" >&2
    exit 2
  fi
done
case "$KK_ADCS_EXPECTED_K" in ''|*[!0-9]*) echo "KK_ADCS_EXPECTED_K must be a non-negative integer" >&2; echo "$USAGE" >&2; exit 2;; esac
K="$KK_ADCS_EXPECTED_K"
PAGE_SIZE="${KK_ADCS_PAGE_SIZE:-1000}"
DC_OS="${KK_ADCS_DC_OS:-unspecified}"
DC_COUNT="${KK_ADCS_DC_COUNT:-}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-adcs.XXXXXX)"
HUB_DIR=/tmp/kk-uat-adcs-hub
HUB_PORT=8097
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
RESULTS_FILE="$REPO_ROOT/docs/release/LIVE_RESULTS_ADCS_v0.12.md"

FAILED=0
ROWS=""
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; ROWS="${ROWS}| $1 | PASS | ${2:-} |"$'\n'; }
FAIL() { echo "FAIL: $*"; FAILED=1; ROWS="${ROWS}| $1 | FAIL | ${2:-} |"$'\n'; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

HUB_PID=""
cleanup() {
  [ -n "${KK_KEEP:-}" ] && { echo "KK_KEEP set: leaving $WORK and $HUB_DIR"; return; }
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
  rm -rf "$WORK" "$HUB_DIR"
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d=d.get(k) if isinstance(d,dict) else None
print("" if d is None else d)' "$1" 2>/dev/null; }
now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

STEP "build + start hub"
rm -rf "$HUB_DIR"; mkdir -p "$HUB_DIR/data"
( cd "$REPO_ROOT" && go build -o "$HUB_DIR/kryptkeeper" ./cmd/kryptkeeper ) || DIE "go build failed"
# adcs_live dials with the system trust store (no per-source CA setting): the
# lab root CA must already be in the host trust store (README, trap).
export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file KRYPTKEEPER_TLS_DISABLE=true \
  APP_CREDENTIAL_STORE_PASSPHRASE="$(openssl rand -hex 24)" \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE="$(openssl rand -hex 24)" \
  KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" \
  APP_CA_FILE="$HUB_DIR/data/cas.json" APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" \
  APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" APP_AUDIT_FILE="$HUB_DIR/data/audit.json" \
  APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA" \
  APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT"
# Refuse to talk to a foreign process squatting on the hub port.
if curl -sS -o /dev/null --max-time 2 "${HUB_BASE}/healthz" 2>/dev/null; then
  DIE "something already listens on 127.0.0.1:${HUB_PORT}; free the port first"
fi
"$HUB_DIR/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
tries=30
until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null; do
  kill -0 "$HUB_PID" 2>/dev/null || DIE "hub exited during startup, see $WORK/hub.log"
  tries=$((tries - 1)); [ $tries -le 0 ] && DIE "hub never answered /api/v1/cas, see $WORK/hub.log"
  sleep 1
done
kill -0 "$HUB_PID" 2>/dev/null || DIE "hub exited during startup, see $WORK/hub.log"
HUB_VER="$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
PASS "hub up" "commit $HUB_VER"

# Build JSON in ONE python call reading secrets from the environment (argv-free).
mk_cred() { # $1=name $2=env var holding the password
  PW_VAR="$2" CRED_NAME="$1" python3 -c 'import json,os
print(json.dumps({"name":os.environ["CRED_NAME"],"credential_type":"api_token","payload":{"password":os.environ[os.environ["PW_VAR"]]}}))'
}
mk_src() { # $1=name $2=credential id
  SRC_NAME="$1" CRED_ID="$2" python3 -c 'import json,os
e=os.environ
cfg={"ldap_url":e["KK_ADCS_LDAP_URL"],"bind_dn":e["KK_ADCS_BIND_DN"],"search_base":e["KK_ADCS_SEARCH_BASE"],"page_size":int(e.get("KK_ADCS_PAGE_SIZE") or 1000)}
if e.get("KK_ADCS_FILTER"): cfg["filter"]=e["KK_ADCS_FILTER"]
print(json.dumps({"name":e["SRC_NAME"],"type":"adcs_live","config_json":json.dumps(cfg),"credential_ref":e["CRED_ID"]}))'
}

STEP "register credential + adcs_live source"
CRED_ID="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "$(mk_cred uat-adcs-bind KK_ADCS_BIND_PASSWORD)" | jget data.id)"
[ -n "$CRED_ID" ] || DIE "credential create failed"
SRC_ID="$(curlj -X POST "${HUB_BASE}/api/v1/inventory-sources" -d "$(mk_src uat-adcs-live "$CRED_ID")" | jget data.id)"
[ -n "$SRC_ID" ] || DIE "inventory source create failed"
PASS "source registered" "page_size=$PAGE_SIZE"

total() { curlj "${HUB_BASE}/api/v1/certificates?origin=synced&limit=1" | jget meta.total; }

STEP "sync 1: expect synced == K ($K)"
T0="$(now_ms)"
R1="$(curlj -X POST "${HUB_BASE}/api/v1/inventory-sources/${SRC_ID}/sync")"
D1=$(( $(now_ms) - T0 ))
S1="$(echo "$R1" | jget data.synced)"; F1="$(echo "$R1" | python3 -c 'import json,sys; d=json.load(sys.stdin).get("data"); print("?" if d is None else len(d.get("failed") or []))' 2>/dev/null)"
TOT1="$(total)"
[ "$S1" = "$K" ] && [ "$F1" = "0" ] && PASS "sync 1 synced == K" "synced=$S1 failed=$F1 ${D1}ms" || FAIL "sync 1 synced == K" "synced=$S1 failed=$F1 want K=$K"
[ "$TOT1" = "$K" ] && PASS "inventory total == K after sync 1" "meta.total=$TOT1" || FAIL "inventory total == K after sync 1" "meta.total=$TOT1"

STEP "sync 2: expect +0 (synced 0, skipped K)"
T0="$(now_ms)"
R2="$(curlj -X POST "${HUB_BASE}/api/v1/inventory-sources/${SRC_ID}/sync")"
D2=$(( $(now_ms) - T0 ))
S2="$(echo "$R2" | jget data.synced)"; K2="$(echo "$R2" | jget data.skipped)"
TOT2="$(total)"
[ "$S2" = "0" ] && [ "$K2" = "$K" ] && PASS "sync 2 adds 0 duplicates" "synced=$S2 skipped=$K2 ${D2}ms" || FAIL "sync 2 adds 0 duplicates" "synced=$S2 skipped=$K2 want skipped=$K"
[ "$TOT2" = "$K" ] && PASS "inventory total unchanged after sync 2" "meta.total=$TOT2" || FAIL "inventory total unchanged after sync 2" "meta.total=$TOT2"

if [ -n "$DC_COUNT" ]; then
  [ "$DC_COUNT" = "$K" ] && PASS "DC-side count (PowerShell) == K" "dc_count=$DC_COUNT" || FAIL "DC-side count (PowerShell) == K" "dc_count=$DC_COUNT expected_k=$K"
fi

STEP "negative: wrong bind password"
BADPW="wrong-$(openssl rand -hex 8)"
export KK_ADCS_BADPW="$BADPW"
BADCRED="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "$(mk_cred uat-adcs-bad KK_ADCS_BADPW)" | jget data.id)"
BADSRC="$(curlj -X POST "${HUB_BASE}/api/v1/inventory-sources" -d "$(mk_src uat-adcs-bad "$BADCRED")" | jget data.id)"
CODE="$(curlj -o "$WORK/bad.body" -w '%{http_code}' -X POST "${HUB_BASE}/api/v1/inventory-sources/${BADSRC}/sync")"
if [ "${CODE:0:1}" != "2" ] && ! grep -qF "$BADPW" "$WORK/bad.body" "$WORK/hub.log"; then
  PASS "wrong password rejected, secret not leaked" "http=$CODE"
else
  FAIL "wrong password rejected, secret not leaked" "http=$CODE"
fi
R3="$(curlj -X POST "${HUB_BASE}/api/v1/inventory-sources/${SRC_ID}/sync")"
[ "$(echo "$R3" | jget data.synced)" = "0" ] && [ "$(echo "$R3" | jget data.skipped)" = "$K" ] \
  && PASS "first source unaffected" "skipped=$K" || FAIL "first source unaffected" "$(echo "$R3" | head -c 200)"
unset KK_ADCS_BADPW

if [ "$FAILED" -eq 0 ]; then VERDICT="PASS"; else VERDICT="FAIL"; fi
RESULTS="# Live validation W24-27: ADCS LDAP inventory sync vs Windows DC - v0.12

Date: $(date -u +%Y-%m-%d). Hub commit: $HUB_VER. Harness: \`tests/live/ad-ldap/windows/run.sh\`.
DC OS: $DC_OS. Search base: $KK_ADCS_SEARCH_BASE. Page size: $PAGE_SIZE.

## Verdict: $VERDICT

| Field | Value |
|---|---|
| K (expected distinct certs) | $K |
| DC-side count (PowerShell) | ${DC_COUNT:-not supplied} |
| Sync 1 synced / failed / duration | ${S1:-?} / ${F1:-?} / ${D1:-?} ms |
| Sync 2 synced / skipped / duration | ${S2:-?} / ${K2:-?} / ${D2:-?} ms |
| Inventory meta.total after sync 1 / 2 | ${TOT1:-?} / ${TOT2:-?} |

## Steps

| Step | Result | Evidence |
|---|---|---|
${ROWS}
Samba is unsupported for adcs_live (see tests/live/ad-ldap/README.md)."
echo; echo "$RESULTS"
if [ "${KK_WRITE_RESULTS:-}" = "1" ]; then
  printf '%s\n' "$RESULTS" > "$RESULTS_FILE" && echo "wrote $RESULTS_FILE"
fi

STEP "result"
if [ "$FAILED" -eq 0 ]; then echo "ALL PASS"; exit 0; else echo "FAILED"; exit 1; fi
