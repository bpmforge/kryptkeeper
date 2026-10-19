#!/usr/bin/env bash
# filename: tests/live/inventory-sources/run.sh
#
# W24-28: real-vendor inventory sync UAT.
#   - DigiCert CertCentral SANDBOX (needs KK_DIGICERT_API_KEY; named SKIP otherwise)
#   - Sectigo, Entrust, AWS Private CA, Google CAS against local recorded-fixture
#     servers (fixture_server.py), plus a per-source isolation check.
# Each source is synced twice: sync 1 imports N, sync 2 adds 0 (skipped == N).
#
# Env: KK_DIGICERT_API_KEY (optional) KK_DIGICERT_BASE_URL (default
#   https://demo.digicert.com) KK_DIGICERT_EXPECTED_ORDERS (optional override)
#   KK_INVSRC_FIXTURE_PORT (default 8099) KK_KEEP
#
# EGRESS TRAP: the hub's inventory HTTP client blocks loopback (only a
# test-only var allows it; production never sets it), so the fixture server
# binds a non-loopback RFC1918 address. With none available the four fixture
# vendors are SKIPPED with a named reason (never a silent pass). Credentials
# come from the environment / are generated at run time and never printed.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-invsrc.XXXXXX)"
HUB_DIR=/tmp/kk-uat-invsrc-hub
HUB_PORT=8098
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
FIX_PORT="${KK_INVSRC_FIXTURE_PORT:-8099}"
TOKEN=uat-token
DC_BASE="${KK_DIGICERT_BASE_URL:-https://demo.digicert.com}"
DC_KEY="${KK_DIGICERT_API_KEY:-}"

FAILED=0
SKIPPED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
SKIP() { echo "SKIP $*"; SKIPPED=$((SKIPPED + 1)); }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

HUB_PID=""; FIX_PID=""
cleanup() {
  [ -n "${KK_KEEP:-}" ] && { echo "KK_KEEP set: leaving $WORK and $HUB_DIR"; return; }
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
  [ -n "$FIX_PID" ] && kill "$FIX_PID" 2>/dev/null || true
  rm -rf "$WORK" "$HUB_DIR"
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d=d.get(k) if isinstance(d,dict) else None
print("" if d is None else d)' "$1" 2>/dev/null; }
nfailed() { python3 -c 'import json,sys
d=json.load(sys.stdin).get("data")
print("?" if d is None else len(d.get("failed") or []))' 2>/dev/null; }
synced_total() { curlj "${HUB_BASE}/api/v1/certificates?origin=synced&limit=1" | jget meta.total; }

# --- non-loopback private address for the fixture server -----------------
FIX_IP=""
for cand in "$(ipconfig getifaddr en0 2>/dev/null)" "$(hostname -I 2>/dev/null | awk '{print $1}')"; do
  case "$cand" in
    127.*|169.254.*|"") ;;
    10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) FIX_IP="$cand"; break;;
  esac
done

# --- hub ------------------------------------------------------------------
STEP "build + start hub"
rm -rf "$HUB_DIR"; mkdir -p "$HUB_DIR/data"
( cd "$REPO_ROOT" && go build -o "$HUB_DIR/kryptkeeper" ./cmd/kryptkeeper ) || DIE "go build failed"
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
# Never use a foreign process squatting on the hub port.
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
PASS "hub answering on $HUB_BASE"

# create_cred NAME PAYLOAD_JSON -> id.  The payload JSON is built by the caller
# from environment variables inside python, never from argv.
create_cred() {
  curlj -X POST "${HUB_BASE}/api/v1/credentials" \
    -d "$(CNAME="$1" CPAYLOAD="$2" python3 -c 'import json,os; print(json.dumps({"name":os.environ["CNAME"],"credential_type":"api_token","payload":json.loads(os.environ["CPAYLOAD"])}))')" | jget data.id
}
# create_src NAME TYPE CONFIG_JSON CRED_ID -> id
create_src() {
  curlj -X POST "${HUB_BASE}/api/v1/inventory-sources" \
    -d "$(SNAME="$1" STYPE="$2" SCFG="$3" SCRED="$4" python3 -c 'import json,os; e=os.environ; print(json.dumps({"name":e["SNAME"],"type":e["STYPE"],"config_json":e["SCFG"],"credential_ref":e["SCRED"]}))')" | jget data.id
}
sync_src() { curlj -X POST "${HUB_BASE}/api/v1/inventory-sources/$1/sync"; }

# check_twice LABEL SRC_ID EXPECT_N [mode]
#   mode "exact": sync1 synced == N.  mode "total": sync1 synced+skipped == N (DigiCert).
# Asserts failed == [], sync 2 synced == 0 and skipped == N, and that the
# origin=synced total changes by exactly N on sync 1 and 0 on sync 2.
check_twice() {
  local label="$1" id="$2" n="$3" mode="${4:-exact}" t0 t1 t2 r1 r2 s1 k1 s2 k2
  t0="$(synced_total)"
  r1="$(sync_src "$id")"; t1="$(synced_total)"
  s1="$(echo "$r1" | jget data.synced)"; k1="$(echo "$r1" | jget data.skipped)"
  if [ "$mode" = total ]; then
    [ "$(( ${s1:-0} + ${k1:-0} ))" = "$n" ] && [ "$(echo "$r1" | nfailed)" = 0 ] \
      && PASS "$label sync 1: synced+skipped == $n" || FAIL "$label sync 1 want $n: $(echo "$r1" | head -c 300)"
  else
    [ "$s1" = "$n" ] && [ "$(echo "$r1" | nfailed)" = 0 ] \
      && PASS "$label sync 1: synced == $n" || FAIL "$label sync 1 want synced=$n: $(echo "$r1" | head -c 300)"
  fi
  r2="$(sync_src "$id")"; t2="$(synced_total)"
  s2="$(echo "$r2" | jget data.synced)"; k2="$(echo "$r2" | jget data.skipped)"
  [ "$s2" = 0 ] && [ "$k2" = "$n" ] \
    && PASS "$label sync 2: synced 0, skipped $n (0 duplicates)" || FAIL "$label sync 2 want synced=0 skipped=$n: $(echo "$r2" | head -c 300)"
  [ "$t2" = "$t1" ] && [ -n "$s1" ] && [ "$(( ${t1:-0} - ${t0:-0} ))" = "$s1" ] \
    && PASS "$label inventory total: +${s1} then unchanged ($t0 -> $t1 -> $t2)" || FAIL "$label inventory total $t0 -> $t1 -> $t2 (synced1=$s1)"
}

# --- DigiCert sandbox ------------------------------------------------------
STEP "digicert sandbox"
if [ -z "$DC_KEY" ]; then
  SKIP "digicert-sandbox: KK_DIGICERT_API_KEY not set"
else
  echo "digicert key set: yes (base $DC_BASE)"
  EXPECT="${KK_DIGICERT_EXPECTED_ORDERS:-}"
  if [ -z "$EXPECT" ]; then
    # Independent ground truth with the same filter digicertSource.Fetch applies
    # (certificate.id != 0). The key goes to curl via stdin config, not argv.
    EXPECT="$(printf 'header = "X-DC-DEVKEY: %s"\n' "$DC_KEY" \
      | curl -sS -K - "$DC_BASE/services/v2/order/certificate" \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(1 for o in d.get("orders",[]) if (o.get("certificate") or {}).get("id",0)!=0))' 2>/dev/null)"
  fi
  case "$EXPECT" in ''|*[!0-9]*) FAIL "digicert: could not determine expected order count";; *)
    DC_CRED="$(DCK="$DC_KEY" create_cred uat-digicert "$(DCK="$DC_KEY" python3 -c 'import json,os; print(json.dumps(os.environ["DCK"]))')")"
    DC_SRC="$(create_src uat-digicert digicert "$(DCB="$DC_BASE" python3 -c 'import json,os; print(json.dumps({"base_url":os.environ["DCB"]}))')" "$DC_CRED")"
    if [ -z "$DC_SRC" ]; then FAIL "digicert source create failed"; else check_twice digicert "$DC_SRC" "$EXPECT" total; fi;;
  esac
fi

# --- recorded-fixture vendors ---------------------------------------------
STEP "recorded-fixture vendors (sectigo entrust aws_pca gcp_cas)"
if [ -z "$FIX_IP" ]; then
  for v in sectigo entrust aws_pca gcp_cas; do SKIP "fixtures[$v]: no non-loopback private address (hub egress policy blocks loopback)"; done
else
  PEMS="$WORK/pems"; mkdir -p "$PEMS"
  # One EC key; distinct serial + CN per cert so fingerprints differ.
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/fixture.key" 2>/dev/null || DIE "openssl ecparam failed"
  serial=100
  for pair in sectigo:3 entrust:2 aws:4 gcp:3; do
    v="${pair%%:*}"; n="${pair##*:}"
    for i in $(seq 1 "$n"); do
      serial=$((serial + 1))
      openssl req -x509 -new -key "$WORK/fixture.key" -subj "/CN=${v}-${i}.fixture.test" -set_serial "$serial" -days 30 -out "$PEMS/${v}_${i}.pem" 2>/dev/null \
        || DIE "openssl req failed for ${v}_${i}"
    done
  done
  python3 "$HERE/fixture_server.py" "$FIX_PORT" "$HERE/fixtures" "$PEMS" "$FIX_IP" >"$WORK/fixture.log" 2>&1 &
  FIX_PID=$!
  FIX_BASE="http://${FIX_IP}:${FIX_PORT}"
  tries=15
  until curl -sS -f -o /dev/null "${FIX_BASE}/healthz" 2>/dev/null; do
    kill -0 "$FIX_PID" 2>/dev/null || DIE "fixture server exited, see $WORK/fixture.log"
    tries=$((tries - 1)); [ $tries -le 0 ] && DIE "fixture server never answered on ${FIX_BASE}"
    sleep 1
  done
  PASS "fixture server on ${FIX_BASE}"

  SEC_PW="$(openssl rand -hex 8)"; ENT_KEY="$(openssl rand -hex 12)"
  AWS_AK="AKIA$(openssl rand -hex 8 | tr a-f A-F)"; AWS_SK="$(openssl rand -hex 16)"
  GCP_TOK="ya29.$(openssl rand -hex 12)"; BAD_PW="$(openssl rand -hex 8)"
  export SEC_PW ENT_KEY AWS_AK AWS_SK GCP_TOK BAD_PW

  C_SEC="$(create_cred uat-sectigo "$(python3 -c 'import json,os; print(json.dumps({"login":"kk-fixture-login","password":os.environ["SEC_PW"]}))')")"
  C_ENT="$(create_cred uat-entrust "$(python3 -c 'import json,os; print(json.dumps({"api_key":os.environ["ENT_KEY"]}))')")"
  C_AWS="$(create_cred uat-aws "$(python3 -c 'import json,os; e=os.environ; print(json.dumps({"access_key_id":e["AWS_AK"],"secret_access_key":e["AWS_SK"]}))')")"
  # gcp_cas / digicert read the payload as one opaque string; POST /credentials
  # keeps payload as raw JSON, so the string arrives JSON-quoted (see summary).
  C_GCP="$(create_cred uat-gcp "$(python3 -c 'import json,os; print(json.dumps(os.environ["GCP_TOK"]))')")"
  C_BAD="$(create_cred uat-sectigo-bad "$(python3 -c 'import json,os; print(json.dumps({"login":"kk-bad-login","password":os.environ["BAD_PW"]}))')")"
  S_SEC="$(create_src uat-sectigo sectigo "{\"base_url\":\"${FIX_BASE}/sectigo\",\"customer_uri\":\"kkfixture\"}" "$C_SEC")"
  S_ENT="$(create_src uat-entrust entrust "{\"base_url\":\"${FIX_BASE}/entrust\"}" "$C_ENT")"
  S_AWS="$(create_src uat-aws aws_pca "{\"region\":\"us-east-1\",\"endpoint\":\"${FIX_BASE}/aws\"}" "$C_AWS")"
  S_GCP="$(create_src uat-gcp gcp_cas "{\"base_url\":\"${FIX_BASE}/gcp\",\"project\":\"proj\",\"location\":\"us-central1\",\"ca_pool\":\"pool-1\"}" "$C_GCP")"
  S_BAD="$(create_src uat-sectigo-bad sectigo "{\"base_url\":\"${FIX_BASE}/sectigo\",\"customer_uri\":\"kkfixture\"}" "$C_BAD")"
  for pair in "sectigo:$S_SEC" "entrust:$S_ENT" "aws_pca:$S_AWS" "gcp_cas:$S_GCP" "bad-sectigo:$S_BAD"; do
    [ -n "${pair#*:}" ] || DIE "source create failed for ${pair%%:*}"
  done

  check_twice sectigo "$S_SEC" 3
  check_twice entrust "$S_ENT" 2
  check_twice aws_pca "$S_AWS" 4
  check_twice gcp_cas "$S_GCP" 3

  STEP "isolation: bad credential on one source"
  CODE="$(curlj -o "$WORK/bad.body" -w '%{http_code}' -X POST "${HUB_BASE}/api/v1/inventory-sources/${S_BAD}/sync")"
  if [ "${CODE:0:1}" != "2" ] && ! grep -qF "$BAD_PW" "$WORK/bad.body" "$WORK/hub.log"; then
    PASS "bad-credential source fails (http $CODE), secret not in response or hub log"
  else
    FAIL "bad-credential source http=$CODE body: $(head -c 200 "$WORK/bad.body")"
  fi
  RE="$(sync_src "$S_ENT")"; RA="$(sync_src "$S_AWS")"
  [ "$(echo "$RE" | jget data.skipped)" = 2 ] && [ "$(echo "$RA" | jget data.skipped)" = 4 ] \
    && PASS "entrust and aws_pca unaffected after the bad source (2, 4)" || FAIL "other sources broke: $(echo "$RE" | head -c 150) / $(echo "$RA" | head -c 150)"
  LIST="$(curlj "${HUB_BASE}/api/v1/inventory-sources")"
  ERRNAMES="$(echo "$LIST" | python3 -c 'import json,sys
d=json.load(sys.stdin)["data"]
print(",".join(sorted(s["name"] for s in d if "\"error\"" in (s.get("last_sync_result") or ""))))' 2>/dev/null)"
  [ "$ERRNAMES" = "uat-sectigo-bad" ] \
    && PASS "last_sync_result carries an error for the bad source only" || FAIL "sources with error in last_sync_result: '$ERRNAMES'"
fi

STEP "result"
if [ "$FAILED" -eq 0 ]; then echo "ALL PASS ($SKIPPED skipped)"; exit 0; else echo "FAILED ($SKIPPED skipped)"; exit 1; fi
