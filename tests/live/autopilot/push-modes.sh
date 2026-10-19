#!/usr/bin/env bash
# W27-06 scheduler-driven autopilot UAT for the push modes that are not ssh.
#
#   MODES=plugin        (default) delivery-plugin mode against two mock devices
#   MODES=plugin,iis    adds the IIS leg (needs a Windows lab host)
#
# plugin leg: a hub container (RENEWAL_POLL_MINUTES=1) with the example
# delivery plugin enabled (install -> enable -> second admin approves), two
# mock appliances (tests/live/plugins/mockdevice) on a podman network, one
# healthy and one started with -fail-bind. Each device gets a plugin target
# armed with auto_renew=true and one short-lived certificate bound to it
# (POST /targets/{id}/bindings). After "setup done" nothing but observation:
#   * healthy device: the served leaf changes within POLL_SECONDS + 60 s; the
#     audit holds a certificate.renew_execute row by renewal-scheduler with
#     install=installed*, and ZERO renew_execute rows by any other actor
#   * -fail-bind device: the push fails after the upload; the served leaf DER
#     sha256 is byte-identical before and after, and a
#     certificate.renew_execute_partial (or _failed) row carries attempt=1/5
#   * the device token appears 0 times in hub log and audit
#
# iis leg: SKIP unless KK_IIS_HOST, KK_IIS_USER and KK_IIS_PASSWORD_FILE are
# set. The scripted IIS flow is NOT implemented in this harness (it needs a
# hands-on Windows lab, see docs/ops/WINRM_ENABLEMENT.md); with the variables
# set the leg reports NOT RUN rather than pretending.
#
# Podman only. The hub and devices share a private network (the hub's verify
# dial refuses loopback). Per-run ids; cleans up on exit.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
MODES="${MODES:-plugin}"
WORK="$(mktemp -d /tmp/kk-uat-pmodes.XXXXXX)"
MOUNT_DIR="$(mktemp -d "$HOME/.kk-uat-pmodes.XXXXXX")"
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"; MGMT_PORT="$(free_port)"; SVC_PORT="$(free_port)"
SVC_OK_HOST="$(free_port)"; SVC_BAD_HOST="$(free_port)"
BASE="http://127.0.0.1:$HUB_PORT"
TOKEN="uat-pmodes-bootstrap-token"
POLL_SECONDS=60
DEADLINE=$((POLL_SECONDS + 60))
NET="kk-uat-pm-net-$RUN_ID"
HUB_IMAGE="localhost/kk-uat-pm-hub:$RUN_ID"
DEV_IMAGE="localhost/kk-uat-pm-dev:$RUN_ID"
CTR_HUB="kkhub-pm-$RUN_ID"; CTR_OK="mockok-$RUN_ID"; CTR_BAD="mockbad-$RUN_ID"
TOK_OK="uat-dev-ok-$RANDOM$RANDOM$RANDOM"; TOK_BAD="uat-dev-bad-$RANDOM$RANDOM$RANDOM"

PASS_N=0; FAIL_N=0; SKIP_N=0
log()  { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
PASS() { PASS_N=$((PASS_N+1)); log "PASS: $*"; }
FAIL() { FAIL_N=$((FAIL_N+1)); log "FAIL: $*"; }
SKIP() { SKIP_N=$((SKIP_N+1)); log "SKIP: $*"; }
summary() { echo; echo "=== push-modes summary: $PASS_N passed, $FAIL_N failed, $SKIP_N skipped/not run ==="; }
DIE()  { FAIL "$*"; summary; exit 1; }
hublog() { podman logs "$CTR_HUB" 2>&1; }
cleanup() {
  log "cleanup"
  kk_rm "$CTR_HUB" "$CTR_OK" "$CTR_BAD"
  podman network rm "$NET" >/dev/null 2>&1
  podman rmi -f "$HUB_IMAGE" "$DEV_IMAGE" >/dev/null 2>&1
  rm -rf "$WORK" "$MOUNT_DIR"
}
trap cleanup EXIT

api()  { local tok="$1"; shift; curl -sS -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
code() { local tok="$1"; shift; curl -sS -o "$WORK/last.json" -w '%{http_code}' -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split('.'):
    d=d[int(k)] if k.isdigit() else d.get(k) if isinstance(d,dict) else None
    if d is None: break
print('' if d is None else d)" "$1" 2>/dev/null; }
# sha256 of the DER leaf the device serves right now (byte-level identity).
served_der_sum() { echo | openssl s_client -connect "$1" 2>/dev/null | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 -r | cut -d' ' -f1; }
audit_json() { api "$TOKEN" "$BASE/api/v1/audit?limit=200&$1"; }

want_mode() { case ",$MODES," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

# ---------------------------------------------------------------- iis leg ----
iis_leg() {
  if [ -z "${KK_IIS_HOST:-}" ] || [ -z "${KK_IIS_USER:-}" ] || [ -z "${KK_IIS_PASSWORD_FILE:-}" ]; then
    SKIP "iis: NOT RUN (KK_IIS_HOST, KK_IIS_USER and KK_IIS_PASSWORD_FILE are not all set; no Windows lab host)"
    return 0
  fi
  SKIP "iis: NOT RUN (the scripted IIS flow is not implemented in this harness; run the operator procedure in docs/ops/WINRM_ENABLEMENT.md and record it by hand)"
}

if ! want_mode plugin; then
  want_mode iis && iis_leg
  summary; echo "PUSH-MODES: no plugin leg selected"; [ "$FAIL_N" -eq 0 ]; exit $?
fi

# -------------------------------------------------------------- plugin leg ---
GOARCH="$(kk_goarch)"
log "building hub, mock device, example plugin (linux/$GOARCH)"
mkdir -p "$WORK/hubctx" "$WORK/devctx"
( cd "$ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper \
  && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/devctx/mockdevice" ./tests/live/plugins/mockdevice ) || DIE "go build failed"
cp "$HERE/hub.Containerfile" "$WORK/hubctx/Containerfile"
cp "$ROOT/tests/live/plugins/device.Containerfile" "$WORK/devctx/Containerfile"
podman build -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 || DIE "hub image build, see $WORK/build-hub.log"
podman build -t "$DEV_IMAGE" "$WORK/devctx" >"$WORK/build-dev.log" 2>&1 || DIE "device image build, see $WORK/build-dev.log"
( cd "$ROOT/plugins/example" && GOOS=wasip1 GOARCH=wasm GOFLAGS=-mod=mod go build -buildmode=c-shared -o "$WORK/plugin.wasm" . ) || DIE "plugin build failed"
python3 - "$ROOT/plugins/example/manifest.json" "$WORK" "$MGMT_PORT" <<'PY'
import hashlib, json, sys, base64
src, work, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
m = json.load(open(src))
wasm = open(f"{work}/plugin.wasm", "rb").read()
m["artifact"]["sha256"] = hashlib.sha256(wasm).hexdigest()
m["version"] = "1.0.0-live"
m["capabilities"]["network"]["ports"] = [port]
json.dump({"manifest": m, "wasm_base64": base64.b64encode(wasm).decode()}, open(f"{work}/install.json", "w"))
PY
PASS "built"

ADMIN2_SECRET="$(openssl rand -hex 24)"
ADMIN2_VERIFIER="$(printf '%s' "$ADMIN2_SECRET" | openssl dgst -sha256 -hmac 'uat-pepper-32-characters-minimum!!' -hex | awk '{print $NF}')"
ADMIN2_KEYS_JSON="[{\"name\":\"second-admin\",\"kid\":\"uatadmin2\",\"secret_verifier\":\"$ADMIN2_VERIFIER\",\"principal_id\":\"second-admin\",\"role\":\"pki-admin\",\"active\":true}]"
ADMIN2="kk_uatadmin2_${ADMIN2_SECRET}"

podman network create "$NET" >/dev/null || DIE "network create"
mkdir -p "$MOUNT_DIR/ok" "$MOUNT_DIR/bad" "$MOUNT_DIR/data"
podman run -d --name "$CTR_OK" --network "$NET" -p "127.0.0.1:$SVC_OK_HOST:$SVC_PORT" -v "$MOUNT_DIR/ok:/out" "$DEV_IMAGE" \
  -mgmt "0.0.0.0:$MGMT_PORT" -service "0.0.0.0:$SVC_PORT" -token "$TOK_OK" -ca-out /out/device-ca.pem -san "$CTR_OK" >/dev/null || DIE "start healthy device"
podman run -d --name "$CTR_BAD" --network "$NET" -p "127.0.0.1:$SVC_BAD_HOST:$SVC_PORT" -v "$MOUNT_DIR/bad:/out" "$DEV_IMAGE" \
  -mgmt "0.0.0.0:$MGMT_PORT" -service "0.0.0.0:$SVC_PORT" -token "$TOK_BAD" -ca-out /out/device-ca.pem -san "$CTR_BAD" -fail-bind >/dev/null || DIE "start -fail-bind device"
cat >"$WORK/hub.env" <<ENVEOF
APP_BOOTSTRAP_TOKEN=$TOKEN
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_NOTIFICATION_PROVIDER=file
APP_API_KEY_PEPPER=uat-pepper-32-characters-minimum!!
APP_API_KEY_AUTH_ENABLED=true
APP_API_KEYS_JSON=$ADMIN2_KEYS_JSON
APP_CREDENTIAL_STORE_PASSPHRASE=uat-cred-passphrase-32-bytes-long!!
KRYPTKEEPER_KEYSTORE_PASSPHRASE=uat-keystore-passphrase-32-bytes!!
KRYPTKEEPER_DATA_DIR=/data
KRYPTKEEPER_KEYSTORE_DIR=/data/keystore
APP_CA_FILE=/data/cas.json
APP_TEMPLATE_FILE=/data/templates.json
APP_CERTIFICATE_FILE=/data/certificates.json
APP_AUDIT_FILE=/data/audit.json
APP_CERTS_SUMMARY_FILE=/data/certs_summary.json
KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true
KRYPTKEEPER_CA_NAME=UAT Root CA
APP_BIND_ADDR=0.0.0.0
PORT=$HUB_PORT
KRYPTKEEPER_TLS_DISABLE=true
RENEWAL_POLL_MINUTES=1
ENVEOF
podman run -d --name "$CTR_HUB" --network "$NET" -p "127.0.0.1:$HUB_PORT:$HUB_PORT" --env-file "$WORK/hub.env" -v "$MOUNT_DIR/data:/data" "$HUB_IMAGE" >/dev/null || DIE "start hub"
for _ in $(seq 1 60); do curl -sf "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$BASE/healthz" >/dev/null 2>&1 || { hublog | tail -20; DIE "hub did not start"; }
for _ in $(seq 1 20); do [ -s "$MOUNT_DIR/ok/device-ca.pem" ] && [ -s "$MOUNT_DIR/bad/device-ca.pem" ] && break; sleep 0.25; done
[ -s "$MOUNT_DIR/ok/device-ca.pem" ] && [ -s "$MOUNT_DIR/bad/device-ca.pem" ] || DIE "devices wrote no CA"
PASS "hub up (RENEWAL_POLL_MINUTES=1), healthy device and -fail-bind device up"

c=$(code "$TOKEN" -X POST "$BASE/api/v1/delivery-plugins" --data @"$WORK/install.json")
[ "$c" = 201 ] && PASS "plugin installed (201)" || DIE "install -> $c $(cat "$WORK/last.json")"
c=$(code "$TOKEN" -X POST "$BASE/api/v1/delivery-plugins/kryptkeeper.example-device/versions/1.0.0-live/enable")
ACTION="$(jget data.pending_action_id <"$WORK/last.json")"
[ "$c" = 202 ] && [ -n "$ACTION" ] || DIE "enable -> $c $(cat "$WORK/last.json")"
c=$(code "$ADMIN2" -X POST "$BASE/api/v1/pending-actions/$ACTION/approve")
[ "$c" = 200 ] && PASS "plugin enabled via second admin's approval" || DIE "approve -> $c $(cat "$WORK/last.json")"

mk_cred() { # name token ca-file host
  python3 - "$1" "$2" "$3" "$4" "$MGMT_PORT" >"$WORK/cred.json" <<'PY'
import json, sys
name, tok, ca, host, port = sys.argv[1:6]
print(json.dumps({"name": name, "credential_type": "api_token", "payload": {"base_url": f"https://{host}:{port}", "token": tok, "tls_ca_pem": open(ca).read()}}))
PY
  api "$TOKEN" -X POST "$BASE/api/v1/credentials" --data @"$WORK/cred.json" | jget data.id
}
mk_target() { # name host cred listener
  api "$TOKEN" -X POST "$BASE/api/v1/targets" -d "{\"name\":\"$1\",\"host\":\"$2\",\"discovery_mode\":\"none\",\"install_mode\":\"plugin\",\"renewal_method\":\"manual\",\"credential_ref\":\"$3\",\"plugin_id\":\"kryptkeeper.example-device\",\"plugin_settings\":{\"listener\":\"vip-443\"},\"auto_renew\":true,\"verify_host_port\":\"$2:$SVC_PORT\"}" | jget data.id
}
CRED_OK="$(mk_cred dev-ok "$TOK_OK" "$MOUNT_DIR/ok/device-ca.pem" "$CTR_OK")"
CRED_BAD="$(mk_cred dev-bad "$TOK_BAD" "$MOUNT_DIR/bad/device-ca.pem" "$CTR_BAD")"
[ -n "$CRED_OK" ] && [ -n "$CRED_BAD" ] || DIE "credential create failed"
T_OK="$(mk_target plug-ok "$CTR_OK" "$CRED_OK")"; T_BAD="$(mk_target plug-bad "$CTR_BAD" "$CRED_BAD")"
[ -n "$T_OK" ] && [ -n "$T_BAD" ] || DIE "target create failed"
ARMED="$(api "$TOKEN" "$BASE/api/v1/targets/$T_OK" | jget data.auto_renew_set_by)"
[ -n "$ARMED" ] && PASS "targets armed by a pki-admin (auto_renew_set_by=$ARMED)" || FAIL "auto_renew_set_by not stamped"

CA_ID="$(api "$TOKEN" "$BASE/api/v1/cas" | jget data.0.id)"
# 72h: inside the default 30-day window, so due on the next tick.
TPL_ID="$(api "$TOKEN" -X POST "$BASE/api/v1/templates" -d '{"name":"uat-pmodes","display_name":"pmodes","validity_period":"72h","key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"active":true}' | jget data.id)"
[ -n "$CA_ID" ] && [ -n "$TPL_ID" ] || DIE "no CA/template"
issue() { # cn -> fp
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/$1.key" 2>/dev/null
  openssl req -new -key "$WORK/$1.key" -subj "/CN=$1.uat.example" -addext "subjectAltName=DNS:$1.uat.example" -out "$WORK/$1.csr" 2>/dev/null
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$TPL_ID" "$WORK/$1.csr" "$WORK/$1.issue.json"
  api "$TOKEN" -X POST "$BASE/api/v1/certificates" --data @"$WORK/$1.issue.json" | jget data.fingerprint_sha256
}
FP_OK="$(issue plug-ok)"; FP_BAD="$(issue plug-bad)"
[ -n "$FP_OK" ] && [ -n "$FP_BAD" ] || DIE "issue failed"
BCODE="$(code "$TOKEN" "$BASE/api/v1/targets/$T_OK/bindings")"
if [ "$BCODE" = 200 ]; then
  c1=$(code "$TOKEN" -X POST "$BASE/api/v1/targets/$T_OK/bindings" -d "{\"cert_fingerprint\":\"$FP_OK\"}")
  c2=$(code "$TOKEN" -X POST "$BASE/api/v1/targets/$T_BAD/bindings" -d "{\"cert_fingerprint\":\"$FP_BAD\"}")
  case "$c1$c2" in 201201|200200|201200|200201) PASS "certificates bound to their targets (W27-02 bindings)" ;; *) DIE "binding create -> $c1/$c2" ;; esac
else
  log "NOTE: bindings route -> $BCODE; this build predates W27-02, scheduler may skip the targets"
fi

DER_OK0="$(served_der_sum 127.0.0.1:$SVC_OK_HOST)"; DER_BAD0="$(served_der_sum 127.0.0.1:$SVC_BAD_HOST)"
[ -n "$DER_OK0" ] && [ -n "$DER_BAD0" ] || DIE "devices not serving"
PASS "before: healthy device serves ${DER_OK0:0:16}.., -fail-bind device serves ${DER_BAD0:0:16}.. (factory certificates)"
T0=$SECONDS
log "== setup done; only observing. Deadline ${DEADLINE}s (RENEWAL_POLL_MINUTES=1 + 60) =="

# --- healthy: the scheduler renews it, nobody calls renew -----------------------
DER_OK1=""; while [ $((SECONDS-T0)) -lt $((DEADLINE+120)) ]; do
  d="$(served_der_sum 127.0.0.1:$SVC_OK_HOST)"; [ -n "$d" ] && [ "$d" != "$DER_OK0" ] && { DER_OK1="$d"; break; }; sleep 3
done
ELAPSED=$((SECONDS-T0))
if [ -n "$DER_OK1" ]; then
  [ "$ELAPSED" -le "$DEADLINE" ] && PASS "healthy: served leaf changed after ${ELAPSED}s (limit ${DEADLINE}s): ${DER_OK0:0:16}.. -> ${DER_OK1:0:16}.." \
    || FAIL "healthy: served leaf changed but after ${ELAPSED}s (limit ${DEADLINE}s)"
else
  FAIL "healthy: served leaf never changed (waited $((SECONDS-T0))s)"; hublog | tail -20
fi
AJ="$(audit_json "action=certificate.renew_execute&resource_id=$FP_OK")"
printf '%s' "$AJ" | python3 -c 'import json,sys
d=json.load(sys.stdin)["data"]
sys.exit(0 if any(e["actor_id"]=="renewal-scheduler" and e["outcome"]=="success" and "install=installed" in e.get("change_summary","") for e in d) else 1)' \
  && PASS "healthy: certificate.renew_execute by renewal-scheduler, install=installed*" || { FAIL "healthy: scheduler audit row missing"; echo "$AJ" | head -c 600; }
NHUMAN="$(audit_json "action=certificate.renew_execute" | python3 -c 'import json,sys; print(sum(1 for e in json.load(sys.stdin)["data"] if e["actor_id"]!="renewal-scheduler"))')"
[ "$NHUMAN" = "0" ] && PASS "0 renew_execute audit rows by a human principal" || FAIL "$NHUMAN renew_execute row(s) by a non-scheduler actor"

# --- -fail-bind: the previous certificate stays current, byte for byte ---------
end=$((SECONDS+DEADLINE+120)); BJ=""
while [ $SECONDS -lt $end ]; do
  BJ="$(audit_json "resource_id=$FP_BAD")"
  printf '%s' "$BJ" | python3 -c 'import json,sys
d=json.load(sys.stdin)["data"]
sys.exit(0 if any(e["action"] in ("certificate.renew_execute_partial","certificate.renew_execute_failed") for e in d) else 1)' && break
  sleep 3
done
printf '%s' "$BJ" | python3 -c 'import json,sys
d=json.load(sys.stdin)["data"]
sys.exit(0 if any(e["action"] in ("certificate.renew_execute_partial","certificate.renew_execute_failed") and e["outcome"]=="failure" and "attempt=1/5" in e.get("change_summary","") + e.get("details","") for e in d) else 1)' \
  && PASS "-fail-bind: failure audit row with attempt=1/5" || { FAIL "-fail-bind: no partial/failed row with attempt=1/5"; printf '%s' "$BJ" | head -c 800; }
DER_BAD1="$(served_der_sum 127.0.0.1:$SVC_BAD_HOST)"
[ "$DER_BAD1" = "$DER_BAD0" ] && PASS "-fail-bind: served leaf is byte-identical before and after (sha256 $DER_BAD0)" || FAIL "-fail-bind: served leaf changed $DER_BAD0 -> $DER_BAD1"
SUCC="$(audit_json "action=certificate.renew_execute&resource_id=$FP_BAD" | python3 -c 'import json,sys; print(sum(1 for e in json.load(sys.stdin)["data"] if e["outcome"]=="success"))')"
[ "$SUCC" = "0" ] && PASS "-fail-bind: no success row for the failing target" || FAIL "-fail-bind: $SUCC success row(s)"

# --- secrets: 0 occurrences in hub log and audit ---------------------------------------
hublog >"$WORK/hub.log"
python3 - "$BASE" "$TOKEN" "$WORK/audit-dump.json" <<'PY'
import json, sys, urllib.request
hub, token, out = sys.argv[1:4]
rows, cursor = [], ""
while True:
    url = hub + "/api/v1/audit?limit=100" + ("&cursor=" + cursor if cursor else "")
    d = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Bearer " + token})))
    rows += d["data"]
    cursor = (d.get("meta") or {}).get("next_cursor") or ""
    if not cursor:
        break
json.dump(rows, open(out, "w"))
sys.exit(0 if rows else 1)
PY
[ $? -eq 0 ] && PASS "read the full audit trail ($(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$WORK/audit-dump.json") entries)" || { FAIL "empty audit trail"; : >"$WORK/audit-dump.json"; }
n_tok=$(cat "$WORK/hub.log" "$WORK/audit-dump.json" | grep -c -e "$TOK_OK" -e "$TOK_BAD" -e "PRIVATE KEY")
[ "$n_tok" = 0 ] && PASS "device tokens and private-key markers: 0 occurrences in hub log and audit" || FAIL "$n_tok line(s) in hub log/audit contain a device token or key marker"

want_mode iis && iis_leg
summary
[ "$FAIL_N" -eq 0 ] && echo "PUSH-MODES: ALL PASS" || echo "PUSH-MODES: FAILED"
[ "$FAIL_N" -eq 0 ]
