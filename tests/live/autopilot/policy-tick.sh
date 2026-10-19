#!/usr/bin/env bash
# W27-06 policy-tick E2E: raising a target's renewal threshold takes effect on
# the NEXT scheduler tick, with no hub restart.
#
#   1. a hub (container, RENEWAL_POLL_MINUTES=1) manages one ssh nginx target
#      (auto_renew=true, certificate bound with POST /targets/{id}/bindings);
#      the certificate has 40 days left and the default threshold is 30
#   2. across a full scheduler tick: last_candidates == 0 and the served
#      certificate is unchanged
#   3. PATCH /api/v1/targets/{id} renewal_threshold_days=45 (the only change)
#   4. on the next tick: last_candidates == 1, and the scheduler (not a human)
#      renews it; the hub container's StartedAt is unchanged (0 restarts)
#
# The threshold is matched to a certificate by target host == cert CN/SAN, so
# the target host is the container name the certificate carries.
# Podman only; per-run ids; cleans up on exit.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-ptick.XXXXXX)"
MOUNT_DIR="$(mktemp -d "$HOME/.kk-uat-ptick.XXXXXX")"
SSH_CTX="$ROOT/tests/live/ssh-install"
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"; BASE="https://127.0.0.1:$HUB_PORT"
TOKEN=uat-token
TICK_TIMEOUT="${TICK_TIMEOUT:-200}"
NET="kk-uat-ptick-net-$RUN_ID"
HUB_IMAGE="localhost/kk-uat-ptick-hub:$RUN_ID"
SSH_IMAGE="localhost/kk-uat-ptick-ssh:$RUN_ID"
CTR_HUB="kkhub-ptick-$RUN_ID"; CTR_A="nginxt-$RUN_ID"
A_SSH="$(free_port)"; A_TLS="$(free_port)"

PASS_N=0; FAIL_N=0
log()  { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
PASS() { PASS_N=$((PASS_N+1)); log "PASS: $*"; }
FAIL() { FAIL_N=$((FAIL_N+1)); log "FAIL: $*"; }
summary() { echo; echo "=== policy-tick summary: $PASS_N passed, $FAIL_N failed ==="; }
DIE()  { FAIL "$*"; summary; exit 1; }
hublog() { podman logs "$CTR_HUB" 2>&1; }
cleanup() {
  log "cleanup"
  kk_rm "$CTR_HUB" "$CTR_A"
  podman network rm "$NET" >/dev/null 2>&1
  podman rmi -f "$HUB_IMAGE" "$SSH_IMAGE" >/dev/null 2>&1
  rm -f "$SSH_CTX/authorized_keys"
  rm -rf "$WORK" "$MOUNT_DIR"
}
trap cleanup EXIT

api()  { curl -sSk -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split('.'):
    d=d[int(k)] if k.isdigit() else d.get(k) if isinstance(d,dict) else None
    if d is None: break
print('' if d is None else d)" "$1" 2>/dev/null; }
served_fp() {
  echo | openssl s_client -connect "$1" -servername "$2" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
}
audit_json() { api "$BASE/api/v1/audit?limit=200&$1"; }
sched_status() { api "$BASE/api/v1/scheduler/renewal/status"; }

GOARCH="$(kk_goarch)"
log "building hub (linux/$GOARCH)"
mkdir -p "$WORK/hubctx"
( cd "$ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper ) || DIE "hub build failed"
cp "$HERE/hub.Containerfile" "$WORK/hubctx/Containerfile"
podman build -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 || DIE "hub image build, see $WORK/build-hub.log"
ssh-keygen -t ed25519 -N '' -f "$WORK/id_ed25519" -C kk-ptick >/dev/null || DIE "ssh-keygen"
cp "$WORK/id_ed25519.pub" "$SSH_CTX/authorized_keys"
podman build -t "$SSH_IMAGE" "$SSH_CTX" >"$WORK/build-ssh.log" 2>&1 || DIE "ssh image build, see $WORK/build-ssh.log"
rm -f "$SSH_CTX/authorized_keys"
PASS "images built"

podman network create "$NET" >/dev/null || DIE "network create"
cat >"$WORK/hub.env" <<ENVEOF
APP_BOOTSTRAP_TOKEN=$TOKEN
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_DISCOVERY_PROVIDER=db
APP_NOTIFICATION_PROVIDER=file
KRYPTKEEPER_TLS_SANS=$CTR_HUB,localhost,127.0.0.1
APP_CREDENTIAL_STORE_PASSPHRASE=uat-cred-passphrase-32-bytes-long!!
KRYPTKEEPER_KEYSTORE_PASSPHRASE=uat-keystore-passphrase-32-bytes!!
KRYPTKEEPER_DATA_DIR=/data
APP_CA_FILE=/data/cas.json
APP_TEMPLATE_FILE=/data/templates.json
APP_CERTIFICATE_FILE=/data/certificates.json
APP_AUDIT_FILE=/data/audit.json
APP_CERTS_SUMMARY_FILE=/data/certs_summary.json
KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true
KRYPTKEEPER_CA_NAME=UAT Root CA
APP_BIND_ADDR=0.0.0.0
PORT=$HUB_PORT
RENEWAL_POLL_MINUTES=1
ENVEOF
podman run -d --name "$CTR_HUB" --network "$NET" -p "127.0.0.1:$HUB_PORT:$HUB_PORT" --env-file "$WORK/hub.env" "$HUB_IMAGE" >/dev/null || DIE "start hub"
for _ in $(seq 1 40); do curl -fsSk "$BASE/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsSk "$BASE/healthz" >/dev/null 2>&1 || { hublog | tail -20; DIE "hub never became healthy"; }
HUB_STARTED_0="$(podman inspect --format '{{.State.StartedAt}}' "$CTR_HUB")"
PASS "hub up (RENEWAL_POLL_MINUTES=1, default threshold 30 days), StartedAt=$HUB_STARTED_0"

CA_ID="$(api "$BASE/api/v1/cas" | jget data.0.id)"; [ -n "$CA_ID" ] || DIE "no hub CA"
# 960h = 40 days: outside the 30-day default window, inside a 45-day one.
TPL_ID="$(api -X POST "$BASE/api/v1/templates" -d '{"name":"uat-ptick","display_name":"ptick","allowed_algorithms":["ECDSA","RSA-2048"],"key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"validity_period":"960h","active":true}' | jget data.id)"
[ -n "$TPL_ID" ] || DIE "template create failed"

podman run -d --name "$CTR_A" --network "$NET" -p "$A_SSH:22" -p "127.0.0.1:$A_TLS:443" -e ROLE=nginx "$SSH_IMAGE" >/dev/null || DIE "start nginx"
HK=""; for _ in $(seq 1 20); do
  k="$(ssh-keyscan -p "$A_SSH" -t ed25519 127.0.0.1 2>/dev/null | grep -v '^#' | awk '{print $3}')"
  [ -n "$k" ] && { HK="ssh-ed25519 $k"; break; }; sleep 1; done
[ -n "$HK" ] || DIE "no ssh host key"
python3 - "$HK" "$WORK/id_ed25519" <<'PY' > "$WORK/cred.json"
import json,sys
hk,keyf=sys.argv[1],sys.argv[2]
print(json.dumps({"name":"ptick","credential_type":"ssh_key","payload":{"user":"root","private_key_pem":open(keyf).read(),"host_public_key":hk,"port":22}}))
PY
CRED="$(api -X POST "$BASE/api/v1/credentials" -d @"$WORK/cred.json" | jget data.id)"; [ -n "$CRED" ] || DIE "credential create failed"
TGT="$(api -X POST "$BASE/api/v1/targets" -d "{\"name\":\"ptick\",\"host\":\"$CTR_A\",\"discovery_mode\":\"network\",\"install_mode\":\"ssh\",\"credential_ref\":\"$CRED\",\"install_server_type\":\"nginx\",\"install_cert_path\":\"/etc/ssl/kk/server.crt\",\"install_key_path\":\"/etc/ssl/kk/server.key\",\"install_reload_method\":\"binary\",\"auto_renew\":true}" | jget data.id)"
[ -n "$TGT" ] || DIE "target create failed"

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/a.key" -out "$WORK/a.csr" \
  -subj "/CN=$CTR_A" -addext "subjectAltName=DNS:$CTR_A" >/dev/null 2>&1
CSR="$(python3 -c "import json;print(json.dumps(open('$WORK/a.csr').read()))")"
FP0="$(api -X POST "$BASE/api/v1/certificates" -d "{\"ca_id\":\"$CA_ID\",\"template_id\":\"$TPL_ID\",\"csr_pem\":$CSR}" | jget data.fingerprint_sha256)"
[ -n "$FP0" ] || DIE "issue failed"
api "$BASE/api/v1/certificates/$FP0/download?format=pem&include_chain=true" > "$WORK/a.crt"
podman cp "$WORK/a.crt" "$CTR_A:/etc/ssl/kk/server.crt" && podman cp "$WORK/a.key" "$CTR_A:/etc/ssl/kk/server.key" \
  && podman exec "$CTR_A" sh -c 'chmod 600 /etc/ssl/kk/server.key && nginx -s reload' >/dev/null 2>&1 || DIE "install initial cert"
for _ in $(seq 1 15); do [ "$(served_fp 127.0.0.1:$A_TLS x)" = "$FP0" ] && break; sleep 1; done
[ "$(served_fp 127.0.0.1:$A_TLS x)" = "$FP0" ] || DIE "nginx is not serving the initial cert"

BCODE="$(curl -sSk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/targets/$TGT/bindings")"
if [ "$BCODE" = 200 ]; then
  api -X POST "$BASE/api/v1/targets/$TGT/bindings" -d "{\"cert_fingerprint\":\"$FP0\"}" >"$WORK/bind.json"
  [ -n "$(jget data.target_id <"$WORK/bind.json")" ] && PASS "bound $FP0 to the target (W27-02 bindings)" || FAIL "binding create: $(cat "$WORK/bind.json")"
else
  log "NOTE: bindings route returned $BCODE; this build predates W27-02"
fi
DAYS="$(openssl x509 -in "$WORK/a.crt" -noout -enddate | cut -d= -f2 | { read -r d; python3 -c "
import sys,email.utils,time
t=email.utils.parsedate_to_datetime(sys.argv[1]).timestamp(); print(int((t-time.time())/86400))" "$d"; })"
PASS "target armed (auto_renew=true), certificate ${FP0:0:16}.. has $DAYS days left, threshold 30"

# --- phase 1: a full tick with threshold 30 must see 0 candidates -------------------
log "== waiting for the first scheduler tick =="
end=$((SECONDS+TICK_TIMEOUT)); RUN1=""
while [ $SECONDS -lt $end ]; do
  RUN1="$(sched_status | jget data.status.last_run_at)"; [ -n "$RUN1" ] && break; sleep 3
done
[ -n "$RUN1" ] || DIE "scheduler never ticked"
C1="$(sched_status | jget data.status.last_candidates)"
[ "$C1" = "0" ] && PASS "tick at $RUN1: last_candidates=0 (40 days > 30)" || FAIL "tick at $RUN1: last_candidates=$C1, want 0"
# One more full tick, so 'stays at 0' is observed across a second scan.
end=$((SECONDS+TICK_TIMEOUT)); RUN2=""
while [ $SECONDS -lt $end ]; do
  RUN2="$(sched_status | jget data.status.last_run_at)"; [ -n "$RUN2" ] && [ "$RUN2" != "$RUN1" ] && break; sleep 3
done
[ "$RUN2" != "$RUN1" ] || DIE "scheduler did not tick a second time"
C2="$(sched_status | jget data.status.last_candidates)"
[ "$C2" = "0" ] && PASS "tick at $RUN2: last_candidates still 0" || FAIL "tick at $RUN2: last_candidates=$C2, want 0"
[ "$(served_fp 127.0.0.1:$A_TLS x)" = "$FP0" ] && PASS "served certificate unchanged across the ticks" || FAIL "certificate changed with threshold 30"

# --- phase 2: raise the threshold, nothing else ---------------------------------------
PCODE="$(curl -sSk -o "$WORK/patch.json" -w '%{http_code}' -X PATCH -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$BASE/api/v1/targets/$TGT" -d '{"renewal_threshold_days":45}')"
[ "$PCODE" = 200 ] && PASS "PATCH renewal_threshold_days=45 -> 200" || DIE "PATCH -> $PCODE $(cat "$WORK/patch.json")"
T_PATCH="$SECONDS"
end=$((SECONDS+TICK_TIMEOUT)); RUN3=""; C3=""
while [ $SECONDS -lt $end ]; do
  st="$(sched_status)"; RUN3="$(printf '%s' "$st" | jget data.status.last_run_at)"
  if [ -n "$RUN3" ] && [ "$RUN3" != "$RUN2" ]; then C3="$(printf '%s' "$st" | jget data.status.last_candidates)"; break; fi
  sleep 2
done
ELAPSED=$((SECONDS-T_PATCH))
[ "$C3" = "1" ] && PASS "next tick ($RUN3, ${ELAPSED}s after the PATCH): last_candidates=1" || FAIL "next tick: last_candidates='$C3', want 1"
MAXT="$(printf '%s' "$st" | jget data.status.max_threshold_days)"
[ "$MAXT" = "45" ] && PASS "status max_threshold_days=45" || FAIL "status max_threshold_days='$MAXT'"
HUB_STARTED_1="$(podman inspect --format '{{.State.StartedAt}}' "$CTR_HUB")"
[ "$HUB_STARTED_1" = "$HUB_STARTED_0" ] && PASS "0 hub restarts (StartedAt unchanged)" || FAIL "hub restarted: $HUB_STARTED_0 -> $HUB_STARTED_1"

# The scheduler (not a human) then renews it.
NEWFP=""; end=$((SECONDS+TICK_TIMEOUT))
while [ $SECONDS -lt $end ]; do
  fp="$(served_fp 127.0.0.1:$A_TLS x)"; [ -n "$fp" ] && [ "$fp" != "$FP0" ] && { NEWFP="$fp"; break; }; sleep 3
done
[ -n "$NEWFP" ] && PASS "the renewed leaf is now served ($NEWFP)" || FAIL "certificate never renewed after the threshold change"
NHUMAN="$(audit_json "action=certificate.renew_execute" | python3 -c 'import json,sys; print(sum(1 for e in json.load(sys.stdin)["data"] if e["actor_id"]!="renewal-scheduler"))')"
[ "$NHUMAN" = "0" ] && PASS "0 renew_execute audit rows by a human principal" || FAIL "$NHUMAN renew_execute row(s) by a non-scheduler actor"
hublog >"$WORK/hub.log"
if grep -q "PRIVATE KEY" "$WORK/hub.log"; then FAIL "private key marker in hub log"; else PASS "no private-key marker in the hub log"; fi

summary
[ "$FAIL_N" -eq 0 ] && echo "POLICY-TICK: ALL PASS" || echo "POLICY-TICK: FAILED"
[ "$FAIL_N" -eq 0 ]
