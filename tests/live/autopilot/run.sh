#!/usr/bin/env bash
# Live "autopilot" UAT: certificates are renewed AND installed on ordinary
# servers that speak no ACME/EST/SCEP, with NO human calling renew.
#
#   A. agentless: hub scheduler renews a due cert and installs it on an nginx
#      host over SSH (config test + reload + verify), unattended.
#   B. agent: kryptkeeper-agent in a container with nginx is tasked by the hub
#      and renews/installs/reloads on its own.
#   C. negative: the same scheduler path against an nginx whose config does
#      not use the recipe's key path, so the new cert fails `nginx -t` ->
#      rollback, previous cert keeps serving, a failure audit event and the
#      owner notification.
#
# Everything after the "setup done" line is waiting and observing; the harness
# asserts the audit log holds no renew_execute written by a human principal.
#
# Real product config only: RENEWAL_POLL_MINUTES (scheduler cadence) and
# AGENT_RENEWAL_SWEEP_MINUTES (agent driver cadence). Podman only.
#
# The hub runs in a container on the same podman network as the servers it
# manages (reached by container name; the agent host also answers to the
# network alias "agenthost", the name its fixture certificate carries). The hub's ACME server refuses
# localhost names and loopback http-01 targets, so a real private network is
# the honest environment for the agent path (and needs no privileged ports).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"

WORK="$(mktemp -d /tmp/kk-uat-autopilot.XXXXXX)"
# podman machine only virtiofs-mounts $HOME; bind-mounted files live there.
MOUNT_DIR="$(mktemp -d "$HOME/.kk-uat-autopilot.XXXXXX")"
SSH_CTX="$ROOT/tests/live/ssh-install"
AGENT_CTX="$ROOT/tests/live/agent"

# Free host ports and a per-run id, so concurrent runs (another worktree, a CI
# job) never share container names, the network or published ports.
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"
BASE="https://127.0.0.1:$HUB_PORT"
TOKEN=uat-token
AUTOPILOT_TIMEOUT="${AUTOPILOT_TIMEOUT:-300}"
NET="kk-uat-ap-net-$RUN_ID"
HUB_IMAGE="localhost/kk-uat-autopilot-hub:$RUN_ID"
SSH_IMAGE="localhost/kk-uat-autopilot-ssh:$RUN_ID"
AGENT_BASE="localhost/kk-uat-autopilot-agent-base:$RUN_ID"
AGENT_IMAGE="localhost/kk-uat-autopilot-agent:$RUN_ID"
CTR_HUB="kkhub-$RUN_ID"; CTR_A="nginxa-$RUN_ID"; CTR_C="nginxc-$RUN_ID"; CTR_B="agenthost-$RUN_ID"
A_SSH="$(free_port)"; C_SSH="$(free_port)"; A_TLS="$(free_port)"; C_TLS="$(free_port)"; B_TLS="$(free_port)"

PASS_N=0; FAIL_N=0
log()  { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
PASS() { PASS_N=$((PASS_N+1)); log "PASS: $*"; }
FAIL() { FAIL_N=$((FAIL_N+1)); log "FAIL: $*"; }
summary() { echo; echo "=== autopilot summary: $PASS_N passed, $FAIL_N failed ==="; }
DIE()  { FAIL "$*"; summary; exit 1; }

hublog() { podman logs "$CTR_HUB" 2>&1; }
cleanup() {
  log "cleanup"
  kk_rm "$CTR_HUB" "$CTR_A" "$CTR_B" "$CTR_C"
  podman network rm "$NET" >/dev/null 2>&1
  podman rmi -f "$HUB_IMAGE" "$SSH_IMAGE" "$AGENT_BASE" "$AGENT_IMAGE" >/dev/null 2>&1
  rm -f "$SSH_CTX/authorized_keys" "$AGENT_CTX/kryptkeeper-agent"
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

served_fp() { # host:port sni
  echo | openssl s_client -connect "$1" -servername "$2" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
}
served_serial() {
  echo | openssl s_client -connect "$1" -servername "$2" 2>/dev/null \
    | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2
}
wait_served_change() { # host:port sni old_fp timeout -> prints new fp
  local end=$((SECONDS+$4)) fp
  while [ $SECONDS -lt $end ]; do
    fp="$(served_fp "$1" "$2")"
    if [ -n "$fp" ] && [ "$fp" != "$3" ]; then echo "$fp"; return 0; fi
    sleep 3
  done
  return 1
}
wait_served() { # host:port sni want_fp timeout
  local end=$((SECONDS+$4)) fp
  while [ $SECONDS -lt $end ]; do
    fp="$(served_fp "$1" "$2")"
    [ "$fp" = "$3" ] && return 0
    sleep 1
  done
  return 1
}
audit_json()  { api "$BASE/api/v1/audit?limit=200&$1"; }
audit_count() { audit_json "$1" | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("data",[])))' 2>/dev/null; }
fp_of() { openssl x509 -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'; }

# --- images / binaries -------------------------------------------------------
GOARCH="$(kk_goarch)"
log "building hub + agent (linux/$GOARCH)"
mkdir -p "$WORK/hubctx"
( cd "$ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper ) || DIE "hub build failed"
( cd "$ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/kryptkeeper-agent" ./cmd/kryptkeeper-agent ) || DIE "agent build failed"
cp "$HERE/hub.Containerfile" "$WORK/hubctx/Containerfile"
podman build -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 || DIE "hub image build, see $WORK/build-hub.log"

ssh-keygen -t ed25519 -N '' -f "$WORK/id_ed25519" -C kk-autopilot >/dev/null || DIE "ssh-keygen"
cp "$WORK/id_ed25519.pub" "$SSH_CTX/authorized_keys"
podman build -t "$SSH_IMAGE" "$SSH_CTX" >"$WORK/build-ssh.log" 2>&1 || DIE "ssh image build, see $WORK/build-ssh.log"
rm -f "$SSH_CTX/authorized_keys"
cp "$WORK/kryptkeeper-agent" "$AGENT_CTX/kryptkeeper-agent"
podman build -t "$AGENT_BASE" "$AGENT_CTX" >"$WORK/build-agent.log" 2>&1 || DIE "agent base image build, see $WORK/build-agent.log"
rm -f "$AGENT_CTX/kryptkeeper-agent"
podman build -t "$AGENT_IMAGE" --build-arg BASE="$AGENT_BASE" -f "$HERE/agent.Containerfile" "$HERE" >>"$WORK/build-agent.log" 2>&1 || DIE "agent image build, see $WORK/build-agent.log"
PASS "images built"

# --- hub ---------------------------------------------------------------------
# Configured the way an operator would: a one-minute scheduler cadence and a
# one-minute agent sweep. Nothing else is special.
kk_rm "$CTR_HUB" "$CTR_A" "$CTR_B" "$CTR_C"
podman network rm "$NET" >/dev/null 2>&1
podman network create "$NET" >/dev/null || DIE "network create"
cat >"$WORK/hub.env" <<EOF
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
KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS=uat-enrollment-secret
KRYPTKEEPER_BASE_URL=https://$CTR_HUB:$HUB_PORT
RENEWAL_POLL_MINUTES=1
AGENT_RENEWAL_SWEEP_MINUTES=1
RENEWAL_RETRY_BASE_MINUTES=1
EOF
podman run -d --name "$CTR_HUB" --network "$NET" -p "127.0.0.1:$HUB_PORT:$HUB_PORT" --env-file "$WORK/hub.env" "$HUB_IMAGE" >/dev/null || DIE "start hub"
for _ in $(seq 1 40); do curl -fsSk "$BASE/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsSk "$BASE/healthz" >/dev/null 2>&1 || { hublog; DIE "hub never became healthy"; }
PASS "hub container up (RENEWAL_POLL_MINUTES=1 AGENT_RENEWAL_SWEEP_MINUTES=1)"

HUB_CA_PEM="$MOUNT_DIR/hub-ca.pem"
curl -sSk -o "$WORK/cacerts.b64" "$BASE/.well-known/est/cacerts" \
  && openssl base64 -d -A -in "$WORK/cacerts.b64" -out "$WORK/cacerts.p7" \
  && openssl pkcs7 -inform der -in "$WORK/cacerts.p7" -print_certs -out "$HUB_CA_PEM" \
  && [ -s "$HUB_CA_PEM" ] || DIE "could not export the hub CA via EST cacerts"
# The scheduler's one-time CN/SAN->binding backfill runs on its first tick and
# binds any cert whose CN equals a target host. Let it finish while there are no
# certs, so the explicit bind below is the only binding (otherwise a first tick
# landing after issuance binds and renews the cert behind the harness's back).
for _ in $(seq 1 90); do hublog | grep -q "migrated 0 CN/SAN host match" && break; sleep 1; done
hublog | grep -q "migrated 0 CN/SAN host match" || DIE "scheduler binding backfill did not run on the empty hub"
CA_ID="$(api "$BASE/api/v1/cas" | jget data.0.id)"
[ -n "$CA_ID" ] || DIE "no hub CA"
# Short-lived: 72h. A renewal keeps its template's validity, so the successor is
# also 72h; the scheduler holds a successor to half its own lifetime (1 day
# here), so it is not due again within this run (no renewal storm).
TPL_ID="$(api -X POST "$BASE/api/v1/templates" -d '{"name":"uat-autopilot","display_name":"autopilot","allowed_algorithms":["ECDSA","RSA-2048"],"key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"validity_period":"72h","active":true}' | jget data.id)"
[ -n "$TPL_ID" ] || DIE "template create failed"
PASS "CA $CA_ID, 72h template $TPL_ID"

# --- targets (A: renewable nginx, C: nginx whose config ignores the recipe) -----
podman run -d --name "$CTR_A" --network "$NET" -p "$A_SSH:22" -p "127.0.0.1:$A_TLS:443" -e ROLE=nginx "$SSH_IMAGE" >/dev/null || DIE "start A"
podman run -d --name "$CTR_C" --network "$NET" -p "$C_SSH:22" -p "127.0.0.1:$C_TLS:443" -e ROLE=nginx "$SSH_IMAGE" >/dev/null || DIE "start C"
hostkey() {
  local k; for _ in $(seq 1 20); do
    k="$(ssh-keyscan -p "$1" -t ed25519 127.0.0.1 2>/dev/null | grep -v '^#' | awk '{print $3}')"
    [ -n "$k" ] && { echo "ssh-ed25519 $k"; return 0; }; sleep 1; done; return 1; }
A_HK="$(hostkey $A_SSH)"; C_HK="$(hostkey $C_SSH)"
[ -n "$A_HK" ] && [ -n "$C_HK" ] || DIE "no ssh host keys"
for _ in $(seq 1 20); do
  [ -n "$(served_fp 127.0.0.1:$A_TLS x)" ] && [ -n "$(served_fp 127.0.0.1:$C_TLS x)" ] && break; sleep 1
done
[ -n "$(served_fp 127.0.0.1:$C_TLS x)" ] || DIE "nginx containers not serving TLS"

mk_cred() { # name port hostkey -> id
  python3 - "$1" "$2" "$3" "$WORK/id_ed25519" <<'PY' > "$WORK/cred.json"
import json,sys
name,port,hk,keyf=sys.argv[1],int(sys.argv[2]),sys.argv[3],sys.argv[4]
print(json.dumps({"name":name,"credential_type":"ssh_key","payload":{"user":"root","private_key_pem":open(keyf).read(),"host_public_key":hk,"port":port}}))
PY
  api -X POST "$BASE/api/v1/credentials" -d @"$WORK/cred.json" | jget data.id
}
# The whole operator-facing policy is these target fields: auto_renew plus the
# install recipe. The hub scheduler does the rest.
mk_target() { # name host cred -> id
  api -X POST "$BASE/api/v1/targets" -d "{\"name\":\"$1\",\"host\":\"$2\",\"discovery_mode\":\"network\",\"install_mode\":\"ssh\",\"credential_ref\":\"$3\",\"install_server_type\":\"nginx\",\"install_cert_path\":\"/etc/ssl/kk/server.crt\",\"install_key_path\":\"/etc/ssl/kk/server.key\",\"install_reload_method\":\"binary\",\"auto_renew\":true}" | jget data.id
}
# Stands in for an earlier manual enrolment: issue, then place cert+key on the host.
issue_install() { # name cn container -> fp
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/$1.key" -out "$WORK/$1.csr" \
    -subj "/CN=$2" -addext "subjectAltName=DNS:$2" >/dev/null 2>&1
  local csr fp
  csr="$(python3 -c "import json;print(json.dumps(open('$WORK/$1.csr').read()))")"
  fp="$(api -X POST "$BASE/api/v1/certificates" -d "{\"ca_id\":\"$CA_ID\",\"template_id\":\"$TPL_ID\",\"csr_pem\":$csr}" | jget data.fingerprint_sha256)"
  [ -n "$fp" ] || return 1
  api "$BASE/api/v1/certificates/$fp/download?format=pem&include_chain=true" > "$WORK/$1.crt"
  podman cp "$WORK/$1.crt" "$3:/etc/ssl/kk/server.crt" && podman cp "$WORK/$1.key" "$3:/etc/ssl/kk/server.key" \
    && podman exec "$3" sh -c 'chmod 600 /etc/ssl/kk/server.key && cp /etc/ssl/kk/server.key /etc/ssl/kk/other.key' || return 1
  echo "$fp"
}

A_CRED="$(mk_cred ap-a 22 "$A_HK")"; C_CRED="$(mk_cred ap-c 22 "$C_HK")"
[ -n "$A_CRED" ] && [ -n "$C_CRED" ] || DIE "credential create failed"
A_TGT="$(mk_target ap-nginx "$CTR_A" "$A_CRED")"; C_TGT="$(mk_target ap-negative "$CTR_C" "$C_CRED")"
[ -n "$A_TGT" ] && [ -n "$C_TGT" ] || DIE "target create failed"
A_FP0="$(issue_install a "$CTR_A" "$CTR_A")" || DIE "issue/install A"
C_FP0="$(issue_install c "$CTR_C" "$CTR_C")" || DIE "issue/install C"
# Since W27-02 the scheduler renews a certificate only onto targets an operator
# bound it to; a CN == host match alone is never acted on (the hub pushes a
# private key, so it must not guess). The first-tick backfill ran at hub start,
# before these certs existed, so bind explicitly -- the operator step.
# C's owner is set BEFORE the bindings: a binding makes the cert eligible for the
# scheduler's very next tick, which reads certificates once. An owner patched
# after the bind raced that tick (the tick saw no owner_email, so it neither
# sent nor audited-as-skipped the owner reminder the leg asserts below).
OWN_RESP="$(api -X PATCH "$BASE/api/v1/certificates/$C_FP0/ownership" -d '{"owner_email":"owner@example.test","owner_team":"uat","service_name":"negative"}')"
bind_cert() { # target fp
  local resp; resp="$(api -w '\nHTTP %{http_code}' -X POST "$BASE/api/v1/targets/$1/bindings" -d "{\"cert_fingerprint\":\"$2\"}")"
  [ -n "$(printf '%s' "$resp" | sed '$d' | jget data.target_id)" ] && return 0
  echo "bind target=$1 fp=$2 -> $(printf '%s' "$resp" | tr '\n' ' ')" >&2; return 1
}
# C's nginx reads its key from a path the install recipe does not know about (a
# very common wrong-recipe misconfiguration): a renewed cert written beside the
# old key at that path can never pass `nginx -t`.
podman exec "$CTR_C" sh -c 'sed -i "s#/etc/ssl/kk/server.key#/etc/ssl/kk/other.key#" /etc/nginx/sites-enabled/kk.conf' || DIE "prepare C"
# nginx may still be starting in the container; retry the reload briefly.
reload_nginx() { local c="$1" i out; for i in $(seq 1 20); do out="$(podman exec "$c" nginx -s reload 2>&1)" && return 0; sleep 1; done; echo "reload $c: $out"; return 1; }
reload_nginx "$CTR_A" || DIE "reload A"
reload_nginx "$CTR_C" || DIE "reload C"
wait_served 127.0.0.1:$A_TLS x "$A_FP0" 15 || { echo "A served: $(served_fp 127.0.0.1:$A_TLS x) want $A_FP0"; podman logs --tail 15 "$CTR_A" 2>&1; DIE "A is not serving its initial cert"; }
wait_served 127.0.0.1:$C_TLS x "$C_FP0" 15 || DIE "C is not serving its initial cert"
A_SERIAL0="$(served_serial 127.0.0.1:$A_TLS x)"
C_CRT_SUM0="$(podman exec "$CTR_C" sha256sum /etc/ssl/kk/server.crt | cut -d' ' -f1)"
# Bind only after both hosts are verified serving their initial certs: a binding
# makes the cert eligible for the scheduler's next tick, which renews the 72h
# cert at once and would otherwise race the initial-state checks above.
bind_cert "$A_TGT" "$A_FP0" && bind_cert "$C_TGT" "$C_FP0" || DIE "binding cert to target failed"
PASS "A+C: targets (auto_renew + install recipe) and 72h initial certs installed; A serves serial $A_SERIAL0"

# --- B: agent container --------------------------------------------------------
REG="$(curl -sSk -X POST "$BASE/api/v1/agent/register" -H 'Content-Type: application/json' \
  -d '{"name":"kk-uat-ap-agent","type":"linux","enrollment_secret":"uat-enrollment-secret"}')"
AGENT_ID="$(printf '%s' "$REG" | jget agent_id)"; AGENT_TOKEN="$(printf '%s' "$REG" | jget token)"
[ -n "$AGENT_ID" ] && [ -n "$AGENT_TOKEN" ] || DIE "agent register: $REG"
podman run -d --name "$CTR_B" --network "$NET" --network-alias agenthost -p "127.0.0.1:$B_TLS:443" \
  -v "$HUB_CA_PEM:/etc/kryptkeeper/hub-ca.pem:ro" \
  -e KRYPTKEEPER_HUB_URL="https://$CTR_HUB:$HUB_PORT" \
  -e KRYPTKEEPER_HUB_CA_CERT_FILE=/etc/kryptkeeper/hub-ca.pem \
  -e KRYPTKEEPER_AGENT_ID="$AGENT_ID" -e KRYPTKEEPER_AGENT_TOKEN="$AGENT_TOKEN" -e KRYPTKEEPER_AGENT_NAME=kk-uat-ap-agent \
  -e KRYPTKEEPER_POLL_INTERVAL=8 -e KRYPTKEEPER_SCAN_PATHS=/etc/nginx/ssl,/etc/ssl/certs-extra \
  -e KRYPTKEEPER_CONFIG_PATHS=/etc/nginx -e KRYPTKEEPER_WEB_ROOT=/var/www/html \
  "$AGENT_IMAGE" >/dev/null || DIE "start B"
B_FP0=""; for _ in $(seq 1 20); do B_FP0="$(served_fp 127.0.0.1:$B_TLS x)"; [ -n "$B_FP0" ] && break; sleep 1; done
[ -n "$B_FP0" ] || DIE "B nginx not serving"
B_SERIAL0="$(served_serial 127.0.0.1:$B_TLS x)"
PASS "B: agent enrolled, nginx serving its initial self-signed serial $B_SERIAL0"

# --- SETUP DONE: from here only waiting and observing -----------------------------
log "== setup done; no further state-changing hub calls. Waiting up to ${AUTOPILOT_TIMEOUT}s =="

# A
A_FP1="$(wait_served_change 127.0.0.1:$A_TLS x "$A_FP0" "$AUTOPILOT_TIMEOUT")" \
  && PASS "A: nginx now serves a new leaf ($A_FP1) and nobody called renew" \
  || { FAIL "A: served leaf never changed within ${AUTOPILOT_TIMEOUT}s"; hublog | tail -30; }
if [ -n "${A_FP1:-}" ]; then
  A_SERIAL1="$(served_serial 127.0.0.1:$A_TLS x)"
  [ "$A_SERIAL1" != "$A_SERIAL0" ] && PASS "A: serial changed $A_SERIAL0 -> $A_SERIAL1" || FAIL "A: serial unchanged"
  VOUT="$(echo | openssl s_client -connect 127.0.0.1:$A_TLS -servername "$CTR_A" -CAfile "$HUB_CA_PEM" -verify_return_error -verify_hostname "$CTR_A" 2>&1)"
  echo "$VOUT" | grep -q "Verify return code: 0 (ok)" && PASS "A: served chain verifies against the hub CA for $CTR_A (openssl)" || { FAIL "A: openssl verify against hub CA failed"; echo "$VOUT" | grep -i verif; }
  ON_DISK="$(podman exec "$CTR_A" cat /etc/ssl/kk/server.crt | fp_of)"
  [ "$ON_DISK" = "$A_FP1" ] && PASS "A: file on the nginx host == served leaf (nginx reloaded)" || FAIL "A: disk $ON_DISK != served $A_FP1"
  PERM="$(podman exec "$CTR_A" stat -c %a /etc/ssl/kk/server.key)"
  [ "$PERM" = "600" ] && PASS "A: installed key mode 0600" || FAIL "A: installed key mode $PERM"
  SUCC="$(api "$BASE/api/v1/certificates/$A_FP0" | jget data.successor_fingerprint)"
  [ "$SUCC" = "$A_FP1" ] && PASS "A: old cert superseded in inventory (successor == served leaf)" || FAIL "A: successor_fingerprint '$SUCC' != $A_FP1"
  AJ="$(audit_json "action=certificate.renew_execute&resource_id=$A_FP0")"
  echo "$AJ" | python3 -c 'import json,sys
d=json.load(sys.stdin)["data"]
sys.exit(0 if any(e["actor_id"]=="renewal-scheduler" and e["outcome"]=="success" and "install=installed_verified" in e.get("change_summary","") for e in d) else 1)' \
    && PASS "A: audit certificate.renew_execute by renewal-scheduler, install=installed_verified" || { FAIL "A: scheduler audit event missing"; echo "$AJ"; }
  NHUMAN="$(audit_json "action=certificate.renew_execute" | python3 -c 'import json,sys; print(sum(1 for e in json.load(sys.stdin)["data"] if e["actor_id"]!="renewal-scheduler"))')"
  [ "$NHUMAN" = "0" ] && PASS "A: no renew_execute was written by any human/API principal" || FAIL "A: $NHUMAN renew_execute event(s) from non-scheduler actors"
fi

# C: same scheduler ticks as A; its first attempt fails the config test and rolls back.
end=$((SECONDS+AUTOPILOT_TIMEOUT)); CJ=""
while [ $SECONDS -lt $end ]; do
  CJ="$(audit_json "action=certificate.renew_execute_partial&resource_id=$C_FP0")"
  [ "$(printf '%s' "$CJ" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["data"]))' 2>/dev/null)" != "0" ] && break
  sleep 3
done
printf '%s' "$CJ" | python3 -c 'import json,sys
d=json.load(sys.stdin)["data"]
sys.exit(0 if any(e["outcome"]=="failure" and "config_test_failed" in e.get("change_summary","") for e in d) else 1)' \
  && PASS "C: failure audit event with install=config_test_failed" || { FAIL "C: no failure audit event with config_test_failed"; echo "$CJ"; }
wait_served 127.0.0.1:$C_TLS x "$C_FP0" 15 && PASS "C: rollback left the previous cert serving" || FAIL "C: previous cert is not serving after the failed install"
[ "$(podman exec "$CTR_C" sha256sum /etc/ssl/kk/server.crt | cut -d' ' -f1)" = "$C_CRT_SUM0" ] && PASS "C: cert file restored byte-for-byte" || FAIL "C: cert file differs from pre-install"
sleep 5
# The hub runs with APP_NOTIFICATION_PROVIDER=file, which records but never
# delivers (RC5 A1): the owner reminder must be audited as SKIPPED with the
# provider named, never as "sent". The row also has to survive the real audit
# store's outcome CHECK (RC7: skipped used to be refused and silently lost).
NJ="$(audit_json "action=renewal_notification_sent&resource_id=$C_FP0")"
printf '%s' "$NJ" | python3 -c 'import json,sys
d=json.load(sys.stdin)["data"]
sys.exit(0 if d and not any(e["outcome"]=="success" for e in d) and any(e["outcome"]=="skipped" and "does not deliver" in e.get("change_summary","") for e in d) else 1)' \
  && PASS "C: owner reminder audited as skipped (provider does not deliver), not as sent" || { FAIL "C: no skipped renewal_notification_sent (reason 'does not deliver') for the failed auto-renew"; echo "$NJ"; echo "ownership resp: $OWN_RESP"; hublog | grep -i "renewal scheduler" | tail -8; }
# The operator repairs the nginx config (it now reads the recipe's key path).
# Nothing else is touched: the scheduler must retry on its own, back off
# between attempts, and finally install and verify.
[ "$(audit_count "action=certificate.renew_execute_partial&resource_id=$C_FP0")" -ge 1 ] 2>/dev/null \
  && PASS "C: failed attempt(s) audited with attempt numbers" || FAIL "C: no numbered failure audit"
podman exec "$CTR_C" sh -c 'sed -i "s#/etc/ssl/kk/other.key#/etc/ssl/kk/server.key#" /etc/nginx/sites-enabled/kk.conf && nginx -s reload' >/dev/null 2>&1 || FAIL "C: could not repair nginx config"
C_FP1="$(wait_served_change 127.0.0.1:$C_TLS x "$C_FP0" "$AUTOPILOT_TIMEOUT")" \
  && PASS "C: after the config fix the scheduler's retry installed a new leaf ($C_FP1) unattended" \
  || { FAIL "C: retry never installed after the config fix"; hublog | grep -i "renewal scheduler" | tail -8; }
if [ -n "${C_FP1:-}" ]; then
  VOUT="$(echo | openssl s_client -connect 127.0.0.1:$C_TLS -servername "$CTR_C" -CAfile "$HUB_CA_PEM" -verify_return_error -verify_hostname "$CTR_C" 2>&1)"
  echo "$VOUT" | grep -q "Verify return code: 0 (ok)" && PASS "C: retried leaf verifies against the hub CA (openssl)" || FAIL "C: retried leaf does not verify"
  # The leaf is served as soon as nginx reloads; the success audit row follows
  # the post-install verification, so poll for it instead of reading once.
  for _ in $(seq 1 15); do
    CJ="$(audit_json "action=certificate.renew_execute&resource_id=$C_FP0")"
    printf '%s' "$CJ" | python3 -c 'import json,sys
d=json.load(sys.stdin)["data"]
sys.exit(0 if any(e["outcome"]=="success" and "install=installed_verified" in e.get("change_summary","") and "attempt=1" not in e.get("change_summary","") for e in d) else 1)' && break
    sleep 2
  done
  printf '%s' "$CJ" | python3 -c 'import json,sys
d=json.load(sys.stdin)["data"]
sys.exit(0 if any(e["outcome"]=="success" and "install=installed_verified" in e.get("change_summary","") and "attempt=1" not in e.get("change_summary","") for e in d) else 1)' \
    && PASS "C: audit shows the retry succeeded (attempt >= 2, installed_verified)" || { FAIL "C: no success audit for the retry"; echo "$CJ"; }
  [ "$(podman exec "$CTR_C" stat -c %a /etc/ssl/kk/server.key)" = "600" ] && PASS "C: retried key mode 0600" || FAIL "C: retried key mode"
  PEND="$(api "$BASE/api/v1/scheduler/renewal/status" | jget data.status.pending_installs)"
  [ "$PEND" = "0" ] && PASS "C: scheduler status shows no pending installs after the retry" || FAIL "C: pending_installs=$PEND"
fi

# B
B_FP1="$(wait_served_change 127.0.0.1:$B_TLS x "$B_FP0" "$AUTOPILOT_TIMEOUT")" \
  && PASS "B: agent's nginx now serves a new leaf ($B_FP1)" \
  || { FAIL "B: served leaf never changed"; podman logs "$CTR_B" 2>&1 | tail -25; }
if [ -n "${B_FP1:-}" ]; then
  B_SERIAL1="$(served_serial 127.0.0.1:$B_TLS x)"
  [ "$B_SERIAL1" != "$B_SERIAL0" ] && PASS "B: serial changed $B_SERIAL0 -> $B_SERIAL1" || FAIL "B: serial unchanged"
  VOUT="$(echo | openssl s_client -connect 127.0.0.1:$B_TLS -servername agenthost -CAfile "$HUB_CA_PEM" -verify_return_error -verify_hostname agenthost 2>&1)"
  echo "$VOUT" | grep -q "Verify return code: 0 (ok)" && PASS "B: served chain verifies against the hub CA for agenthost (openssl)" || { FAIL "B: openssl verify against hub CA failed"; echo "$VOUT" | grep -i verif; }
  PERM="$(podman exec "$CTR_B" stat -c %a /etc/nginx/ssl/server.key)"
  [ "$PERM" = "600" ] && PASS "B: key written mode 0600" || FAIL "B: key mode $PERM (want 600)"
  [ "$(podman exec "$CTR_B" cat /etc/nginx/ssl/server.crt | fp_of)" = "$B_FP1" ] && PASS "B: cert file on disk == served leaf (reload ran)" || FAIL "B: disk cert != served leaf"
  [ "$(audit_count "action=agent.renewal_result")" -ge 1 ] 2>/dev/null && PASS "B: hub audit recorded agent.renewal_result" || FAIL "B: no agent.renewal_result audit event"
fi

summary
[ "$FAIL_N" -eq 0 ] && echo "AUTOPILOT: ALL PASS" || echo "AUTOPILOT: FAILED"
[ "$FAIL_N" -eq 0 ]
