#!/usr/bin/env bash
# W27-16: prove cluster-atomic staged rollout (W27-15) against three REAL
# nginx+sshd containers: happy path (canary first), an injected flip failure on
# node 3 (all three nodes end on ONE identical old fingerprint), and an injected
# canary failure (the other nodes are never flipped).
#
# Fault injection: nginx-flipfail.sh wraps `nginx` and fails exactly one
# `nginx -s reload` while /etc/kk-fail-reload exists. Targets use
# install_reload_method=binary, so the flip's reload is `nginx -s reload`.
#
# Reuses the tests/live/ssh-install image (copied into a temp context so no
# generated key is ever written into the repo), the autopilot hub Containerfile
# and the same hub/credential/target/template calls as ssh-install/run.sh.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
SSH_INSTALL="$REPO_ROOT/tests/live/ssh-install"
WORK="$(mktemp -d /tmp/kk-uat-rollout.XXXXXX)"
RUN_ID="$(openssl rand -hex 3)"
T0=$SECONDS
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
BASE_IMAGE="localhost/kk-uat-rollout-base:$RUN_ID"
IMAGE="localhost/kk-uat-rollout:$RUN_ID"
HUB_IMAGE="localhost/kk-uat-rollout-hub:$RUN_ID"
NET="kk-uat-rollout-net-$RUN_ID"
HUB_CTR="kk-uat-rollout-hub-$RUN_ID"
NODES=(n1 n2 n3)
declare -A CTR SSH_PORT TLS_PORT HOSTKEY TARGET_ID
for n in "${NODES[@]}"; do
  CTR[$n]="kk-uat-rollout-$n-$RUN_ID"; SSH_PORT[$n]="$(free_port)"; TLS_PORT[$n]="$(free_port)"
done

FAILED=0
CASE_A=NOT_RUN; CASE_B=NOT_RUN; CASE_C=NOT_RUN
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; FAILED=1; cleanup; exit 1; }

cleanup() {
  STEP "cleanup"
  for n in "${NODES[@]}"; do kk_rm "${CTR[$n]}"; done
  kk_rm "$HUB_CTR"
  podman network rm "$NET" >/dev/null 2>&1 || true
  podman rmi -f "$IMAGE" "$BASE_IMAGE" "$HUB_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }

# ---------------------------------------------------------------------------
# 1. Keypair, images, network, three node containers.
# ---------------------------------------------------------------------------
STEP "generate SSH keypair"
ssh-keygen -t ed25519 -N '' -f "$WORK/id_ed25519" -C kk-uat >/dev/null \
  && PASS "keypair generated in $WORK" || DIE "ssh-keygen failed"

STEP "build images"
mkdir -p "$WORK/base"
cp -R "$SSH_INSTALL/." "$WORK/base/"
rm -f "$WORK/base/authorized_keys" "$WORK/base/run.sh" "$WORK/base/README.md"
cp "$WORK/id_ed25519.pub" "$WORK/base/authorized_keys"
podman build -t "$BASE_IMAGE" "$WORK/base" >"$WORK/build-base.log" 2>&1 \
  && PASS "base image built" || DIE "base build failed, see $WORK/build-base.log"
podman build --build-arg "BASE=$BASE_IMAGE" -t "$IMAGE" "$HERE" >"$WORK/build.log" 2>&1 \
  && PASS "fault-injection image built" || DIE "image build failed, see $WORK/build.log"

podman network create "$NET" >/dev/null && PASS "network $NET" || DIE "network create failed"

STEP "start three nginx nodes"
for n in "${NODES[@]}"; do
  podman run -d --name "${CTR[$n]}" --network "$NET" \
    -p "${SSH_PORT[$n]}:22" -p "${TLS_PORT[$n]}:443" -e ROLE=nginx "$IMAGE" >/dev/null \
    && PASS "container ${CTR[$n]} up" || DIE "failed to start ${CTR[$n]}"
done

wait_for_port() {
  local port=$1 tries=30
  while [ $tries -gt 0 ]; do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 3<&- 3>&-; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  return 1
}
ssh_host_key() {
  local port=$1 tries=15 key
  while [ $tries -gt 0 ]; do
    key="$(ssh-keyscan -p "$port" -t ed25519 127.0.0.1 2>/dev/null | grep -v '^#' | awk '{print $3}')"
    [ -n "$key" ] && { echo "ssh-ed25519 $key"; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  return 1
}
tls_fingerprint() {
  echo | openssl s_client -connect "127.0.0.1:${1}" -servername kk-uat 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
}
# `nginx -s reload` returns before workers switch, so retry the real handshake.
wait_tls_fingerprint_matching() {
  local port=$1 want=$2 tries=${3:-15} fp
  while [ $tries -gt 0 ]; do
    fp="$(tls_fingerprint "$port")"
    [ "$fp" = "$want" ] && { echo "$fp"; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  echo "$fp"
  return 1
}
wait_tls_any() {
  local port=$1 tries=30 fp
  while [ $tries -gt 0 ]; do
    fp="$(tls_fingerprint "$port")"
    [ -n "$fp" ] && { echo "$fp"; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  return 1
}

for n in "${NODES[@]}"; do
  wait_for_port "${SSH_PORT[$n]}" || DIE "$n sshd never came up"
  wait_tls_any "${TLS_PORT[$n]}" >/dev/null || DIE "$n :443 never served TLS"
  HOSTKEY[$n]="$(ssh_host_key "${SSH_PORT[$n]}")"
  [ -n "${HOSTKEY[$n]}" ] || DIE "could not capture host key for $n"
done
[ "$(printf '%s\n' "${HOSTKEY[n1]}" "${HOSTKEY[n2]}" "${HOSTKEY[n3]}" | sort -u | wc -l | tr -d ' ')" = 3 ] \
  || DIE "nodes share a host key -- host-key pinning would not be a meaningful test"
PASS "three nodes up (ssh + tls), three distinct host keys captured"

STEP "wrapper check: injected nginx wrapper is first on the SSH PATH"
for n in "${NODES[@]}"; do
  got="$(ssh -i "$WORK/id_ed25519" -p "${SSH_PORT[$n]}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR root@127.0.0.1 'command -v nginx' 2>/dev/null)"
  [ "$got" = "/usr/local/bin/nginx" ] || DIE "wrapper not first on PATH for $n (got '$got')"
done
PASS "command -v nginx = /usr/local/bin/nginx on all three nodes"

# ---------------------------------------------------------------------------
# 2. Hub from this checkout.
# ---------------------------------------------------------------------------
STEP "build hub"
GOARCH="$(kk_goarch)"
mkdir -p "$WORK/hubctx"
( cd "$REPO_ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper ) \
  && PASS "hub built (linux/$GOARCH)" || DIE "go build failed"
cp "$REPO_ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile"
podman build -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 \
  && PASS "hub image built" || DIE "hub image build failed, see $WORK/build-hub.log"

cat >"$WORK/hub.env" <<EOF
APP_BOOTSTRAP_TOKEN=$TOKEN
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_DISCOVERY_PROVIDER=db
APP_NOTIFICATION_PROVIDER=file
KRYPTKEEPER_TLS_DISABLE=true
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
EOF

STEP "start hub"
podman run -d --name "$HUB_CTR" --network "$NET" -p "127.0.0.1:${HUB_PORT}:${HUB_PORT}" \
  --env-file "$WORK/hub.env" "$HUB_IMAGE" >/dev/null \
  && PASS "hub container $HUB_CTR up" || DIE "failed to start the hub container"
tries=30
until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}"; do
  tries=$((tries - 1)); [ $tries -le 0 ] && { podman logs "$HUB_CTR" 2>&1 | tail -20; DIE "hub never answered a real /api/v1/cas 200"; }
  sleep 1
done
PASS "hub answering on $HUB_BASE"

jq_py() { python3 -c "import json,sys; d=json.load(sys.stdin); $1" 2>/dev/null; }
CA_ID="$(curlj "${HUB_BASE}/api/v1/cas" | jq_py 'print(d["data"][0]["id"])')"
[ -n "$CA_ID" ] && PASS "root CA: $CA_ID" || DIE "no CA found"

TEMPLATE_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/templates" -d '{
  "name": "uat-rollout-server",
  "display_name": "UAT rollout server cert",
  "allowed_algorithms": ["ECDSA", "RSA-2048"],
  "key_usage": ["digitalSignature", "keyEncipherment"],
  "extended_key_usage": ["serverAuth"],
  "validity_period": "2160h",
  "active": true
}')"
TEMPLATE_ID="$(echo "$TEMPLATE_RESP" | jq_py 'print(d["data"]["id"])')"
[ -n "$TEMPLATE_ID" ] && PASS "template: $TEMPLATE_ID" || DIE "template create failed: $TEMPLATE_RESP"

STEP "credential + target per node, issue cluster certificate C0"
PRIV="$(python3 -c "print(open('$WORK/id_ed25519').read().replace(chr(10), chr(92)+'n'), end='')")"
for n in "${NODES[@]}"; do
  body="$(python3 - "$PRIV" "${HOSTKEY[$n]}" "$n" <<'PY'
import json, sys
priv, hostkey, n = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({"name": f"uat-rollout-{n}", "credential_type": "ssh_key",
  "payload": {"user": "root", "private_key_pem": priv.replace('\\n', '\n'), "host_public_key": hostkey, "port": 22}}))
PY
)"
  cred_id="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "$body" | jq_py 'print(d["data"]["id"])')"
  [ -n "$cred_id" ] || DIE "credential create failed for $n"
  tbody="$(python3 - "${CTR[$n]}" "$cred_id" "$n" <<'PY'
import json, sys
host, cred, n = sys.argv[1:4]
print(json.dumps({"host": host, "discovery_mode": "network", "install_mode": "ssh", "credential_ref": cred,
  "install_server_type": "nginx", "install_cert_path": "/etc/ssl/kk/server.crt",
  "install_key_path": "/etc/ssl/kk/server.key", "install_reload_method": "binary",
  "name": f"{n}.cluster.kk-uat.local"}))
PY
)"
  TARGET_ID[$n]="$(curlj -X POST "${HUB_BASE}/api/v1/targets" -d "$tbody" | jq_py 'print(d["data"]["id"])')"
  [ -n "${TARGET_ID[$n]}" ] || DIE "target create failed for $n"
done
PASS "three credentials (own pinned host key each) and three ssh targets created"

CN="cluster.kk-uat.local"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$WORK/c0.key" -out "$WORK/c0.csr" -subj "/CN=${CN}" -addext "subjectAltName=DNS:${CN}" >/dev/null 2>&1
CSR_JSON="$(python3 -c "import json; print(json.dumps(open('$WORK/c0.csr').read()))")"
C0="$(curlj -X POST "${HUB_BASE}/api/v1/certificates" -d "{\"ca_id\":\"${CA_ID}\",\"template_id\":\"${TEMPLATE_ID}\",\"csr_pem\":${CSR_JSON}}" | jq_py 'print(d["data"]["fingerprint_sha256"])')"
[ -n "$C0" ] && PASS "issued C0: $C0" || DIE "issue C0 failed"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
rollout() { # rollout <fingerprint> -> response JSON
  curlj -X POST "${HUB_BASE}/api/v1/renewal/rollout" -d "$(python3 - "$1" "${TARGET_ID[n1]}" "${TARGET_ID[n2]}" "${TARGET_ID[n3]}" <<'PY'
import json, sys
fp, t1, t2, t3 = sys.argv[1:5]
print(json.dumps({"fingerprint": fp, "group": "uat",
  "nodes": [{"target_id": t1, "is_canary": True}, {"target_id": t2}, {"target_id": t3}]}))
PY
)"
}
node_outcome() { # node_outcome <resp-file> <target_id>
  python3 - "$1" "$2" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["data"]
print(next((r["outcome"] for r in d["node_results"] if r["node_id"] == sys.argv[2]), "MISSING"))
PY
}
residue_ok() { # every node's /etc/ssl/kk holds exactly the live cert and key
  local label=$1 n ls_out ok=0
  for n in "${NODES[@]}"; do
    ls_out="$(podman exec "${CTR[$n]}" sh -c 'cd /etc/ssl/kk && ls | grep -v "^haproxy.pem$" | tr "\n" " "')"
    if [ "$ls_out" != "server.crt server.key " ]; then
      FAIL "[$label] residue on $n: '$ls_out' (want exactly server.crt server.key)"; ok=1
    fi
  done
  [ $ok -eq 0 ] && PASS "[$label] no .kk-staged / .kk-prev residue on any node"
  return $ok
}
read_all_fps() { # sets FP_n1..FP_n3 from the published TLS ports, waiting for $1 on each
  local want=$1 n
  for n in "${NODES[@]}"; do
    printf -v "FP_$n" '%s' "$(wait_tls_fingerprint_matching "${TLS_PORT[$n]}" "$want")"
  done
}
arm() { podman exec "${CTR[$1]}" touch /etc/kk-fail-reload; }

# ---------------------------------------------------------------------------
# Case A: happy path
# ---------------------------------------------------------------------------
STEP "Case A: happy path rollout of C0 to 3 nodes (canary n1 first)"
A_OK=1
rollout "$C0" >"$WORK/a.json"
echo "  raw=$(cat "$WORK/a.json")"
A_HALT="$(jq_py 'print(d["data"]["halted"])' <"$WORK/a.json")"
A_MODE="$(jq_py 'print(d["data"]["mode"])' <"$WORK/a.json")"
NF1="$(jq_py 'print(d["data"]["new_fingerprint"])' <"$WORK/a.json")"
[ "$A_HALT" = False ] && PASS "halted=false" || { FAIL "[A] halted=$A_HALT"; A_OK=0; }
[ "$A_MODE" = staged ] && PASS "mode=staged" || { FAIL "[A] mode=$A_MODE (want staged)"; A_OK=0; }
[ -n "$NF1" ] && [ "$NF1" != "$C0" ] && PASS "new_fingerprint NF1=$NF1" || { FAIL "[A] new_fingerprint empty or unchanged: '$NF1'"; A_OK=0; }
for n in "${NODES[@]}"; do
  o="$(node_outcome "$WORK/a.json" "${TARGET_ID[$n]}")"
  [ "$o" = installed ] && PASS "[A] $n outcome=installed" || { FAIL "[A] $n outcome=$o (want installed)"; A_OK=0; }
done
if [ -n "$NF1" ]; then
  read_all_fps "$NF1"
  for n in "${NODES[@]}"; do
    v="FP_$n"
    [ "${!v}" = "$NF1" ] && PASS "[A] $n serves NF1" || { FAIL "[A] $n serves ${!v}, want $NF1"; A_OK=0; }
  done
fi
z1="$(podman exec "${CTR[n1]}" stat -c %z /etc/ssl/kk/server.crt)"
z2="$(podman exec "${CTR[n2]}" stat -c %z /etc/ssl/kk/server.crt)"
z3="$(podman exec "${CTR[n3]}" stat -c %z /etc/ssl/kk/server.crt)"
echo "  flip times (stat %z): n1=$z1 n2=$z2 n3=$z3"
if [[ ! "$z1" > "$z2" ]] && [[ ! "$z2" > "$z3" ]]; then
  PASS "[A] canary first: n1 <= n2 <= n3 by flip time"
else
  FAIL "[A] flip order not canary-first: $z1 / $z2 / $z3"; A_OK=0
fi
residue_ok A || A_OK=0
[ $A_OK -eq 1 ] && CASE_A=PASS || CASE_A=FAIL

# ---------------------------------------------------------------------------
# Case B: node 3 fails at flip
# ---------------------------------------------------------------------------
if [ -n "${NF1:-}" ]; then
  STEP "Case B: injected flip failure on n3 -> all three nodes keep ONE identical old fingerprint"
  B_OK=1
  arm n3
  rollout "$NF1" >"$WORK/b.json"
  echo "  raw=$(cat "$WORK/b.json")"
  B_HALT="$(jq_py 'print(d["data"]["halted"])' <"$WORK/b.json")"
  NF2="$(jq_py 'print(d["data"]["new_fingerprint"])' <"$WORK/b.json")"
  [ "$B_HALT" = True ] && PASS "[B] halted=true" || { FAIL "[B] halted=$B_HALT"; B_OK=0; }
  want=(rolled_back rolled_back failed); i=0
  for n in "${NODES[@]}"; do
    o="$(node_outcome "$WORK/b.json" "${TARGET_ID[$n]}")"
    [ "$o" = "${want[$i]}" ] && PASS "[B] $n outcome=$o" || { FAIL "[B] $n outcome=$o (want ${want[$i]})"; B_OK=0; }
    i=$((i + 1))
  done
  read_all_fps "$NF1"
  # shellcheck disable=SC2154 # FP_n1..3 are set by read_all_fps via printf -v
  echo "  served: n1=$FP_n1 n2=$FP_n2 n3=$FP_n3 (NF1=$NF1, rejected NF2=${NF2:-})"
  if [ "$FP_n1" = "$FP_n2" ] && [ "$FP_n2" = "$FP_n3" ] && [ "$FP_n1" = "$NF1" ]; then
    PASS "[B] 3 of 3 nodes serve one identical fingerprint, the OLD one (NF1)"
  else
    FAIL "[B] split identity: n1=$FP_n1 n2=$FP_n2 n3=$FP_n3 (want all $NF1)"; B_OK=0
  fi
  [ -n "${NF2:-}" ] && [ "$NF2" != "$NF1" ] && PASS "[B] the rejected NF2 is a distinct certificate and is served nowhere" \
    || { FAIL "[B] new_fingerprint missing or equal to NF1: '${NF2:-}'"; B_OK=0; }
  residue_ok B || B_OK=0
  [ $B_OK -eq 1 ] && CASE_B=PASS || CASE_B=FAIL

  # -------------------------------------------------------------------------
  # Case C: canary fails
  # -------------------------------------------------------------------------
  STEP "Case C: injected canary (n1) flip failure -> n2 and n3 are never flipped"
  C_OK=1
  arm n1
  # NF1 now has a successor (case B's renewal minted NF2 even though no node
  # kept it), so rolling out NF1 again is a 409 "certificate conflict". The
  # renewable head of the chain is NF2; the nodes still serve NF1.
  rollout "${NF2:-$NF1}" >"$WORK/c.json"
  echo "  raw=$(cat "$WORK/c.json")"
  want=(failed skipped skipped); i=0
  for n in "${NODES[@]}"; do
    o="$(node_outcome "$WORK/c.json" "${TARGET_ID[$n]}")"
    [ "$o" = "${want[$i]}" ] && PASS "[C] $n outcome=$o" || { FAIL "[C] $n outcome=$o (want ${want[$i]})"; C_OK=0; }
    i=$((i + 1))
  done
  read_all_fps "$NF1"
  if [ "$FP_n1" = "$NF1" ] && [ "$FP_n2" = "$NF1" ] && [ "$FP_n3" = "$NF1" ]; then
    PASS "[C] all three nodes still serve NF1"
  else
    FAIL "[C] n1=$FP_n1 n2=$FP_n2 n3=$FP_n3 (want all $NF1)"; C_OK=0
  fi
  residue_ok C || C_OK=0
  [ $C_OK -eq 1 ] && CASE_C=PASS || CASE_C=FAIL
else
  FAIL "Case A produced no NF1; cases B and C NOT RUN"
fi

# ---------------------------------------------------------------------------
# Result + last-run.json
# ---------------------------------------------------------------------------
STEP "result"
ELAPSED=$((SECONDS - T0))
MACHINE="$(uname -sm), $(sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo | cut -d: -f2), podman $(podman --version | awk '{print $3}')"
HUB_VER="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
OVERALL=PASS; [ "$FAILED" -eq 0 ] || OVERALL=FAIL
python3 - "$HERE/last-run.json" "$HUB_VER" "$ELAPSED" "$MACHINE" "$CASE_A" "$CASE_B" "$CASE_C" "$OVERALL" <<'PY'
import json, sys, datetime
p, ver, el, mach, a, b, c, overall = sys.argv[1:9]
json.dump({
  "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "hub_version": ver, "elapsed_s": int(el), "machine": mach,
  "cases": {"A_happy_path": a, "B_node3_flip_failure": b, "C_canary_flip_failure": c},
  "result": overall,
}, open(p, "w"), indent=2)
open(p, "a").write("\n")
PY
cat "$HERE/last-run.json"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL PASS"
  exit 0
else
  echo "ONE OR MORE STEPS FAILED (see FAIL lines above; hub logs: podman logs $HUB_CTR)"
  exit 1
fi
