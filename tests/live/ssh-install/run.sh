#!/usr/bin/env bash
# W19-02: prove the hub's agentless SSH install path against a REAL sshd
# host running real nginx and real apache -- renew, install over SSH,
# reload, verify the served leaf, and prove rollback on a verify mismatch.
#
# Idempotent, PASS/FAIL per step, non-zero exit on any FAIL, cleans up its
# own containers/state on exit (trap). No real key material is ever
# committed: the SSH keypair is generated fresh into a temp dir every run.
#
# The hub runs in a container on the same podman network as the two servers
# it manages and reaches them by container name, as it would in production.
# The hub refuses to verify-dial loopback (RC1-A-04), so a hub on the host
# talking to 127.0.0.1 is no longer a valid setup. Container names, the
# network and published ports are unique per run, so concurrent runs and
# other fixtures never collide.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-ssh.XXXXXX)"
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
NGINX_SSH_PORT="$(free_port)"
APACHE_SSH_PORT="$(free_port)"
NGINX_TLS_PORT="$(free_port)"
APACHE_TLS_PORT="$(free_port)"
IMAGE="localhost/kk-uat-ssh:$RUN_ID"
HUB_IMAGE="localhost/kk-uat-ssh-hub:$RUN_ID"
NET="kk-uat-ssh-net-$RUN_ID"
NGINX_CTR="kk-uat-ssh-nginx-$RUN_ID"
APACHE_CTR="kk-uat-ssh-apache-$RUN_ID"
HUB_CTR="kk-uat-ssh-hub-$RUN_ID"

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

cleanup() {
  STEP "cleanup"
  podman rm -f "$NGINX_CTR" "$APACHE_CTR" "$HUB_CTR" >/dev/null 2>&1 || true
  podman network rm "$NET" >/dev/null 2>&1 || true
  podman rmi -f "$IMAGE" "$HUB_IMAGE" >/dev/null 2>&1 || true
  rm -f "$HERE/authorized_keys"
  rm -rf "$WORK"
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }

# ---------------------------------------------------------------------------
# 1. Fresh SSH keypair (never committed -- generated here, deleted on exit).
# ---------------------------------------------------------------------------
STEP "generate SSH keypair"
ssh-keygen -t ed25519 -N '' -f "$WORK/id_ed25519" -C kk-uat >/dev/null \
  && PASS "keypair generated in $WORK" || DIE "ssh-keygen failed"
cp "$WORK/id_ed25519.pub" "$HERE/authorized_keys"

# ---------------------------------------------------------------------------
# 2. Build and run the two target containers (nginx-role, apache-role).
# ---------------------------------------------------------------------------
STEP "build image"
podman build -t "$IMAGE" "$HERE" >"$WORK/build.log" 2>&1 \
  && PASS "image built" || DIE "podman build failed, see $WORK/build.log"
rm -f "$HERE/authorized_keys"

podman network create "$NET" >/dev/null && PASS "network $NET" || DIE "network create failed"

STEP "start nginx-role container"
podman run -d --name "$NGINX_CTR" --network "$NET" \
  -p "${NGINX_SSH_PORT}:22" -p "${NGINX_TLS_PORT}:443" \
  -e ROLE=nginx "$IMAGE" >/dev/null \
  && PASS "container $NGINX_CTR up" || DIE "failed to start $NGINX_CTR"

STEP "start apache-role container"
podman run -d --name "$APACHE_CTR" --network "$NET" \
  -p "${APACHE_SSH_PORT}:22" -p "${APACHE_TLS_PORT}:443" \
  -e ROLE=apache "$IMAGE" >/dev/null \
  && PASS "container $APACHE_CTR up" || DIE "failed to start $APACHE_CTR"

wait_for_port() {
  local port=$1 name=$2 tries=30
  while [ $tries -gt 0 ]; do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 3<&- 3>&-; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  return 1
}
wait_for_port "$NGINX_SSH_PORT" nginx-sshd || DIE "nginx container sshd never came up"
wait_for_port "$APACHE_SSH_PORT" apache-sshd || DIE "apache container sshd never came up"
wait_for_port "$NGINX_TLS_PORT" nginx-tls || DIE "nginx :443 never came up"
wait_for_port "$APACHE_TLS_PORT" apache-tls || DIE "apache :443 never came up"
PASS "both containers reachable (ssh + tls)"

ssh_host_key_once() {
  # ssh-keyscan writes its "# host SSH-2.0-..." banner line to STDOUT (not
  # stderr, despite appearances) -- grep it out explicitly or it pollutes
  # the captured host key with the banner's own fields.
  ssh-keyscan -p "$1" -t ed25519 127.0.0.1 2>/dev/null | grep -v '^#' | awk '{print $3}'
}
# wait_for_port above only proves the TCP listener accepts a connection,
# which can happen a moment before sshd has actually sent its protocol
# banner -- observed directly (an empty scan on one container, a stale
# banner-only partial read on the other). Retry the real handshake.
ssh_host_key() {
  local port=$1 tries=15 key
  while [ $tries -gt 0 ]; do
    key="$(ssh_host_key_once "$port")"
    [ -n "$key" ] && { echo "ssh-ed25519 $key"; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  return 1
}
NGINX_HOSTKEY="$(ssh_host_key "$NGINX_SSH_PORT")"
APACHE_HOSTKEY="$(ssh_host_key "$APACHE_SSH_PORT")"
[ -n "$NGINX_HOSTKEY" ] && [ -n "$APACHE_HOSTKEY" ] || DIE "could not capture host keys via ssh-keyscan"
[ "$NGINX_HOSTKEY" != "$APACHE_HOSTKEY" ] || DIE "nginx and apache containers reported the SAME host key -- host-key pinning would not be a meaningful test"
PASS "captured host keys for pinning"

tls_fingerprint() {
  local port=$1
  echo | openssl s_client -connect "127.0.0.1:${port}" -servername kk-uat 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
}
# A raw TCP accept (wait_for_port above) can succeed while apache/nginx are
# still mid-fork and not yet actually terminating TLS -- observed directly:
# apache's listen socket opens before mod_ssl finishes child-process setup,
# so the very next handshake attempt gets a reset. Retry the real thing
# (a full TLS handshake) rather than trusting the TCP-level check.
wait_tls_fingerprint() {
  local port=$1 tries=15 fp
  while [ $tries -gt 0 ]; do
    fp="$(tls_fingerprint "$port")"
    [ -n "$fp" ] && { echo "$fp"; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  return 1
}
# `nginx -s reload` / `apachectl -k graceful` (and the hub's own best-effort
# rollback reload, which uses the same command) return as soon as the signal
# is SENT, not once new workers are actually live -- the same race the hub
# code itself now retries around (internal/agentinstall/installer.go,
# verifyRetryAttempts). This fixture's OWN post-rollback read needs the same
# tolerance or it can catch the same in-flight handover and report a false
# rollback failure.
wait_tls_fingerprint_matching() {
  local port=$1 want=$2 tries=10 fp
  while [ $tries -gt 0 ]; do
    fp="$(tls_fingerprint "$port")"
    [ "$fp" = "$want" ] && { echo "$fp"; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  echo "$fp"
  return 1
}
NGINX_PLACEHOLDER_FP="$(wait_tls_fingerprint "$NGINX_TLS_PORT")"
APACHE_PLACEHOLDER_FP="$(wait_tls_fingerprint "$APACHE_TLS_PORT")"
[ -n "$NGINX_PLACEHOLDER_FP" ] && [ -n "$APACHE_PLACEHOLDER_FP" ] || DIE "could not read placeholder cert fingerprints"
PASS "placeholder fingerprints: nginx=$NGINX_PLACEHOLDER_FP apache=$APACHE_PLACEHOLDER_FP"

# ---------------------------------------------------------------------------
# 3. Build and run the hub from this checkout.
# ---------------------------------------------------------------------------
STEP "build hub"
case "$(podman info --format '{{.Host.Arch}}' 2>/dev/null)" in arm64|aarch64) GOARCH=arm64 ;; *) GOARCH=amd64 ;; esac
mkdir -p "$WORK/hubctx"
( cd "$REPO_ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper ) \
  && PASS "hub built (linux/$GOARCH)" || DIE "go build failed"
cp "$REPO_ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile"
podman build -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 \
  && PASS "hub image built" || DIE "hub image build failed, see $WORK/build-hub.log"

# W19-31: KRYPTKEEPER_TLS_DISABLE=true -- since W19-14 the hub self-issues a
# TLS listener by default with APP_CERTIFICATE_PROVIDER=ca (below), which
# would break every plain-HTTP curl_hub call this fixture makes. The surface
# under test here is agentless SSH install to nginx/apache, not the hub's
# own TLS listener (proven separately by tests/live/tls/run.sh).
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
# -f (fail on HTTP error) matters here: some other process on this dev
# machine may already be squatting on HUB_PORT (this bit us in dev -- a
# stray container answered every path with its own 404), and a plain
# TCP-connect check would call that "the hub is up".
until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}"; do
  tries=$((tries - 1)); [ $tries -le 0 ] && { podman logs "$HUB_CTR" 2>&1 | tail -20; DIE "hub never answered a real /api/v1/cas 200"; }
  sleep 1
done
PASS "hub answering on $HUB_BASE"

CA_ID="$(curlj "${HUB_BASE}/api/v1/cas" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["data"][0]["id"])' 2>/dev/null)"
[ -n "$CA_ID" ] && PASS "root CA: $CA_ID" || DIE "no CA found (hub container logs: podman logs $HUB_CTR)"

STEP "create template"
TEMPLATE_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/templates" -d '{
  "name": "uat-ssh-server",
  "display_name": "UAT SSH server cert",
  "allowed_algorithms": ["ECDSA", "RSA-2048"],
  "key_usage": ["digitalSignature", "keyEncipherment"],
  "extended_key_usage": ["serverAuth"],
  "validity_period": "2160h",
  "active": true
}')"
TEMPLATE_ID="$(echo "$TEMPLATE_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
[ -n "$TEMPLATE_ID" ] && PASS "template: $TEMPLATE_ID" || DIE "template create failed: $TEMPLATE_RESP"

# ---------------------------------------------------------------------------
# One credential/target/issue/renew cycle per server type.
# ---------------------------------------------------------------------------
run_server_case() {
  local server_type=$1 ssh_port=$2 tls_port=$3 host_key=$4 prior_placeholder_fp=$5 other_tls_port=$6 ctr=$7 other_ctr=$8
  local cn="kk-uat-${server_type}.local"

  STEP "[$server_type] create ssh_key credential"
  local priv payload cred_resp cred_id
  priv="$(python3 -c "print(open('$WORK/id_ed25519').read().replace(chr(10), chr(92)+'n'), end='')")"
  # ssh_port is the HOST-published port (used only to scan the host key); the
  # hub is on the container network and dials sshd on 22.
  payload="$(python3 - "$priv" "$host_key" 22 <<'PY'
import json, sys
priv, hostkey, ssh_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
priv = priv.replace('\\n', '\n')
print(json.dumps({
    "user": "root",
    "private_key_pem": priv,
    "host_public_key": hostkey,
    "port": ssh_port,
}))
PY
)"
  cred_resp="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "$(python3 - "$payload" "$server_type" <<'PY'
import json, sys
payload, server_type = sys.argv[1], sys.argv[2]
print(json.dumps({
    "name": f"uat-ssh-{server_type}",
    "credential_type": "ssh_key",
    "payload": json.loads(payload),
}))
PY
)")"
  cred_id="$(echo "$cred_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
  [ -n "$cred_id" ] && PASS "[$server_type] credential: $cred_id" || { FAIL "[$server_type] credential create: $cred_resp"; return 1; }

  STEP "[$server_type] create target"
  local target_resp target_id
  target_resp="$(curlj -X POST "${HUB_BASE}/api/v1/targets" -d "$(python3 - "$server_type" "$ctr" "$cred_id" "$cn" <<'PY'
import json, sys
server_type, host, cred_id, cn = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
print(json.dumps({
    "host": host,
    "discovery_mode": "network",
    "install_mode": "ssh",
    "credential_ref": cred_id,
    "install_server_type": server_type,
    "install_cert_path": "/etc/ssl/kk/server.crt",
    "install_key_path": "/etc/ssl/kk/server.key",
    "install_reload_method": "binary",
    "name": cn,
}))
PY
)")"
  target_id="$(echo "$target_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
  [ -n "$target_id" ] && PASS "[$server_type] target: $target_id" || { FAIL "[$server_type] target create: $target_resp"; return 1; }

  STEP "[$server_type] issue initial certificate"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$WORK/${server_type}.key" -out "$WORK/${server_type}.csr" \
    -subj "/CN=${cn}" \
    -addext "subjectAltName=DNS:${cn}" >/dev/null 2>&1
  local csr_json issue_resp fp
  csr_json="$(python3 -c "import json; print(json.dumps(open('$WORK/${server_type}.csr').read()))")"
  issue_resp="$(curlj -X POST "${HUB_BASE}/api/v1/certificates" -d "{\"ca_id\":\"${CA_ID}\",\"template_id\":\"${TEMPLATE_ID}\",\"csr_pem\":${csr_json}}")"
  fp="$(echo "$issue_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["fingerprint_sha256"])' 2>/dev/null)"
  [ -n "$fp" ] && PASS "[$server_type] issued: $fp" || { FAIL "[$server_type] issue: $issue_resp"; return 1; }

  STEP "[$server_type] renewal/execute (correct verify_host_port)"
  local exec_resp outcome new_fp
  exec_resp="$(curlj -X POST "${HUB_BASE}/api/v1/renewal/execute" -d "$(python3 - "$fp" "$target_id" "$server_type" "$ctr" <<'PY'
import json, sys
fp, target_id, server_type, vhost = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
print(json.dumps({
    "fingerprint": fp,
    "target_id": target_id,
    "install": {
        "server_type": server_type,
        "cert_path": "/etc/ssl/kk/server.crt",
        "key_path": "/etc/ssl/kk/server.key",
        "reload_method": "binary",
        "verify_host_port": f"{vhost}:443",
    },
}))
PY
)")"
  outcome="$(echo "$exec_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("install_outcome",""))' 2>/dev/null)"
  new_fp="$(echo "$exec_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("new_fingerprint",""))' 2>/dev/null)"
  echo "  outcome=$outcome new_fp=$new_fp raw=$exec_resp"
  if [ "$outcome" != "installed_verified" ]; then
    FAIL "[$server_type] install_outcome=$outcome (want installed_verified)"
    return 1
  fi

  STEP "[$server_type] independent openssl verification"
  local served_fp
  local want_fp; want_fp="$(echo "$new_fp" | tr 'A-F' 'a-f' | tr -d ':')"
  # The hub already verified over the container network; this is the host's
  # independent read through the published port, which can lag a reload.
  served_fp="$(wait_tls_fingerprint_matching "$tls_port" "$want_fp")"
  if [ "$served_fp" = "$want_fp" ]; then
    PASS "[$server_type] served leaf matches new_fingerprint ($served_fp)"
  else
    FAIL "[$server_type] served leaf $served_fp != new_fingerprint $want_fp"
    return 1
  fi

  STEP "[$server_type] negative: verify_host_port pointed at the OTHER server -> expect verify_failed + rollback"
  # New cert/CSR so this is a fresh renewal, not a replay of the one just proven.
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$WORK/${server_type}-neg.key" -out "$WORK/${server_type}-neg.csr" \
    -subj "/CN=${cn}" -addext "subjectAltName=DNS:${cn}" >/dev/null 2>&1
  local neg_csr_json neg_issue_resp neg_fp
  neg_csr_json="$(python3 -c "import json; print(json.dumps(open('$WORK/${server_type}-neg.csr').read()))")"
  neg_issue_resp="$(curlj -X POST "${HUB_BASE}/api/v1/certificates" -d "{\"ca_id\":\"${CA_ID}\",\"template_id\":\"${TEMPLATE_ID}\",\"csr_pem\":${neg_csr_json}}")"
  neg_fp="$(echo "$neg_issue_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["fingerprint_sha256"])' 2>/dev/null)"
  [ -n "$neg_fp" ] || { FAIL "[$server_type] negative-case issue failed: $neg_issue_resp"; return 1; }

  local neg_resp neg_outcome
  neg_resp="$(curlj -X POST "${HUB_BASE}/api/v1/renewal/execute" -d "$(python3 - "$neg_fp" "$target_id" "$server_type" "$other_ctr" <<'PY'
import json, sys
fp, target_id, server_type, vhost = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
print(json.dumps({
    "fingerprint": fp,
    "target_id": target_id,
    "install": {
        "server_type": server_type,
        "cert_path": "/etc/ssl/kk/server.crt",
        "key_path": "/etc/ssl/kk/server.key",
        "reload_method": "binary",
        "verify_host_port": f"{vhost}:443",
    },
}))
PY
)")"
  neg_outcome="$(echo "$neg_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("install_outcome",""))' 2>/dev/null)"
  echo "  negative outcome=$neg_outcome raw=$neg_resp"
  if [ "$neg_outcome" != "verify_failed" ]; then
    FAIL "[$server_type] negative case install_outcome=$neg_outcome (want verify_failed)"
    return 1
  fi
  # Rollback proof: the server must still be serving the PREVIOUS good cert
  # ($new_fp from the positive case above), not the just-rejected one.
  local post_rollback_fp
  post_rollback_fp="$(wait_tls_fingerprint_matching "$tls_port" "$want_fp")"
  if [ "$post_rollback_fp" = "$want_fp" ]; then
    PASS "[$server_type] rollback proven: still serving prior good cert ($post_rollback_fp)"
  else
    FAIL "[$server_type] rollback NOT proven: serving $post_rollback_fp, expected prior good $want_fp"
    return 1
  fi
}

run_server_case nginx  "$NGINX_SSH_PORT"  "$NGINX_TLS_PORT"  "$NGINX_HOSTKEY"  "$NGINX_PLACEHOLDER_FP"  "$APACHE_TLS_PORT" "$NGINX_CTR" "$APACHE_CTR" || true
run_server_case apache "$APACHE_SSH_PORT" "$APACHE_TLS_PORT" "$APACHE_HOSTKEY" "$APACHE_PLACEHOLDER_FP" "$NGINX_TLS_PORT" "$APACHE_CTR" "$NGINX_CTR" || true

STEP "result"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL PASS"
  exit 0
else
  echo "ONE OR MORE STEPS FAILED (see FAIL lines above; hub logs: podman logs $HUB_CTR)"
  exit 1
fi
