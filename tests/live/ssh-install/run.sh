#!/usr/bin/env bash
# W19-02 / W27-08: prove the hub's agentless SSH install path against a REAL
# sshd host running real nginx, apache, HAProxy and Tomcat -- renew, install
# over SSH, reload, verify the served leaf, and prove rollback on a verify
# mismatch (all four) and on a config-test failure (HAProxy, Tomcat).
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
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
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
HAPROXY_SSH_PORT="$(free_port)"
TOMCAT_SSH_PORT="$(free_port)"
HAPROXY_TLS_PORT="$(free_port)"
TOMCAT_TLS_PORT="$(free_port)"
TOMCATJKS_SSH_PORT="$(free_port)"
TOMCATJKS_TLS_PORT="$(free_port)"
# FIXTURE-ONLY constant: the throwaway Tomcat keystore password baked into the
# image (Containerfile, tomcat-server.xml). Grepped for in hub logs/audit at
# the end; it must appear 0 times.
TOMCAT_KS_PW="kk-uat-fixture-pw"
IMAGE="localhost/kk-uat-ssh:$RUN_ID"
HUB_IMAGE="localhost/kk-uat-ssh-hub:$RUN_ID"
NET="kk-uat-ssh-net-$RUN_ID"
NGINX_CTR="kk-uat-ssh-nginx-$RUN_ID"
APACHE_CTR="kk-uat-ssh-apache-$RUN_ID"
HAPROXY_CTR="kk-uat-ssh-haproxy-$RUN_ID"
TOMCAT_CTR="kk-uat-ssh-tomcat-$RUN_ID"
TOMCATJKS_CTR="kk-uat-ssh-tomcatjks-$RUN_ID"
HUB_CTR="kk-uat-ssh-hub-$RUN_ID"

FAILED=0
PASSES=0
STEP() { echo; echo "== $* =="; }
PASS() { PASSES=$((PASSES + 1)); echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

cleanup() {
  STEP "cleanup"
  kk_rm "$NGINX_CTR" "$APACHE_CTR" "$HAPROXY_CTR" "$TOMCAT_CTR" "$TOMCATJKS_CTR" "$HUB_CTR"
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

STEP "start haproxy-role container"
podman run -d --name "$HAPROXY_CTR" --network "$NET" \
  -p "${HAPROXY_SSH_PORT}:22" -p "${HAPROXY_TLS_PORT}:443" \
  -e ROLE=haproxy "$IMAGE" >/dev/null \
  && PASS "container $HAPROXY_CTR up" || DIE "failed to start $HAPROXY_CTR"

STEP "start tomcat-jks-role container (same Tomcat, connector reads a JKS keystore)"
podman run -d --name "$TOMCATJKS_CTR" --network "$NET" \
  -p "${TOMCATJKS_SSH_PORT}:22" -p "${TOMCATJKS_TLS_PORT}:443" \
  -e ROLE=tomcat-jks "$IMAGE" >/dev/null \
  && PASS "container $TOMCATJKS_CTR up" || DIE "failed to start $TOMCATJKS_CTR"

STEP "start tomcat-role container"
podman run -d --name "$TOMCAT_CTR" --network "$NET" \
  -p "${TOMCAT_SSH_PORT}:22" -p "${TOMCAT_TLS_PORT}:443" \
  -e ROLE=tomcat "$IMAGE" >/dev/null \
  && PASS "container $TOMCAT_CTR up" || DIE "failed to start $TOMCAT_CTR"

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
wait_for_port "$HAPROXY_SSH_PORT" haproxy-sshd || DIE "haproxy container sshd never came up"
wait_for_port "$TOMCAT_SSH_PORT" tomcat-sshd || DIE "tomcat container sshd never came up"
wait_for_port "$TOMCATJKS_SSH_PORT" tomcatjks-sshd || DIE "tomcat-jks container sshd never came up"
wait_for_port "$HAPROXY_TLS_PORT" haproxy-tls || DIE "haproxy :443 never came up"
# Tomcat's JVM takes several seconds to open :443 -- give it the full bound.
wait_for_port "$TOMCAT_TLS_PORT" tomcat-tls || DIE "tomcat :443 never came up"
wait_for_port "$TOMCATJKS_TLS_PORT" tomcatjks-tls || DIE "tomcat-jks :443 never came up"
PASS "all five containers reachable (ssh + tls)"

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
HAPROXY_HOSTKEY="$(ssh_host_key "$HAPROXY_SSH_PORT")"
TOMCAT_HOSTKEY="$(ssh_host_key "$TOMCAT_SSH_PORT")"
TOMCATJKS_HOSTKEY="$(ssh_host_key "$TOMCATJKS_SSH_PORT")"
[ -n "$NGINX_HOSTKEY" ] && [ -n "$APACHE_HOSTKEY" ] && [ -n "$HAPROXY_HOSTKEY" ] && [ -n "$TOMCAT_HOSTKEY" ] && [ -n "$TOMCATJKS_HOSTKEY" ] || DIE "could not capture host keys via ssh-keyscan"
[ "$(printf '%s\n' "$NGINX_HOSTKEY" "$APACHE_HOSTKEY" "$HAPROXY_HOSTKEY" "$TOMCAT_HOSTKEY" "$TOMCATJKS_HOSTKEY" | sort -u | wc -l | tr -d ' ')" = 5 ] \
  || DIE "two containers reported the SAME host key -- host-key pinning would not be a meaningful test"
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
  local port=$1 tries=${2:-15} fp
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
  local port=$1 want=$2 tries=${3:-10} fp
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
HAPROXY_PLACEHOLDER_FP="$(wait_tls_fingerprint "$HAPROXY_TLS_PORT" 60)"
TOMCAT_PLACEHOLDER_FP="$(wait_tls_fingerprint "$TOMCAT_TLS_PORT" 60)"
TOMCATJKS_PLACEHOLDER_FP="$(wait_tls_fingerprint "$TOMCATJKS_TLS_PORT" 60)"
[ -n "$NGINX_PLACEHOLDER_FP" ] && [ -n "$APACHE_PLACEHOLDER_FP" ] && [ -n "$HAPROXY_PLACEHOLDER_FP" ] && [ -n "$TOMCAT_PLACEHOLDER_FP" ] && [ -n "$TOMCATJKS_PLACEHOLDER_FP" ] || DIE "could not read placeholder cert fingerprints"
PASS "placeholder fingerprints: nginx=$NGINX_PLACEHOLDER_FP apache=$APACHE_PLACEHOLDER_FP haproxy=$HAPROXY_PLACEHOLDER_FP tomcat=$TOMCAT_PLACEHOLDER_FP"

# ---------------------------------------------------------------------------
# 3. Build and run the hub from this checkout.
# ---------------------------------------------------------------------------
STEP "build hub"
GOARCH="$(kk_goarch)"
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
# profile_for <server_type> -> "cert_path key_path reload_method" ("-" = omit
# the reload method so the installer's default (systemctl) applies). HAProxy
# keeps chain+key in ONE file; Tomcat keeps one PKCS#12 keystore, so for both
# the key path is the same file as the cert path.
profile_for() {
  case "$1" in
    haproxy) echo "/etc/ssl/kk/haproxy.pem /etc/ssl/kk/haproxy.pem -" ;;
    tomcat)  echo "/opt/tomcat/conf/kk.p12 /opt/tomcat/conf/kk.p12 -" ;;
    tomcat-jks) echo "/opt/tomcat/conf/kk.jks /opt/tomcat/conf/kk.jks -" ;;
    *)       echo "/etc/ssl/kk/server.crt /etc/ssl/kk/server.key binary" ;;
  esac
}
# Per-server file whose bytes must be unchanged by a rolled-back install.
installed_file_for() { profile_for "$1" | cut -d' ' -f1; }
# Config breakers/repairers for the config-test-failure case. Both daemons keep
# serving their in-memory config after the file is broken, which is exactly why
# a failed config test must leave the OLD serial live.
break_config() {
  case "$1" in
    haproxy) podman exec "$2" sh -c 'echo "invalid-directive" >> /etc/haproxy/haproxy.cfg' ;;
    tomcat)  podman exec "$2" sed -i 's#</Server>##' /opt/tomcat/conf/server.xml ;;
  esac
}
repair_config() {
  case "$1" in
    haproxy) podman exec "$2" sed -i '/^invalid-directive$/d' /etc/haproxy/haproxy.cfg ;;
    tomcat)  podman exec "$2" sh -c 'echo "</Server>" >> /opt/tomcat/conf/server.xml' ;;
  esac
}
# exec_renewal fp target_id server_type verify_host cert_path key_path reload_method
exec_renewal() {
  curlj -X POST "${HUB_BASE}/api/v1/renewal/execute" -d "$(python3 - "$@" <<'PY'
import json, sys
fp, target_id, server_type, vhost, cert_path, key_path, reload_method = sys.argv[1:8]
install = {
    "server_type": server_type,
    "cert_path": cert_path,
    "key_path": key_path,
    "verify_host_port": f"{vhost}:443",
}
if reload_method != "-":
    install["reload_method"] = reload_method
print(json.dumps({"fingerprint": fp, "target_id": target_id, "install": install}))
PY
)"
}
# Reads a JSON field of the execute response.
jget() { python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get(sys.argv[1],""))' "$1" 2>/dev/null; }
run_server_case() {
  # label distinguishes fixture variants (tomcat-jks) of one product server_type.
  local label=$1 ssh_port=$2 tls_port=$3 host_key=$4 prior_placeholder_fp=$5 other_tls_port=$6 ctr=$7 other_ctr=$8
  local server_type="${label%-jks}" ks_format=""
  [ "$label" = tomcat-jks ] && ks_format=jks
  local cn="kk-uat-${label}.local"
  local cert_path key_path reload_method
  read -r cert_path key_path reload_method <<<"$(profile_for "$label")"
  # The verify reads on the host go through the published port; Tomcat's JVM
  # restart makes those slow, so every server gets the full 60 s bound.
  local TLS_TRIES=60

  STEP "[$label] create ssh_key credential"
  local priv payload cred_resp cred_id
  priv="$(python3 -c "print(open('$WORK/id_ed25519').read().replace(chr(10), chr(92)+'n'), end='')")"
  # ssh_port is the HOST-published port (used only to scan the host key); the
  # hub is on the container network and dials sshd on 22.
  payload="$(python3 - "$priv" "$host_key" 22 "$server_type" "$TOMCAT_KS_PW" "$ks_format" <<'PY'
import json, sys
priv, hostkey, ssh_port, server_type, ks_pw, ks_format = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6]
priv = priv.replace('\\n', '\n')
cred = {
    "user": "root",
    "private_key_pem": priv,
    "host_public_key": hostkey,
    "port": ssh_port,
}
if server_type == "tomcat":
    cred["keystore_password"] = ks_pw
    if ks_format:
        cred["keystore_format"] = ks_format
print(json.dumps(cred))
PY
)"
  cred_resp="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "$(python3 - "$payload" "$label" <<'PY'
import json, sys
payload, label = sys.argv[1], sys.argv[2]
print(json.dumps({
    "name": f"uat-ssh-{label}",
    "credential_type": "ssh_key",
    "payload": json.loads(payload),
}))
PY
)")"
  cred_id="$(echo "$cred_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
  [ -n "$cred_id" ] && PASS "[$label] credential: $cred_id" || { FAIL "[$label] credential create: $cred_resp"; return 1; }

  STEP "[$label] create target"
  local target_resp target_id
  target_resp="$(curlj -X POST "${HUB_BASE}/api/v1/targets" -d "$(python3 - "$server_type" "$ctr" "$cred_id" "$cn" "$cert_path" "$key_path" "$reload_method" <<'PY'
import json, sys
server_type, host, cred_id, cn, cert_path, key_path, reload_method = sys.argv[1:8]
t = {
    "host": host,
    "discovery_mode": "network",
    "install_mode": "ssh",
    "credential_ref": cred_id,
    "install_server_type": server_type,
    "install_cert_path": cert_path,
    "install_key_path": key_path,
    "name": cn,
}
if reload_method != "-":
    t["install_reload_method"] = reload_method
print(json.dumps(t))
PY
)")"
  target_id="$(echo "$target_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
  [ -n "$target_id" ] && PASS "[$label] target: $target_id" || { FAIL "[$label] target create: $target_resp"; return 1; }

  STEP "[$label] issue initial certificate"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$WORK/${label}.key" -out "$WORK/${label}.csr" \
    -subj "/CN=${cn}" \
    -addext "subjectAltName=DNS:${cn}" >/dev/null 2>&1
  local csr_json issue_resp fp
  csr_json="$(python3 -c "import json; print(json.dumps(open('$WORK/${label}.csr').read()))")"
  issue_resp="$(curlj -X POST "${HUB_BASE}/api/v1/certificates" -d "{\"ca_id\":\"${CA_ID}\",\"template_id\":\"${TEMPLATE_ID}\",\"csr_pem\":${csr_json}}")"
  fp="$(echo "$issue_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["fingerprint_sha256"])' 2>/dev/null)"
  [ -n "$fp" ] && PASS "[$label] issued: $fp" || { FAIL "[$label] issue: $issue_resp"; return 1; }

  STEP "[$label] renewal/execute (correct verify_host_port)"
  local exec_resp outcome new_fp
  exec_resp="$(exec_renewal "$fp" "$target_id" "$server_type" "$ctr" "$cert_path" "$key_path" "$reload_method")"
  outcome="$(echo "$exec_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("install_outcome",""))' 2>/dev/null)"
  new_fp="$(echo "$exec_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("new_fingerprint",""))' 2>/dev/null)"
  local exec_done; exec_done=$SECONDS
  echo "  outcome=$outcome new_fp=$new_fp raw=$exec_resp"
  if [ "$outcome" != "installed_verified" ]; then
    FAIL "[$label] install_outcome=$outcome (want installed_verified)"
    return 1
  fi

  STEP "[$label] independent openssl verification"
  local served_fp
  local want_fp; want_fp="$(echo "$new_fp" | tr 'A-F' 'a-f' | tr -d ':')"
  # The hub already verified over the container network; this is the host's
  # independent read through the published port, which can lag a reload.
  served_fp="$(wait_tls_fingerprint_matching "$tls_port" "$want_fp" "$TLS_TRIES")"
  if [ "$served_fp" = "$want_fp" ]; then
    PASS "[$label] served leaf matches new_fingerprint ($served_fp) $((SECONDS - exec_done))s after the install response (bound 60s)"
  else
    FAIL "[$label] served leaf $served_fp != new_fingerprint $want_fp"
    return 1
  fi

  STEP "[$label] negative: verify_host_port pointed at the OTHER server -> expect verify_failed + rollback"
  # New cert/CSR so this is a fresh renewal, not a replay of the one just proven.
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$WORK/${label}-neg.key" -out "$WORK/${label}-neg.csr" \
    -subj "/CN=${cn}" -addext "subjectAltName=DNS:${cn}" >/dev/null 2>&1
  local neg_csr_json neg_issue_resp neg_fp
  neg_csr_json="$(python3 -c "import json; print(json.dumps(open('$WORK/${label}-neg.csr').read()))")"
  neg_issue_resp="$(curlj -X POST "${HUB_BASE}/api/v1/certificates" -d "{\"ca_id\":\"${CA_ID}\",\"template_id\":\"${TEMPLATE_ID}\",\"csr_pem\":${neg_csr_json}}")"
  neg_fp="$(echo "$neg_issue_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["fingerprint_sha256"])' 2>/dev/null)"
  [ -n "$neg_fp" ] || { FAIL "[$label] negative-case issue failed: $neg_issue_resp"; return 1; }

  local neg_resp neg_outcome
  neg_resp="$(exec_renewal "$neg_fp" "$target_id" "$server_type" "$other_ctr" "$cert_path" "$key_path" "$reload_method")"
  neg_outcome="$(echo "$neg_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("install_outcome",""))' 2>/dev/null)"
  echo "  negative outcome=$neg_outcome raw=$neg_resp"
  if [ "$neg_outcome" != "verify_failed" ]; then
    FAIL "[$label] negative case install_outcome=$neg_outcome (want verify_failed)"
    return 1
  fi
  # Rollback proof: the server must still be serving the PREVIOUS good cert
  # ($new_fp from the positive case above), not the just-rejected one.
  local post_rollback_fp
  post_rollback_fp="$(wait_tls_fingerprint_matching "$tls_port" "$want_fp" "$TLS_TRIES")"
  if [ "$post_rollback_fp" = "$want_fp" ]; then
    PASS "[$label] rollback proven: still serving prior good cert ($post_rollback_fp)"
  else
    FAIL "[$label] rollback NOT proven: serving $post_rollback_fp, expected prior good $want_fp"
    return 1
  fi

  case "$server_type" in haproxy|tomcat) ;; *) return 0 ;; esac

  STEP "[$label] negative: forced config-test failure -> expect config_test_failed, old serial kept, file untouched"
  local file; file="$(installed_file_for "$label")"
  local hash_before; hash_before="$(podman exec "$ctr" sha256sum "$file" | cut -d' ' -f1)"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$WORK/${label}-cfg.key" -out "$WORK/${label}-cfg.csr" \
    -subj "/CN=${cn}" -addext "subjectAltName=DNS:${cn}" >/dev/null 2>&1
  local cfg_csr_json cfg_issue_resp cfg_fp
  cfg_csr_json="$(python3 -c "import json; print(json.dumps(open('$WORK/${label}-cfg.csr').read()))")"
  cfg_issue_resp="$(curlj -X POST "${HUB_BASE}/api/v1/certificates" -d "{\"ca_id\":\"${CA_ID}\",\"template_id\":\"${TEMPLATE_ID}\",\"csr_pem\":${cfg_csr_json}}")"
  cfg_fp="$(echo "$cfg_issue_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["fingerprint_sha256"])' 2>/dev/null)"
  [ -n "$cfg_fp" ] || { FAIL "[$label] config-test-case issue failed: $cfg_issue_resp"; return 1; }
  break_config "$server_type" "$ctr" || { FAIL "[$label] could not break the config"; return 1; }
  local cfg_resp cfg_outcome
  cfg_resp="$(exec_renewal "$cfg_fp" "$target_id" "$server_type" "$ctr" "$cert_path" "$key_path" "$reload_method")"
  cfg_outcome="$(echo "$cfg_resp" | jget install_outcome)"
  echo "  config-test outcome=$cfg_outcome raw=$cfg_resp"
  # Repair BEFORE any assertion returns, so a failure cannot leave the fixture broken.
  repair_config "$server_type" "$ctr" || FAIL "[$label] could not repair the config"
  if [ "$cfg_outcome" != "config_test_failed" ]; then
    FAIL "[$label] config-test case install_outcome=$cfg_outcome (want config_test_failed)"
    return 1
  fi
  PASS "[$label] config_test_failed reported"
  local cfg_served; cfg_served="$(tls_fingerprint "$tls_port")"
  if [ "$cfg_served" = "$want_fp" ]; then
    PASS "[$label] old serial still served after config-test failure ($cfg_served)"
  else
    FAIL "[$label] served $cfg_served after config-test failure, expected old $want_fp"
    return 1
  fi
  local hash_after; hash_after="$(podman exec "$ctr" sha256sum "$file" | cut -d' ' -f1)"
  if [ "$hash_before" = "$hash_after" ]; then
    PASS "[$label] $file restored byte-for-byte (sha256 $hash_after)"
  else
    FAIL "[$label] $file hash changed: $hash_before -> $hash_after"
    return 1
  fi
}

run_server_case nginx  "$NGINX_SSH_PORT"  "$NGINX_TLS_PORT"  "$NGINX_HOSTKEY"  "$NGINX_PLACEHOLDER_FP"  "$APACHE_TLS_PORT" "$NGINX_CTR" "$APACHE_CTR" || true
run_server_case apache "$APACHE_SSH_PORT" "$APACHE_TLS_PORT" "$APACHE_HOSTKEY" "$APACHE_PLACEHOLDER_FP" "$NGINX_TLS_PORT" "$APACHE_CTR" "$NGINX_CTR" || true

run_server_case haproxy "$HAPROXY_SSH_PORT" "$HAPROXY_TLS_PORT" "$HAPROXY_HOSTKEY" "$HAPROXY_PLACEHOLDER_FP" "$TOMCAT_TLS_PORT" "$HAPROXY_CTR" "$TOMCAT_CTR" || true
run_server_case tomcat  "$TOMCAT_SSH_PORT"  "$TOMCAT_TLS_PORT"  "$TOMCAT_HOSTKEY"  "$TOMCAT_PLACEHOLDER_FP"  "$HAPROXY_TLS_PORT" "$TOMCAT_CTR" "$HAPROXY_CTR" || true
run_server_case tomcat-jks "$TOMCATJKS_SSH_PORT" "$TOMCATJKS_TLS_PORT" "$TOMCATJKS_HOSTKEY" "$TOMCATJKS_PLACEHOLDER_FP" "$HAPROXY_TLS_PORT" "$TOMCATJKS_CTR" "$HAPROXY_CTR" || true

STEP "[tomcat-jks] installed keystore really is JKS (magic FEEDFEED), not PKCS12"
JKS_MAGIC="$(podman exec "$TOMCATJKS_CTR" od -An -tx1 -N4 /opt/tomcat/conf/kk.jks | tr -d ' \n')"
[ "$JKS_MAGIC" = feedfeed ] && PASS "kk.jks starts with JKS magic ($JKS_MAGIC)" || FAIL "kk.jks magic is '$JKS_MAGIC', want feedfeed"
podman exec "$TOMCATJKS_CTR" grep -q 'certificateKeystoreType="JKS"' /opt/tomcat/conf/server.xml \
  && PASS "server.xml connector declares certificateKeystoreType=JKS" || FAIL "server.xml does not declare JKS"

STEP "fixture secret never leaks to hub logs / audit"
LEAKS="$( { podman logs "$HUB_CTR" 2>&1; curlj "${HUB_BASE}/api/v1/audit?limit=1000"; } | grep -c -F -e "$TOMCAT_KS_PW" || true)"
[ "$LEAKS" = 0 ] && PASS "keystore password appears 0 times in hub log and audit" || FAIL "keystore password found $LEAKS time(s) in hub log/audit"

STEP "result"
echo "checks: $PASSES passed"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL PASS"
  exit 0
else
  echo "ONE OR MORE STEPS FAILED (see FAIL lines above; hub logs: podman logs $HUB_CTR)"
  exit 1
fi
