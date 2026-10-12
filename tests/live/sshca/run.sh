#!/usr/bin/env bash
# W11-07 live proof: the hub's SSH CA against a real OpenSSH server and
# client. The server has no authorized_keys; it trusts only the hub's CA.
#
#   1. the hub publishes its CA line; a user cert (principal deploy) and a
#      host cert (over the container's own host key) are issued by the API
#   2. ssh logs in as deploy with the user cert, verifying the host through
#      @cert-authority with StrictHostKeyChecking=yes; sshd logs the key ID
#   3. refusals by real OpenSSH: the bare key, a cert for another principal,
#      an expired cert, and a host checked against a different CA
#   4. policy: a TTL over the ceiling is refused; issuance is audited
#   5. who may issue: viewer and mcp-agent keys must not mint certificates
#   6. template policy (A01S-4): every certificate is issued against a
#      template whose ssh_policy lists the principals/hosts it may sign;
#      a principal outside it (root) and a request with no template_id are
#      refused
#
# Idempotent, PASS/FAIL per step, cleans up on exit. Keys are generated per
# run and never committed.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-sshca.XXXXXX)"
HUB_PORT="${HUB_PORT:-8098}"
SSH_PORT="${SSH_PORT:-2224}"
HUB="http://127.0.0.1:$HUB_PORT"
TOKEN="uat-sshca-bootstrap-token"
IMAGE=localhost/kk-uat-sshca:latest
CTR=kk-uat-sshca
HOSTNAME_CERT=sshca.kk-uat.test
USER_TPL=""
OTHER_TPL=""
HOST_TPL=""
FAILED=0
HUB_PID=""

STEP() { echo; echo "=== $* ==="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; exit 1; }
cleanup() {
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null
  podman rm -f "$CTR" >/dev/null 2>&1
  wait 2>/dev/null
  if [ "$FAILED" = 1 ] && [ -f "$WORK/hub.log" ]; then echo "--- hub.log (last 20) ---"; tail -20 "$WORK/hub.log"; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
code() { local tok="$1"; shift; curl -sS -o "$WORK/last.json" -w '%{http_code}' -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
# issue <token> <out-file> <json body>: writes certificate_line to out-file.
issue() {
  local c; c=$(code "$1" -X POST "$HUB/api/v1/ssh/certificates" -d "$3")
  [ "$c" = 201 ] || { echo "$c $(cat "$WORK/last.json")"; return 1; }
  jget 'd["data"]["certificate_line"]' <"$WORK/last.json" >"$2"
}
body() { # body <pubkey file> <type> <key_id> <principal> <ttl_hours> <template_id; "" omits it>
  python3 -c 'import json,sys; d={"public_key":open(sys.argv[1]).read().strip(),"cert_type":sys.argv[2],"key_id":sys.argv[3],"principals":[sys.argv[4]],"ttl_hours":float(sys.argv[5])}
if sys.argv[6]: d["template_id"]=sys.argv[6]
print(json.dumps(d))' "$@"
}
# mktpl <name> <ssh_policy json>: creates a template, prints its id.
mktpl() {
  local c; c=$(code "$TOKEN" -X POST "$HUB/api/v1/templates" -d "{\"name\":\"$1\",\"display_name\":\"$1\",\"key_usage\":[\"digitalSignature\"],\"extended_key_usage\":[\"clientAuth\"],\"allowed_algorithms\":[\"ECDSA\"],\"validity_period\":\"P1D\",\"active\":true,\"ssh_policy\":$2}")
  [ "$c" = 201 ] || { echo "template $1: $c $(cat "$WORK/last.json")" >&2; return 1; }
  jget 'd["data"]["id"]' <"$WORK/last.json"
}
# try_login <identity> <known_hosts> [extra ssh options...]: prints the remote user.
try_login() {
  local id="$1" kh="$2"; shift 2
  ssh -F /dev/null -p "$SSH_PORT" -i "$id" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$kh" -o GlobalKnownHostsFile=/dev/null \
    -o HostKeyAlias="$HOSTNAME_CERT" "$@" deploy@127.0.0.1 'id -un' 2>"$WORK/ssh.err"
}

STEP "build hub and sshd image"
(cd "$REPO_ROOT" && go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper) || DIE "go build failed"
podman build -q -t "$IMAGE" "$HERE" >"$WORK/build.log" 2>&1 || DIE "podman build failed: $(tail -5 "$WORK/build.log")"
PASS "built"

STEP "start hub and sshd container"
mkdir -p "$WORK/data"
env APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_API_KEY_PEPPER='uat-pepper-32-characters-minimum!!' APP_API_KEY_AUTH_ENABLED=true \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
  KRYPTKEEPER_DATA_DIR="$WORK/data" APP_CA_FILE="$WORK/data/cas.json" APP_TEMPLATE_FILE="$WORK/data/templates.json" \
  APP_CERTIFICATE_FILE="$WORK/data/certificates.json" APP_AUDIT_FILE="$WORK/data/audit.json" APP_CERTS_SUMMARY_FILE="$WORK/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA" APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT" \
  KRYPTKEEPER_TLS_DISABLE=true "$WORK/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
for _ in $(seq 1 60); do curl -sf "$HUB/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$HUB/healthz" >/dev/null || DIE "hub did not start"
podman rm -f "$CTR" >/dev/null 2>&1
podman run -d --name "$CTR" -p "127.0.0.1:$SSH_PORT:22" "$IMAGE" >/dev/null || DIE "container did not start"
for _ in $(seq 1 50); do podman exec "$CTR" test -f /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null && break; sleep 0.2; done
PASS "hub and container up"

STEP "templates carrying the SSH policy"
USER_TPL="$(mktpl kk-uat-ssh-user '{"cert_types":["user"],"allowed_principals":["deploy"],"max_ttl_hours":24}')" || DIE "user template not created"
OTHER_TPL="$(mktpl kk-uat-ssh-other '{"cert_types":["user"],"allowed_principals":["someone-else"],"max_ttl_hours":24}')" || DIE "other-principal template not created"
HOST_TPL="$(mktpl kk-uat-ssh-host "{\"cert_types\":[\"host\"],\"host_patterns\":[\"$HOSTNAME_CERT\"],\"max_ttl_hours\":24}")" || DIE "host template not created"
PASS "user ($USER_TPL), other-principal ($OTHER_TPL) and host ($HOST_TPL) templates created with ssh_policy"

STEP "CA line, host certificate, user certificates"
c=$(code "$TOKEN" "$HUB/api/v1/ssh/ca")
[ "$c" = 200 ] || DIE "GET /ssh/ca -> $c $(cat "$WORK/last.json")"
jget 'd["authority_line"].strip()' <"$WORK/last.json" >"$WORK/ca.pub"
PASS "CA $(jget 'd["authority_fingerprint"]' <"$WORK/last.json")"

podman exec "$CTR" cat /etc/ssh/ssh_host_ed25519_key.pub >"$WORK/host.pub"
issue "$TOKEN" "$WORK/host-cert.pub" "$(body "$WORK/host.pub" host kk-uat-host "$HOSTNAME_CERT" 1 "$HOST_TPL")" || DIE "host cert not issued"
podman cp "$WORK/ca.pub" "$CTR:/etc/ssh/kk_user_ca.pub" && podman cp "$WORK/host-cert.pub" "$CTR:/etc/ssh/ssh_host_ed25519_key-cert.pub" \
  && podman exec "$CTR" sh -c 'chmod 644 /etc/ssh/kk_user_ca.pub /etc/ssh/ssh_host_ed25519_key-cert.pub && touch /etc/ssh/kk-ready' \
  || DIE "could not install CA line and host cert"
PASS "host cert issued over the container's own host key and installed"

ssh-keygen -q -t ed25519 -N '' -f "$WORK/deploy" -C kk-uat-deploy
issue "$TOKEN" "$WORK/deploy-cert.pub" "$(body "$WORK/deploy.pub" user kk-uat-deploy deploy 1 "$USER_TPL")" || DIE "user cert not issued"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/other" -C kk-uat-other
issue "$TOKEN" "$WORK/other-cert.pub" "$(body "$WORK/other.pub" user kk-uat-other someone-else 1 "$OTHER_TPL")" || DIE "other-principal cert not issued"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/short" -C kk-uat-short
# 72 seconds of TTL. The hub backdates valid_after by a minute for clock
# skew but not valid_before, so this expires 72 s after issue: long enough
# to log in with it first, short enough to wait out.
issue "$TOKEN" "$WORK/short-cert.pub" "$(body "$WORK/short.pub" user kk-uat-short deploy 0.02 "$USER_TPL")" || DIE "short cert not issued"
EXPIRES="$(jget 'd["data"]["valid_before"]' <"$WORK/last.json")"
PASS "user certs issued (deploy, someone-else, short-lived until $EXPIRES)"
echo "@cert-authority $HOSTNAME_CERT $(cat "$WORK/ca.pub")" >"$WORK/known_hosts"
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$SSH_PORT") 2>/dev/null && break; sleep 0.2; done

STEP "login with the user certificate, host verified by the CA"
WHO="$(try_login "$WORK/deploy" "$WORK/known_hosts" -o CertificateFile="$WORK/deploy-cert.pub")"
[ "$WHO" = deploy ] && PASS "logged in as $WHO with a hub-issued cert; host accepted via @cert-authority" || FAIL "cert login failed: $(cat "$WORK/ssh.err")"
# sshd's log line can trail the session's end by a moment.
# Capture first: with pipefail, grep -q exiting early SIGPIPEs podman logs
# and fails the pipeline even on a match. OpenSSH may quote the key ID.
for _ in $(seq 1 25); do SSHD_LOG="$(podman logs "$CTR" 2>&1)"; grep -qE 'ID "?kk-uat-deploy"? ' <<<"$SSHD_LOG" && break; sleep 0.2; done
grep -qE 'ID "?kk-uat-deploy"? ' <<<"$SSHD_LOG" && PASS "sshd logged the certificate key ID (kk-uat-deploy)" || FAIL "sshd log lacks the key ID: $(podman logs "$CTR" 2>&1 | grep -i 'accepted\|deploy' | head -3)"

STEP "refusals by real OpenSSH"
WHO="$(try_login "$WORK/deploy" "$WORK/known_hosts" -o CertificateFile=/dev/null)"
[ -z "$WHO" ] && PASS "the same key without its certificate is refused" || FAIL "bare key logged in as $WHO"
WHO="$(try_login "$WORK/other" "$WORK/known_hosts" -o CertificateFile="$WORK/other-cert.pub")"
[ -z "$WHO" ] && PASS "a cert for another principal cannot log in as deploy" || FAIL "wrong-principal cert logged in as $WHO"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/rogue-ca" -C rogue
echo "@cert-authority $HOSTNAME_CERT $(cat "$WORK/rogue-ca.pub")" >"$WORK/rogue_known_hosts"
WHO="$(try_login "$WORK/deploy" "$WORK/rogue_known_hosts" -o CertificateFile="$WORK/deploy-cert.pub")"
[ -z "$WHO" ] && grep -qi "host key verification failed\|no matching host key\|REMOTE HOST IDENTIFICATION" "$WORK/ssh.err" \
  && PASS "a client trusting a different CA rejects the host" || FAIL "host accepted under a rogue CA: $WHO $(cat "$WORK/ssh.err")"
WHO="$(try_login "$WORK/short" "$WORK/known_hosts" -o CertificateFile="$WORK/short-cert.pub")"
[ "$WHO" = deploy ] && PASS "short-lived cert works while valid" || FAIL "short-lived cert refused while valid: $(cat "$WORK/ssh.err")"
echo "waiting for the short-lived cert to expire ($EXPIRES)..."
for _ in $(seq 1 90); do
  python3 -c 'import sys,datetime; sys.exit(0 if datetime.datetime.now(datetime.timezone.utc) > datetime.datetime.fromisoformat(sys.argv[1].replace("Z","+00:00")) + datetime.timedelta(seconds=2) else 1)' "$EXPIRES" && break
  sleep 2
done
WHO="$(try_login "$WORK/short" "$WORK/known_hosts" -o CertificateFile="$WORK/short-cert.pub")"
[ -z "$WHO" ] && PASS "the same cert is refused once expired" || FAIL "expired cert logged in as $WHO"

STEP "policy and audit"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/long" -C kk-uat-long
c=$(code "$TOKEN" -X POST "$HUB/api/v1/ssh/certificates" -d "$(body "$WORK/long.pub" user kk-uat-long deploy 25 "$USER_TPL")")
[ "$c" = 400 ] && PASS "a 25-hour user cert is refused (ceiling and template max 24h)" || FAIL "over-ceiling TTL -> $c"
c=$(code "$TOKEN" "$HUB/api/v1/ssh/certificates")
N="$(jget 'len(d["data"])' <"$WORK/last.json" 2>/dev/null)"
[ "$c" = 200 ] && [ "$N" = 4 ] && PASS "4 issued certs listed" || FAIL "list -> $c, $N records"
AUD="$(curl -sS -H "Authorization: Bearer $TOKEN" "$HUB/api/v1/audit?limit=100" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; rows=d if isinstance(d,list) else d.get("entries",d.get("items",[])); print(sum(1 for r in rows if r["action"]=="ssh_certificate.issue" and r["outcome"]=="success"))')"
[ "$AUD" = 4 ] && PASS "4 ssh_certificate.issue audit rows" || FAIL "audit rows: $AUD"

STEP "who may issue"
for role in viewer mcp-agent; do
  KEY="$(curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X POST "$HUB/api/v1/api-keys" \
    -d "{\"name\":\"uat-$role\",\"principal_id\":\"uat-$role\",\"role\":\"$role\"}" | jget 'd["data"]["token"]')"
  [ -n "$KEY" ] || { FAIL "could not create a $role key"; continue; }
  ssh-keygen -q -t ed25519 -N '' -f "$WORK/$role" -C "kk-uat-$role"
  c=$(code "$KEY" -X POST "$HUB/api/v1/ssh/certificates" -d "$(body "$WORK/$role.pub" user "kk-uat-$role" deploy 1 "$USER_TPL")")
  case "$c" in 401|403) PASS "a $role key cannot issue SSH certs ($c)" ;; *) FAIL "a $role key issued an SSH cert for deploy ($c)" ;; esac
done

STEP "template policy refusals (A01S-4)"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/rootreq" -C kk-uat-rootreq
c=$(code "$TOKEN" -X POST "$HUB/api/v1/ssh/certificates" -d "$(body "$WORK/rootreq.pub" user kk-uat-root root 1 "$USER_TPL")")
[ "$c" = 400 ] && PASS "a principal outside the template policy (root) is refused ($c)" || FAIL "root principal -> $c $(cat "$WORK/last.json")"
c=$(code "$TOKEN" -X POST "$HUB/api/v1/ssh/certificates" -d "$(body "$WORK/rootreq.pub" user kk-uat-notpl deploy 1 "")")
[ "$c" = 400 ] && PASS "a request without template_id is refused ($c)" || FAIL "no template_id -> $c $(cat "$WORK/last.json")"
c=$(code "$TOKEN" -X POST "$HUB/api/v1/ssh/certificates" -d "$(body "$WORK/rootreq.pub" host kk-uat-wronghost evil.example 1 "$HOST_TPL")")
[ "$c" = 400 ] && PASS "a host name outside the template's host_patterns is refused ($c)" || FAIL "wrong host -> $c $(cat "$WORK/last.json")"
c=$(code "$TOKEN" "$HUB/api/v1/ssh/certificates")
N="$(jget 'len(d["data"])' <"$WORK/last.json" 2>/dev/null)"
[ "$c" = 200 ] && [ "$N" = 4 ] && PASS "the refusals signed nothing (still 4 certs)" || FAIL "list after refusals -> $c, $N records"

echo
[ "$FAILED" = 0 ] && echo "ALL STEPS PASSED" || echo "ONE OR MORE STEPS FAILED"
exit "$FAILED"
