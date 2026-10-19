#!/usr/bin/env bash
# W26-16 live proof: issuance policy rejection and the approval gate, over the
# X.509 API and over SSH certificates, against a real hub and a real sshd.
#
#   1. RSA-1024 CSR against a min_key_size 2048 template: refused HTTP 422
#      policy_violation naming the rule; nothing signed
#   2. approval-required template: 202 pending_approval, no certificate until a
#      DIFFERENT principal approves (201); the proposer cannot self-approve
#   3. same key + template again (idempotency): recorded as the product answers
#   4. SSH cert from an approval-required template: 202 pending_approval, then a
#      different principal approves (201 with the SSH cert record), then real
#      sshd accepts the cert; a TTL above the template ceiling is 400
#
# alice and bob are two named pki-admin humans from APP_API_KEYS_JSON. The
# bootstrap token and keys minted with it can propose but NEVER approve
# (separation_of_duties.go), so they cannot stand in for the approver.
#
# PASS/FAIL per step; known-gap FAILs stay FAIL. Writes nothing into the repo.
# Cleans up the hub, container and temp dir on exit. Needs podman, go, openssl,
# ssh, python3, curl.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-issapp.XXXXXX)"
HUB_PORT="${HUB_PORT:-8101}"
SSH_PORT="${SSH_PORT:-2225}"
HUB="http://127.0.0.1:$HUB_PORT"
BOOT="uat-issapp-bootstrap-token"
PEPPER="uat-pepper-32-characters-minimum!!"
IMAGE=localhost/kk-uat-issapp:latest
CTR=kk-uat-issapp
HOSTNAME_CERT=issapp.kk-uat.test
FAILED=0
HUB_PID=""
ENTRIES=""

STEP() { echo; echo "=== $* ==="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; FAILED=1; exit 1; }
cleanup() {
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null
  kk_rm "$CTR"
  wait 2>/dev/null
  if [ "$FAILED" = 1 ] && [ -f "$WORK/hub.log" ]; then echo "--- hub.log (last 20) ---"; tail -20 "$WORK/hub.log"; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
code() { local tok="$1"; shift; curl -sS -o "$WORK/last.json" -w '%{http_code}' -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
mkident() { # name role -> sets T_<name>
  local name="$1" role="$2" secret verifier
  secret="$(openssl rand -hex 24)"
  verifier="$(printf '%s' "$secret" | openssl dgst -sha256 -hmac "$PEPPER" -hex | awk '{print $NF}')"
  eval "T_$name=kk_uat${name}_${secret}"
  ENTRIES="${ENTRIES:+$ENTRIES,}{\"name\":\"$name\",\"kid\":\"uat$name\",\"secret_verifier\":\"$verifier\",\"principal_id\":\"$name\",\"role\":\"$role\",\"active\":true}"
}
mktpl() { # mktpl <name> <extra json fields, leading comma> -> prints template id
  local c; c=$(code "$T_alice" -X POST "$HUB/api/v1/templates" -d "{\"name\":\"$1\",\"display_name\":\"$1\",\"key_usage\":[\"digitalSignature\",\"keyEncipherment\"],\"extended_key_usage\":[\"serverAuth\",\"clientAuth\"],\"allowed_algorithms\":[\"RSA\",\"ECDSA\"],\"validity_period\":\"P30D\",\"active\":true$2}")
  [ "$c" = 201 ] || { echo "template $1: $c $(cat "$WORK/last.json")" >&2; return 1; }
  jget 'd["data"]["id"]' <"$WORK/last.json"
}
certcount() { code "$T_alice" "$HUB/api/v1/certificates?q=$1&limit=100" >/dev/null; jget 'len(d["data"])' <"$WORK/last.json"; }
csr() { # csr <bits> <cn> <base>: RSA key + CSR in <base>.key/.csr/.json (needs $CA_ID and a template id in $4)
  openssl genrsa -out "$3.key" "$1" 2>/dev/null
  openssl req -new -key "$3.key" -subj "/CN=$2" -addext "subjectAltName=DNS:$2" -out "$3.csr" 2>/dev/null
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$4" "$3.csr" "$3.json"
}
sshbody() { # sshbody <pubkey file> <type> <key_id> <principal> <ttl_hours> <template_id>
  python3 -c 'import json,sys; print(json.dumps({"public_key":open(sys.argv[1]).read().strip(),"cert_type":sys.argv[2],"key_id":sys.argv[3],"principals":[sys.argv[4]],"ttl_hours":float(sys.argv[5]),"template_id":sys.argv[6]}))' "$@"
}
try_login() { # try_login <identity> <known_hosts> [extra ssh options...]: prints the remote user
  local id="$1" kh="$2"; shift 2
  ssh -F /dev/null -p "$SSH_PORT" -i "$id" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$kh" -o GlobalKnownHostsFile=/dev/null \
    -o HostKeyAlias="$HOSTNAME_CERT" "$@" deploy@127.0.0.1 'id -un' 2>"$WORK/ssh.err"
}

STEP "build hub and sshd image"
mkident alice pki-admin; mkident bob pki-admin
(cd "$REPO_ROOT" && go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper) || DIE "go build failed"
podman build -q -t "$IMAGE" "$HERE" >"$WORK/build.log" 2>&1 || DIE "podman build failed: $(tail -5 "$WORK/build.log")"
PASS "built"

STEP "start hub (bootstrap root CA, alice and bob as pki-admin) and sshd container"
mkdir -p "$WORK/data"
env APP_BOOTSTRAP_TOKEN="$BOOT" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_API_KEY_PEPPER="$PEPPER" APP_API_KEY_AUTH_ENABLED=true APP_API_KEYS_JSON="[$ENTRIES]" \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
  KRYPTKEEPER_DATA_DIR="$WORK/data" APP_CA_FILE="$WORK/data/cas.json" APP_TEMPLATE_FILE="$WORK/data/templates.json" \
  APP_CERTIFICATE_FILE="$WORK/data/certificates.json" APP_AUDIT_FILE="$WORK/data/audit.json" APP_CERTS_SUMMARY_FILE="$WORK/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA" APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT" \
  KRYPTKEEPER_TLS_DISABLE=true "$WORK/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
for _ in $(seq 1 60); do curl -sf "$HUB/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$HUB/healthz" >/dev/null || DIE "hub did not start"
kk_rm "$CTR"
podman run -d --name "$CTR" -p "127.0.0.1:$SSH_PORT:22" "$IMAGE" >/dev/null || DIE "container did not start"
for _ in $(seq 1 50); do podman exec "$CTR" test -f /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null && break; sleep 0.2; done
c=$(code "$T_alice" "$HUB/api/v1/cas"); [ "$c" = 200 ] || DIE "alice cannot list CAs: $c $(cat "$WORK/last.json")"
CA_ID="$(jget 'd["data"][0]["id"]' <"$WORK/last.json")"
[ -n "$CA_ID" ] || DIE "no bootstrap root CA"
PASS "hub and container up; root CA $CA_ID"

STEP "templates"
RSA_DIRECT="$(mktpl rsa-direct ',"min_key_size":2048')" || DIE "rsa-direct not created"
RSA_APPR="$(mktpl rsa-approval ',"min_key_size":2048,"require_approval":true,"approval_roles":["pki-admin"]')" || DIE "rsa-approval not created"
PASS "rsa-direct ($RSA_DIRECT) and rsa-approval ($RSA_APPR) created, min_key_size 2048"

STEP "1. policy rejection: RSA-1024 CSR"
BEFORE="$(certcount weak.issapp.test)"
csr 1024 weak.issapp.test "$WORK/weak" "$RSA_DIRECT"
c=$(code "$T_alice" -X POST "$HUB/api/v1/certificates" --data @"$WORK/weak.json")
echo "observed: HTTP $c $(head -c 300 "$WORK/last.json")"
[ "$c" = 422 ] && PASS "RSA-1024 refused with HTTP 422 (the owner 2026-10-16: 422, not 400)" || FAIL "RSA-1024 -> $c, want 422"
ERR="$(jget 'd.get("error","")' <"$WORK/last.json" 2>/dev/null)"
[ "$ERR" = policy_violation ] && PASS "error code is policy_violation" || FAIL "error code is '$ERR'"
jget 'd.get("message","")' <"$WORK/last.json" 2>/dev/null | grep -q 'key_size' \
  && PASS "message names the rule (key_size; the template field is min_key_size)" || FAIL "message does not name the key_size rule: $(cat "$WORK/last.json")"
[ "$(certcount weak.issapp.test)" = "$BEFORE" ] && PASS "nothing was signed for the refused CSR" || FAIL "a certificate exists for the refused CSR"

STEP "2. approval-required template: 202, then second principal approves"
CN=app.issapp.test
csr 4096 "$CN" "$WORK/app" "$RSA_APPR"
c=$(code "$T_alice" -X POST "$HUB/api/v1/certificates" --data @"$WORK/app.json")
[ "$c" = 202 ] && PASS "alice's request answers 202" || DIE "approval-required issuance -> $c $(cat "$WORK/last.json")"
[ "$(jget 'd.get("status","")' <"$WORK/last.json")" = pending_approval ] && PASS "body status is pending_approval" || FAIL "body: $(cat "$WORK/last.json")"
APR="$(jget 'd.get("approval_id","")' <"$WORK/last.json")"
[ -n "$APR" ] && PASS "approval_id $APR" || DIE "no approval_id"
[ "$(certcount "$CN")" = 0 ] && PASS "no certificate is listed while pending" || FAIL "a certificate exists before approval"
c=$(code "$T_alice" -X POST "$HUB/api/v1/approvals/$APR/approve")
[ "$c" = 403 ] && PASS "alice approving her own request is refused ($c)" || FAIL "self-approval -> $c $(cat "$WORK/last.json")"
[ "$(certcount "$CN")" = 0 ] && PASS "still no certificate after the refused self-approval" || FAIL "self-approval issued a certificate"
c=$(code "$BOOT" -X POST "$HUB/api/v1/approvals/$APR/approve")
[ "$c" = 403 ] && PASS "the bootstrap token cannot approve either ($c)" || FAIL "bootstrap approve -> $c $(cat "$WORK/last.json")"
c=$(code "$T_bob" -X POST "$HUB/api/v1/approvals/$APR/approve")
[ "$c" = 201 ] && PASS "bob approves: 201" || FAIL "bob approve -> $c $(cat "$WORK/last.json")"
SERIAL1="$(jget 'd["data"]["serial_number"]' <"$WORK/last.json" 2>/dev/null)"
FP1="$(jget 'd["data"]["fingerprint_sha256"]' <"$WORK/last.json" 2>/dev/null)"
[ -n "$FP1" ] || DIE "approval returned no certificate"
code "$T_alice" "$HUB/api/v1/certificates?q=$CN" >/dev/null
SRC="$(jget 'd["data"][0]["source"]' <"$WORK/last.json" 2>/dev/null)"
[ "$(certcount "$CN")" = 1 ] && [ "$SRC" = api ] && PASS "certificate is now listed (source=$SRC, serial $SERIAL1)" || FAIL "after approval: count $(certcount "$CN"), source '$SRC'"
c=$(code "$T_bob" -X POST "$HUB/api/v1/approvals/$APR/approve")
[ "$c" = 409 ] && PASS "approving again is 409 (not pending)" || FAIL "second approve -> $c"

STEP "3. idempotency: same CSR (same key + template) again"
c=$(code "$T_alice" -X POST "$HUB/api/v1/certificates" --data @"$WORK/app.json")
echo "observed on the approval template: HTTP $c $(head -c 200 "$WORK/last.json")"
if [ "$c" = 200 ] && [ "$(jget 'd["data"]["serial_number"]' <"$WORK/last.json")" = "$SERIAL1" ]; then
  PASS "same key + template returned the same serial ($SERIAL1) with HTTP 200 (W26-32 reuse)"
else
  FAIL "same key + template did not return the same serial (HTTP $c); HANDOFF: US-010 AC4 same-key idempotency not implemented"
fi
csr 4096 direct.issapp.test "$WORK/direct" "$RSA_DIRECT"
c1=$(code "$T_alice" -X POST "$HUB/api/v1/certificates" --data @"$WORK/direct.json"); S1="$(jget 'd.get("data",{}).get("serial_number","")' <"$WORK/last.json" 2>/dev/null)"
c2=$(code "$T_alice" -X POST "$HUB/api/v1/certificates" --data @"$WORK/direct.json"); S2="$(jget 'd.get("data",{}).get("serial_number","")' <"$WORK/last.json" 2>/dev/null)"
echo "observed on the direct template: first HTTP $c1 serial $S1; second HTTP $c2 serial '$S2'"
[ "$c1" = 201 ] && [ "$c2" = 200 ] && [ -n "$S1" ] && [ "$S1" = "$S2" ] \
  && PASS "direct template: same key issued twice returns one serial" || FAIL "direct template: same key twice -> $c1/$c2, serials '$S1' vs '$S2'; HANDOFF: US-010 AC4"

STEP "4. SSH: approval-required template, second principal approves, real sshd accepts"
c=$(code "$T_alice" "$HUB/api/v1/ssh/ca"); [ "$c" = 200 ] || DIE "GET /ssh/ca -> $c $(cat "$WORK/last.json")"
jget 'd["authority_line"].strip()' <"$WORK/last.json" >"$WORK/ca.pub"
HOST_TPL="$(mktpl kk-uat-ssh-host ",\"ssh_policy\":{\"cert_types\":[\"host\"],\"host_patterns\":[\"$HOSTNAME_CERT\"],\"max_ttl_hours\":24}")" || DIE "host template"
SSH_APPR="$(mktpl kk-uat-ssh-appr ',"require_approval":true,"approval_roles":["pki-admin"],"ssh_policy":{"cert_types":["user"],"allowed_principals":["deploy"],"max_ttl_hours":24}')" || DIE "approval ssh template"
podman exec "$CTR" cat /etc/ssh/ssh_host_ed25519_key.pub >"$WORK/host.pub"
c=$(code "$T_alice" -X POST "$HUB/api/v1/ssh/certificates" -d "$(sshbody "$WORK/host.pub" host kk-uat-host "$HOSTNAME_CERT" 1 "$HOST_TPL")")
[ "$c" = 201 ] || DIE "host cert -> $c $(cat "$WORK/last.json")"
jget 'd["data"]["certificate_line"]' <"$WORK/last.json" >"$WORK/host-cert.pub"
podman cp "$WORK/ca.pub" "$CTR:/etc/ssh/kk_user_ca.pub" && podman cp "$WORK/host-cert.pub" "$CTR:/etc/ssh/ssh_host_ed25519_key-cert.pub" \
  && podman exec "$CTR" sh -c 'chmod 644 /etc/ssh/kk_user_ca.pub /etc/ssh/ssh_host_ed25519_key-cert.pub && touch /etc/ssh/kk-ready' \
  || DIE "could not install CA line and host cert"
echo "@cert-authority $HOSTNAME_CERT $(cat "$WORK/ca.pub")" >"$WORK/known_hosts"
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$SSH_PORT") 2>/dev/null && break; sleep 0.2; done
PASS "host cert issued (no approval on that template) and installed with the CA line"

ssh-keygen -q -t ed25519 -N '' -f "$WORK/deploy" -C kk-uat-deploy
c=$(code "$T_alice" -X POST "$HUB/api/v1/ssh/certificates" -d "$(sshbody "$WORK/deploy.pub" user kk-uat-deploy deploy 1 "$SSH_APPR")")
[ "$c" = 202 ] && PASS "SSH issuance from the approval template answers 202" || DIE "SSH issue -> $c $(cat "$WORK/last.json")"
[ "$(jget 'd.get("status","")' <"$WORK/last.json")" = pending_approval ] && PASS "body status is pending_approval" || FAIL "body: $(cat "$WORK/last.json")"
SAPR="$(jget 'd.get("approval_id","")' <"$WORK/last.json")"
[ -n "$SAPR" ] || DIE "no SSH approval_id"
code "$T_alice" "$HUB/api/v1/ssh/certificates" >/dev/null
[ "$(jget 'len([r for r in d["data"] if r["key_id"]=="kk-uat-deploy"])' <"$WORK/last.json")" = 0 ] \
  && PASS "no SSH cert record exists while pending" || FAIL "an SSH cert record exists before approval"
WHO="$(try_login "$WORK/deploy" "$WORK/known_hosts")"
[ -z "$WHO" ] && PASS "sshd refuses the bare key while the request is pending" || FAIL "bare key logged in as $WHO"
c=$(code "$T_alice" -X POST "$HUB/api/v1/approvals/$SAPR/approve")
[ "$c" = 403 ] && PASS "alice cannot approve her own SSH request ($c)" || FAIL "SSH self-approval -> $c $(cat "$WORK/last.json")"
c=$(code "$T_bob" -X POST "$HUB/api/v1/approvals/$SAPR/approve")
[ "$c" = 201 ] && PASS "bob approves the SSH request: 201" || DIE "bob SSH approve -> $c $(cat "$WORK/last.json")"
jget 'd["data"]["certificate_line"]' <"$WORK/last.json" >"$WORK/deploy-cert.pub" || DIE "approval body has no certificate_line"
WHO="$(try_login "$WORK/deploy" "$WORK/known_hosts" -o CertificateFile="$WORK/deploy-cert.pub")"
[ "$WHO" = deploy ] && PASS "sshd accepts the approved cert: logged in as $WHO, host verified via @cert-authority" || FAIL "approved cert login failed: $(cat "$WORK/ssh.err")"
for _ in $(seq 1 25); do SSHD_LOG="$(podman logs "$CTR" 2>&1)"; grep -qE 'ID "?kk-uat-deploy"? ' <<<"$SSHD_LOG" && break; sleep 0.2; done
grep -qE 'ID "?kk-uat-deploy"? ' <<<"$SSHD_LOG" && PASS "sshd logged the certificate key ID" || FAIL "sshd log lacks the key ID"

STEP "5. SSH TTL ceiling and audit"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/long" -C kk-uat-long
c=$(code "$T_alice" -X POST "$HUB/api/v1/ssh/certificates" -d "$(sshbody "$WORK/long.pub" user kk-uat-long deploy 25 "$SSH_APPR")")
[ "$c" = 400 ] && PASS "a 25-hour user cert is refused 400 (template ceiling 24h), before any approval row" || FAIL "25h TTL -> $c $(cat "$WORK/last.json")"
AUD="$(curl -sS -H "Authorization: Bearer $T_alice" "$HUB/api/v1/audit?limit=200" | python3 -c '
import json,sys
d=json.load(sys.stdin)["data"]; rows=d if isinstance(d,list) else d.get("entries",d.get("items",[]))
print(sum(1 for r in rows if r["action"]=="ssh_certificate.issue" and r["outcome"]=="pending_approval"), sum(1 for r in rows if r["action"]=="approval.approve" and r["outcome"]=="success"))')"
echo "audit (ssh pending_approval rows, approval.approve success rows): $AUD"
[ "${AUD%% *}" -ge 1 ] 2>/dev/null && PASS "the SSH pending request is audited" || FAIL "no ssh_certificate.issue pending_approval audit row"
[ "${AUD##* }" -ge 2 ] 2>/dev/null && PASS "both approvals (X.509 and SSH) are audited" || FAIL "approval.approve success rows: ${AUD##* }, want >= 2"

echo
[ "$FAILED" = 0 ] && echo "ALL STEPS PASSED" || echo "ONE OR MORE STEPS FAILED"
exit "$FAILED"
