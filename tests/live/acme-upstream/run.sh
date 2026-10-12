#!/usr/bin/env bash
# W20-29 live proof: renew a certificate at a REAL public CA (Let's Encrypt
# staging) through the ACME upstream connector, solving dns-01 in a REAL
# Cloudflare zone, then install it over SSH into a real nginx and verify the
# served certificate -- V5's "renew upstream with no human step" loop,
# driven only through the hub API.
#
#   1. an unmanaged certificate for a throwaway name in the zone is imported
#   2. a Cloudflare credential, an ACME connector (dns-01) and a takeover
#      put it on the connector's renewal path
#   3. renewal/execute: order at the CA, TXT record published and removed,
#      issued by the staging CA, installed to nginx over SSH, verified
#
# Needs: a Cloudflare API token with DNS edit on the zone, in
# ~/.config/kryptkeeper-lab/cloudflare-token (KK_CF_TOKEN_FILE overrides). The token
# is read by Python straight from that file and sent only to the hub; it is
# never printed or passed on a command line. KK_ACME_ZONE (default
# kryptkeeper.io) and KK_ACME_DIRECTORY (default LE staging) override.
#
# The hub runs in a container on a podman network shared with the nginx
# fixture and reaches it by container name; the hub refuses to verify-dial
# loopback (RC1-A-04). Names, network and published ports are unique per run.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
SSH_FIXTURE="$REPO_ROOT/tests/live/ssh-install"
WORK="$(mktemp -d /tmp/kk-uat-acmeup.XXXXXX)"
TOKEN_FILE="${KK_CF_TOKEN_FILE:-$HOME/.config/kryptkeeper-lab/cloudflare-token}"
ZONE="${KK_ACME_ZONE:-kryptkeeper.io}"
DIRECTORY="${KK_ACME_DIRECTORY:-https://acme-staging-v02.api.letsencrypt.org/directory}"
NAME="kk-uat-$(date -u +%Y%m%d%H%M%S).$ZONE"
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"
SSH_PORT="$(free_port)"
TLS_PORT="$(free_port)"
HUB="http://127.0.0.1:$HUB_PORT"
TOKEN="uat-acmeup-bootstrap-token"
IMAGE="localhost/kk-uat-acmeup-ssh:$RUN_ID"
HUB_IMAGE="localhost/kk-uat-acmeup-hub:$RUN_ID"
NET="kk-uat-acmeup-net-$RUN_ID"
CTR="kk-uat-acmeup-nginx-$RUN_ID"
HUB_CTR="kk-uat-acmeup-hub-$RUN_ID"
FAILED=0

STEP() { echo; echo "=== $* ==="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; exit 1; }
cleanup() {
  if [ "$FAILED" = 1 ]; then echo "--- hub log (last 25) ---"; podman logs "$HUB_CTR" 2>&1 | tail -25; fi
  podman rm -f "$CTR" "$HUB_CTR" >/dev/null 2>&1
  podman network rm "$NET" >/dev/null 2>&1
  podman rmi -f "$IMAGE" "$HUB_IMAGE" >/dev/null 2>&1
  rm -f "$SSH_FIXTURE/authorized_keys"
  rm -rf "$WORK"
}
trap cleanup EXIT
[ -s "$TOKEN_FILE" ] || { echo "SKIP: no Cloudflare token at $TOKEN_FILE"; exit 2; }
code() { curl -sS -m "${CURL_MAX:-30}" -o "$WORK/last.json" -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
tls_fp() { echo | openssl s_client -connect "127.0.0.1:$TLS_PORT" 2>/dev/null | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 -r | cut -d' ' -f1; }

STEP "build hub and the nginx+sshd fixture"
case "$(podman info --format '{{.Host.Arch}}' 2>/dev/null)" in arm64|aarch64) GOARCH=arm64 ;; *) GOARCH=amd64 ;; esac
mkdir -p "$WORK/hubctx"
(cd "$REPO_ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper) || DIE "go build failed"
cp "$REPO_ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile"
podman build -q -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 || DIE "hub image build failed: $(tail -5 "$WORK/build-hub.log")"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/id_ed25519" -C kk-uat
cp "$WORK/id_ed25519.pub" "$SSH_FIXTURE/authorized_keys"
podman build -q -t "$IMAGE" "$SSH_FIXTURE" >"$WORK/build.log" 2>&1 || DIE "podman build failed: $(tail -5 "$WORK/build.log")"
rm -f "$SSH_FIXTURE/authorized_keys"
podman network create "$NET" >/dev/null || DIE "network create failed"
podman run -d --name "$CTR" --network "$NET" -p "127.0.0.1:$SSH_PORT:22" -p "127.0.0.1:$TLS_PORT:443" -e ROLE=nginx "$IMAGE" >/dev/null || DIE "container did not start"
for _ in $(seq 1 30); do HOSTKEY="$(ssh-keyscan -p "$SSH_PORT" -t ed25519 127.0.0.1 2>/dev/null | grep -v '^#' | awk '{print $2" "$3}')"; [ -n "$HOSTKEY" ] && break; sleep 1; done
for _ in $(seq 1 30); do BEFORE="$(tls_fp)"; [ -n "$BEFORE" ] && break; sleep 1; done
[ -n "$HOSTKEY" ] && [ -n "$BEFORE" ] || DIE "fixture not reachable"
PASS "fixture up; nginx serves the placeholder ($BEFORE)"

STEP "start hub"
cat >"$WORK/hub.env" <<EOF
APP_BOOTSTRAP_TOKEN=$TOKEN
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_API_KEY_PEPPER=uat-pepper-32-characters-minimum!!
APP_API_KEY_AUTH_ENABLED=true
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
KRYPTKEEPER_TLS_DISABLE=true
EOF
podman run -d --name "$HUB_CTR" --network "$NET" -p "127.0.0.1:$HUB_PORT:$HUB_PORT" --env-file "$WORK/hub.env" "$HUB_IMAGE" >/dev/null || DIE "hub container did not start"
for _ in $(seq 1 60); do curl -sf "$HUB/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$HUB/healthz" >/dev/null || DIE "hub did not start"
PASS "hub up"

STEP "an unmanaged certificate for $NAME"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
  -keyout "$WORK/old.key" -out "$WORK/old.crt" -subj "/CN=$NAME" -addext "subjectAltName=DNS:$NAME" >/dev/null 2>&1
c=$(code -X POST "$HUB/api/v1/certificates/import" -d "$(python3 -c 'import json,sys; print(json.dumps({"certificate_pem": open(sys.argv[1]).read()}))' "$WORK/old.crt")")
case "$c" in 20*) ;; *) DIE "import -> $c $(cat "$WORK/last.json")" ;; esac
FP="$(jget 'd["data"].get("fingerprint_sha256") or d["data"]["certificate"]["fingerprint_sha256"]' <"$WORK/last.json" 2>/dev/null)"
[ -n "$FP" ] && PASS "imported $FP" || DIE "no fingerprint in $(cat "$WORK/last.json")"

STEP "Cloudflare credential, ACME connector (dns-01), takeover"
# The token goes file -> Python -> HTTP body; it is never echoed or put in argv.
CF_CRED="$(python3 - "$TOKEN_FILE" "$HUB" "$TOKEN" <<'PY'
import json, sys, urllib.request
token_file, hub, bearer = sys.argv[1:4]
body = json.dumps({"name": "uat-cloudflare-dns", "credential_type": "api_token",
                   "payload": {"cloudflare_api_token": open(token_file).read().strip()}}).encode()
req = urllib.request.Request(hub + "/api/v1/credentials", data=body, method="POST",
                             headers={"Authorization": "Bearer " + bearer, "Content-Type": "application/json"})
print(json.load(urllib.request.urlopen(req))["data"]["id"])
PY
)" || DIE "credential create failed"
PASS "credential $CF_CRED (token not shown)"
c=$(code -X POST "$HUB/api/v1/connectors" -d "$(python3 -c 'import json,sys; print(json.dumps({"name":"LE staging (dns-01)","type":"acme","credential_ref":sys.argv[2],"config_json":json.dumps({"directory_url":sys.argv[1],"challenge":"dns-01","dns_provider":"cloudflare"})}))' "$DIRECTORY" "$CF_CRED")")
[ "$c" = 201 ] || DIE "connector -> $c $(cat "$WORK/last.json")"
CONN="$(jget 'd["data"]["id"]' <"$WORK/last.json")"
PASS "connector $CONN -> $DIRECTORY"
c=$(code -X POST "$HUB/api/v1/estate/takeover" -d "{\"fingerprint\":\"$FP\",\"owner_team\":\"uat\",\"renewal_path\":{\"mode\":\"connector\",\"connector_id\":\"$CONN\"}}")
[ "$c" = 200 ] && PASS "taken over: renews through $CONN" || DIE "takeover -> $c $(cat "$WORK/last.json")"

STEP "SSH credential and nginx target"
CRED="$(python3 - "$WORK/id_ed25519" "$HOSTKEY" 22 "$HUB" "$TOKEN" <<'PY'
import json, sys, urllib.request
key, hostkey, port, hub, bearer = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
body = json.dumps({"name": "uat-ssh", "credential_type": "ssh_key",
                   "payload": {"user": "root", "private_key_pem": open(key).read(), "host_public_key": hostkey, "port": port}}).encode()
req = urllib.request.Request(hub + "/api/v1/credentials", data=body, method="POST",
                             headers={"Authorization": "Bearer " + bearer, "Content-Type": "application/json"})
print(json.load(urllib.request.urlopen(req))["data"]["id"])
PY
)" || DIE "ssh credential failed"
c=$(code -X POST "$HUB/api/v1/targets" -d "{\"name\":\"$NAME\",\"host\":\"$CTR\",\"discovery_mode\":\"network\",\"install_mode\":\"ssh\",\"credential_ref\":\"$CRED\",\"install_server_type\":\"nginx\",\"install_cert_path\":\"/etc/ssl/kk/server.crt\",\"install_key_path\":\"/etc/ssl/kk/server.key\",\"install_reload_method\":\"binary\"}")
[ "$c" = 201 ] || DIE "target -> $c $(cat "$WORK/last.json")"
TGT="$(jget 'd["data"]["id"]' <"$WORK/last.json")"
PASS "target $TGT"

STEP "renew at Let's Encrypt staging, install, verify (no human step)"
START=$(date +%s)
c=$(CURL_MAX=240 code -X POST "$HUB/api/v1/renewal/execute" -d "{\"fingerprint\":\"$FP\",\"target_id\":\"$TGT\",\"install\":{\"server_type\":\"nginx\",\"cert_path\":\"/etc/ssl/kk/server.crt\",\"key_path\":\"/etc/ssl/kk/server.key\",\"reload_method\":\"binary\",\"verify_host_port\":\"$CTR:443\"}}")
OUT="$(jget 'str(d["data"].get("install_outcome"))+" verified="+str(d["data"].get("verified"))' <"$WORK/last.json" 2>/dev/null)"
NEWFP="$(jget 'd["data"].get("new_fingerprint","")' <"$WORK/last.json" 2>/dev/null | tr -d ':' | tr 'A-F' 'a-f')"
case "$c:$OUT" in 200:installed_verified\ verified=True) PASS "renewed and installed in $(( $(date +%s) - START ))s: $OUT" ;; *) FAIL "renewal -> $c $(cat "$WORK/last.json")" ;; esac
AFTER="$(tls_fp)"
[ -n "$NEWFP" ] && [ "$AFTER" = "$NEWFP" ] && PASS "nginx serves the renewed certificate ($AFTER)" || FAIL "nginx serves $AFTER, renewed $NEWFP"
echo | openssl s_client -connect "127.0.0.1:$TLS_PORT" 2>/dev/null | openssl x509 -noout -issuer -subject -ext subjectAltName >"$WORK/served.txt" 2>/dev/null
grep -qi "issuer=.*(STAGING)" "$WORK/served.txt" && PASS "issued by Let's Encrypt staging: $(grep -i issuer= "$WORK/served.txt")" || FAIL "unexpected issuer: $(cat "$WORK/served.txt")"
grep -q "DNS:$NAME" "$WORK/served.txt" && PASS "for $NAME" || FAIL "SAN mismatch: $(cat "$WORK/served.txt")"

STEP "the challenge record is gone, the token never leaked"
python3 - "$TOKEN_FILE" "$ZONE" "_acme-challenge.$NAME" <<'PY' && PASS "no _acme-challenge record left in the zone" || FAIL "a challenge TXT record was left behind"
import json, sys, urllib.request, urllib.parse
token_file, zone, name = sys.argv[1:4]
h = {"Authorization": "Bearer " + open(token_file).read().strip()}
get = lambda p: json.load(urllib.request.urlopen(urllib.request.Request("https://api.cloudflare.com/client/v4" + p, headers=h)))
zid = get("/zones?name=" + urllib.parse.quote(zone))["result"][0]["id"]
left = get(f"/zones/{zid}/dns_records?type=TXT&name=" + urllib.parse.quote(name))["result"]
sys.exit(1 if left else 0)
PY
podman logs "$HUB_CTR" >"$WORK/hub.log" 2>&1
# Read the whole trail through the API (works for the DB and file stores) and
# insist it is non-empty: a scan over zero entries proves nothing.
if ! python3 - "$HUB" "$TOKEN" "$WORK/audit-dump.json" <<'PY'
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
then
  FAIL "could not read a non-empty audit trail through the API"
  : >"$WORK/audit-dump.json"
fi
if python3 -c 'import sys; t=open(sys.argv[1]).read().strip(); sys.exit(0 if any(t in open(f, errors="ignore").read() for f in sys.argv[2:]) else 1)' "$TOKEN_FILE" "$WORK/hub.log" "$WORK/audit-dump.json" 2>/dev/null; then
  FAIL "the Cloudflare token appears in the hub log or audit"
else
  PASS "the Cloudflare token is in neither hub log nor audit"
fi

echo
[ "$FAILED" = 0 ] && echo "ALL STEPS PASSED" || echo "ONE OR MORE STEPS FAILED"
exit "$FAILED"
