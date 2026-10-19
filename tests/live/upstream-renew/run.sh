#!/usr/bin/env bash
# W27-10 live upstream-renewal UAT against INDEPENDENT servers.
#
#   servers   micromdm/scep scepserver v2.3.0 (SCEP, RFC 8894) and Cisco libest
#             r3.2.0 estserver (EST, RFC 7030), each built from its pinned tag
#             in its own container (servers/*.Containerfile)
#   leg 1     connector level: `go test` of upstream_renew_live_test.go calls
#             the SCEP and EST clients directly, serves the issued leaf over
#             TLS and compares fingerprints; the DigiCert 429 test runs too
#   leg 2     hub level: a hub container creates scep and est connectors with
#             POST /api/v1/connectors, imports a certificate, takes it over onto
#             the connector, runs POST /api/v1/renewal/execute into an nginx
#             over SSH and compares the SERVED fingerprint with new_fingerprint;
#             the EST password must appear 0 times in hub log AND audit
#   NOT RUN   WSTEP (needs an AD CS lab) and DigiCert (needs a CertCentral
#             sandbox): set KK_UP_WSTEP_* / KK_UP_DIGICERT_* to run them
#
# Podman only. Per-run ids, networks and ports; cleans up what it created.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
SSH_FIXTURE="$ROOT/tests/live/ssh-install"
WORK="$(mktemp -d /tmp/kk-uat-upren.XXXXXX)"
MOUNT_DIR="$(mktemp -d "$HOME/.kk-uat-upren.XXXXXX")"
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"; SCEP_PORT="$(free_port)"; EST_PORT="$(free_port)"; SSH_PORT="$(free_port)"; TLS_PORT="$(free_port)"
HUB="http://127.0.0.1:$HUB_PORT"
TOKEN="uat-upren-bootstrap-token"
NET="kk-uat-upren-net-$RUN_ID"
SCEP_IMG="localhost/kk-uat-upren-scep:$RUN_ID"; EST_IMG="localhost/kk-uat-upren-est:$RUN_ID"
SSH_IMG="localhost/kk-uat-upren-ssh:$RUN_ID"; HUB_IMG="localhost/kk-uat-upren-hub:$RUN_ID"
C_SCEP="upscep-$RUN_ID"; C_EST="upest-$RUN_ID"; C_NGINX="upnginx-$RUN_ID"; C_HUB="upren-hub-$RUN_ID"
EST_USER=estuser   # libest's documented example credential for its test server
EST_PASSWORD=estpwd
FAILED=0

STEP() { echo; echo "=== $* ==="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; exit 1; }
cleanup() {
  if [ "$FAILED" = 1 ]; then echo "--- hub log (last 25) ---"; podman logs "$C_HUB" 2>&1 | tail -25; fi
  kk_rm "$C_SCEP" "$C_EST" "$C_NGINX" "$C_HUB"
  podman network rm "$NET" >/dev/null 2>&1
  podman rmi -f "$SCEP_IMG" "$EST_IMG" "$SSH_IMG" "$HUB_IMG" >/dev/null 2>&1
  rm -f "$SSH_FIXTURE/authorized_keys"
  rm -rf "$WORK" "$MOUNT_DIR"
}
trap cleanup EXIT
code() { curl -sS -m "${CURL_MAX:-60}" -o "$WORK/last.json" -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
tls_fp() { echo | openssl s_client -connect "127.0.0.1:$TLS_PORT" 2>/dev/null | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 -r | cut -d' ' -f1; }

STEP "build the independent servers (pinned tags and base digests)"
podman build -q -t "$SCEP_IMG" -f "$HERE/servers/scep.Containerfile" "$HERE/servers" >"$WORK/b-scep.log" 2>&1 || DIE "scep image: $(tail -5 "$WORK/b-scep.log")"
podman build -q -t "$EST_IMG" -f "$HERE/servers/est.Containerfile" "$HERE/servers" >"$WORK/b-est.log" 2>&1 || DIE "est image: $(tail -5 "$WORK/b-est.log")"
PASS "scep image $(podman image inspect "$SCEP_IMG" --format '{{.Id}}' | cut -c1-19), est image $(podman image inspect "$EST_IMG" --format '{{.Id}}' | cut -c1-19)"
podman network create "$NET" >/dev/null || DIE "network create"
podman run -d --name "$C_SCEP" --network "$NET" -p "127.0.0.1:$SCEP_PORT:2016" "$SCEP_IMG" >/dev/null || DIE "start scep"
mkdir -p "$MOUNT_DIR/est"
podman run -d --name "$C_EST" --network "$NET" -e "EST_SERVER_NAME=$C_EST" -p "127.0.0.1:$EST_PORT:8085" -v "$MOUNT_DIR/est:/out" "$EST_IMG" >/dev/null || DIE "start est"
for _ in $(seq 1 40); do [ -s "$MOUNT_DIR/est/est-ca.pem" ] && curl -s --cacert "$MOUNT_DIR/est/est-ca.pem" -o /dev/null "https://localhost:$EST_PORT/.well-known/est/cacerts" && break; sleep 1; done
printf '%s' "$EST_PASSWORD" >"$WORK/est-password"

STEP "the servers speak their protocols (independent of the clients under test)"
CAPS="$(curl -s "http://127.0.0.1:$SCEP_PORT/scep?operation=GetCACaps" | tr '\n' ' ')"
case "$CAPS" in *POSTPKIOperation*SCEPStandard*|*SCEPStandard*POSTPKIOperation*) PASS "SCEP GetCACaps: $CAPS" ;; *) FAIL "SCEP GetCACaps unexpected: $CAPS" ;; esac
curl -s "http://127.0.0.1:$SCEP_PORT/scep?operation=GetCACert" | openssl x509 -inform DER -out "$WORK/scep-ca.pem" 2>/dev/null \
  && PASS "SCEP GetCACert: $(openssl x509 -in "$WORK/scep-ca.pem" -noout -subject)" || FAIL "SCEP GetCACert did not return a certificate"
curl -s --cacert "$MOUNT_DIR/est/est-ca.pem" "https://localhost:$EST_PORT/.well-known/est/cacerts" | base64 -d 2>/dev/null | openssl pkcs7 -inform DER -print_certs -noout 2>/dev/null | grep -q subject \
  && PASS "EST /cacerts returns a PKCS#7 certs-only response" || FAIL "EST /cacerts is not a PKCS#7 bundle"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /dev/null -subj /CN=probe.example -outform DER -out "$WORK/probe.der" 2>/dev/null
{ base64 <"$WORK/probe.der" | tr -d '\n'; echo; } >"$WORK/probe.b64"
ECODE="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$MOUNT_DIR/est/est-ca.pem" -X POST -H 'Content-Type: application/pkcs10' -H 'Content-Transfer-Encoding: base64' --data-binary @"$WORK/probe.b64" "https://localhost:$EST_PORT/.well-known/est/simpleenroll")"
[ "$ECODE" = 401 ] && PASS "EST simpleenroll with a valid CSR but no credentials -> 401 (authentication enforced)" || FAIL "EST unauthenticated simpleenroll -> $ECODE"
echo "  versions: micromdm/scep scepserver v2.3.0 (go install tag); libest r3.2.0 commit $(podman run --rm --entrypoint cat "$EST_IMG" /libest-commit)"

STEP "leg 1: connector level (go test)"
(cd "$ROOT" && KK_LIVE_UPSTREAM=1 KK_UP_SCEP_URL="http://127.0.0.1:$SCEP_PORT/scep" KK_UP_SCEP_CA_FILE="$WORK/scep-ca.pem" \
  KK_UP_EST_URL="https://localhost:$EST_PORT" KK_UP_EST_CA_FILE="$MOUNT_DIR/est/est-ca.pem" KK_UP_EST_USER="$EST_USER" KK_UP_EST_PASSWORD_FILE="$WORK/est-password" \
  go test ./tests/live/upstream-renew/ -count=1 -v) >"$WORK/gotest.txt" 2>&1
GT=$?
grep -E "^(=== RUN|--- (PASS|FAIL|SKIP)|\s+upstream_renew_live_test.go:[0-9]+: (PASS|NOT RUN))" "$WORK/gotest.txt"
[ "$GT" = 0 ] && PASS "go test exit 0" || { FAIL "go test failed"; tail -20 "$WORK/gotest.txt"; }
grep -q "PASS scep:" "$WORK/gotest.txt" && PASS "SCEP leg ran and matched" || FAIL "SCEP leg did not run to a match"
grep -q "PASS est:" "$WORK/gotest.txt" && PASS "EST leg ran and matched" || FAIL "EST leg did not run to a match"
grep -q "PASS digicert 429" "$WORK/gotest.txt" && PASS "DigiCert 429 rate-limit test ran" || FAIL "DigiCert 429 test did not run"
grep -q "NOT RUN" "$WORK/gotest.txt" && echo "NOTE: legs reported NOT RUN above (WSTEP, DigiCert) are not claimed."
[ -n "${KK_EVIDENCE_DIR:-}" ] && { mkdir -p "$KK_EVIDENCE_DIR"; cp "$WORK/gotest.txt" "$KK_EVIDENCE_DIR/connector-level.txt"; }

STEP "leg 2: hub level (POST /api/v1/connectors + renewal/execute into nginx)"
GOARCH="$(kk_goarch)"
mkdir -p "$WORK/hubctx"
(cd "$ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper) || DIE "hub build"
cp "$ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile"
podman build -q -t "$HUB_IMG" "$WORK/hubctx" >"$WORK/b-hub.log" 2>&1 || DIE "hub image: $(tail -3 "$WORK/b-hub.log")"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/id_ed25519" -C kk-uat
cp "$WORK/id_ed25519.pub" "$SSH_FIXTURE/authorized_keys"
podman build -q -t "$SSH_IMG" "$SSH_FIXTURE" >"$WORK/b-ssh.log" 2>&1 || DIE "ssh image: $(tail -3 "$WORK/b-ssh.log")"
rm -f "$SSH_FIXTURE/authorized_keys"
podman run -d --name "$C_NGINX" --network "$NET" -p "127.0.0.1:$SSH_PORT:22" -p "127.0.0.1:$TLS_PORT:443" -e ROLE=nginx "$SSH_IMG" >/dev/null || DIE "start nginx"
for _ in $(seq 1 30); do HOSTKEY="$(ssh-keyscan -p "$SSH_PORT" -t ed25519 127.0.0.1 2>/dev/null | grep -v '^#' | awk '{print $2" "$3}')"; [ -n "$HOSTKEY" ] && break; sleep 1; done
for _ in $(seq 1 30); do BEFORE="$(tls_fp)"; [ -n "$BEFORE" ] && break; sleep 1; done
[ -n "$HOSTKEY" ] && [ -n "$BEFORE" ] || DIE "nginx fixture not reachable"

cat >"$WORK/hub.env" <<ENVEOF
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
SSL_CERT_FILE=/trust/est-ca.pem
ENVEOF
podman run -d --name "$C_HUB" --network "$NET" -p "127.0.0.1:$HUB_PORT:$HUB_PORT" --env-file "$WORK/hub.env" -v "$MOUNT_DIR/est/est-ca.pem:/trust/est-ca.pem:ro" "$HUB_IMG" >/dev/null || DIE "start hub"
for _ in $(seq 1 60); do curl -sf "$HUB/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$HUB/healthz" >/dev/null || DIE "hub did not start"
PASS "hub up, nginx serves its placeholder ($BEFORE)"

SSHCRED="$(python3 - "$WORK/id_ed25519" "$HOSTKEY" "$SSH_PORT" "$HUB" "$TOKEN" <<'PY'
import json, sys, urllib.request
key, hostkey, _, hub, bearer = sys.argv[1:6]
body = json.dumps({"name": "uat-ssh", "credential_type": "ssh_key", "payload": {"user": "root", "private_key_pem": open(key).read(), "host_public_key": hostkey, "port": 22}}).encode()
req = urllib.request.Request(hub + "/api/v1/credentials", data=body, method="POST", headers={"Authorization": "Bearer " + bearer, "Content-Type": "application/json"})
print(json.load(urllib.request.urlopen(req))["data"]["id"])
PY
)" || DIE "ssh credential"
c=$(code -X POST "$HUB/api/v1/targets" -d "{\"name\":\"upren-nginx\",\"host\":\"$C_NGINX\",\"discovery_mode\":\"network\",\"install_mode\":\"ssh\",\"credential_ref\":\"$SSHCRED\",\"install_server_type\":\"nginx\",\"install_cert_path\":\"/etc/ssl/kk/server.crt\",\"install_key_path\":\"/etc/ssl/kk/server.key\",\"install_reload_method\":\"binary\"}")
[ "$c" = 201 ] || DIE "target -> $c $(cat "$WORK/last.json")"
TGT="$(jget 'd["data"]["id"]' <"$WORK/last.json")"

# The EST password goes file -> Python -> hub; it is never on a command line.
ESTCRED="$(python3 - "$WORK/est-password" "$HUB" "$TOKEN" <<'PY'
import json, sys, urllib.request
pwfile, hub, bearer = sys.argv[1:4]
body = json.dumps({"name": "uat-est", "credential_type": "api_token", "payload": {"password": open(pwfile).read().strip()}}).encode()
req = urllib.request.Request(hub + "/api/v1/credentials", data=body, method="POST", headers={"Authorization": "Bearer " + bearer, "Content-Type": "application/json"})
print(json.load(urllib.request.urlopen(req))["data"]["id"])
PY
)" || DIE "est credential"

hub_leg() { # name connector-json cn
  local name="$1" connjson="$2" cn="$3"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -keyout "$WORK/$name.key" -out "$WORK/$name.crt" -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn" >/dev/null 2>&1
  local c
  c=$(code -X POST "$HUB/api/v1/connectors" -d "$connjson")
  [ "$c" = 201 ] || { FAIL "$name: POST /connectors -> $c $(cat "$WORK/last.json" | head -c 300)"; return 1; }
  local conn; conn="$(jget 'd["data"]["id"]' <"$WORK/last.json")"
  local health; health="$(code "$HUB/api/v1/connectors" >/dev/null; python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["data"]; print([r["health"]["status"] for r in d if r["id"]==sys.argv[2]][0])' "$WORK/last.json" "$conn")"
  [ "$health" = healthy ] && PASS "$name: connector $conn created, live health probe healthy" || FAIL "$name: connector health is '$health'"
  c=$(code -X POST "$HUB/api/v1/certificates/import" -d "$(python3 -c 'import json,sys; print(json.dumps({"certificate_pem": open(sys.argv[1]).read()}))' "$WORK/$name.crt")")
  case "$c" in 20*) ;; *) FAIL "$name: import -> $c $(head -c 300 "$WORK/last.json")"; return 1 ;; esac
  local fp; fp="$(jget 'd["data"].get("fingerprint_sha256") or d["data"]["certificate"]["fingerprint_sha256"]' <"$WORK/last.json")"
  c=$(code -X POST "$HUB/api/v1/estate/takeover" -d "{\"fingerprint\":\"$fp\",\"owner_team\":\"uat\",\"renewal_path\":{\"mode\":\"connector\",\"connector_id\":\"$conn\"}}")
  [ "$c" = 200 ] || { FAIL "$name: takeover -> $c $(head -c 300 "$WORK/last.json")"; return 1; }
  local start; start=$(date +%s)
  c=$(CURL_MAX=240 code -X POST "$HUB/api/v1/renewal/execute" -d "{\"fingerprint\":\"$fp\",\"target_id\":\"$TGT\",\"install\":{\"server_type\":\"nginx\",\"cert_path\":\"/etc/ssl/kk/server.crt\",\"key_path\":\"/etc/ssl/kk/server.key\",\"reload_method\":\"binary\",\"verify_host_port\":\"$C_NGINX:443\"}}")
  local out newfp elapsed; elapsed=$(( $(date +%s) - start ))
  out="$(jget 'str(d["data"].get("install_outcome"))+" verified="+str(d["data"].get("verified"))' <"$WORK/last.json" 2>/dev/null)"
  newfp="$(jget 'd["data"].get("new_fingerprint","")' <"$WORK/last.json" 2>/dev/null | tr -d ':' | tr 'A-F' 'a-f')"
  case "$c:$out" in 200:installed_verified\ verified=True) PASS "$name: renewed through the connector and installed in ${elapsed}s: $out" ;; *) FAIL "$name: renewal -> $c $(head -c 400 "$WORK/last.json")"; return 1 ;; esac
  local served; served="$(tls_fp)"
  [ -n "$newfp" ] && [ "$served" = "$newfp" ] && PASS "$name: nginx serves new_fingerprint ($served)" || FAIL "$name: nginx serves '$served', renewed '$newfp'"
  echo | openssl s_client -connect "127.0.0.1:$TLS_PORT" 2>/dev/null | openssl x509 -noout -issuer >"$WORK/$name-issuer.txt" 2>/dev/null
  echo "  $name served issuer: $(cat "$WORK/$name-issuer.txt")"
  grep -qi "$4" "$WORK/$name-issuer.txt" && PASS "$name: issued by the independent server's CA, not the hub CA" || FAIL "$name: unexpected issuer $(cat "$WORK/$name-issuer.txt")"
}

hub_leg scep "$(python3 -c 'import json,sys; print(json.dumps({"name":"uat-scep","type":"scep","config_json":json.dumps({"endpoint_url":sys.argv[1]})}))' "http://$C_SCEP:2016/scep")" scep-hub.uat.example "UAT SCEP Independent CA"
hub_leg est "$(python3 -c 'import json,sys; print(json.dumps({"name":"uat-est","type":"est","credential_ref":sys.argv[2],"config_json":json.dumps({"base_url":sys.argv[1],"username":sys.argv[3]})}))' "https://$C_EST:8085" "$ESTCRED" "$EST_USER")" est-hub.uat.example "$(openssl x509 -in "$MOUNT_DIR/est/est-ca.pem" -noout -issuer | sed 's/.*CN *= *//')"

STEP "credentials: 0 occurrences in hub log AND audit"
podman logs "$C_HUB" >"$WORK/hub.log" 2>&1
if python3 - "$HUB" "$TOKEN" "$WORK/audit-dump.json" <<'PY'
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
then PASS "read the full audit trail ($(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$WORK/audit-dump.json") entries)"
else FAIL "could not read a non-empty audit trail"; : >"$WORK/audit-dump.json"; fi
n_log=$(grep -c -F -e "$EST_PASSWORD" "$WORK/hub.log")
n_aud=$(grep -c -F -e "$EST_PASSWORD" "$WORK/audit-dump.json")
n_key=$(cat "$WORK/hub.log" "$WORK/audit-dump.json" | grep -c "PRIVATE KEY")
[ "$n_log" = 0 ] && [ "$n_aud" = 0 ] && PASS "EST password: $n_log lines in hub log, $n_aud in audit" || FAIL "EST password found: hub log $n_log, audit $n_aud"
[ "$n_key" = 0 ] && PASS "private-key markers: 0 in hub log and audit" || FAIL "$n_key key marker line(s)"
grep -q '"connector.create"' "$WORK/audit-dump.json" && PASS "connector.create is audited" || FAIL "no connector.create audit row"
[ -n "${KK_EVIDENCE_DIR:-}" ] && { cp "$WORK/hub.log" "$KK_EVIDENCE_DIR/hub.log"; cp "$WORK/audit-dump.json" "$KK_EVIDENCE_DIR/audit.json"; }

echo
echo "NOT RUN: WSTEP (no AD CS lab) and DigiCert issuance (no CertCentral sandbox) unless KK_UP_WSTEP_* / KK_UP_DIGICERT_* were set for the go test."
[ "$FAILED" = 0 ] && echo "ALL STEPS PASSED" || echo "ONE OR MORE STEPS FAILED"
exit "$FAILED"
