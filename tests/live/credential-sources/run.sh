#!/usr/bin/env bash
# W38-07 (D-324): an SSH credential that is NOT stored in the hub, resolved from
# a real HashiCorp Vault and a real OpenBao at use time, drives a real agentless
# discovery against a real sshd.
#
# Per secret manager (vault, then openbao; KK_CS_FLAVORS narrows) it asserts:
#   1. the KV v2 read path, 404 shape and 403 shape this implementation relies on
#      (read from the live server, not assumed);
#   2. a least-privilege token (read on secret/data/ssh/* only) drives an ssh
#      discovery: the scan completes and finds the host's certificate with the
#      right fingerprint, though the hub never held the private key;
#   3. version pinning: version 1 keeps working after version 2 is written with
#      an unusable key, while "latest" fails with a clear message;
#   4. a path outside the token's policy is refused with a clear denied message;
#   5. AppRole login drives the same scan, and a bad secret_id is a clear failure;
#   6. every resolve is audited (credential.resolve, source and outcome) and no
#      audit row, hub log line or hub data file contains the key or the token.
#
# The hub runs in a container on the same network as the manager and the host,
# so the egress guard sees what production sees: a private address, https, and a
# pinned CA. Shared-Mac rules: unique names per run, only this run's containers,
# network and images are removed, nothing is pruned. Podman only.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=../lib/podman.sh
. "$ROOT/tests/live/lib/podman.sh"
# podman machine on macOS virtiofs-mounts only $HOME, not /tmp.
WORK="$(mktemp -d "$HOME/.kk-w38-credsrc.XXXXXX")"
RUN_ID="$(openssl rand -hex 3)"
P="kk-w38-cs-$RUN_ID"
NET="$P-net"
HUB_PORT="$(kk_free_port)"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
HOST_IMAGE="localhost/$P-host:latest"
HUB_IMAGE="localhost/$P-hub:latest"
FLAVORS="${KK_CS_FLAVORS:-vault openbao}"
HUB=$P-hub
SSHC=$P-ssh
FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE() { echo "FAIL: $*"; exit 1; }

cleanup() {
  STEP "cleanup"
  kk_rm "$HUB" "$SSHC" "$P-vault" "$P-openbao"
  podman network rm "$NET" >/dev/null 2>&1 || true
  podman rmi -f "$HOST_IMAGE" "$HUB_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
[ "${KK_CS_KEEP:-}" = 1 ] || trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null; }

STEP "preflight, keys, certificates, images"
command -v podman >/dev/null || DIE "podman is required"
GOARCH="$(kk_goarch)"
ssh-keygen -t ed25519 -N '' -f "$WORK/id_ed25519" -C kk-credsrc >/dev/null && cp "$WORK/id_ed25519.pub" "$WORK/authorized_keys" \
  && PASS "login key pair generated" || DIE "keygen failed"
KEY_MARK="$(sed -n 2p "$WORK/id_ed25519")" # a line of the private key body: must never reach hub logs, audit or disk
[ -n "$KEY_MARK" ] || DIE "no key marker"
podman network create "$NET" >/dev/null && PASS "network $NET" || DIE "network create failed"
podman build -t "$HOST_IMAGE" -f "$HERE/Dockerfile.host" "$HERE" >"$WORK/build-host.log" 2>&1 \
  && PASS "ssh host image built" || { tail -20 "$WORK/build-host.log"; DIE "host image build failed"; }
mkdir -p "$WORK/hubctx" "$WORK/hubdata"
( cd "$ROOT" && GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper ) \
  && cp "$ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile" \
  && podman build -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 \
  && PASS "hub image built (linux/$GOARCH)" || DIE "hub build failed"
cat >"$WORK/hub.env" <<ENV
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
ENV

STEP "start the ssh host and the hub"
podman run -d --name "$SSHC" --network "$NET" -v "$WORK/authorized_keys:/tmp/authorized_keys:ro" "$HOST_IMAGE" >/dev/null \
  && PASS "ssh host $SSHC" || DIE "ssh host failed to start"
podman run -d --name "$HUB" --network "$NET" --env-file "$WORK/hub.env" -v "$WORK/hubdata:/data" -p "127.0.0.1:${HUB_PORT}:${HUB_PORT}" "$HUB_IMAGE" >/dev/null \
  && PASS "hub $HUB" || DIE "hub failed to start"
tries=60
until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null; do
  tries=$((tries - 1)); [ $tries -le 0 ] && { podman logs "$HUB" 2>&1 | tail -20; DIE "hub never answered"; }
  sleep 1
done
PASS "hub answering on $HUB_BASE"
HOSTKEY=""
for _ in $(seq 1 60); do
  HOSTKEY="$(podman exec "$SSHC" cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null | awk '{print $1" "$2}')"
  [ -n "$HOSTKEY" ] && podman exec "$SSHC" pgrep -x sshd >/dev/null 2>&1 && break
  sleep 1
done
[ -n "$HOSTKEY" ] && PASS "sshd up, host key read" || DIE "sshd never came up"
CERT_FP="$(podman exec "$SSHC" openssl x509 -in /etc/nginx/ssl/web.crt -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
[ -n "$CERT_FP" ] && PASS "host certificate sha256 ${CERT_FP:0:16}..." || DIE "no host certificate fingerprint"

scan_job() { # target -> final status
  local id st t0
  id="$(curlj -X POST "${HUB_BASE}/api/v1/discovery/scans" -d "{\"scan_type\":\"ssh\",\"target\":\"$1\"}" | jget 'd["data"]["scan_job"]["id"]')"
  [ -n "$id" ] || { echo submit_failed; return 1; }
  t0=$(date +%s)
  while [ $(( $(date +%s) - t0 )) -lt 120 ]; do
    st="$(curlj "${HUB_BASE}/api/v1/discovery/scan-jobs?limit=100" | python3 -c '
import json,sys
for j in json.load(sys.stdin)["data"]["scan_jobs"]:
    if j["id"]==sys.argv[1]: print(j["status"]); break' "$id" 2>/dev/null)"
    case "$st" in queued|running|"") sleep 2 ;; *) echo "$st"; return 0 ;; esac
  done
  echo timeout; return 1
}
dump_endpoints() {
  python3 - "$HUB_BASE" "$TOKEN" "$1" <<'PY'
import json, sys, urllib.request
hub, token, out = sys.argv[1:4]
rows, cursor = [], ""
while True:
    url = hub + "/api/v1/discovery/endpoints?limit=100" + ("&cursor=" + str(cursor) if cursor != "" else "")
    d = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Bearer " + token})))
    rows += d["data"]["endpoints"]
    cursor = (d.get("meta") or {}).get("next_cursor")
    if cursor is None:
        break
json.dump(rows, open(out, "w"))
PY
}
mktarget() { # name -> id
  python3 - "$1" "$SSHC" "$2" "$HOSTKEY" <<'PY' | curlj -X POST "${HUB_BASE}/api/v1/targets" -d @- | jget 'd["data"]["id"]'
import json, sys
name, host, cred, hk = sys.argv[1:5]
print(json.dumps({"name": name, "host": host, "discovery_mode": "network", "install_mode": "ssh", "credential_ref": cred,
  "install_server_type": "nginx", "install_cert_path": "/etc/nginx/ssl/web.crt", "install_key_path": "/etc/nginx/ssl/web.key", "ssh_host_key": hk}))
PY
}
# scan_finds_cert STATUS_FILE-less check: the ssh endpoint row carries the host certificate.
ssh_endpoint_has_cert() { # -> 0 when the web.crt fingerprint is among the host's mapped certs
  dump_endpoints "$WORK/ep.json"
  python3 - "$WORK/ep.json" "$SSHC" "$CERT_FP" <<'PY'
import json, sys
eps, host, fp = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
rows = [e for e in eps if e.get("hostname") == host and e.get("port") == 22]
if not rows:
    print("  no ssh endpoint row"); sys.exit(1)
got = {(c.get("fingerprint") or "").replace(":", "").lower() for c in rows[0].get("mapped_certs") or []}
print("  mapped certs:", sorted(x[:16] for x in got), "error:", (rows[0].get("error") or "")[:200])
sys.exit(0 if fp in got else 1)
PY
}
ssh_endpoint_error() { # -> prints the ssh endpoint's error text from the latest dump
  python3 - "$WORK/ep.json" "$SSHC" <<'PY'
import json, sys
rows = [e for e in json.load(open(sys.argv[1])) if e.get("hostname") == sys.argv[2] and e.get("port") == 22]
print((rows[0].get("error") or "") if rows else "")
PY
}

run_flavor() {
  local F=$1 IMG CLI NAME ADDR
  case "$F" in
    vault) IMG=docker.io/hashicorp/vault:1.20; CLI=vault ;;
    openbao) IMG=docker.io/openbao/openbao:2; CLI=bao ;;
    *) FAIL "unknown flavor $F"; return ;;
  esac
  NAME="$P-$F"
  ADDR="https://$NAME:8200"
  STEP "[$F] start $IMG with TLS (server mode, file storage)"
  mkdir -p "$WORK/$F/tls" "$WORK/$F/cfg"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -keyout "$WORK/$F/tls/tls.key" -out "$WORK/$F/tls/tls.crt" -subj "/CN=$NAME" \
    -addext "subjectAltName=DNS:$NAME,DNS:localhost,IP:127.0.0.1" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1 \
    && chmod 644 "$WORK/$F/tls/tls.key" && PASS "[$F] server certificate (SAN $NAME) generated; it is also the pinned CA" || { FAIL "[$F] cert generation"; return; }
  # OpenBao 2 dropped the file backend; it takes integrated storage (raft).
  if [ "$F" = openbao ]; then
    printf 'storage "raft" {\n  path    = "/tmp/kvdata"\n  node_id = "kk-credsrc"\n}\napi_addr     = "https://%s:8200"\ncluster_addr = "https://127.0.0.1:8201"\n' "$NAME" >"$WORK/$F/cfg/server.hcl"
  else
    printf 'storage "file" { path = "/tmp/kvdata" }\n' >"$WORK/$F/cfg/server.hcl"
  fi
  cat >>"$WORK/$F/cfg/server.hcl" <<'HCL'
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/tls/tls.crt"
  tls_key_file  = "/tls/tls.key"
}
disable_mlock = true
ui = false
HCL
  podman run -d --name "$NAME" --network "$NET" --cap-add IPC_LOCK \
    -v "$WORK/$F/tls:/tls:ro" -v "$WORK/$F/cfg:/cfg:ro" "$IMG" server -config=/cfg/server.hcl >/dev/null \
    && PASS "[$F] container $NAME" || { FAIL "[$F] could not start"; return; }
  mgr() { podman exec -e VAULT_ADDR=https://127.0.0.1:8200 -e VAULT_CACERT=/tls/tls.crt -e BAO_ADDR=https://127.0.0.1:8200 -e BAO_CACERT=/tls/tls.crt ${MGR_TOKEN:+-e VAULT_TOKEN=$MGR_TOKEN -e BAO_TOKEN=$MGR_TOKEN} "$NAME" "$CLI" "$@"; }
  podman ps --format '{{.Names}}' | grep -qx "$NAME" || { podman logs "$NAME" 2>&1 | tail -15; FAIL "[$F] the container exited"; return; }
  local i; for i in $(seq 1 60); do mgr status -format=json >/dev/null 2>&1; [ $? -le 2 ] && mgr status -format=json 2>/dev/null | grep -q '"initialized"' && break; sleep 1; done
  MGR_TOKEN=""
  INIT="$(mgr operator init -key-shares=1 -key-threshold=1 -format=json)" || { FAIL "[$F] init"; return; }
  UNSEAL="$(echo "$INIT" | jget 'd["unseal_keys_b64"][0]')"; ROOT="$(echo "$INIT" | jget 'd["root_token"]')"
  mgr operator unseal "$UNSEAL" >/dev/null && PASS "[$F] initialised and unsealed" || { FAIL "[$F] unseal"; return; }
  MGR_TOKEN="$ROOT"
  mgr secrets enable -path=secret -version=2 kv >/dev/null && PASS "[$F] KV v2 mounted at secret/" || { FAIL "[$F] kv enable"; return; }
  printf 'path "secret/data/ssh/*" { capabilities = ["read"] }\n' >"$WORK/$F/cfg/ssh-read.hcl"
  mgr policy write ssh-read /cfg/ssh-read.hcl >/dev/null || { FAIL "[$F] policy"; return; }
  RO_TOKEN="$(mgr token create -policy=ssh-read -format=json | jget 'd["auth"]["client_token"]')"
  mgr auth enable approle >/dev/null && mgr write auth/approle/role/kk token_policies=ssh-read token_ttl=5m >/dev/null || { FAIL "[$F] approle"; return; }
  ROLE_ID="$(mgr read -field=role_id auth/approle/role/kk/role-id)"
  SECRET_ID="$(mgr write -f -field=secret_id auth/approle/role/kk/secret-id)"
  [ -n "$RO_TOKEN" ] && [ -n "$ROLE_ID" ] && [ -n "$SECRET_ID" ] && PASS "[$F] read-only token (policy ssh-read) and AppRole created" || { FAIL "[$F] token/approle"; return; }

  STEP "[$F] write the SSH secret (the key never goes to the hub)"
  podman cp "$WORK/id_ed25519" "$NAME:/tmp/id_ed25519" >/dev/null
  mgr kv put -mount=secret ssh/web1 private_key_pem=@/tmp/id_ed25519 user=kkscan host_public_key="$HOSTKEY" port=22 >/dev/null \
    && PASS "[$F] secret/ssh/web1 version 1 written" || { FAIL "[$F] kv put"; return; }

  STEP "[$F] the live API shapes the implementation relies on"
  local CA_PEM; CA_PEM="$(cat "$WORK/$F/tls/tls.crt")"
  # Raw HTTP from the ssh host's container (curl), so the status codes are the server's own.
  podman cp "$WORK/$F/tls/tls.crt" "$SSHC:/tmp/$F-ca.crt" >/dev/null
  http_status() { # token path -> the status code
    podman exec "$SSHC" curl -sS -o /dev/null -w '%{http_code}' --cacert "/tmp/$F-ca.crt" -H "X-Vault-Token: $1" "$ADDR$2" 2>&1
  }
  s404="$(http_status "$RO_TOKEN" /v1/secret/data/ssh/nope)"
  s403="$(http_status "$RO_TOKEN" /v1/secret/data/other/web1)"
  s200="$(http_status "$RO_TOKEN" /v1/secret/data/ssh/web1)"
  s200v="$(http_status "$RO_TOKEN" '/v1/secret/data/ssh/web1?version=1')"
  echo "  missing path: $s404 | outside policy: $s403 | readable: $s200 | pinned version: $s200v"
  [ "$s404" = 404 ] && PASS "[$F] a missing path answers 404" || FAIL "[$F] missing path answer: $s404"
  [ "$s403" = 403 ] && PASS "[$F] a path outside the policy answers 403" || FAIL "[$F] denied path answer: $s403"
  [ "$s200" = 200 ] && [ "$s200v" = 200 ] && PASS "[$F] GET /v1/secret/data/<path>[?version=N] answers 200 for a readable secret" || FAIL "[$F] read answers: $s200 / $s200v"

  STEP "[$F] hub: login credential, source, test, external credential"
  LOGIN="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "{\"name\":\"$F login\",\"credential_type\":\"api_token\",\"payload\":{\"token\":\"$RO_TOKEN\"}}" | jget 'd["data"]["id"]')"
  SRC="$(python3 - "$LOGIN" "$ADDR" "$CA_PEM" "$F" <<'PY' | curlj -X POST "${HUB_BASE}/api/v1/credential-sources" -d @- | jget 'd["data"]["id"]'
import json, sys
login, addr, ca, f = sys.argv[1:5]
print(json.dumps({"name": f + " kv2", "kind": "vault_kv2", "credential_ref": login, "config": {"base_url": addr, "ca_cert_pem": ca, "mount": "secret"}}))
PY
)"
  [ -n "$LOGIN" ] && [ -n "$SRC" ] && PASS "[$F] login credential $LOGIN, source $SRC" || { FAIL "[$F] login/source create"; return; }
  T="$(curlj -X POST "${HUB_BASE}/api/v1/credential-sources/$SRC/test" -d '{"credential_type":"ssh_key","reference":{"path":"ssh/web1"}}')"
  echo "  test: $(echo "$T" | cut -c1-300)"
  [ "$(echo "$T" | jget 'd["data"]["ok"]')" = True ] && ! echo "$T" | grep -q "$KEY_MARK" && PASS "[$F] test reference: ok, field names only, no key material in the response" || FAIL "[$F] test reference"
  CRED="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "{\"name\":\"web1 ssh from $F\",\"credential_type\":\"ssh_key\",\"source\":\"external\",\"source_id\":\"$SRC\",\"reference\":{\"path\":\"ssh/web1\"}}" | jget 'd["data"]["id"]')"
  [ -n "$CRED" ] && PASS "[$F] external ssh_key credential $CRED (reference only)" || { FAIL "[$F] external credential create"; return; }
  TGT="$(mktarget "t-$F" "$CRED")"
  [ -n "$TGT" ] && PASS "[$F] managed target $TGT uses credential $CRED" || { FAIL "[$F] target create"; return; }

  STEP "[$F] agentless discovery with the credential resolved from $F"
  st="$(scan_job "$TGT")"; echo "  scan status: $st"
  if [ "$st" = completed ] && ssh_endpoint_has_cert; then
    PASS "[$F] discovery completed and found the host certificate (${CERT_FP:0:16}...) with a key the hub never stored"
  else
    FAIL "[$F] discovery with the external credential (status $st)"; podman logs "$HUB" 2>&1 | tail -15
  fi

  STEP "[$F] version pinning"
  PINNED="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "{\"name\":\"web1 pinned v1\",\"credential_type\":\"ssh_key\",\"source\":\"external\",\"source_id\":\"$SRC\",\"reference\":{\"path\":\"ssh/web1\",\"version\":\"1\"}}" | jget 'd["data"]["id"]')"
  mgr kv put -mount=secret ssh/web1 private_key_pem="not a key" user=kkscan host_public_key="$HOSTKEY" port=22 >/dev/null && PASS "[$F] version 2 written with an unusable key"
  st="$(scan_job "$(mktarget "t-$F-latest" "$CRED")")"; echo "  latest: scan status $st"
  dump_endpoints "$WORK/ep.json"; msg="$(ssh_endpoint_error)"; echo "  latest error: ${msg:0:240}"
  podman logs "$HUB" 2>&1 | grep "could not be resolved" | tail -1 | cut -c1-300
  [ "$st" != completed ] && PASS "[$F] latest (version 2) fails" || FAIL "[$F] latest should not have scanned with a broken key"
  # The unusable key has the right shape (a string), so the failure is the SSH key parse, named by credential.
  LASTFAIL="$(podman logs "$HUB" 2>&1 | grep "ssh discovery" | tail -1 | cut -c1-300)"; echo "  hub log: $LASTFAIL"
  [ -n "$LASTFAIL" ] && PASS "[$F] the hub logged why the latest version could not drive a scan" || FAIL "[$F] no failure line in the hub log"
  st="$(scan_job "$(mktarget "t-$F-pinned" "$PINNED")")"; echo "  pinned v1: scan status $st"
  [ "$st" = completed ] && ssh_endpoint_has_cert && PASS "[$F] version 1 still drives the scan" || FAIL "[$F] pinned version 1 did not scan"

  STEP "[$F] a path outside the token's policy is refused clearly"
  T="$(curlj -X POST "${HUB_BASE}/api/v1/credential-sources/$SRC/test" -d '{"credential_type":"ssh_key","reference":{"path":"other/web1"}}')"
  echo "  test: $(echo "$T" | cut -c1-300)"
  echo "$T" | grep -q '"ok":false' && echo "$T" | grep -qi "denied" && PASS "[$F] 403 is surfaced as a clear denied message" || FAIL "[$F] denied path message"
  T="$(curlj -X POST "${HUB_BASE}/api/v1/credential-sources/$SRC/test" -d '{"credential_type":"ssh_key","reference":{"path":"ssh/nope"}}')"
  echo "$T" | grep -q '"ok":false' && echo "$T" | grep -qi "nothing at secret/ssh/nope" && PASS "[$F] 404 is surfaced as a clear not-found message" || FAIL "[$F] not-found path message"

  STEP "[$F] AppRole login"
  mgr kv put -mount=secret ssh/web1 private_key_pem=@/tmp/id_ed25519 user=kkscan host_public_key="$HOSTKEY" port=22 >/dev/null
  LOGIN2="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "{\"name\":\"$F approle\",\"credential_type\":\"api_token\",\"payload\":{\"role_id\":\"$ROLE_ID\",\"secret_id\":\"$SECRET_ID\"}}" | jget 'd["data"]["id"]')"
  SRC2="$(python3 - "$LOGIN2" "$ADDR" "$CA_PEM" "$F" <<'PY' | curlj -X POST "${HUB_BASE}/api/v1/credential-sources" -d @- | jget 'd["data"]["id"]'
import json, sys
login, addr, ca, f = sys.argv[1:5]
print(json.dumps({"name": f + " approle", "kind": "vault_kv2", "credential_ref": login, "config": {"base_url": addr, "ca_cert_pem": ca}}))
PY
)"
  CRED2="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "{\"name\":\"web1 via approle\",\"credential_type\":\"ssh_key\",\"source\":\"external\",\"source_id\":\"$SRC2\",\"reference\":{\"path\":\"ssh/web1\"}}" | jget 'd["data"]["id"]')"
  st="$(scan_job "$(mktarget "t-$F-approle" "$CRED2")")"; echo "  scan status: $st"
  [ "$st" = completed ] && ssh_endpoint_has_cert && PASS "[$F] AppRole login drove the same discovery" || FAIL "[$F] AppRole discovery (status $st)"
  LOGIN3="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "{\"name\":\"$F bad approle\",\"credential_type\":\"api_token\",\"payload\":{\"role_id\":\"$ROLE_ID\",\"secret_id\":\"00000000-0000-0000-0000-000000000000\"}}" | jget 'd["data"]["id"]')"
  SRC3="$(python3 - "$LOGIN3" "$ADDR" "$CA_PEM" "$F" <<'PY' | curlj -X POST "${HUB_BASE}/api/v1/credential-sources" -d @- | jget 'd["data"]["id"]'
import json, sys
login, addr, ca, f = sys.argv[1:5]
print(json.dumps({"name": f + " bad approle", "kind": "vault_kv2", "credential_ref": login, "config": {"base_url": addr, "ca_cert_pem": ca}}))
PY
)"
  T="$(curlj -X POST "${HUB_BASE}/api/v1/credential-sources/$SRC3/test" -d '{"credential_type":"ssh_key","reference":{"path":"ssh/web1"}}')"
  echo "  bad secret_id: $(echo "$T" | cut -c1-300)"
  echo "$T" | grep -q '"ok":false' && ! echo "$T" | grep -q "00000000-0000" && PASS "[$F] a bad secret_id is a clear failure that does not echo it" || FAIL "[$F] bad AppRole message"

  STEP "[$F] audit rows"
  curlj "${HUB_BASE}/api/v1/audit?action=credential.resolve&limit=100" >"$WORK/audit-$F.json"
  python3 - "$WORK/audit-$F.json" "$F" <<'PY' && PASS "[$F] credential.resolve rows exist for success and failure, with source and no values" || FAIL "[$F] audit rows"
import json, sys
d = json.load(open(sys.argv[1]))
data = d.get("data")
rows = data if isinstance(data, list) else ((data or {}).get("entries") or (data or {}).get("items") or [])
rows = [r for r in rows if r.get("action") == "credential.resolve"]
ok = [r for r in rows if r.get("outcome") == "success"]
bad = [r for r in rows if r.get("outcome") == "failure"]
print(f"  {len(rows)} credential.resolve rows ({len(ok)} success, {len(bad)} failure)")
for r in rows[:3]: print("  e.g.", r.get("outcome"), r.get("change_summary"))
sys.exit(0 if ok and bad and all("source=vault_kv2:" in (r.get("change_summary") or "") for r in rows) else 1)
PY
  kk_rm "$NAME"
}

for F in $FLAVORS; do run_flavor "$F"; done

STEP "no key or token anywhere in the hub"
podman logs "$HUB" >"$WORK/hub.log" 2>&1
LEAK=0
for pat in "$KEY_MARK"; do
  if grep -rqF -- "$pat" "$WORK/hub.log" "$WORK/hubdata" 2>/dev/null; then LEAK=1; echo "  LEAK: key material found under hub logs or data"; fi
done
[ $LEAK = 0 ] && PASS "the private key's body appears in no hub log line, audit row or data file" || FAIL "key material leaked into the hub"
grep -rqF -- "-----BEGIN OPENSSH PRIVATE KEY-----" "$WORK/hub.log" "$WORK/hubdata" 2>/dev/null && FAIL "a PEM header is on the hub's disk or logs" || PASS "no private-key PEM header on the hub's disk or in its logs"  # secret-scan:allow: asserts the header is absent from hub logs

echo
if [ "$FAILED" = 0 ]; then echo "ALL PASS"; else echo "SOME FAILED"; fi
exit "$FAILED"
