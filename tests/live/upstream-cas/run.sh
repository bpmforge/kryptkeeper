#!/usr/bin/env bash
# W36-16 live proof: the hub issues and revokes through REAL upstream CAs.
#
#   A  HashiCorp Vault PKI  (dev server with TLS; the hub needs HTTPS to send credentials)
#   B  EJBCA Community      (see scenario_b; honest time box)
#   C  AWS Private CA       (moto: only if the pulled moto implements acm-pca issue/revoke)
#
# Everything is driven through the hub API. The hub, the upstream CAs, a
# tamper proxy and the ACME client run as containers on one private podman
# network created for this run; every name carries a random RUN_ID and the
# cleanup trap removes only those names. Pass KK_SCENARIOS="A" (default "A B C")
# to run a subset. PASS/FAIL per step, non-zero exit on any FAIL.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
RUN_ID="$(openssl rand -hex 3)"
# Under $HOME: the podman machine on macOS only mounts /Users.
WORK="$HOME/kk-uat-upca-$RUN_ID"
SCENARIOS="${KK_SCENARIOS:-A B C}"

VAULT_IMG="${KK_VAULT_IMAGE:-docker.io/hashicorp/vault:1.18.5}"
LEGO_IMG="${KK_LEGO_IMAGE:-docker.io/goacme/lego:v4.21.0}"
PY_IMG="${KK_PY_IMAGE:-docker.io/library/python:3.12-alpine}"
EJBCA_IMG="${KK_EJBCA_IMAGE:-docker.io/keyfactor/ejbca-ce:9.3.7}"
MOTO_IMG="${KK_MOTO_IMAGE:-docker.io/motoserver/moto:5.0.28}"
ALPINE_IMG=docker.io/library/alpine:3

NET="kk-upca-net-$RUN_ID"
HUB_CTR="kk-upca-hub-$RUN_ID"
VAULT_CTR="kk-upca-vault-$RUN_ID"
PROXY_CTR="kk-upca-proxy-$RUN_ID"
LEGO_CTR="kk-upca-lego-$RUN_ID"
EJBCA_CTR="kk-upca-ejbca-$RUN_ID"
MOTO_CTR="kk-upca-moto-$RUN_ID"
HUB_PORT=8080
HOST_PORT="$(kk_free_port)"
HUB="https://localhost:$HOST_PORT"
BOOT="uat-upca-bootstrap-token"
# Dual control guards creating an external CA (a second pki-admin approves), and
# the bootstrap token can propose but never approve: two named pki-admins.
PEPPER="uat-pepper-32-characters-minimum!!"
ALICE_SECRET="$(openssl rand -hex 24)"; BOB_SECRET="$(openssl rand -hex 24)"
verifier() { printf '%s' "$1" | openssl dgst -sha256 -hmac "$PEPPER" -hex | awk '{print $NF}'; }
API_KEYS_JSON="[{\"name\":\"alice\",\"kid\":\"uatalice\",\"secret_verifier\":\"$(verifier "$ALICE_SECRET")\",\"principal_id\":\"alice\",\"role\":\"pki-admin\",\"active\":true},{\"name\":\"bob\",\"kid\":\"uatbob\",\"secret_verifier\":\"$(verifier "$BOB_SECRET")\",\"principal_id\":\"bob\",\"role\":\"pki-admin\",\"active\":true}]"
ALICE="kk_uatalice_$ALICE_SECRET"; BOB="kk_uatbob_$BOB_SECRET"
TOK="$ALICE"
DOMAIN="uat.example"
ACME_HOST="acme-$RUN_ID.$DOMAIN"
FAILED=0

STEP() { echo; echo "=== $* ==="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; FAILED=1; exit 1; }
SKIP() { echo "SKIP: $*"; }
want() { case " $SCENARIOS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

cleanup() {
  if [ "$FAILED" = 1 ]; then echo "--- hub log (last 30) ---"; podman logs "$HUB_CTR" 2>&1 | tail -30; fi
  kk_rm "$LEGO_CTR" "$PROXY_CTR" "$VAULT_CTR" "$EJBCA_CTR" "$MOTO_CTR" "$HUB_CTR"
  podman network rm "$NET" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- helpers -----------------------------------------------------------------
hub() { # hub METHOD PATH [JSON]: body in $WORK/last.json, prints the HTTP code
  local m="$1" p="$2"; shift 2
  curl -sS -m "${CURL_MAX:-60}" --cacert "$WORK/tls-export/ca.pem" -o "$WORK/last.json" -w '%{http_code}' \
    -X "$m" -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/json' "$HUB$p" ${1:+-d "$1"}
}
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
jstr() { python3 -c 'import json,sys; print(json.dumps({sys.argv[i]: sys.argv[i+1] for i in range(1, len(sys.argv), 2)}))' "$@"; }
first_pem() { python3 -c '
import json,sys,re
t=open(sys.argv[1]).read()
def walk(o):
    if isinstance(o,dict):
        for k in ("certificate_pem","certificate"):
            v=o.get(k)
            if isinstance(v,str) and "BEGIN CERTIFICATE" in v: return v
        for v in o.values():
            r=walk(v)
            if r: return r
    elif isinstance(o,list):
        for v in o:
            r=walk(v)
            if r: return r
d=json.loads(t); p=walk(d)
m=re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",p or "",re.S)
print(m.group(0) if m else "")' "$1"; }
first_pem_raw() { sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/{p;/END CERTIFICATE/q;}' "$1"; }
fp_of() { openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }
serial_of() { openssl x509 -in "$1" -noout -serial | cut -d= -f2; }
colon_serial() { echo "$1" | sed 's/../&:/g; s/:$//' | tr 'A-F' 'a-f'; }
issuer_of() { openssl x509 -in "$1" -noout -issuer | sed 's/^issuer= *//'; }
mkcsr() { # mkcsr NAME [extra SAN...] -> $WORK/NAME.key / .csr
  local n="$1"; shift
  local san="DNS:$n"; for e in "$@"; do san="$san,DNS:$e"; done
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/$n.key" -out "$WORK/$n.csr" \
    -subj "/CN=$n" -addext "subjectAltName=$san" >/dev/null 2>&1
}

# check_cert LABEL CERTFILE CA_ISSUER_SUBSTR ROOTFILE: issuer + openssl verify
check_cert() {
  local label="$1" cert="$2" issuer_sub="$3" root="$4"
  local iss; iss="$(issuer_of "$cert")"
  case "$iss" in *"$issuer_sub"*) PASS "$label: issuer is the upstream CA ($iss), serial $(serial_of "$cert")" ;; *) FAIL "$label: issuer '$iss' is not '$issuer_sub'" ;; esac
  if openssl verify -CAfile "$root" "$cert" >"$WORK/verify.out" 2>&1; then PASS "$label: openssl verify -CAfile <upstream root> -> $(tr '\n' ' ' <"$WORK/verify.out")"; else FAIL "$label: openssl verify failed: $(cat "$WORK/verify.out")"; fi
}

audit_has() { # audit_has EVENT: any audit row mentioning EVENT
  python3 - "$HUB" "$TOK" "$WORK/tls-export/ca.pem" "$1" "${2:-1}" <<'PY'
import json, ssl, sys, urllib.request
hub, token, ca, needle, want = sys.argv[1:6]
want, found = int(want), []
ctx = ssl.create_default_context(cafile=ca)
cursor = ""
while True:
    url = hub + "/api/v1/audit?limit=100" + ("&cursor=" + cursor if cursor else "")
    d = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Bearer " + token}), context=ctx))
    for r in d["data"]:
        if needle in json.dumps(r):
            found.append(r.get("change_summary", ""))
    cursor = (d.get("meta") or {}).get("next_cursor") or ""
    if not cursor:
        print("%d row(s): %s" % (len(found), " | ".join(found)))
        sys.exit(0 if len(found) >= want else 1)
PY
}

# wait_name NAME: the name resolves on the run network. tests/live/lib kk_wait_dns
# uses nslookup, which busybox answers NXDOMAIN on this host's podman 6 stack even
# though the name resolves; getent is what the clients' resolvers do.
wait_name() {
  local i
  for i in $(seq 1 30); do
    podman run --rm --network "$NET" "$ALPINE_IMG" getent hosts "$1" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}

start_hub() { # start_hub [extra podman args...]
  kk_rm "$HUB_CTR"
  podman run -d --name "$HUB_CTR" --network "$NET" --hostname "$HUB_CTR" -p "127.0.0.1:$HOST_PORT:$HUB_PORT" \
    -v "$WORK/bin/kryptkeeper:/kryptkeeper:ro" -v "$WORK/data:/data" -v "$WORK/tls-export:/tls-export" \
    -v "$HERE/../protocols/est-users.json:/est-users.json:ro" \
    -e APP_BOOTSTRAP_TOKEN="$BOOT" -e AUTH_MODE=bootstrap \
    -e APP_CERTIFICATE_PROVIDER=ca -e APP_DISCOVERY_PROVIDER=db -e APP_NOTIFICATION_PROVIDER=file \
    -e SSL_CERT_FILE=/tls-export/svc-ca.pem \
    -e KRYPTKEEPER_TLS_CERT_FILE=/tls-export/hub.pem -e KRYPTKEEPER_TLS_KEY_FILE=/tls-export/hub.key \
    -e KRYPTKEEPER_EST_USERS_FILE=/est-users.json \
    -e APP_API_KEY_AUTH_ENABLED=true -e APP_API_KEY_PEPPER="$PEPPER" -e APP_API_KEYS_JSON="$API_KEYS_JSON" \
    -e APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
    -e KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
    -e KRYPTKEEPER_DATA_DIR=/data \
    -e APP_CA_FILE=/data/cas.json -e APP_TEMPLATE_FILE=/data/templates.json \
    -e APP_CERTIFICATE_FILE=/data/certificates.json -e APP_AUDIT_FILE=/data/audit.json \
    -e APP_CERTS_SUMMARY_FILE=/data/certs_summary.json \
    -e KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true -e KRYPTKEEPER_CA_NAME="UAT Hub Root CA" \
    -e APP_BIND_ADDR=0.0.0.0 -e PORT="$HUB_PORT" \
    -e KRYPTKEEPER_BASE_URL="https://$HUB_CTR:$HUB_PORT" \
    "$@" "$ALPINE_IMG" /kryptkeeper >/dev/null || return 1
  local i
  for i in $(seq 1 120); do
    curl -sf --cacert "$WORK/tls-export/ca.pem" "$HUB/healthz" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# ext_ca NAME CONNECTOR_ID TRUST_FILE -> prints CA id
ext_ca() {
  local body; body="$(python3 -c 'import json,sys; print(json.dumps({"name":sys.argv[1],"connector_id":sys.argv[2],"trust_pem":open(sys.argv[3]).read()}))' "$1" "$2" "$3")"
  local c; c=$(hub POST /api/v1/cas/external "$body")
  if [ "$c" = 202 ]; then # dual control: bob approves alice's proposal, alice redeems it
    local act; act="$(jget 'd["data"]["action_id"]' <"$WORK/last.json")"
    c=$(TOK="$BOB" hub POST "/api/v1/pending-actions/$act/approve" '{}')
    [ "$c" = 200 ] || { echo "approve -> $c $(cat "$WORK/last.json")" >&2; return 1; }
    body="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["approved_action_id"]=sys.argv[2]; print(json.dumps(d))' "$body" "$act")"
    c=$(hub POST /api/v1/cas/external "$body")
  fi
  [ "$c" = 201 ] || { echo "cas/external -> $c $(cat "$WORK/last.json")" >&2; return 1; }
  jget 'd["data"]["id"]' <"$WORK/last.json"
}
# mk_connector NAME TYPE CRED_ID CONFIG_JSON -> prints connector id
mk_connector() {
  local body; body="$(python3 -c 'import json,sys; print(json.dumps({"name":sys.argv[1],"type":sys.argv[2],"credential_ref":sys.argv[3],"config_json":sys.argv[4]}))' "$1" "$2" "$3" "$4")"
  local c; c=$(hub POST /api/v1/connectors "$body")
  [ "$c" = 201 ] || { echo "connector -> $c $(cat "$WORK/last.json")" >&2; return 1; }
  jget 'd["data"]["id"]' <"$WORK/last.json"
}
# rest_issue CA_ID NAME -> HTTP code; cert in $WORK/NAME.crt on 200/201
rest_issue() {
  local ca="$1" n="$2"
  local body; body="$(python3 -c 'import json,sys; print(json.dumps({"ca_id":sys.argv[1],"template_id":sys.argv[2],"csr_pem":open(sys.argv[3]).read()}))' "$ca" "$TPL" "$WORK/$n.csr")"
  local c; c=$(hub POST /api/v1/certificates "$body")
  case "$c" in
    200 | 201)
      local fp; fp="$(jget 'd["data"]["fingerprint_sha256"]' <"$WORK/last.json")"
      cp "$WORK/last.json" "$WORK/$n.issue.json"
      hub GET "/api/v1/certificates/$fp/download?format=pem" >/dev/null
      first_pem_raw "$WORK/last.json" >"$WORK/$n.crt"
      cp "$WORK/$n.issue.json" "$WORK/last.json" ;;
  esac
  echo "$c"
}

# --- common setup ------------------------------------------------------------
STEP "build hub, create network $NET"
mkdir -p "$WORK/bin" "$WORK/data" "$WORK/tls-export" "$WORK/acme"
# The hub's listener certificate comes from a throwaway CA, not from the hub's own
# CA: self-issue signs it from the default CA, which EST makes the external one.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -keyout "$WORK/tlsca.key" -out "$WORK/tls-export/ca.pem" -subj "/CN=UAT listener CA" -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/tls-export/hub.key" -out "$WORK/hub.csr" -subj "/CN=$HUB_CTR" >/dev/null 2>&1
printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\n' "$HUB_CTR" >"$WORK/hub.ext"
openssl x509 -req -in "$WORK/hub.csr" -CA "$WORK/tls-export/ca.pem" -CAkey "$WORK/tlsca.key" -CAcreateserial -days 2 -extfile "$WORK/hub.ext" -out "$WORK/tls-export/hub.pem" >/dev/null 2>&1
chmod 644 "$WORK/tls-export/hub.key"
# One throwaway CA for fixture TLS (moto). The hub trusts it as its system roots (alpine ships none),
# which is how the aws_pca connector (no ca_cert_pem setting) verifies its endpoint_url.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -keyout "$WORK/svcca.key" -out "$WORK/tls-export/svc-ca.pem" -subj "/CN=UAT fixture CA" -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
# mk_svc_cert NAME: $WORK/svc-NAME.pem / .key for DNS:NAME signed by the fixture CA
mk_svc_cert() {
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/svc-$1.key" -out "$WORK/svc-$1.csr" -subj "/CN=$1" >/dev/null 2>&1
  printf 'subjectAltName=DNS:%s\n' "$1" >"$WORK/svc-$1.ext"
  openssl x509 -req -in "$WORK/svc-$1.csr" -CA "$WORK/tls-export/svc-ca.pem" -CAkey "$WORK/svcca.key" -CAcreateserial -days 2 -extfile "$WORK/svc-$1.ext" -out "$WORK/svc-$1.pem" >/dev/null 2>&1
  chmod 644 "$WORK/svc-$1.key"
}
(cd "$REPO_ROOT" && GOOS=linux GOARCH="$(kk_goarch)" CGO_ENABLED=0 go build -o "$WORK/bin/kryptkeeper" ./cmd/kryptkeeper) || DIE "go build failed"
podman network create "$NET" >/dev/null || DIE "network create failed"
start_hub || DIE "hub did not start"
PASS "hub up at $HUB (container $HUB_CTR); commit $(git -C "$REPO_ROOT" rev-parse --short HEAD)"
c=$(hub POST /api/v1/templates '{"name":"upca-server","display_name":"upca-server","validity_period":"P30D","key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","RSA"],"active":true,"enrollment_permissions":{"enroll":["pki-admin"]}}')
[ "$c" = 201 ] || DIE "template -> $c $(cat "$WORK/last.json")"
TPL="$(jget 'd["data"]["id"]' <"$WORK/last.json")"
PASS "template $TPL"
# Neither EJBCA nor moto takes a validity in the request, so those scenarios use a template whose cap
# (397 days, under the Baseline policy's 398) covers what they issue. The hub's cap check stays on.
c=$(hub POST /api/v1/templates '{"name":"upca-long","display_name":"upca-long","validity_period":"P397D","key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","RSA"],"active":true,"enrollment_permissions":{"enroll":["pki-admin"]}}')
[ "$c" = 201 ] || DIE "long template -> $c $(cat "$WORK/last.json")"
TPL_LONG="$(jget 'd["data"]["id"]' <"$WORK/last.json")"

# =============================================================================
# Scenario A: HashiCorp Vault PKI
# =============================================================================
scenario_a() {
  STEP "A1 Vault dev server (TLS) with a PKI mount, internal root and a role for $DOMAIN"
  podman run -d --name "$VAULT_CTR" --network "$NET" --cap-add IPC_LOCK \
    -e VAULT_DEV_ROOT_TOKEN_ID=root \
    "$VAULT_IMG" server -dev -dev-tls -dev-tls-cert-dir=/vault/file -dev-listen-address=0.0.0.0:8200 -dev-tls-san="$VAULT_CTR" >/dev/null || DIE "vault did not start"
  vlt() { podman exec -e VAULT_ADDR=https://127.0.0.1:8200 -e VAULT_CACERT=/vault/file/vault-ca.pem -e VAULT_TOKEN=root "$VAULT_CTR" vault "$@"; }
  local i; for i in $(seq 1 60); do vlt status >/dev/null 2>&1 && break; sleep 1; done
  vlt status >/dev/null 2>&1 || DIE "vault not ready"
  podman exec "$VAULT_CTR" cat /vault/file/vault-ca.pem >"$WORK/vault-tls-ca.pem"
  vlt secrets enable pki >/dev/null && vlt secrets tune -max-lease-ttl=8760h pki >/dev/null || DIE "pki mount"
  vlt write -field=certificate pki/root/generate/internal common_name="UAT Vault PKI Root" ttl=8760h >"$WORK/vault-root.pem" || DIE "root generate"
  vlt write pki/roles/uat allowed_domains="$DOMAIN" allow_subdomains=true allow_bare_domains=true key_type=any max_ttl=720h ttl=240h >/dev/null || DIE "role"
  PASS "vault $(vlt version) ready; root: $(openssl x509 -in "$WORK/vault-root.pem" -noout -subject)"

  STEP "A2 hub: outbound credential, vault_pki connector, /test, external CA"
  local c; c=$(hub POST /api/v1/credentials "$(python3 -c 'import json; print(json.dumps({"name":"upca-vault-token","credential_type":"api_token","payload":{"token":"root"}}))')")
  [ "$c" = 201 ] || DIE "credential -> $c $(cat "$WORK/last.json")"
  local cred; cred="$(jget 'd["data"]["id"]' <"$WORK/last.json")"; VCRED="$cred"
  local cfg; cfg="$(python3 -c 'import json,sys; print(json.dumps({"base_url":"https://%s:8200"%sys.argv[1],"role":"uat","ca_cert_pem":open(sys.argv[2]).read(),"ttl":"240h"}))' "$VAULT_CTR" "$WORK/vault-tls-ca.pem")"
  VCONN="$(mk_connector "vault-live" vault_pki "$cred" "$cfg")" || DIE "vault connector"
  c=$(hub POST "/api/v1/connectors/$VCONN/test" '{}')
  if [ "$c" = 200 ] && grep -qi 'healthy' "$WORK/last.json"; then PASS "connector test -> 200 $(head -c 200 "$WORK/last.json")"; else FAIL "connector test -> $c $(cat "$WORK/last.json")"; fi
  VCA="$(ext_ca "Vault PKI (live)" "$VCONN" "$WORK/vault-root.pem")" && PASS "external CA $VCA bound to $VCONN" || DIE "external CA"

  STEP "A3 issue via REST POST /api/v1/certificates"
  mkcsr rest1.$DOMAIN; mkcsr rest2.$DOMAIN
  c=$(rest_issue "$VCA" rest1.$DOMAIN)
  case "$c" in 20*) PASS "REST issue -> $c" ;; *) FAIL "REST issue -> $c $(cat "$WORK/last.json")" ;; esac
  if [ -s "$WORK/rest1.$DOMAIN.crt" ]; then check_cert "REST" "$WORK/rest1.$DOMAIN.crt" "UAT Vault PKI Root" "$WORK/vault-root.pem"; else FAIL "REST: no certificate in response"; fi
  c=$(rest_issue "$VCA" rest2.$DOMAIN)
  case "$c" in 20*) PASS "REST issue #2 -> $c ($(serial_of "$WORK/rest2.$DOMAIN.crt"))" ;; *) FAIL "REST issue #2 -> $c $(cat "$WORK/last.json")" ;; esac

  STEP "A4 issue via ACME (lego, http-01) on a provisioner bound to the external CA"
  c=$(hub POST /api/v1/acme/provisioners "$(python3 -c 'import json,sys; print(json.dumps({"name":"vaultca","ca_id":sys.argv[1],"allow_names":["*."+sys.argv[2]],"challenges":["http-01"]}))' "$VCA" "$DOMAIN")")
  case "$c" in 20*) PASS "ACME provisioner vaultca -> $c" ;; *) FAIL "ACME provisioner -> $c $(cat "$WORK/last.json")" ;; esac
  wait_name "$HUB_CTR" || FAIL "dns for $HUB_CTR"
  podman run --rm --name "$LEGO_CTR" --network "$NET" --network-alias "$ACME_HOST" \
    -v "$WORK/acme:/data" -v "$WORK/tls-export/ca.pem:/etc/kk-ca/ca.pem:ro" -e LEGO_CA_CERTIFICATES=/etc/kk-ca/ca.pem \
    "$LEGO_IMG" --accept-tos --email uat@example.test --server "https://$HUB_CTR:$HUB_PORT/acme/vaultca/directory" --path /data \
    --domains "$ACME_HOST" --http run >"$WORK/lego.log" 2>&1
  local lc=$?
  if [ -s "$WORK/acme/certificates/$ACME_HOST.crt" ]; then
    openssl x509 -in "$WORK/acme/certificates/$ACME_HOST.crt" -out "$WORK/acme-leaf.pem"
    PASS "lego obtained a certificate (exit $lc)"
    check_cert "ACME" "$WORK/acme-leaf.pem" "UAT Vault PKI Root" "$WORK/vault-root.pem"
  else
    FAIL "lego produced no certificate (exit $lc): $(tail -8 "$WORK/lego.log")"
  fi

  STEP "A5 issue via EST simpleenroll (default CA = the external CA)"
  mkcsr est1.est.$DOMAIN
  if start_hub -e KRYPTKEEPER_DEFAULT_CA_ID="$VCA"; then
    openssl req -in "$WORK/est1.est.$DOMAIN.csr" -outform DER | base64 >"$WORK/est.csr.b64"
    c=$(curl -sS -m 60 --cacert "$WORK/tls-export/ca.pem" -o "$WORK/est.out" -w '%{http_code}' -u uat-est:uat-est-password \
      -H 'Content-Type: application/pkcs10' -H 'Content-Transfer-Encoding: base64' --data-binary @"$WORK/est.csr.b64" \
      "$HUB/.well-known/est/simpleenroll")
    if [ "$c" = 200 ] && base64 -d <"$WORK/est.out" 2>/dev/null | openssl pkcs7 -inform DER -print_certs 2>/dev/null | awk '/BEGIN CERT/{f=1} f{print} /END CERT/{exit}' >"$WORK/est.crt" && [ -s "$WORK/est.crt" ]; then
      PASS "EST simpleenroll -> 200"
      check_cert "EST" "$WORK/est.crt" "UAT Vault PKI Root" "$WORK/vault-root.pem"
    else
      FAIL "EST simpleenroll -> $c $(head -c 300 "$WORK/est.out")"
    fi
  else
    FAIL "hub restart with KRYPTKEEPER_DEFAULT_CA_ID failed"
  fi

  STEP "A6 revoke through the hub -> upstream (Vault) revocation"
  local fp1 s1 vs; fp1="$(fp_of "$WORK/rest1.$DOMAIN.crt")"; s1="$(serial_of "$WORK/rest1.$DOMAIN.crt")"; vs="$(colon_serial "$s1")"
  c=$(hub POST "/api/v1/certificates/$fp1/revoke" '{"reason_code":1}')
  local scope; scope="$(jget 'd["data"].get("revocation_scope")' <"$WORK/last.json" 2>/dev/null)"
  if [ "$c" = 200 ] && [ "$scope" = upstream ]; then PASS "revoke -> 200 revocation_scope=$scope"; else FAIL "revoke -> $c $(cat "$WORK/last.json")"; hub GET "/api/v1/certificates/$fp1" >/dev/null; echo "  diag: $(jget '"origin="+str(d["data"].get("origin"))+" renewal_connector_id="+str(d["data"].get("renewal_connector_id"))+" source="+str(d["data"].get("source"))' <"$WORK/last.json")"; fi
  local rt; rt="$(vlt read -format=json "pki/cert/$vs" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"].get("revocation_time",0))')"
  if [ "${rt:-0}" -gt 0 ] 2>/dev/null; then PASS "vault pki/cert/$vs revocation_time=$rt"; else FAIL "vault does not show $vs revoked (revocation_time=${rt:-?})"; fi

  STEP "A7 tamper: a CA that returns something other than the request is refused"
  # Own CA for the proxy so the hub verifies the proxy with ca_cert_pem like any connector.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -keyout "$WORK/pxca.key" -out "$WORK/pxca.pem" -subj "/CN=UAT tamper proxy CA" -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/px.key" -out "$WORK/px.csr" -subj "/CN=$PROXY_CTR" >/dev/null 2>&1
  printf 'subjectAltName=DNS:%s\n' "$PROXY_CTR" >"$WORK/px.ext"
  openssl x509 -req -in "$WORK/px.csr" -CA "$WORK/pxca.pem" -CAkey "$WORK/pxca.key" -CAcreateserial -days 2 -extfile "$WORK/px.ext" -out "$WORK/px.pem" >/dev/null 2>&1
  mkcsr tk.$DOMAIN; mkcsr tkother.$DOMAIN; mkcsr ts.$DOMAIN
  # key mode: the proxy swaps in a CSR for a different key (names unchanged); san mode: an extra name.
  # csr-key: tk's names, a different key; csr-san: ts's key plus an extra name
  openssl req -new -key "$WORK/tkother.$DOMAIN.key" -out "$WORK/csr-key.pem" -subj "/CN=tk.$DOMAIN" -addext "subjectAltName=DNS:tk.$DOMAIN" >/dev/null 2>&1
  openssl req -new -key "$WORK/ts.$DOMAIN.key" -out "$WORK/csr-san.pem" -subj "/CN=ts.$DOMAIN" -addext "subjectAltName=DNS:ts.$DOMAIN,DNS:extra-san.$DOMAIN" >/dev/null 2>&1
  echo key >"$WORK/mode"; cp "$HERE/tamper_proxy.py" "$WORK/tamper_proxy.py"
  podman run -d --name "$PROXY_CTR" --network "$NET" -v "$WORK:/w:ro" "$PY_IMG" \
    python3 /w/tamper_proxy.py 8443 /w/px.pem /w/px.key "$VAULT_CTR:8200" /w/vault-tls-ca.pem /w/mode /w/csr-key.pem /w/csr-san.pem >/dev/null || DIE "proxy did not start"
  local cred2="$VCRED" cfg2
  cfg2="$(python3 -c 'import json,sys; print(json.dumps({"base_url":"https://%s:8443"%sys.argv[1],"role":"uat","ca_cert_pem":open(sys.argv[2]).read(),"ttl":"240h"}))' "$PROXY_CTR" "$WORK/pxca.pem")"
  TCONN="$(mk_connector "vault-tamper" vault_pki "$cred2" "$cfg2")" || DIE "tamper connector"
  for i in $(seq 1 20); do c=$(hub POST "/api/v1/connectors/$TCONN/test" '{}'); [ "$c" = 200 ] && break; sleep 1; done
  [ "$c" = 200 ] && PASS "tamper connector reaches Vault through the proxy" || FAIL "tamper connector test -> $c $(cat "$WORK/last.json")"
  TCA="$(ext_ca "Vault PKI (tamper proxy)" "$TCONN" "$WORK/vault-root.pem")" || DIE "tamper CA"
  c=$(rest_issue "$TCA" tk.$DOMAIN)
  case "$c" in 20*) FAIL "key-swap issuance was ACCEPTED ($c)" ;; *) PASS "key-swapped certificate refused -> $c $(head -c 220 "$WORK/last.json")" ;; esac
  echo san >"$WORK/mode"
  c=$(rest_issue "$TCA" ts.$DOMAIN)
  case "$c" in 20*) FAIL "extra-SAN issuance was ACCEPTED ($c)" ;; *) PASS "extra-SAN certificate refused -> $c $(head -c 220 "$WORK/last.json")" ;; esac
  local ev; if ev="$(audit_has certificate.issue.upstream_rejected 2)"; then PASS "audit has certificate.issue.upstream_rejected for both tampers: $ev"; else FAIL "audit lacks two certificate.issue.upstream_rejected rows: $ev"; fi
  hub GET "/api/v1/certificates?limit=100" >/dev/null
  if grep -q "tk.$DOMAIN\|ts.$DOMAIN" "$WORK/last.json"; then FAIL "a rejected certificate was stored in the inventory"; else PASS "no rejected certificate was stored"; fi

  STEP "A8 revoke while Vault is unreachable -> 502, NOT revoked in the hub"
  local fp2; fp2="$(fp_of "$WORK/rest2.$DOMAIN.crt")"
  podman stop -t 2 "$VAULT_CTR" >/dev/null
  c=$(CURL_MAX=120 hub POST "/api/v1/certificates/$fp2/revoke" '{"reason_code":1}')
  if [ "$c" = 502 ] && grep -q upstream_revoke_failed "$WORK/last.json"; then PASS "revoke with Vault down -> 502 $(head -c 200 "$WORK/last.json")"; else FAIL "revoke with Vault down -> $c $(cat "$WORK/last.json")"; fi
  hub GET "/api/v1/certificates/$fp2" >/dev/null
  local st; st="$(jget '"revoked_at=%s revocation_scope=%s" % (d["data"].get("revoked_at"), d["data"].get("revocation_scope"))' <"$WORK/last.json" 2>/dev/null)"
  case "$st" in "revoked_at=None revocation_scope=None") PASS "certificate NOT revoked in the hub after the failed upstream revoke ($st)" ;; *) FAIL "certificate state after failed revoke: $st" ;; esac
  if ev="$(audit_has certificate.revoke.upstream_failed)"; then PASS "audit has certificate.revoke.upstream_failed"; else FAIL "audit has no certificate.revoke.upstream_failed"; fi
}

# =============================================================================
# Scenario B: EJBCA Community
# =============================================================================
scenario_b() {
  STEP "B1 EJBCA CE container ($EJBCA_IMG), REST enabled, REST client certificate"
  podman run -d --name "$EJBCA_CTR" --network "$NET" -e TLS_SETUP_ENABLED=simple -e HTTPSERVER_HOSTNAME="$EJBCA_CTR" "$EJBCA_IMG" >/dev/null || { FAIL "ejbca did not start"; return; }
  local i ready=0
  for i in $(seq 1 120); do
    if podman exec "$EJBCA_CTR" curl -sk -m 5 https://localhost:8443/ejbca/publicweb/healthcheck/ejbcahealth 2>/dev/null | grep -q ALLOK; then ready=1; break; fi
    sleep 5
  done
  [ "$ready" = 1 ] || { FAIL "EJBCA not healthy after 10 minutes (stopped here: container start)"; podman logs --tail 20 "$EJBCA_CTR" 2>&1 | cut -c1-200; return; }
  PASS "EJBCA healthy after ~$((i * 5))s"
  ej() { podman exec "$EJBCA_CTR" /opt/keyfactor/bin/ejbca.sh "$@" 2>&1; }
  ej config protocols enable "REST Certificate Management" | grep -q "REST Certificate Management: Enabled" || { FAIL "could not enable REST (stopped here: protocol enable)"; return; }
  ej ra addendentity --username kkrest --password kkrestpw --dn "CN=kkrest" --caname ManagementCA --type 1 --token PEM | grep -q "has been added" || { FAIL "could not add the REST end entity"; return; }
  ej ra setclearpwd --username kkrest --password kkrestpw >/dev/null
  ej batch | grep -q "generated successfully" || { FAIL "batch keystore generation failed"; return; }
  ej roles addrolemember --role "Super Administrator Role" --caname ManagementCA --with WITH_COMMONNAME --value kkrest | grep -q "successfully added" || { FAIL "could not add kkrest to the Super Administrator Role"; return; }
  # Simple TLS mode starts with an EMPTY server truststore, so Wildfly resets any connection that presents a
  # client certificate. Trust ManagementCA in it and soft-reload (the H2 database lives on in the same JVM).
  podman exec "$EJBCA_CTR" sh -c '
    cd /opt/keyfactor/appserver/standalone/configuration
    PW=$(grep -A2 "key-store name=\"httpsTS\"" standalone.xml | grep -o "clear-text=\"[^\"]*\"" | cut -d\" -f2)
    /usr/lib/jvm/java-17-slim/bin/keytool -importcert -noprompt -alias mgmtca -file /opt/keyfactor/p12/pem/kkrest-CA.pem -keystore truststore.jks -storepass "$PW" >/dev/null 2>&1
    /opt/keyfactor/appserver/bin/jboss-cli.sh --connect --command=reload >/dev/null 2>&1' || { FAIL "could not trust ManagementCA in the EJBCA truststore (stopped here: truststore)"; return; }
  sleep 5
  for i in $(seq 1 60); do podman exec "$EJBCA_CTR" curl -sk -m 5 https://localhost:8443/ejbca/publicweb/healthcheck/ejbcahealth 2>/dev/null | grep -q ALLOK && break; sleep 3; done
  # EJBCA's profiles issue 2-year certificates; a CA caps what it issues at its own lifetime. A 300-day CA
  # gives certificates the hub's 397-day template cap accepts, without touching any hub check.
  ej ca init --caname kkshort --dn "CN=UAT EJBCA Short Root" --tokenType soft --tokenPass null --keytype RSA --keyspec 2048 -s SHA256WithRSA -v 300 --policy null | grep -q "CA initialized" || { FAIL "could not create the 300-day EJBCA CA"; return; }
  ej ca getcacert --caname kkshort -f /tmp/kkshort.pem | grep -q "Wrote CA certificate" || { FAIL "could not export the EJBCA CA certificate"; return; }
  mkdir -p "$WORK/ejbca"; podman cp "$EJBCA_CTR:/opt/keyfactor/p12/pem/." "$WORK/ejbca/" >/dev/null || { FAIL "could not copy the client certificate out"; return; }
  podman cp "$EJBCA_CTR:/tmp/kkshort.pem" "$WORK/ejbca/kkshort.txt" >/dev/null && openssl x509 -in "$WORK/ejbca/kkshort.txt" -out "$WORK/ejbca/kkshort.pem" || { FAIL "could not copy the EJBCA CA certificate out"; return; }
  PASS "REST enabled; client certificate $(openssl x509 -in "$WORK/ejbca/kkrest.pem" -noout -subject) in the Super Administrator Role"
  local ecurl="podman run --rm --network $NET -v $WORK/ejbca:/p:ro docker.io/curlimages/curl:8.10.1"
  c=$($ecurl -s -m 30 -o /dev/null -w '%{http_code}' --cacert /p/kkrest-CA.pem --cert /p/kkrest.pem --key /p/kkrest-Key.pem "https://$EJBCA_CTR:8443/ejbca/ejbca-rest-api/v1/certificate/status")
  if [ "$c" = 200 ]; then PASS "REST client-certificate auth works: GET /v1/certificate/status -> 200"; else
    FAIL "REST auth: GET /v1/certificate/status -> $c (stopped here: REST authentication)"
    $ecurl -sv -m 30 --cacert /p/kkrest-CA.pem --cert /p/kkrest.pem --key /p/kkrest-Key.pem "https://$EJBCA_CTR:8443/ejbca/ejbca-rest-api/v1/certificate/status" 2>&1 | tail -12 | cut -c1-200
    return
  fi

  STEP "B2 hub: credential (client cert+key), ejbca connector, /test, external CA"
  c=$(hub POST /api/v1/credentials "$(python3 -c 'import json,sys; print(json.dumps({"name":"upca-ejbca-client","credential_type":"api_token","payload":{"client_cert_pem":open(sys.argv[1]).read(),"client_key_pem":open(sys.argv[2]).read()}}))' "$WORK/ejbca/kkrest.pem" "$WORK/ejbca/kkrest-Key.pem")")
  [ "$c" = 201 ] || { FAIL "ejbca credential -> $c $(cat "$WORK/last.json")"; return; }
  local cred; cred="$(jget 'd["data"]["id"]' <"$WORK/last.json")"
  local cfg; cfg="$(python3 -c 'import json,sys; print(json.dumps({"base_url":"https://%s:8443/ejbca/ejbca-rest-api"%sys.argv[1],"certificate_profile_name":"SERVER","end_entity_profile_name":"EMPTY","certificate_authority_name":"kkshort","ca_cert_pem":open(sys.argv[2]).read()}))' "$EJBCA_CTR" "$WORK/ejbca/kkrest-CA.pem")"
  ECONN="$(mk_connector "ejbca-live" ejbca "$cred" "$cfg")" || { FAIL "ejbca connector"; return; }
  c=$(hub POST "/api/v1/connectors/$ECONN/test" '{}')
  if [ "$c" = 200 ] && grep -qi 'healthy' "$WORK/last.json"; then PASS "connector test -> 200 $(head -c 160 "$WORK/last.json")"; else FAIL "connector test -> $c $(cat "$WORK/last.json")"; return; fi
  ECA="$(ext_ca "EJBCA (live)" "$ECONN" "$WORK/ejbca/kkshort.pem")" && PASS "external CA $ECA" || { FAIL "ejbca external CA"; return; }

  STEP "B3 issue via REST, then revoke through the hub"
  mkcsr ej1.$DOMAIN; mkcsr ej2.$DOMAIN
  c=$(TPL="$TPL_LONG" rest_issue "$ECA" ej1.$DOMAIN)
  case "$c" in 20*) PASS "REST issue -> $c" ;; *) FAIL "REST issue -> $c $(cat "$WORK/last.json")"; podman logs "$HUB_CTR" 2>&1 | grep -i "ejbca\|reject\|external" | tail -4 | cut -c1-500; return ;; esac
  local eiss; eiss="$(issuer_of "$WORK/ej1.$DOMAIN.crt")"
  check_cert "EJBCA REST" "$WORK/ej1.$DOMAIN.crt" "UAT EJBCA Short Root" "$WORK/ejbca/kkshort.pem"
  echo "  SAN: $(openssl x509 -in "$WORK/ej1.$DOMAIN.crt" -noout -ext subjectAltName 2>&1 | tail -1 | tr -d '\n')"
  c=$(TPL="$TPL_LONG" rest_issue "$ECA" ej2.$DOMAIN); case "$c" in 20*) PASS "REST issue #2 -> $c" ;; *) FAIL "REST issue #2 -> $c $(cat "$WORK/last.json")" ;; esac
  local fp s dn
  fp="$(fp_of "$WORK/ej1.$DOMAIN.crt")"; s="$(serial_of "$WORK/ej1.$DOMAIN.crt" | tr 'A-F' 'a-f')"
  dn="$(openssl x509 -in "$WORK/ej1.$DOMAIN.crt" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')"
  c=$(hub POST "/api/v1/certificates/$fp/revoke" '{"reason_code":1}')
  local scope; scope="$(jget 'd["data"].get("revocation_scope")' <"$WORK/last.json" 2>/dev/null)"
  if [ "$c" = 200 ] && [ "$scope" = upstream ]; then PASS "revoke -> 200 revocation_scope=$scope"; else FAIL "revoke -> $c $(cat "$WORK/last.json")"; fi
  $ecurl -s -m 30 -w '\n%{http_code}' --cacert /p/kkrest-CA.pem --cert /p/kkrest.pem --key /p/kkrest-Key.pem \
    "https://$EJBCA_CTR:8443/ejbca/ejbca-rest-api/v1/certificate/$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$dn")/$s/revocationstatus" >"$WORK/ej-status.json"
  c="$(tail -n1 "$WORK/ej-status.json")"
  if [ "$c" = 200 ] && grep -q '"revoked" *: *true' "$WORK/ej-status.json"; then PASS "EJBCA itself reports the certificate revoked: $(head -n1 "$WORK/ej-status.json" | head -c 240)"; else FAIL "EJBCA revocationstatus -> $c $(head -c 300 "$WORK/ej-status.json")"; fi

  STEP "B4 revoke while EJBCA is unreachable -> 502, NOT revoked"
  local fp2; fp2="$(fp_of "$WORK/ej2.$DOMAIN.crt")"
  podman stop -t 2 "$EJBCA_CTR" >/dev/null
  c=$(CURL_MAX=120 hub POST "/api/v1/certificates/$fp2/revoke" '{"reason_code":1}')
  if [ "$c" = 502 ] && grep -q upstream_revoke_failed "$WORK/last.json"; then PASS "revoke with EJBCA down -> 502 $(head -c 160 "$WORK/last.json")"; else FAIL "revoke with EJBCA down -> $c $(cat "$WORK/last.json")"; fi
  hub GET "/api/v1/certificates/$fp2" >/dev/null
  local st; st="$(jget '"revoked_at=%s revocation_scope=%s" % (d["data"].get("revoked_at"), d["data"].get("revocation_scope"))' <"$WORK/last.json" 2>/dev/null)"
  case "$st" in "revoked_at=None revocation_scope=None") PASS "certificate NOT revoked in the hub ($st)" ;; *) FAIL "state after failed revoke: $st" ;; esac
}

# =============================================================================
# Scenario C: AWS Private CA against moto
# =============================================================================
scenario_c() {
  STEP "C1 moto ($MOTO_IMG): does it implement acm-pca issue/get/revoke?"
  local impl; impl="$(podman run --rm --entrypoint python "$MOTO_IMG" -c "
from moto.acmpca import responses as r
print(' '.join(m for m in ('issue_certificate','get_certificate','revoke_certificate') if hasattr(r.ACMPCAResponse, m)))")"
  echo "  moto acm-pca handlers: $impl"
  case "$impl" in *issue_certificate*get_certificate*revoke_certificate*) PASS "moto implements issue, get and revoke handlers" ;; *) SKIP "moto lacks acm-pca handlers ($impl): AWS PCA stays fixture-only"; return ;; esac
  local revoke_src; revoke_src="$(podman run --rm --entrypoint python "$MOTO_IMG" -c "
import inspect
from moto.acmpca import models
print('NOOP' if 'currently a NO-OP' in inspect.getsource(models.ACMPCABackend.revoke_certificate) else 'REAL')")"
  echo "  moto revoke_certificate: $revoke_src"
  mk_svc_cert "$MOTO_CTR"
  podman run -d --name "$MOTO_CTR" --network "$NET" -v "$WORK:/w:ro" "$MOTO_IMG" -H 0.0.0.0 -p 5000 -c "/w/svc-$MOTO_CTR.pem" -k "/w/svc-$MOTO_CTR.key" >/dev/null || { FAIL "moto did not start"; return; }
  cat >"$WORK/pca_setup.py" <<'PY'
import boto3, sys
ep, ca = sys.argv[1], sys.argv[2]
c = boto3.client("acm-pca", endpoint_url=ep, region_name="us-east-1", verify=ca, aws_access_key_id="testing", aws_secret_access_key="testing")
arn = c.create_certificate_authority(
    CertificateAuthorityConfiguration={"KeyAlgorithm": "RSA_2048", "SigningAlgorithm": "SHA256WITHRSA", "Subject": {"CommonName": "UAT moto PCA Root"}},
    CertificateAuthorityType="ROOT")["CertificateAuthorityArn"]
# A new ROOT CA has no certificate: sign its own CSR with the root template and import it, as on AWS.
csr = c.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"]
cert_arn = c.issue_certificate(CertificateAuthorityArn=arn, Csr=csr.encode(), SigningAlgorithm="SHA256WITHRSA",
    TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1", Validity={"Value": 2, "Type": "YEARS"})["CertificateArn"]
root = c.get_certificate(CertificateAuthorityArn=arn, CertificateArn=cert_arn)["Certificate"]
c.import_certificate_authority_certificate(CertificateAuthorityArn=arn, Certificate=root.encode())
open("/w/moto-root.pem", "w").write(root)
print(arn)
PY
  local arn i
  for i in $(seq 1 30); do
    arn="$(podman run --rm --network "$NET" -v "$WORK:/w" "$PY_IMG" sh -c "pip install -q boto3 >/dev/null 2>&1; python /w/pca_setup.py https://$MOTO_CTR:5000 /w/tls-export/svc-ca.pem" 2>"$WORK/pca.err" | tail -1)"
    case "$arn" in arn:aws:acm-pca*) break ;; esac
    sleep 3
  done
  case "$arn" in arn:aws:acm-pca*) PASS "moto PCA root created: $arn" ;; *) FAIL "could not create the moto CA: $(tail -3 "$WORK/pca.err")"; return ;; esac

  STEP "C2 hub: aws_pca connector -> moto, external CA, issue, revoke"
  c=$(hub POST /api/v1/credentials "$(python3 -c 'import json; print(json.dumps({"name":"upca-aws-static","credential_type":"api_token","payload":{"access_key_id":"testing","secret_access_key":"testing"}}))')")
  [ "$c" = 201 ] || { FAIL "aws credential -> $c $(cat "$WORK/last.json")"; return; }
  local cred; cred="$(jget 'd["data"]["id"]' <"$WORK/last.json")"
  local cfg; cfg="$(python3 -c 'import json,sys; print(json.dumps({"certificate_authority_arn":sys.argv[1],"region":"us-east-1","endpoint_url":"https://%s:5000"%sys.argv[2],"auth":"static","signing_algorithm":"SHA256WITHRSA","validity_days":30}))' "$arn" "$MOTO_CTR")"
  local conn; conn="$(mk_connector "aws-pca-moto" aws_pca "$cred" "$cfg")" || { FAIL "aws_pca connector"; return; }
  c=$(hub POST "/api/v1/connectors/$conn/test" '{}'); if [ "$c" = 200 ]; then PASS "connector test -> 200 $(head -c 160 "$WORK/last.json")"; else FAIL "connector test -> $c $(cat "$WORK/last.json")"; fi
  local cca; cca="$(ext_ca "AWS PCA (moto)" "$conn" "$WORK/moto-root.pem")" && PASS "external CA $cca" || { FAIL "aws external CA"; return; }
  mkcsr pca1.$DOMAIN
  c=$(TPL="$TPL_LONG" rest_issue "$cca" pca1.$DOMAIN)
  case "$c" in
    20*) PASS "REST issue -> $c"; check_cert "AWS PCA (moto)" "$WORK/pca1.$DOMAIN.crt" "UAT moto PCA Root" "$WORK/moto-root.pem" ;;
    *) FAIL "REST issue -> $c $(cat "$WORK/last.json")"; return ;;
  esac
  local fp; fp="$(fp_of "$WORK/pca1.$DOMAIN.crt")"
  c=$(hub POST "/api/v1/certificates/$fp/revoke" '{"reason_code":1}')
  local scope; scope="$(jget 'd["data"].get("revocation_scope")' <"$WORK/last.json" 2>/dev/null)"
  if [ "$c" = 200 ] && [ "$scope" = upstream ]; then
    PASS "revoke -> 200 revocation_scope=$scope (moto revoke_certificate is $revoke_src: the hub's call was accepted, upstream state cannot be checked)"
  else FAIL "revoke -> $c $(cat "$WORK/last.json")"; fi
}

want A && scenario_a
want B && scenario_b
want C && scenario_c

echo
[ "$FAILED" = 0 ] && echo "ALL STEPS PASSED" || echo "ONE OR MORE STEPS FAILED"
exit "$FAILED"
