#!/usr/bin/env bash
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -uo pipefail

# filename: tests/live/acme/fg2-run.sh
#
# W26-05: live proof of the FG2 ACME server features against REAL clients
# (certbot, lego), each in podman:
#   - External Account Binding (W26-01): a no-EAB order is refused with
#     externalAccountRequired; certbot (--eab-kid/--eab-hmac-key) and lego
#     (--eab --kid --hmac) each issue, renew and revoke unchanged
#   - provisioners (W26-02): a named directory /acme/<name>/directory with a
#     domain allow-list; a name outside it is rejectedIdentifier
#   - dns-01 (server-side resolver): certbot and lego issue through a
#     dns-01-only provisioner, the hub resolving TXT through pebble-challtestsrv
#   - ARI (W26-03): the renewalInfo window, byte-identical 404s, and a lego
#     renewal driven by ARI once the certificate is revoked
#   - OCSP answers `revoked` on the FIRST request after an ACME revoke
#
# Copy of the run.sh topology (hub + clients on one podman network, hub's own
# self-issued TLS exported to tls-export/ca.pem and trusted explicitly). run.sh
# is NOT edited or sourced (its 28/28 stays its own). This script differs in:
#   - a fixed-subnet network so every container has a known IP; the hub gets
#     pebble-challtestsrv as its ONLY resolver (--dns), so the hub resolves the
#     client names and the dns-01 TXT records from challtestsrv, whose A records
#     are registered here for the client IPs. The clients keep podman DNS.
#   - APP_ACME_EAB_REQUIRED=true.
#
# Podman only. Idempotent; tears everything down on exit. PASS/FAIL per step,
# non-zero exit on any FAIL. Nothing is written into the repo. See README.md
# ("FG2") for the env and what each step proves.
#
#   bash tests/live/acme/fg2-run.sh
#   KK_UAT_RUN_DIR=$HOME/kk-uat-acme-fg2-run CHALLTEST_IMAGE=ghcr.io/letsencrypt/pebble-challtestsrv:latest \
#     bash tests/live/acme/fg2-run.sh

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$HERE/../../.." && pwd)"
RUN_DIR="${KK_UAT_RUN_DIR:-$HOME/kk-uat-acme-fg2-run}"   # under $HOME: podman machine on macOS only virtiofs-mounts /Users
NETWORK="kk-uat-acme-fg2"
SUBNET_PREFIX="${FG2_SUBNET_PREFIX:-10.91.26}"           # a /24; change if it collides with another network on the VM
HUB_NAME="kk-fg2-hub";        HUB_IP="$SUBNET_PREFIX.10"
CHALL_NAME="kk-fg2-challtest"; CHALL_IP="$SUBNET_PREFIX.53"
CERTBOT_NAME="kk-fg2-certbot"; CERTBOT_IP="$SUBNET_PREFIX.21"
LEGO_IP="$SUBNET_PREFIX.22"
HUB_PORT="8080"
HUB_URL="https://$HUB_NAME:$HUB_PORT"
BOOTSTRAP_TOKEN="uat-token"
CA_NAME="UAT Root CA"
CHALLTEST_IMAGE="${CHALLTEST_IMAGE:-ghcr.io/letsencrypt/pebble-challtestsrv:latest}"
CERTBOT_IMAGE="${CERTBOT_IMAGE:-docker.io/certbot/certbot:latest}"
LEGO_IMAGE="${LEGO_IMAGE:-docker.io/goacme/lego:latest}"
CHALLTEST_API="http://$CHALL_IP:8055"
PROV_TLS="internal-tls"       # http-01 + dns-01, allow *.internal
PROV_DNS="internal-dns"       # dns-01 only, allow *.internal
DIR_TLS="$HUB_URL/acme/$PROV_TLS/directory"
DIR_DNS="$HUB_URL/acme/$PROV_DNS/directory"
DIR_DEFAULT="$HUB_URL/acme/directory"
CB_CERT=web-certbot.internal   # certbot http-01 loop
LG_CERT=web-lego.internal      # lego http-01 loop
CB_DNS=dns-web.internal        # certbot dns-01
LG_DNS=dns-lego.internal       # lego dns-01
LG_ARI=ari-lego.internal       # lego ARI renewal

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP: $1"; }
finish() { echo "=== RESULT: $PASS passed, $FAIL failed ==="; [[ "$FAIL" -eq 0 ]]; }

curl_hub() {
  # curl inside a helper container ON THE NETWORK (container-DNS names do not
  # resolve from the macOS host); --cacert is the hub's own exported CA, never -k.
  podman run --rm --network "$NETWORK" -v "$RUN_DIR/tls-export:/caexport:ro" \
    docker.io/curlimages/curl:8.10.1 --cacert /caexport/ca.pem "$@"
}
admin() { curl_hub -s -H "Authorization: Bearer $BOOTSTRAP_TOKEN" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

cleanup() {
  kk_rm "$CERTBOT_NAME" kk-fg2-lego kk-fg2-verify "$HUB_NAME" "$CHALL_NAME"
  podman network rm "$NETWORK" >/dev/null 2>&1 || true
}

echo "=== W26-05 ACME FG2 UAT: setup ==="
cleanup
trap cleanup EXIT INT TERM
rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR/bin" "$RUN_DIR/data" "$RUN_DIR/certbot" "$RUN_DIR/lego" "$RUN_DIR/lego-dns" "$RUN_DIR/verify" "$RUN_DIR/tls-export"

echo "--- pre-pulling images ---"
for img in "$CERTBOT_IMAGE" "$LEGO_IMAGE" "$CHALLTEST_IMAGE" docker.io/curlimages/curl:8.10.1 docker.io/library/alpine:3; do
  podman pull -q "$img" >/dev/null 2>&1 || true
done

echo "--- building hub binary (linux/arm64, CGO_ENABLED=0) ---"
if ! (cd "$ROOT_DIR" && GOOS=linux GOARCH="$(kk_goarch)" CGO_ENABLED=0 go build -o "$RUN_DIR/bin/kryptkeeper" ./cmd/kryptkeeper); then
  fail "build hub binary"; finish; exit 1
fi
pass "build hub binary"

podman network create --subnet "$SUBNET_PREFIX.0/24" --gateway "$SUBNET_PREFIX.1" "$NETWORK" >/dev/null \
  && pass "create podman network $NETWORK ($SUBNET_PREFIX.0/24)" || { fail "create podman network $NETWORK"; finish; exit 1; }

echo "--- starting pebble-challtestsrv (dns-01 resolver + TXT management API) ---"
# Flags checked against `pebble-challtestsrv -h` (the DNS bind flag is -dnsserver,
# not -dns01); -doh "" is tried first (newer
# builds bind DoH by default and would need a cert) and dropped if unknown.
start_challtest() {
  kk_rm "$CHALL_NAME"
  podman run -d --name "$CHALL_NAME" --network "$NETWORK" --ip "$CHALL_IP" "$CHALLTEST_IMAGE" \
    -dnsserver ":53" -management ":8055" -http01 "" -https01 "" -tlsalpn01 "" "$@" >/dev/null 2>&1 || return 1
  sleep 2
  [[ "$(podman inspect -f '{{.State.Running}}' "$CHALL_NAME" 2>/dev/null)" == true ]]
}
if start_challtest -doh "" || start_challtest; then
  pass "challtestsrv running at $CHALL_IP (image $CHALLTEST_IMAGE: $(podman inspect -f '{{.Id}}' "$CHALLTEST_IMAGE" 2>/dev/null | cut -c1-12))"
else
  fail "challtestsrv did not start"; podman logs "$CHALL_NAME" 2>&1 | tail -10; finish; exit 1
fi

echo "--- verify helper (alpine + openssl 3 on the network) ---"
podman run -d --name kk-fg2-verify --network "$NETWORK" -v "$RUN_DIR/verify:/verify" \
  docker.io/library/alpine:3 sh -c "apk add --no-cache openssl >/dev/null 2>&1 && sleep 7200" >/dev/null
for _ in $(seq 1 30); do podman exec kk-fg2-verify openssl version >/dev/null 2>&1 && break; sleep 1; done
podman exec kk-fg2-verify openssl version >/dev/null 2>&1 && pass "verify helper ready (openssl installed)" || fail "verify helper ready"

echo "--- starting hub: EAB required, resolver = challtestsrv ---"
podman run -d --name "$HUB_NAME" --network "$NETWORK" --ip "$HUB_IP" --hostname "$HUB_NAME" --dns "$CHALL_IP" \
  -v "$RUN_DIR/bin/kryptkeeper:/kryptkeeper:ro" -v "$RUN_DIR/data:/data" -v "$RUN_DIR/tls-export:/tls-export" \
  -e APP_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" -e AUTH_MODE=bootstrap \
  -e APP_CERTIFICATE_PROVIDER=ca -e APP_DISCOVERY_PROVIDER=db -e APP_NOTIFICATION_PROVIDER=file \
  -e APP_ACME_EAB_REQUIRED=true \
  -e KRYPTKEEPER_TLS_SELF_ISSUE=true -e KRYPTKEEPER_TLS_SANS="$HUB_NAME" -e KRYPTKEEPER_TLS_TRUST_EXPORT_DIR=/tls-export \
  -e APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
  -e KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
  -e KRYPTKEEPER_DATA_DIR=/data \
  -e APP_CA_FILE=/data/cas.json -e APP_TEMPLATE_FILE=/data/templates.json \
  -e APP_CERTIFICATE_FILE=/data/certificates.json -e APP_AUDIT_FILE=/data/audit.json \
  -e APP_CERTS_SUMMARY_FILE=/data/certs_summary.json \
  -e KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true -e KRYPTKEEPER_CA_NAME="$CA_NAME" \
  -e APP_BIND_ADDR=0.0.0.0 -e PORT="$HUB_PORT" -e KRYPTKEEPER_BASE_URL="$HUB_URL" \
  docker.io/library/alpine:3 /kryptkeeper >/dev/null
for _ in $(seq 1 30); do [[ -s "$RUN_DIR/tls-export/ca.pem" ]] && break; sleep 1; done
if [[ -s "$RUN_DIR/tls-export/ca.pem" ]] && podman logs "$HUB_NAME" 2>&1 | grep -q "starting kryptkeeper"; then
  pass "hub started and exported its listener CA"
else
  fail "hub startup (see: podman logs $HUB_NAME)"; podman logs "$HUB_NAME" 2>&1 | tail -30; finish; exit 1
fi
curl_hub -sf "$DIR_DEFAULT" | grep -q "$HUB_NAME" && pass "default ACME directory reachable over the hub's TLS" || fail "default ACME directory reachable"

CA_ID=$(admin "$HUB_URL/api/v1/cas" | jget 'd["data"][0]["id"]' 2>/dev/null || true)
[[ -n "$CA_ID" ]] && pass "resolved root CA id ($CA_ID)" || { fail "resolved root CA id"; finish; exit 1; }
admin "$HUB_URL/api/v1/cas/$CA_ID/chain?format=pem" > "$RUN_DIR/verify/ca-chain.pem"
openssl x509 -in "$RUN_DIR/verify/ca-chain.pem" -noout -subject >/dev/null 2>&1 && pass "CA chain PEM parses" || fail "CA chain PEM parses"

# challtestsrv answers A queries from these mocks: it is the hub's only resolver,
# and the hub's http-01 validator must find the client containers by name.
add_a() { curl_hub -s -X POST -d "{\"host\":\"$1.\",\"addresses\":[\"$2\"]}" "$CHALLTEST_API/add-a" >/dev/null; }
add_a "$CB_CERT" "$CERTBOT_IP"; add_a "$CB_DNS" "$CERTBOT_IP"
add_a "$LG_CERT" "$LEGO_IP"; add_a "$LG_DNS" "$LEGO_IP"; add_a "$LG_ARI" "$LEGO_IP"
add_a example.com "$CERTBOT_IP"

# ---------------------------------------------------------------------------
# helpers copied from run.sh (not sourced: run.sh executes on load)
# ---------------------------------------------------------------------------
verify_chain() {
  if openssl verify -CAfile "$RUN_DIR/verify/ca-chain.pem" "$1" >/dev/null 2>&1; then pass "$2: certificate chains to \"$CA_NAME\""
  else fail "$2: certificate chains to \"$CA_NAME\""; openssl verify -CAfile "$RUN_DIR/verify/ca-chain.pem" "$1" || true; fi
}
fp_of() { openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }
inventory_has_source_acme() { # label certfile
  local fp body; fp=$(fp_of "$2")
  body=$(admin "$HUB_URL/api/v1/certificates?limit=100")
  if echo "$body" | python3 -c "
import json,sys
d=json.load(sys.stdin); certs=d.get('data', d.get('certificates', []))
sys.exit(0 if any(c.get('source')=='acme' and str(c.get('fingerprint_sha256','')).lower()=='$fp' for c in certs) else 1)" 2>/dev/null; then
    pass "$1: hub inventory lists this exact certificate with source acme (fp=$fp)"
  else fail "$1: hub inventory lists this exact certificate with source acme (fp=$fp)"; fi
}
crl_lists_serial() { # label serial_hex
  curl_hub -s "$HUB_URL/crl/$CA_ID.crl" > "$RUN_DIR/verify/$1.crl.der"
  if openssl crl -inform DER -in "$RUN_DIR/verify/$1.crl.der" -noout -text 2>/dev/null | grep -qi "$2"; then pass "$1: CRL lists the revoked serial"
  else fail "$1: CRL lists the revoked serial"; fi
}
ocsp_check() { # label certfile want  -- ONE request, no retry loop (step 8: first request after revoke)
  local resp
  resp=$(podman exec kk-fg2-verify openssl ocsp -issuer /verify/ca-chain.pem -CAfile /verify/ca-chain.pem \
    -cert "/verify/$(basename "$2")" -url "$HUB_URL/ocsp" -no_nonce 2>&1) || true
  if echo "$resp" | grep -qi ": $3" && echo "$resp" | grep -qi "Response verify OK"; then pass "$1: OCSP reports $3 on the first request (signature verified)"
  else fail "$1: OCSP reports $3 on the first request (signature verified)"; echo "$resp"; fi
}
serial_of() { openssl x509 -in "$1" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f'; }

# ---------------------------------------------------------------------------
# 1. EAB keys and provisioners
# ---------------------------------------------------------------------------
echo "=== 1. EAB keys and provisioners ==="
mint_eab() { # label -> "kid hmac"; the secret appears only in this 201
  local out kid hmac
  out=$(admin -X POST -d "{\"label\":\"$1\"}" "$HUB_URL/api/v1/acme/eab-keys")
  kid=$(echo "$out" | jget 'd["data"]["kid"]' 2>/dev/null); hmac=$(echo "$out" | jget 'd["data"]["hmac_key"]' 2>/dev/null)
  echo "$kid $hmac"
}
read -r CB_KID CB_HMAC < <(mint_eab certbot-uat)
read -r CBD_KID CBD_HMAC < <(mint_eab certbot-dns-uat)
read -r LG_KID LG_HMAC < <(mint_eab lego-uat)
read -r LGD_KID LGD_HMAC < <(mint_eab lego-dns-uat)
if [[ -n "$CB_KID" && -n "$CB_HMAC" && -n "$CBD_KID" && -n "$LG_KID" && -n "$LGD_KID" && -n "$LGD_HMAC" ]]; then
  pass "minted four EAB keys; each 201 carried kid and hmac_key"
else
  fail "EAB key minting (kid/hmac_key missing)"; finish; exit 1
fi
if admin "$HUB_URL/api/v1/acme/eab-keys" | grep -q "$CB_HMAC"; then fail "GET /acme/eab-keys leaked an hmac_key"
else pass "GET /acme/eab-keys lists the keys without any hmac_key"; fi
admin "$HUB_URL/api/v1/acme/eab-keys" | grep -q "$CB_KID" && pass "the minted kid is listed" || fail "the minted kid is not listed"

mkprov() { # name challenges-json
  admin -X POST -o /dev/null -w '%{http_code}' \
    -d "{\"name\":\"$1\",\"ca_id\":\"$CA_ID\",\"allow_names\":[\"*.internal\"],\"challenges\":$2}" "$HUB_URL/api/v1/acme/provisioners"
}
c=$(mkprov "$PROV_TLS" '["http-01","dns-01"]'); [[ "$c" == 201 ]] && pass "provisioner $PROV_TLS created (http-01 + dns-01, allow *.internal)" || fail "provisioner $PROV_TLS -> $c"
c=$(mkprov "$PROV_DNS" '["dns-01"]');          [[ "$c" == 201 ]] && pass "provisioner $PROV_DNS created (dns-01 only, allow *.internal)" || fail "provisioner $PROV_DNS -> $c"
curl_hub -sf "$DIR_TLS" | grep -q "newAccount" && pass "provisioner directory $DIR_TLS answers" || fail "provisioner directory $DIR_TLS answers"

# ---------------------------------------------------------------------------
# 2. no-EAB refusal
# ---------------------------------------------------------------------------
echo "=== 2. no-EAB account refused ==="
podman run -d --name "$CERTBOT_NAME" --network "$NETWORK" --ip "$CERTBOT_IP" --hostname kk-fg2-certbot \
  -v "$RUN_DIR/certbot:/etc/letsencrypt" -v "$RUN_DIR/tls-export/ca.pem:/etc/kk-ca/ca.pem:ro" \
  -v "$HERE/fg2-hooks:/hooks:ro" -e REQUESTS_CA_BUNDLE=/etc/kk-ca/ca.pem \
  --entrypoint sh "$CERTBOT_IMAGE" -c "sleep 7200" >/dev/null
sleep 2
certbot_exec() { podman exec "$CERTBOT_NAME" certbot "$@"; }
CB_VERSION=$(podman exec "$CERTBOT_NAME" certbot --version 2>&1 | head -1)
echo "certbot: $CB_VERSION"

# certbot prints only the problem's detail text; the RFC 8555 problem type (the
# urn) is in its debug log, so assert on the real type there, falling back to
# nothing weaker.
noeab_problem() { # <logs-dir in the certbot container> <stdout-log>
  podman exec "$CERTBOT_NAME" grep -q "urn:ietf:params:acme:error:externalAccountRequired" "$1/letsencrypt.log" 2>/dev/null \
    || grep -q "urn:ietf:params:acme:error:externalAccountRequired" "$2"
}
certbot_exec register --server "$DIR_DEFAULT" --config-dir /tmp/noeab/c --work-dir /tmp/noeab/w --logs-dir /tmp/noeab/l \
  --agree-tos -m uat@example.test --no-eff-email --non-interactive > "$RUN_DIR/certbot/noeab.log" 2>&1
noeab_problem /tmp/noeab/l "$RUN_DIR/certbot/noeab.log" \
  && pass "certbot register without EAB on the default directory: externalAccountRequired" \
  || { fail "certbot register without EAB: externalAccountRequired not seen"; tail -8 "$RUN_DIR/certbot/noeab.log"; }
certbot_exec register --server "$DIR_TLS" --config-dir /tmp/noeab2/c --work-dir /tmp/noeab2/w --logs-dir /tmp/noeab2/l \
  --agree-tos -m uat@example.test --no-eff-email --non-interactive > "$RUN_DIR/certbot/noeab2.log" 2>&1
noeab_problem /tmp/noeab2/l "$RUN_DIR/certbot/noeab2.log" \
  && pass "certbot register without EAB on the provisioner directory: externalAccountRequired" \
  || { fail "provisioner directory accepted or mis-answered a no-EAB account"; tail -8 "$RUN_DIR/certbot/noeab2.log"; }
AUD=$(admin "$HUB_URL/api/v1/audit?limit=200" | python3 -c '
import json,sys
d=json.load(sys.stdin)["data"]; rows=d if isinstance(d,list) else d.get("entries",d.get("items",[]))
print(sum(1 for r in rows if r["action"]=="acme.eab.reject"))' 2>/dev/null)
[[ "${AUD:-0}" -ge 1 ]] && pass "audit holds acme.eab.reject ($AUD rows)" || fail "no acme.eab.reject audit row"

# ---------------------------------------------------------------------------
# 3. certbot with EAB: issue, renew, revoke on the provisioner directory
# ---------------------------------------------------------------------------
echo "=== 3. certbot with EAB on $PROV_TLS ==="
certbot_exec certonly --standalone --server "$DIR_TLS" --eab-kid "$CB_KID" --eab-hmac-key "$CB_HMAC" \
  --agree-tos -m uat@example.test --no-eff-email --non-interactive -d "$CB_CERT" > "$RUN_DIR/certbot/issue.log" 2>&1
if grep -q "Successfully received certificate" "$RUN_DIR/certbot/issue.log"; then pass "certbot (EAB): obtain certificate for $CB_CERT"
else fail "certbot (EAB): obtain certificate"; tail -30 "$RUN_DIR/certbot/issue.log"; fi
CB_LIVE="$RUN_DIR/certbot/live/$CB_CERT/cert.pem"
if [[ -f "$CB_LIVE" ]]; then
  cp "$CB_LIVE" "$RUN_DIR/verify/certbot-cert.pem"
  verify_chain "$RUN_DIR/verify/certbot-cert.pem" "certbot"
  inventory_has_source_acme "certbot" "$RUN_DIR/verify/certbot-cert.pem"
else fail "certbot: certificate file present"; fi

certbot_exec renew --force-renewal --server "$DIR_TLS" --non-interactive > "$RUN_DIR/certbot/renew.log" 2>&1
if grep -qi "congratulations\|renewed\|success" "$RUN_DIR/certbot/renew.log"; then pass "certbot (EAB): renew"
else fail "certbot (EAB): renew"; tail -30 "$RUN_DIR/certbot/renew.log"; fi
if [[ -f "$CB_LIVE" ]]; then
  cp "$CB_LIVE" "$RUN_DIR/verify/certbot-cert.pem"   # revoke/OCSP/CRL target the RENEWED cert
  verify_chain "$RUN_DIR/verify/certbot-cert.pem" "certbot (post-renewal)"
  ocsp_check "certbot (pre-revocation)" "$RUN_DIR/verify/certbot-cert.pem" good
fi

certbot_exec revoke --cert-path "/etc/letsencrypt/live/$CB_CERT/fullchain.pem" --server "$DIR_TLS" \
  --non-interactive --delete-after-revoke > "$RUN_DIR/certbot/revoke.log" 2>&1
if grep -qi "revoked" "$RUN_DIR/certbot/revoke.log"; then
  pass "certbot (EAB): revoke"
  ocsp_check "certbot (post-revocation)" "$RUN_DIR/verify/certbot-cert.pem" revoked   # first request, no retry
  crl_lists_serial "certbot" "$(serial_of "$RUN_DIR/verify/certbot-cert.pem")"
else fail "certbot (EAB): revoke"; tail -30 "$RUN_DIR/certbot/revoke.log"; fi

# ---------------------------------------------------------------------------
# 4. lego with EAB: issue, renew, revoke
# ---------------------------------------------------------------------------
echo "=== 4. lego with EAB on $PROV_TLS ==="
LEGO_CA=(-e LEGO_CA_CERTIFICATES=/etc/kk-ca/ca.pem -v "$RUN_DIR/tls-export/ca.pem:/etc/kk-ca/ca.pem:ro")
lego_run() { # lego_run <data-dir-name> <args...>  (one-off container with the fixed lego IP)
  local d="$1"; shift
  kk_rm kk-fg2-lego
  podman run --name kk-fg2-lego --network "$NETWORK" --ip "$LEGO_IP" --hostname kk-fg2-lego \
    -v "$RUN_DIR/$d:/data" -v "$HERE/fg2-hooks:/hooks:ro" "${LEGO_CA[@]}" ${LEGO_ENV_EXTRA[@]+"${LEGO_ENV_EXTRA[@]}"} "$LEGO_IMAGE" "$@"
  local rc=$?
  kk_rm kk-fg2-lego
  return $rc
}
LEGO_ENV_EXTRA=()
LEGO_VERSION=$(podman run --rm "$LEGO_IMAGE" --version 2>&1 | head -1)
echo "lego: $LEGO_VERSION"
LEGO_BASE=(--accept-tos --email uat@example.test --path /data)

lego_run lego run "${LEGO_BASE[@]}" --server "$DIR_TLS" --eab --eab.kid "$LG_KID" --eab.hmac "$LG_HMAC" \
  --domains "$LG_CERT" --http --http.address :80 > "$RUN_DIR/lego/issue.log" 2>&1
LG_FILE="$RUN_DIR/lego/certificates/$LG_CERT.crt"
if [[ -s "$LG_FILE" ]]; then
  pass "lego (EAB): obtain certificate for $LG_CERT"
  cp "$LG_FILE" "$RUN_DIR/verify/lego-cert.pem"
  verify_chain "$RUN_DIR/verify/lego-cert.pem" "lego"
  inventory_has_source_acme "lego" "$RUN_DIR/verify/lego-cert.pem"
else fail "lego (EAB): obtain certificate"; tail -30 "$RUN_DIR/lego/issue.log"; fi

LG_PRE=$(fp_of "$RUN_DIR/verify/lego-cert.pem" 2>/dev/null || true)
lego_run lego run "${LEGO_BASE[@]}" --server "$DIR_TLS" --domains "$LG_CERT" --http --http.address :80 \
  --renew-force --ari-disable --no-random-sleep > "$RUN_DIR/lego/renew.log" 2>&1
LG_POST=$(fp_of "$LG_FILE" 2>/dev/null || true)
if [[ -n "$LG_POST" && "$LG_POST" != "$LG_PRE" ]]; then
  pass "lego (EAB account reused): renew (new fingerprint)"
  cp "$LG_FILE" "$RUN_DIR/verify/lego-cert.pem"
  verify_chain "$RUN_DIR/verify/lego-cert.pem" "lego (post-renewal)"
  ocsp_check "lego (pre-revocation)" "$RUN_DIR/verify/lego-cert.pem" good
else fail "lego: renew (new fingerprint)"; tail -30 "$RUN_DIR/lego/renew.log"; fi

lego_run lego certificates revoke --email uat@example.test --server "$DIR_TLS" --path /data --cert.name "$LG_CERT" \
  > "$RUN_DIR/lego/revoke.log" 2>&1
if grep -qi "revoked" "$RUN_DIR/lego/revoke.log"; then
  pass "lego (EAB): revoke"
  ocsp_check "lego (post-revocation)" "$RUN_DIR/verify/lego-cert.pem" revoked   # first request, no retry
  crl_lists_serial "lego" "$(serial_of "$RUN_DIR/verify/lego-cert.pem")"
else fail "lego (EAB): revoke"; tail -30 "$RUN_DIR/lego/revoke.log"; fi

# ---------------------------------------------------------------------------
# 5. provisioner allow-list
# ---------------------------------------------------------------------------
echo "=== 5. allow-list ==="
certbot_exec certonly --standalone --server "$DIR_TLS" --agree-tos -m uat@example.test --no-eff-email \
  --non-interactive -d example.com > "$RUN_DIR/certbot/outside.log" 2>&1
if grep -qiE "rejectedIdentifier|not permitted" "$RUN_DIR/certbot/outside.log"; then
  pass "certbot: example.com (outside *.internal) is rejectedIdentifier / not permitted"
else fail "certbot: example.com was not refused by the allow-list"; tail -12 "$RUN_DIR/certbot/outside.log"; fi
[[ -f "$RUN_DIR/certbot/live/example.com/cert.pem" ]] && fail "a certificate exists for example.com" || pass "no certificate was issued for example.com"
echo "(a name under *.internal still issues: steps 3, 4 and 6 are those proofs)"

# ---------------------------------------------------------------------------
# 6. dns-01 through the dns-01-only provisioner
# ---------------------------------------------------------------------------
echo "=== 6. dns-01 on $PROV_DNS (hub resolver = challtestsrv) ==="
MANUAL_OK=()
CB_MANUAL_HELP=$(certbot_exec --help manual 2>&1)   # captured first: grep -q on a pipe can SIGPIPE under pipefail
grep -q -- "--manual-public-ip-logging-ok" <<<"$CB_MANUAL_HELP" && MANUAL_OK=(--manual-public-ip-logging-ok)
podman exec -e CHALLTEST_API="$CHALLTEST_API" "$CERTBOT_NAME" certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook /hooks/certbot-dns-auth.sh ${MANUAL_OK[@]+"${MANUAL_OK[@]}"} \
  --server "$DIR_DNS" --eab-kid "$CBD_KID" --eab-hmac-key "$CBD_HMAC" \
  --agree-tos -m uat@example.test --no-eff-email --non-interactive -d "$CB_DNS" > "$RUN_DIR/certbot/dns.log" 2>&1
CBD_FILE="$RUN_DIR/certbot/live/$CB_DNS/cert.pem"
if grep -q "Successfully received certificate" "$RUN_DIR/certbot/dns.log" && [[ -f "$CBD_FILE" ]]; then
  pass "certbot dns-01: certificate for $CB_DNS (the provisioner offers dns-01 only)"
  cp "$CBD_FILE" "$RUN_DIR/verify/certbot-dns.pem"; verify_chain "$RUN_DIR/verify/certbot-dns.pem" "certbot dns-01"
  inventory_has_source_acme "certbot dns-01" "$RUN_DIR/verify/certbot-dns.pem"
else fail "certbot dns-01: certificate for $CB_DNS"; tail -30 "$RUN_DIR/certbot/dns.log"; fi

# lego's DNS propagation check queries authoritative servers; against a stub
# resolver it must be skipped or pointed at challtestsrv. Flag names differ
# between lego releases, so pick from the image's own --help.
LEGO_HELP=$(podman run --rm "$LEGO_IMAGE" run --help 2>&1)
LEGO_DNS_FLAGS=(--dns.resolvers "$CHALL_IP:53")
if grep -q -- "--dns.propagation-wait" <<<"$LEGO_HELP"; then LEGO_DNS_FLAGS+=(--dns.propagation-wait 5s)
elif grep -q -- "--dns.propagation.wait" <<<"$LEGO_HELP"; then LEGO_DNS_FLAGS+=(--dns.propagation.wait 5s)
elif grep -q -- "--dns.propagation-disable-ans" <<<"$LEGO_HELP"; then LEGO_DNS_FLAGS+=(--dns.propagation-disable-ans)
elif grep -q -- "--dns.disable-cp" <<<"$LEGO_HELP"; then LEGO_DNS_FLAGS+=(--dns.disable-cp)
else echo "NOTE: no known propagation-skip flag in 'lego run --help'; relying on --dns.resolvers only"; fi
echo "lego dns flags: ${LEGO_DNS_FLAGS[*]}"
LEGO_ENV_EXTRA=(-e EXEC_PATH=/hooks/lego-dns.sh -e CHALLTEST_API="$CHALLTEST_API" -e EXEC_PROPAGATION_TIMEOUT=60 -e EXEC_POLLING_INTERVAL=2)
lego_run lego-dns run "${LEGO_BASE[@]}" --server "$DIR_DNS" --eab --eab.kid "$LGD_KID" --eab.hmac "$LGD_HMAC" \
  --domains "$LG_DNS" --dns exec "${LEGO_DNS_FLAGS[@]}" --no-random-sleep > "$RUN_DIR/lego-dns/issue.log" 2>&1
LEGO_ENV_EXTRA=()
LGD_FILE="$RUN_DIR/lego-dns/certificates/$LG_DNS.crt"
if [[ -s "$LGD_FILE" ]]; then
  pass "lego dns-01 (--dns exec): certificate for $LG_DNS (the provisioner offers dns-01 only)"
  cp "$LGD_FILE" "$RUN_DIR/verify/lego-dns.pem"; verify_chain "$RUN_DIR/verify/lego-dns.pem" "lego dns-01"
  inventory_has_source_acme "lego dns-01" "$RUN_DIR/verify/lego-dns.pem"
else fail "lego dns-01: certificate for $LG_DNS"; tail -30 "$RUN_DIR/lego-dns/issue.log"; fi

# ---------------------------------------------------------------------------
# 7. ARI
# ---------------------------------------------------------------------------
echo "=== 7. ARI (RFC 9773) ==="
lego_run lego run "${LEGO_BASE[@]}" --server "$DIR_TLS" --domains "$LG_ARI" --http --http.address :80 > "$RUN_DIR/lego/ari-issue.log" 2>&1
ARI_FILE="$RUN_DIR/lego/certificates/$LG_ARI.crt"
if [[ ! -s "$ARI_FILE" ]]; then
  fail "lego: obtain $LG_ARI for the ARI steps"; tail -20 "$RUN_DIR/lego/ari-issue.log"
else
  cp "$ARI_FILE" "$RUN_DIR/verify/ari-cert.pem"
  pass "lego: obtained $LG_ARI for the ARI steps"
  RENEWAL_BASE=$(curl_hub -s "$DIR_TLS" | jget 'd["renewalInfo"]' 2>/dev/null)
  [[ -n "$RENEWAL_BASE" ]] && pass "the provisioner directory advertises renewalInfo ($RENEWAL_BASE)" || fail "the provisioner directory has no renewalInfo"

  # certID = base64url(AKI keyIdentifier) "." base64url(serial)
  ari_id() { # certfile [serial-override-hex] -> certID
    local akiout serial
    akiout=$(podman exec kk-fg2-verify openssl x509 -in "/verify/$(basename "$1")" -noout -ext authorityKeyIdentifier 2>&1)
    serial=${2:-$(podman exec kk-fg2-verify openssl x509 -in "/verify/$(basename "$1")" -noout -serial | cut -d= -f2)}
    python3 - "$akiout" "$serial" <<'PY'
import base64, re, sys
aki = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+)', sys.argv[1])
if not aki:
    sys.exit("no keyIdentifier in: " + sys.argv[1])
b = lambda h: base64.urlsafe_b64encode(bytes.fromhex(h)).rstrip(b"=").decode()
s = sys.argv[2]
s = ("0" + s) if len(s) % 2 else s
print(b(aki.group(1).replace(":", "")) + "." + b(s))
PY
  }
  ARI_ID=$(ari_id "$RUN_DIR/verify/ari-cert.pem")
  echo "certID: $ARI_ID"
  ari_get() { # certID -> body\nstatus in $ARI_OUT
    ARI_OUT=$(curl_hub -s -w '\n%{http_code}' "$RENEWAL_BASE/$1")
  }
  window_end_vs_now() { # prints "future" or "past" for suggestedWindow.end
    echo "$1" | python3 -c '
import json,sys,datetime
d=json.loads(sys.stdin.read())
end=datetime.datetime.fromisoformat(d["suggestedWindow"]["end"].replace("Z","+00:00"))
print("future" if end > datetime.datetime.now(datetime.timezone.utc) else "past")'
  }
  ari_get "$ARI_ID"
  if [[ "${ARI_OUT##*$'\n'}" == 200 && "$(window_end_vs_now "${ARI_OUT%$'\n'*}")" == future ]]; then
    pass "ARI for a live certificate: 200 and the window end is in the future (not renew-now)"
  else fail "ARI for a live certificate: ${ARI_OUT}"; fi

  # An unresolvable certID must be indistinguishable: malformed vs unknown serial.
  ari_get "${ARI_ID:1}"; BAD1="$ARI_OUT"
  ari_get "$(ari_id "$RUN_DIR/verify/ari-cert.pem" 0fffffffffffffffffffffffffffffffffffffff)"; BAD2="$ARI_OUT"
  if [[ "${BAD1##*$'\n'}" == 404 && "${BAD2##*$'\n'}" == 404 && "$BAD1" == "$BAD2" ]]; then
    pass "a mangled certID and an unknown serial return byte-identical 404"
  else fail "mangled vs unknown certID differ: [$BAD1] vs [$BAD2]"; fi

  # Negative control: while ARI says "not yet", an ARI-aware lego must not renew.
  if podman run --rm "$LEGO_IMAGE" renew --help >/dev/null 2>&1; then LEGO_RENEW_SUB=renew; else LEGO_RENEW_SUB=run; fi  # lego v5: no "renew"; "run" = get-or-renew, ARI-aware
  echo "lego renewal subcommand: $LEGO_RENEW_SUB"
  ARI_PRE=$(fp_of "$ARI_FILE")
  lego_run lego "$LEGO_RENEW_SUB" "${LEGO_BASE[@]}" --server "$DIR_TLS" --domains "$LG_ARI" --http --http.address :80 --no-random-sleep > "$RUN_DIR/lego/ari-control.log" 2>&1
  [[ "$(fp_of "$ARI_FILE")" == "$ARI_PRE" ]] && pass "control: lego does not renew while the ARI window is in the future" \
    || fail "control: lego renewed although ARI says not yet"

  # Revoke through the admin API (not ACME) to prove the revocation-store path.
  ARI_FP=$(fp_of "$ARI_FILE")
  c=$(admin -X POST -o /dev/null -w '%{http_code}' -d '{"reason_code":1,"reason_text":"fg2 ari revoke"}' "$HUB_URL/api/v1/certificates/$ARI_FP/revoke")
  [[ "$c" == 200 ]] && pass "admin API revoked the ARI certificate ($c)" || fail "admin revoke -> $c"
  ari_get "$ARI_ID"
  if [[ "${ARI_OUT##*$'\n'}" == 200 && "$(window_end_vs_now "${ARI_OUT%$'\n'*}")" == past ]]; then
    pass "ARI immediately after the revoke: window end is now/past (renew now)"
  else fail "ARI after revoke: ${ARI_OUT}"; fi
  ocsp_check "ari cert (admin revoke)" "$RUN_DIR/verify/ari-cert.pem" revoked

  lego_run lego "$LEGO_RENEW_SUB" "${LEGO_BASE[@]}" --server "$DIR_TLS" --domains "$LG_ARI" --http --http.address :80 --no-random-sleep > "$RUN_DIR/lego/ari-renew.log" 2>&1
  ARI_POST=$(fp_of "$ARI_FILE" 2>/dev/null || true)
  if [[ -n "$ARI_POST" && "$ARI_POST" != "$ARI_PRE" ]]; then
    pass "lego renewed the revoked certificate because ARI said renew now (no --renew-force, no --days)"
    cp "$ARI_FILE" "$RUN_DIR/verify/ari-cert2.pem"; verify_chain "$RUN_DIR/verify/ari-cert2.pem" "lego (ARI renewal)"
  else fail "lego did not renew after the ARI window closed"; tail -20 "$RUN_DIR/lego/ari-renew.log"; fi
  echo "NOTE: the hub issues long-lived ACME certificates, so 'inside the window' is proven through the revocation-driven renew-now window, not a natural one."
fi

echo "--- versions ---"
echo "certbot: ${CB_VERSION:-?}  lego: ${LEGO_VERSION:-?}  challtestsrv: $CHALLTEST_IMAGE ($(podman inspect -f '{{index .RepoDigests 0}}' "$CHALLTEST_IMAGE" 2>/dev/null))"
echo "--- hub log tail ---"
podman logs "$HUB_NAME" 2>&1 | tail -40

echo "=== teardown ==="
cleanup
finish
