#!/usr/bin/env bash
set -uo pipefail

# filename: tests/live/acme/run.sh
#
# W19-01: prove the hub's /acme/ endpoint against REAL ACME clients (certbot,
# lego), each in a podman container, running the full
# issue -> renew -> revoke -> (OCSP/CRL reflect revocation) loop, then check
# the hub's own inventory (GET /api/v1/certificates) records the cert with
# source=acme. See README.md in this directory for the full topology
# rationale. Summary:
#   - hub + both clients + a TLS front share one podman network, so the
#     hub's real HTTP-01 validator can dial a client container by its
#     container-DNS name on port 80 (macOS podman has no --network host, so
#     published ports don't get us this).
#   - lego refuses a plain-HTTP ACME directory outright ("HTTPS is
#     required", no override flag exists -- verified against the actual
#     image, see README). W19-31: pre-W19-14 this fixture terminated TLS at
#     a standalone nginx front (hub itself plain HTTP) because the hub had
#     no listener of its own; that now conflicts with W19-13's scheme check
#     (KRYPTKEEPER_BASE_URL's scheme must match what the hub actually
#     serves), so the nginx front is gone. The hub self-issues its own TLS
#     listener (KRYPTKEEPER_TLS_SELF_ISSUE=true) and exports its CA to a
#     mounted volume (KRYPTKEEPER_TLS_TRUST_EXPORT_DIR) that every client --
#     certbot (REQUESTS_CA_BUNDLE), lego (LEGO_CA_CERTIFICATES), and this
#     script's own curl_hub/openssl calls (--cacert/-CAfile) -- trusts
#     explicitly. No client here uses -k/--no-verify-ssl/--tls-skip-verify
#     any more.
#
# Idempotent: tears down and recreates the network/containers/data dir on
# every run. PASS/FAIL per step; non-zero exit on any FAIL.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUN_DIR="${KK_UAT_RUN_DIR:-$HOME/kk-uat-acme-run}"   # must be under $HOME: podman machine on macOS only virtiofs-mounts /Users, not /tmp
NETWORK="kk-uat-acme"
HUB_NAME="kk-acme-hub"
HUB_HOST="kk-acme-hub"          # container hostname == APP_BIND_ADDR, see README "Why bind to a name"
HUB_PORT="8080"
ACME_SERVER="https://$HUB_HOST:$HUB_PORT/acme/directory"
BOOTSTRAP_TOKEN="uat-token"
CA_NAME="UAT Root CA"

PASS=0
FAIL=0

pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

curl_hub() {
  # Runs curl inside a helper container ON THE SAME NETWORK as the hub
  # (rootless podman port publishing on macOS forwards to loopback inside
  # the VM, not to an address the hub's bindAddr:PORT listener answers on --
  # verification has to happen from inside the network, same as the clients
  # do). --cacert against the hub's own self-issued-TLS export -- never -k.
  podman run --rm --network "$NETWORK" -v "$RUN_DIR/tls-export:/caexport:ro" \
    curlimages/curl:8.10.1 --cacert /caexport/ca.pem "$@"
}

cleanup() {
  podman rm -f kk-certbot kk-lego kk-verify "$HUB_NAME" >/dev/null 2>&1 || true
  podman network rm "$NETWORK" >/dev/null 2>&1 || true
}

echo "=== W19-01 ACME UAT: setup ==="
cleanup
trap cleanup EXIT INT TERM
rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR/bin" "$RUN_DIR/data" "$RUN_DIR/certbot" "$RUN_DIR/lego" "$RUN_DIR/verify" "$RUN_DIR/tls-export"

echo "--- pre-pulling images ---"
for img in docker.io/certbot/certbot:latest docker.io/goacme/lego:latest \
           curlimages/curl:8.10.1 alpine:3; do
  podman pull -q "$img" >/dev/null 2>&1 || true
done

echo "--- building hub binary (linux/arm64, CGO_ENABLED=0: pure-Go sqlite driver, no cross-toolchain needed) ---"
if ! (cd "$ROOT_DIR" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$RUN_DIR/bin/kryptkeeper" ./cmd/kryptkeeper); then
  fail "build hub binary"
  echo "=== RESULT: $PASS passed, $FAIL failed ==="
  exit 1
fi
pass "build hub binary"

podman network create "$NETWORK" >/dev/null
pass "create podman network $NETWORK"

echo "--- starting verify helper (openssl on the podman network, for OCSP -- container-DNS names like $HUB_HOST don't resolve from the macOS host) ---"
podman run -d --name kk-verify --network "$NETWORK" \
  -v "$RUN_DIR/verify:/verify" \
  alpine:3 sh -c "apk add --no-cache openssl >/dev/null 2>&1 && sleep 3600" >/dev/null
for _ in $(seq 1 15); do
  podman exec kk-verify openssl version >/dev/null 2>&1 && break
  sleep 1
done
if podman exec kk-verify openssl version >/dev/null 2>&1; then
  pass "verify helper ready (openssl installed on $NETWORK)"
else
  fail "verify helper ready (openssl installed on $NETWORK)"
fi

echo "--- starting hub (self-issues its own TLS listener cert, exports its CA to tls-export) ---"
podman run -d --name "$HUB_NAME" --network "$NETWORK" --hostname "$HUB_HOST" \
  -v "$RUN_DIR/bin/kryptkeeper:/kryptkeeper:ro" \
  -v "$RUN_DIR/data:/data" \
  -v "$RUN_DIR/tls-export:/tls-export" \
  -e APP_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" -e AUTH_MODE=bootstrap \
  -e APP_CERTIFICATE_PROVIDER=ca -e APP_DISCOVERY_PROVIDER=db -e APP_NOTIFICATION_PROVIDER=file \
  -e KRYPTKEEPER_TLS_SELF_ISSUE=true -e KRYPTKEEPER_TLS_SANS="$HUB_HOST" \
  -e KRYPTKEEPER_TLS_TRUST_EXPORT_DIR=/tls-export \
  -e APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
  -e KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
  -e KRYPTKEEPER_DATA_DIR=/data \
  -e APP_CA_FILE=/data/cas.json -e APP_TEMPLATE_FILE=/data/templates.json \
  -e APP_CERTIFICATE_FILE=/data/certificates.json -e APP_AUDIT_FILE=/data/audit.json \
  -e APP_CERTS_SUMMARY_FILE=/data/certs_summary.json \
  -e KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true -e KRYPTKEEPER_CA_NAME="$CA_NAME" \
  -e APP_BIND_ADDR="$HUB_HOST" -e PORT="$HUB_PORT" \
  -e KRYPTKEEPER_BASE_URL="https://$HUB_HOST:$HUB_PORT" \
  alpine:3 /kryptkeeper >/dev/null

sleep 3
if ! podman logs "$HUB_NAME" 2>&1 | grep -q "starting kryptkeeper on $HUB_HOST:$HUB_PORT"; then
  fail "hub startup (see: podman logs $HUB_NAME)"
  podman logs "$HUB_NAME" 2>&1 | tail -40
  echo "=== RESULT: $PASS passed, $FAIL failed ==="
  exit 1
fi
pass "hub startup"

echo "--- waiting for the hub's self-issued CA export (tls-export/ca.pem) ---"
for _ in $(seq 1 15); do
  [[ -s "$RUN_DIR/tls-export/ca.pem" ]] && break
  sleep 1
done
if [[ -s "$RUN_DIR/tls-export/ca.pem" ]]; then
  pass "hub exported its self-issued listener CA to tls-export/ca.pem"
else
  fail "hub exported its self-issued listener CA to tls-export/ca.pem"
  podman logs "$HUB_NAME" 2>&1 | tail -40
  echo "=== RESULT: $PASS passed, $FAIL failed ==="
  exit 1
fi

if curl_hub -sf "$ACME_SERVER" | grep -q "$HUB_HOST"; then
  pass "hub ACME directory reachable over its own TLS listener ($ACME_SERVER)"
else
  fail "hub ACME directory reachable over its own TLS listener"
  curl_hub -s "$ACME_SERVER" || true
  podman logs "$HUB_NAME" 2>&1 | tail -20
fi

CA_ID=$(curl_hub -s -H "Authorization: Bearer $BOOTSTRAP_TOKEN" "https://$HUB_HOST:$HUB_PORT/api/v1/cas" | python3 -c "import json,sys; print(json.load(sys.stdin)['data'][0]['id'])" 2>/dev/null || true)
if [[ -n "$CA_ID" ]]; then
  pass "resolved root CA id ($CA_ID)"
else
  fail "resolved root CA id"
fi

echo "--- fetching CA chain PEM for verification ---"
curl_hub -s -H "Authorization: Bearer $BOOTSTRAP_TOKEN" "https://$HUB_HOST:$HUB_PORT/api/v1/cas/$CA_ID/chain?format=pem" > "$RUN_DIR/verify/ca-chain.pem"
if openssl x509 -in "$RUN_DIR/verify/ca-chain.pem" -noout -subject >/dev/null 2>&1; then
  pass "CA chain PEM is a parseable certificate (W19-01 hub fix verified live)"
else
  fail "CA chain PEM is a parseable certificate"
  cat "$RUN_DIR/verify/ca-chain.pem"
fi

verify_chain() {
  local certfile="$1" label="$2"
  if openssl verify -CAfile "$RUN_DIR/verify/ca-chain.pem" "$certfile" >/dev/null 2>&1; then
    pass "$label: certificate chains to \"$CA_NAME\""
  else
    fail "$label: certificate chains to \"$CA_NAME\""
    openssl verify -CAfile "$RUN_DIR/verify/ca-chain.pem" "$certfile" || true
  fi
}

inventory_has_source_acme() {
  # Matches on THIS client's own certificate fingerprint, not "some cert
  # somewhere has source=acme" -- with two clients issuing in sequence,
  # certbot's recorded row would make a fingerprint-blind check on lego
  # pass even if lego's issuance was never recorded at all, which is
  # exactly the un-exercised path (W18-16) this ticket exists to prove.
  local label="$1" certfile="$2"
  local fp body
  fp=$(openssl x509 -in "$certfile" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')
  body=$(curl_hub -s -H "Authorization: Bearer $BOOTSTRAP_TOKEN" "https://$HUB_HOST:$HUB_PORT/api/v1/certificates?limit=100")
  if echo "$body" | python3 -c "
import json,sys
d=json.load(sys.stdin)
certs=d.get('data', d.get('certificates', []))
fp='$fp'
found = any(c.get('source') == 'acme' and str(c.get('fingerprint_sha256','')).lower() == fp for c in certs)
sys.exit(0 if found else 1)
" 2>/dev/null; then
    pass "$label: hub inventory lists this exact certificate with source: acme (fp=$fp)"
  else
    fail "$label: hub inventory lists this exact certificate with source: acme (fp=$fp)"
    echo "$body"
  fi
}

crl_lists_serial() {
  local label="$1" serial_hex="$2"
  curl_hub -s "https://$HUB_HOST:$HUB_PORT/crl/$CA_ID.crl" > "$RUN_DIR/verify/${label}.crl.der"
  if openssl crl -inform DER -in "$RUN_DIR/verify/${label}.crl.der" -noout -text 2>/dev/null | grep -qi "${serial_hex}"; then
    pass "$label: CRL lists the revoked serial"
  else
    fail "$label: CRL lists the revoked serial"
  fi
}

ocsp_says_good_or_revoked() {
  # Runs openssl ocsp INSIDE the podman network via the kk-verify helper --
  # "$HUB_HOST" is a container-DNS name that only resolves on $NETWORK, not
  # from the macOS host running this script (W19-01: this is what made both
  # clients' OCSP checks look like hub failures when they were a fixture
  # defect). $certfile is a host path under $RUN_DIR/verify, bind-mounted
  # into kk-verify at /verify, so it's referenced there by basename.
  local label="$1" certfile="$2" want="$3"
  local relpath resp
  relpath="/verify/$(basename "$certfile")"
  # -CAfile (not just -issuer): without a trust anchor openssl ocsp cannot
  # check the response's signature at all and silently skips that check --
  # the same "looks right, never actually verified" shape as the fake-PEM
  # bug this ticket already found once (W19-01). Require BOTH the status
  # word and "Response verify OK" so a response that merely claims the
  # right status but doesn't verify against our CA still fails. The hub's
  # OCSP endpoint is now TLS-only (W19-14); openssl ocsp's own -url https://
  # support does the TLS handshake itself, and -CAfile above is what
  # verifies the OCSP response's application-layer signature, not the
  # transport -- so the OCSP responder's signing key (the same CA that
  # issues the TLS listener cert here) is the only trust anchor needed.
  resp=$(podman exec kk-verify openssl ocsp -issuer /verify/ca-chain.pem -CAfile /verify/ca-chain.pem -cert "$relpath" \
    -url "https://$HUB_HOST:$HUB_PORT/ocsp" -no_nonce 2>&1) || true
  if echo "$resp" | grep -qi "$want" && echo "$resp" | grep -qi "Response verify OK"; then
    pass "$label: OCSP responder reports $want (signature verified)"
  else
    fail "$label: OCSP responder reports $want (signature verified)"
    echo "$resp"
  fi
}

# ---------------------------------------------------------------------------
# certbot
# ---------------------------------------------------------------------------
echo "=== certbot ==="
podman run -d --name kk-certbot --network "$NETWORK" --hostname kk-certbot \
  -v "$RUN_DIR/certbot:/etc/letsencrypt" \
  -v "$RUN_DIR/tls-export/ca.pem:/etc/kk-ca/ca.pem:ro" \
  -e REQUESTS_CA_BUNDLE=/etc/kk-ca/ca.pem \
  --entrypoint sh docker.io/certbot/certbot:latest -c "sleep 3600" >/dev/null
sleep 2

certbot_exec() { podman exec kk-certbot certbot "$@"; }

# certbot's ACME client is built on python-requests, which honors
# REQUESTS_CA_BUNDLE (set on the container above) instead of any --cacert
# flag of its own -- so trusting the hub's real self-issued CA needs no
# --no-verify-ssl here (W19-31: the fixture used to skip verification
# entirely against a throwaway nginx front cert; now it verifies against
# the hub's actual listener CA). Gate on the completed log file, not a live
# `| grep -q` on the streamed pipe -- `grep -q` exits as soon as it sees a
# match and can otherwise race a slow/buffered producer under `pipefail`,
# giving false FAILs even though the command (and the file it wrote)
# genuinely succeeded.
certbot_exec certonly --standalone \
    --server "$ACME_SERVER" \
    --agree-tos -m uat@example.test --no-eff-email \
    --non-interactive -d kk-certbot > "$RUN_DIR/certbot/issue.log" 2>&1
if grep -q "Successfully received certificate" "$RUN_DIR/certbot/issue.log"; then
  pass "certbot: obtain certificate"
else
  fail "certbot: obtain certificate"
  tail -30 "$RUN_DIR/certbot/issue.log"
fi

CERTBOT_CERT="$RUN_DIR/certbot/live/kk-certbot/cert.pem"
if [[ -f "$CERTBOT_CERT" ]]; then
  cp "$CERTBOT_CERT" "$RUN_DIR/verify/certbot-cert.pem"
  verify_chain "$RUN_DIR/verify/certbot-cert.pem" "certbot"
  inventory_has_source_acme "certbot" "$RUN_DIR/verify/certbot-cert.pem"
else
  fail "certbot: certificate file present"
fi

certbot_exec renew --force-renewal \
    --server "$ACME_SERVER" --non-interactive > "$RUN_DIR/certbot/renew.log" 2>&1
if grep -qi "congratulations\|renewed\|success" "$RUN_DIR/certbot/renew.log"; then
  pass "certbot: renew"
else
  fail "certbot: renew"
  tail -30 "$RUN_DIR/certbot/renew.log"
fi

# Re-copy: renew replaced live/kk-certbot/*.pem with a NEW cert (same
# lineage, new fingerprint+serial). Every check from here on -- revoke,
# CRL, OCSP, inventory -- must target that renewed cert, not the one from
# before renewal, or revocation checks fail against a cert that was never
# revoked and look like hub defects.
if [[ -f "$CERTBOT_CERT" ]]; then
  cp "$CERTBOT_CERT" "$RUN_DIR/verify/certbot-cert.pem"
  verify_chain "$RUN_DIR/verify/certbot-cert.pem" "certbot (post-renewal)"
  inventory_has_source_acme "certbot (post-renewal)" "$RUN_DIR/verify/certbot-cert.pem"
  ocsp_says_good_or_revoked "certbot (pre-revocation)" "$RUN_DIR/verify/certbot-cert.pem" "good"
else
  fail "certbot: renewed certificate file present"
fi

certbot_exec revoke --cert-path "/etc/letsencrypt/live/kk-certbot/fullchain.pem" \
    --server "$ACME_SERVER" --non-interactive --delete-after-revoke \
    > "$RUN_DIR/certbot/revoke.log" 2>&1
if grep -qi "revoked" "$RUN_DIR/certbot/revoke.log"; then
  pass "certbot: revoke"
  CERTBOT_SERIAL_HEX=$(openssl x509 -in "$RUN_DIR/verify/certbot-cert.pem" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f')
  crl_lists_serial "certbot" "$CERTBOT_SERIAL_HEX"
  ocsp_says_good_or_revoked "certbot (post-revocation)" "$RUN_DIR/verify/certbot-cert.pem" "revoked"
else
  fail "certbot: revoke"
  tail -30 "$RUN_DIR/certbot/revoke.log"
fi

podman rm -f kk-certbot >/dev/null 2>&1

# ---------------------------------------------------------------------------
# lego
# ---------------------------------------------------------------------------
echo "=== lego ==="
# lego 5.x flattened the CLI: there is no top-level "renew"/"revoke" command
# (verified via `lego --help` / `lego certificates revoke --help` against the
# actual pulled image -- the ticket's suggested `lego ... renew`/`revoke`
# top-level syntax is from an older lego release and does not exist here).
# "run" both obtains and (with --renew-force) renews; revocation is
# "certificates revoke". All data/domain/challenge flags belong to the
# subcommand, not to a global preamble. lego trusts the hub's real
# self-issued CA via LEGO_CA_CERTIFICATES (W19-31: replaces the old
# --tls-skip-verify against a throwaway nginx front cert).
LEGO_COMMON=(--accept-tos --email uat@example.test --server "$ACME_SERVER" --path /data)
LEGO_ENV=(-e LEGO_CA_CERTIFICATES=/etc/kk-ca/ca.pem -v "$RUN_DIR/tls-export/ca.pem:/etc/kk-ca/ca.pem:ro")

podman run --name kk-lego --network "$NETWORK" --hostname kk-lego \
    -v "$RUN_DIR/lego:/data" "${LEGO_ENV[@]}" \
    docker.io/goacme/lego:latest \
    run "${LEGO_COMMON[@]}" --domains kk-lego --http --http.address :80 \
    > "$RUN_DIR/lego/issue.log" 2>&1
podman rm -f kk-lego >/dev/null 2>&1

# lego's actual success wording ("Server responded with a certificate", per
# the pulled image) doesn't match "obtained"/"successfully" -- the ticket's
# suggested phrasing is from a different lego release and false-negatived
# here even on a real success (W19-01). Assert on the artifact instead: a
# cert file that chains to our CA and lands in inventory is strictly
# stronger evidence of success than any one log string.
LEGO_CERT="$RUN_DIR/lego/certificates/kk-lego.crt"
if [[ -s "$LEGO_CERT" ]]; then
  pass "lego: obtain certificate (cert file written)"
  cp "$LEGO_CERT" "$RUN_DIR/verify/lego-cert.pem"
  verify_chain "$RUN_DIR/verify/lego-cert.pem" "lego"
  inventory_has_source_acme "lego" "$RUN_DIR/verify/lego-cert.pem"
else
  fail "lego: obtain certificate (cert file written)"
  tail -30 "$RUN_DIR/lego/issue.log"
fi

LEGO_PRE_RENEW_FP=$(openssl x509 -in "$RUN_DIR/verify/lego-cert.pem" -noout -fingerprint -sha256 2>/dev/null || true)
podman run --name kk-lego --network "$NETWORK" --hostname kk-lego \
    -v "$RUN_DIR/lego:/data" "${LEGO_ENV[@]}" \
    docker.io/goacme/lego:latest \
    run "${LEGO_COMMON[@]}" --domains kk-lego --http --http.address :80 --renew-force --ari-disable --no-random-sleep \
    > "$RUN_DIR/lego/renew.log" 2>&1
podman rm -f kk-lego >/dev/null 2>&1

# Same reasoning as the obtain step above: assert on the artifact (a new
# cert file with a DIFFERENT fingerprint than before renewal -- not just any
# file -- since a no-op would leave the prior file's mtime/content in place
# too) instead of log wording.
LEGO_POST_RENEW_FP=$(openssl x509 -in "$LEGO_CERT" -noout -fingerprint -sha256 2>/dev/null || true)
if [[ -s "$LEGO_CERT" && -n "$LEGO_POST_RENEW_FP" && "$LEGO_POST_RENEW_FP" != "$LEGO_PRE_RENEW_FP" ]]; then
  pass "lego: renew (new cert file with a different fingerprint)"
  cp "$LEGO_CERT" "$RUN_DIR/verify/lego-cert.pem"
  verify_chain "$RUN_DIR/verify/lego-cert.pem" "lego (post-renewal)"
  inventory_has_source_acme "lego (post-renewal)" "$RUN_DIR/verify/lego-cert.pem"
  ocsp_says_good_or_revoked "lego (pre-revocation)" "$RUN_DIR/verify/lego-cert.pem" "good"
else
  fail "lego: renew (new cert file with a different fingerprint)"
  tail -30 "$RUN_DIR/lego/renew.log"
fi

podman run --name kk-lego --network "$NETWORK" --hostname kk-lego \
    -v "$RUN_DIR/lego:/data" "${LEGO_ENV[@]}" \
    docker.io/goacme/lego:latest \
    certificates revoke --email uat@example.test --server "$ACME_SERVER" --path /data --cert.name kk-lego \
    > "$RUN_DIR/lego/revoke.log" 2>&1
if grep -qi "revoked" "$RUN_DIR/lego/revoke.log"; then
  pass "lego: revoke"
  LEGO_SERIAL_HEX=$(openssl x509 -in "$RUN_DIR/verify/lego-cert.pem" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f')
  crl_lists_serial "lego" "$LEGO_SERIAL_HEX"
  ocsp_says_good_or_revoked "lego (post-revocation)" "$RUN_DIR/verify/lego-cert.pem" "revoked"
else
  fail "lego: revoke"
  tail -30 "$RUN_DIR/lego/revoke.log"
fi
podman rm -f kk-lego >/dev/null 2>&1

echo "--- hub log tail ---"
podman logs "$HUB_NAME" 2>&1 | tail -60

echo "=== teardown ==="
cleanup

echo "=== RESULT: $PASS passed, $FAIL failed ==="
[[ "$FAIL" -eq 0 ]]
