#!/usr/bin/env bash
# W29-14 live proof: CI OIDC code-signing and RFC 3161 timestamping against a
# real hub (podman), real openssl and real cosign.
#
#   1. a fake CI issuer (fakeidp, TLS) and the hub run in containers on one
#      podman network; the hub trusts the issuer's CA through SSL_CERT_FILE
#      (Go on Linux honours it, macOS does not, hence containers)
#   2. a trust rule is proposed by alice and approved by bob (dual control);
#      the rule is not in force until bob approves
#   3. a fakeidp token is exchanged with a P-256 CSR for a 45 s code-signing
#      certificate; replayed / wrong-repo / wrong-ref tokens are refused
#   4. a blob is signed (openssl and cosign) and the signature is timestamped
#      by the hub TSA (POST /api/v1/tsa); the timestamp verifies with openssl
#   5. the script waits until the certificate has expired, then verifies the
#      timestamp, the cosign bundle and the chain as of the timestamp; the
#      same verification without the timestamp fails
#   6. audit rows (codesign.issue with repo/ref/serial, codesign.timestamp
#      with the digest) are read back through the API
#   7. revoked-certificate semantics (README): issue B, timestamp, revoke B
#
# Idempotent, PASS/FAIL per step, cleans up on exit. Keys are generated per
# run under $RUN and removed; none is committed.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
RUN="${KK_UAT_RUN_DIR:-$HOME/kk-uat-codesign-run}" # under $HOME: podman on macOS only mounts /Users
NET=kk-uat-codesign
IDP=kk-cs-idp
HUBC=kk-cs-hub
REG=kk-cs-registry
REG_PORT="${REG_PORT:-15000}"
IMAGE_REF="localhost:$REG_PORT/app:1"
IDP_PORT="${IDP_PORT:-19443}"
HUB_PORT="${HUB_PORT:-18080}"
HUB="http://127.0.0.1:$HUB_PORT"
IDP_URL="https://$IDP:9443"
TOKEN="uat-codesign-bootstrap-token"
PEPPER='uat-pepper-32-characters-minimum!!'
AUD=lab-hub
REPO=acme/app
REF=refs/heads/main
TTL_SECONDS=45
ARCH="$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
FAILED=0
# cosign 3.x is required (`sign-blob --certificate` does not exist in 2.x); COSIGN points at it
# when the host default is older. OPENSSL names an OpenSSL >= 3.2 (the `codesign` verify purpose
# does not exist in Ubuntu 24.04's 3.0): its directory goes first on PATH for every openssl call
# here, and a build without an rpath also needs LD_LIBRARY_PATH=<prefix>/lib from the caller.
COSIGN="${COSIGN:-cosign}"
[ -n "${OPENSSL:-}" ] && PATH="$(dirname "$OPENSSL"):$PATH" && export PATH

STEP() { echo; echo "=== $* ==="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE() { echo "FAIL: $*"; exit 1; }
cleanup() {
  # One name per call: podman 4.9 rm -f silently removes nothing when any listed name is already gone.
  kk_rm "$IDP" "$HUBC" "$REG"
  podman network rm "$NET" >/dev/null 2>&1
  if [ "$FAILED" = 1 ]; then echo "--- hub log (last 30) ---"; tail -30 "$RUN/hub.log" 2>/dev/null; fi
  rm -rf "$RUN"
}
trap cleanup EXIT

# named administrators come from APP_API_KEYS_JSON: keys minted with the
# bootstrap token are setup credentials and may not approve (RC1-B-01).
ENTRIES=""
mkident() { # name role -> sets T_<name>
  local name="$1" role="$2" secret verifier
  secret="$(openssl rand -hex 24)"
  verifier="$(printf '%s' "$secret" | openssl dgst -sha256 -hmac "$PEPPER" -hex | awk '{print $NF}')"
  eval "T_$name=kk_uat${name}_${secret}"
  ENTRIES="${ENTRIES:+$ENTRIES,}{\"name\":\"$name\",\"kid\":\"uat$name\",\"secret_verifier\":\"$verifier\",\"principal_id\":\"$name\",\"role\":\"$role\",\"active\":true}"
}
mkident alice pki-admin; mkident bob pki-admin
KEYS_JSON="[$ENTRIES]"
epoch() { python3 -c 'import sys,datetime; print(int(datetime.datetime.fromisoformat(sys.argv[1].replace("Z","+00:00")).timestamp()))' "$1"; }
cert_epoch() { epoch "$(openssl x509 -in "$2" -noout "$1" -dateopt iso_8601 | cut -d= -f2 | tr ' ' T)"; } # cert_epoch -startdate|-enddate <pem>

jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
# code <bearer or ""> <curl args...>: prints the status, body to $RUN/last.json
code() {
  local tok="$1"; shift
  if [ -n "$tok" ]; then
    curl -sS -o "$RUN/last.json" -w '%{http_code}' -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"
  else
    curl -sS -o "$RUN/last.json" -w '%{http_code}' -H 'Content-Type: application/json' "$@"
  fi
}
expect() { # expect <label> <want> <got>
  if [ "$2" = "$3" ]; then PASS "$1 -> $3"; else FAIL "$1 -> $3 (want $2): $(head -c 300 "$RUN/last.json" 2>/dev/null)"; fi
}
idp_token() { # idp_token <repo> <ref> [aud] [provider]
  curl -sS --cacert "$RUN/pki/idp-ca.pem" --resolve "$IDP:$IDP_PORT:127.0.0.1" \
    "https://$IDP:$IDP_PORT/token?repo=$1&ref=$2&aud=${3:-$AUD}&provider=${4:-github}" | jget 'd["value"]'
}
make_csr() { # make_csr <key out> <csr out>
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$1" 2>/dev/null
  openssl req -new -key "$1" -subj "/CN=ci-ephemeral" -out "$2"
}
# issue <token> <csr file> <out prefix>: writes <prefix>.cert.pem / .chain.pem / .json
issue() {
  local body c
  body="$(python3 -c 'import json,sys; print(json.dumps({"oidc_token":sys.argv[1],"csr_pem":open(sys.argv[2]).read()}))' "$1" "$2")"
  c=$(code "" -X POST "$HUB/api/v1/codesign/issue" -d "$body")
  cp "$RUN/last.json" "$3.json"
  [ "$c" = 201 ] || { echo "$c"; return 1; }
  jget 'd["data"]["certificate_pem"]' <"$3.json" >"$3.cert.pem"
  jget 'd["data"]["chain_pem"]' <"$3.json" >"$3.chain.pem"
  echo "$c"
}

STEP "build hub and fake issuer (linux/$ARCH)"
rm -rf "$RUN"; mkdir -p "$RUN/bin" "$RUN/data" "$RUN/pki" "$RUN/w"
(cd "$REPO_ROOT" && GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -o "$RUN/bin/kryptkeeper" ./cmd/kryptkeeper \
  && GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -o "$RUN/bin/fakeidp" ./tests/live/codesign-oidc/fakeidp) || DIE "go build failed"
PASS "built"

STEP "PKI: issuer CA + TLS cert, TSA root + TSA cert (operator-provisioned, D-153)"
P="$RUN/pki"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$P/idp-ca.key" -out "$P/idp-ca.pem" -subj "/CN=kk-cs-idp-ca" -days 2 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$P/idp.key" 2>/dev/null
openssl req -new -key "$P/idp.key" -subj "/CN=$IDP" -out "$P/idp.csr"
printf 'subjectAltName=DNS:%s,DNS:localhost\nextendedKeyUsage=serverAuth\n' "$IDP" >"$P/idp.ext"
openssl x509 -req -in "$P/idp.csr" -CA "$P/idp-ca.pem" -CAkey "$P/idp-ca.key" -CAcreateserial -days 2 -extfile "$P/idp.ext" -out "$P/idp.pem" 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$P/tsa-root.key" -out "$P/tsa-root.pem" -subj "/CN=KK UAT TSA Root" -days 30 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$P/tsa.key" 2>/dev/null
chmod 600 "$P/tsa.key"
openssl req -new -key "$P/tsa.key" -subj "/CN=KK UAT TSA" -out "$P/tsa.csr"
printf 'keyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n' >"$P/tsa.ext"
openssl x509 -req -in "$P/tsa.csr" -CA "$P/tsa-root.pem" -CAkey "$P/tsa-root.key" -CAcreateserial -days 30 -extfile "$P/tsa.ext" -out "$P/tsa.pem" 2>/dev/null
chmod 644 "$P/idp.key" "$P/idp-ca.key" "$P/tsa-root.key" # the idp container user must read idp.key; the CA keys are test-only
PASS "issuer CA, TLS cert, TSA root and critical-EKU timeStamping cert generated"

STEP "start issuer and hub on one podman network"
podman network rm "$NET" >/dev/null 2>&1; podman network create "$NET" >/dev/null || DIE "network"
podman run -d --name "$IDP" --network "$NET" --hostname "$IDP" -p "127.0.0.1:$IDP_PORT:9443" \
  -v "$RUN/bin/fakeidp:/fakeidp:ro" -v "$P:/pki:ro" alpine:3 \
  /fakeidp -addr :9443 -issuer "$IDP_URL" -cert /pki/idp.pem -key /pki/idp.key >/dev/null || DIE "issuer container did not start"
podman run -d --name "$HUBC" --network "$NET" --hostname "$HUBC" -p "127.0.0.1:$HUB_PORT:8080" \
  -v "$RUN/bin/kryptkeeper:/kryptkeeper:ro" -v "$RUN/data:/data" -v "$P:/pki:ro" \
  -e SSL_CERT_FILE=/pki/idp-ca.pem \
  -e APP_BOOTSTRAP_TOKEN="$TOKEN" -e AUTH_MODE=bootstrap -e APP_CERTIFICATE_PROVIDER=ca \
  -e APP_API_KEY_PEPPER="$PEPPER" -e APP_API_KEY_AUTH_ENABLED=true -e APP_API_KEYS_JSON="$KEYS_JSON" \
  -e APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' -e KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
  -e KRYPTKEEPER_DATA_DIR=/data -e APP_CA_FILE=/data/cas.json -e APP_TEMPLATE_FILE=/data/templates.json \
  -e APP_CERTIFICATE_FILE=/data/certificates.json -e APP_AUDIT_FILE=/data/audit.json -e APP_CERTS_SUMMARY_FILE=/data/certs_summary.json \
  -e KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true -e KRYPTKEEPER_CA_NAME="UAT Code-signing Root" \
  -e APP_BIND_ADDR=0.0.0.0 -e PORT=8080 -e KRYPTKEEPER_TLS_DISABLE=true \
  -e KRYPTKEEPER_CODESIGN_TTL="${TTL_SECONDS}s" \
  -e KRYPTKEEPER_TSA_CERT_FILE=/pki/tsa.pem -e KRYPTKEEPER_TSA_KEY_FILE=/pki/tsa.key \
  alpine:3 /kryptkeeper >/dev/null || DIE "hub container did not start"
for _ in $(seq 1 60); do curl -sf "$HUB/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$HUB/healthz" >/dev/null || { podman logs "$HUBC" >"$RUN/hub.log" 2>&1; DIE "hub did not start"; }
PASS "issuer and hub up"
kk_rm "$REG"
podman run -d --name "$REG" --network "$NET" -p "127.0.0.1:$REG_PORT:5000" docker.io/library/registry:2 >/dev/null || DIE "registry did not start"
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$REG_PORT/v2/" >/dev/null 2>&1 && break; sleep 0.5; done
podman pull -q alpine:3 >/dev/null 2>&1; podman tag alpine:3 "$IMAGE_REF"
podman push --tls-verify=false --digestfile "$RUN/image.digest" "$IMAGE_REF" >/dev/null 2>&1 || DIE "could not push the test image"
IMAGE_DIGEST="$(cat "$RUN/image.digest" 2>/dev/null)"
[ -n "$IMAGE_DIGEST" ] && PASS "local registry up, test image pushed ($IMAGE_DIGEST)" || DIE "no image digest"
IMAGE_PINNED="localhost:$REG_PORT/app@$IMAGE_DIGEST"
SYFT_REGISTRY_INSECURE_USE_HTTP=true syft "registry:$IMAGE_REF" -o cyclonedx-json="$RUN/sbom.cdx.json" >/dev/null 2>&1 && PASS "syft SBOM generated ($(wc -c <"$RUN/sbom.cdx.json") bytes)" || DIE "syft failed"

STEP "principals and the signing CA"
c=$(code "$T_alice" "$HUB/api/v1/cas"); expect "GET /cas" 200 "$c"
CA_ID="$(jget 'd["data"][0]["id"]' <"$RUN/last.json")"
[ -n "$CA_ID" ] && PASS "signing CA $CA_ID" || DIE "no CA"

STEP "trust rule: dual control"
RULE="{\"provider\":\"github\",\"issuer\":\"$IDP_URL\",\"audience\":\"$AUD\",\"repo_pattern\":\"$REPO\",\"ref_pattern\":\"refs/heads/main\",\"ca_id\":\"$CA_ID\",\"rationale\":\"live test\"}"
c=$(code "$T_alice" -X POST "$HUB/api/v1/codesign/oidc-trust-rules" -d "$RULE"); expect "alice proposes the rule" 202 "$c"
ACT="$(jget 'd["data"]["action_id"]' <"$RUN/last.json")"
python3 -c "import json,sys; sys.exit(0 if json.load(open('$RUN/last.json'))['data']['status']=='pending' else 1)" && PASS "rule is pending"
w="$RUN/w"; make_csr "$w/pre.key" "$w/pre.csr"
c=$(issue "$(idp_token $REPO $REF)" "$w/pre.csr" "$w/pre"); expect "token refused before the rule is approved" 401 "$c"
c=$(code "$T_alice" -X POST "$HUB/api/v1/pending-actions/$ACT/approve"); expect "alice cannot approve her own rule" 403 "$c"
c=$(code "$T_bob" -X POST "$HUB/api/v1/pending-actions/$ACT/approve"); expect "bob approves" 200 "$c"
c=$(code "$T_bob" "$HUB/api/v1/codesign/oidc-trust-rules"); expect "GET trust rules" 200 "$c"
grep -q "\"repo_pattern\":\"$REPO\"" "$RUN/last.json" && PASS "rule in force" || FAIL "rule missing after approval"

STEP "A. exchange: token + CSR -> 45 s code-signing certificate"
make_csr "$w/a.key" "$w/a.csr"
TOKA="$(idp_token $REPO $REF)"
c=$(issue "$TOKA" "$w/a.csr" "$w/a"); expect "POST /codesign/issue" 201 "$c"
openssl x509 -in "$w/a.cert.pem" -noout -text >"$w/a.txt"
grep -q "Code Signing" "$w/a.txt" && PASS "EKU codeSigning" || FAIL "no codeSigning EKU"
grep -q "URI:https://github.com/$REPO@$REF" "$w/a.txt" && PASS "URI SAN binds repo and ref" || FAIL "URI SAN missing: $(grep URI "$w/a.txt")"
A_NOT_BEFORE="$(cert_epoch -startdate "$w/a.cert.pem")"; A_NOT_AFTER="$(cert_epoch -enddate "$w/a.cert.pem")"
SPAN=$(( A_NOT_AFTER - A_NOT_BEFORE ))
[ "$SPAN" -le 900 ] && PASS "validity ${SPAN}s <= 15 min" || FAIL "validity ${SPAN}s"

STEP "B. sign with the issued key, timestamp the signature (inside the certificate's 45 s window)"
echo "release artifact $(date -u +%FT%TZ)" >"$w/blob.txt"
openssl x509 -in "$w/a.cert.pem" -pubkey -noout >"$w/a.pub"
openssl dgst -sha256 -sign "$w/a.key" -out "$w/blob.sig" "$w/blob.txt"
openssl dgst -sha256 -verify "$w/a.pub" -signature "$w/blob.sig" "$w/blob.txt" >/dev/null && PASS "openssl signature verifies against the certificate key" || FAIL "openssl signature"
COSIGN_PASSWORD="" "$COSIGN" import-key-pair --key "$w/a.key" --output-key-prefix "$w/cs" >/dev/null 2>&1 || FAIL "cosign import-key-pair"
# cosign 3.1.3 writes a legacy x509CertificateChain bundle when --certificate-chain is given, and
# its own verifier then fails that bundle's signature; the leaf alone yields a v0.3 bundle and the
# chain is supplied at verification time through --trusted-root.
if COSIGN_PASSWORD="" "$COSIGN" sign-blob --key "$w/cs.key" --certificate "$w/a.cert.pem" \
  --use-signing-config=false --tlog-upload=false --bundle "$w/blob.bundle.json" "$w/blob.txt" >"$w/cosign-sign.log" 2>&1; then
  PASS "cosign sign-blob (--key, --certificate, --bundle)"
else FAIL "cosign sign-blob: $(tail -3 "$w/cosign-sign.log")"; fi
# RFC 3161 reply (the whole TimeStampResp, which is what cosign parses) over cosign's own signature bytes, placed in the bundle (cosign cannot send the hub's Bearer token).
python3 -c "import json,base64,sys; sys.stdout.buffer.write(base64.b64decode(json.load(open('$w/blob.bundle.json'))['messageSignature']['signature']))" >"$w/cosign.sig"
openssl ts -query -data "$w/cosign.sig" -sha256 -cert -out "$w/cq.tsq" 2>/dev/null
c=$(curl -sS -o "$w/cr.tsr" -w '%{http_code}' -H "Authorization: Bearer $T_alice" -H 'Content-Type: application/timestamp-query' --data-binary @"$w/cq.tsq" "$HUB/api/v1/tsa")
expect "POST /api/v1/tsa over cosign's signature" 200 "$c"
cp "$w/blob.bundle.json" "$w/blob.untimestamped.json"
python3 - "$w/blob.bundle.json" "$w/cr.tsr" <<'PY'
import json, base64, sys
d = json.load(open(sys.argv[1]))
d["verificationMaterial"]["timestampVerificationData"] = {"rfc3161Timestamps": [{"signedTimestamp": base64.b64encode(open(sys.argv[2], "rb").read()).decode()}]}
json.dump(d, open(sys.argv[1], "w"))
PY
PASS "RFC 3161 token added to the cosign bundle (timestampVerificationData.rfc3161Timestamps)"
openssl ts -query -data "$w/blob.sig" -sha256 -cert -out "$w/q.tsq" 2>/dev/null
c=$(curl -sS -o "$w/r.tsr" -w '%{http_code}' -H "Authorization: Bearer $T_alice" -H 'Content-Type: application/timestamp-query' --data-binary @"$w/q.tsq" "$HUB/api/v1/tsa")
expect "POST /api/v1/tsa (application/timestamp-query)" 200 "$c"
openssl ts -verify -data "$w/blob.sig" -in "$w/r.tsr" -CAfile "$P/tsa-root.pem" >"$w/ts-verify1.log" 2>&1 && PASS "openssl ts -verify (before expiry): $(cat "$w/ts-verify1.log")" || FAIL "openssl ts -verify: $(cat "$w/ts-verify1.log")"
openssl ts -reply -in "$w/r.tsr" -text >"$w/r.txt" 2>&1
GENTIME="$(grep -i '^Time stamp:' "$w/r.txt" | sed 's/^Time stamp: //')"
[ -n "$GENTIME" ] && PASS "token genTime: $GENTIME" || FAIL "no genTime in the reply"
c=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data '{}' "$HUB/api/v1/tsa"); expect "TSA without a Bearer (anonymous off)" 401 "$c"
c=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $T_alice" -H 'Content-Type: application/json' --data '{}' "$HUB/api/v1/tsa"); expect "TSA with the wrong content type" 415 "$c"
c=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $T_alice" "$HUB/api/v1/tsa"); expect "GET /tsa" 405 "$c"

STEP "B2. revoked-certificate semantics: issue B, timestamp, revoke B (still inside B's window)"
make_csr "$w/b.key" "$w/b.csr"
c=$(issue "$(idp_token $REPO $REF)" "$w/b.csr" "$w/b"); expect "issue certificate B" 201 "$c"
B_FP="$(jget 'd["data"]["fingerprint_sha256"]' <"$w/b.json")"; B_SERIAL="$(jget 'd["data"]["serial_number"]' <"$w/b.json")"
openssl dgst -sha256 -sign "$w/b.key" -out "$w/b.sig" "$w/blob.txt"
openssl ts -query -data "$w/b.sig" -sha256 -cert -out "$w/bq.tsq" 2>/dev/null
c=$(curl -sS -o "$w/br.tsr" -w '%{http_code}' -H "Authorization: Bearer $T_alice" -H 'Content-Type: application/timestamp-query' --data-binary @"$w/bq.tsq" "$HUB/api/v1/tsa"); expect "timestamp B's signature" 200 "$c"
sleep 1
c=$(code "$T_alice" -X POST "$HUB/api/v1/certificates/$B_FP/revoke" -d '{"reason_code":1}'); expect "revoke B (keyCompromise) through the existing path" 200 "$c"
c=$(code "$T_alice" "$HUB/api/v1/certificates/$B_FP"); expect "GET certificate B" 200 "$c"
B_REVOKED_AT="$(jget 'd["data"]["revoked_at"]' <"$RUN/last.json")"
[ -n "$B_REVOKED_AT" ] && [ "$B_REVOKED_AT" != None ] && PASS "inventory shows revoked_at=$B_REVOKED_AT" || FAIL "no revoked_at on B"
openssl ts -verify -data "$w/b.sig" -in "$w/br.tsr" -CAfile "$P/tsa-root.pem" >/dev/null 2>&1 && PASS "B's timestamp still verifies after the revocation (it proves existence-time only)" || FAIL "B's timestamp stopped verifying"
B_GEN="$(openssl ts -reply -in "$w/br.tsr" -text 2>&1 | grep -i '^Time stamp:' | sed 's/^Time stamp: //')"
python3 - "$B_GEN" "$B_REVOKED_AT" <<'PY' && PASS "genTime ($B_GEN) precedes revoked_at ($B_REVOKED_AT): the cut-off a verifier compares against" || FAIL "genTime does not precede revoked_at"
import sys, datetime
g = datetime.datetime.strptime(sys.argv[1].replace(" GMT", ""), "%b %d %H:%M:%S.%f %Y") if "." in sys.argv[1] else datetime.datetime.strptime(sys.argv[1].replace(" GMT", ""), "%b %d %H:%M:%S %Y")
r = datetime.datetime.fromisoformat(sys.argv[2].replace("Z", "+00:00")).replace(tzinfo=None)
sys.exit(0 if g <= r + datetime.timedelta(seconds=2) else 1)
PY
B_SERIAL_UP="$(printf '%s' "$B_SERIAL" | tr a-f A-F | sed 's/^0*//')"
CRL_OK=""
for _ in $(seq 1 20); do
  curl -sS -o "$w/ca.crl" "$HUB/crl/$CA_ID.crl" 2>/dev/null
  CA_CRL="$(openssl crl -inform DER -in "$w/ca.crl" -noout -text 2>&1)"
  if echo "$CA_CRL" | sed 's/^ *Serial Number: *0*//' | grep -qx "$B_SERIAL_UP" && echo "$CA_CRL" | grep -qi "Key Compromise"; then CRL_OK=1; break; fi
  sleep 1
done
[ -n "$CRL_OK" ] && PASS "the CA's CRL lists B ($B_SERIAL_UP) with reason keyCompromise (CRL/OCSP verifiers reject it)" || FAIL "B not on the CRL with keyCompromise: $(echo "$CA_CRL" | head -20 | tr '\n' ' ')"

STEP "B3. container and SBOM signing with a third certificate C (inside C's 45 s window)"
make_csr "$w/c.key" "$w/c.csr"
c=$(issue "$(idp_token $REPO $REF)" "$w/c.csr" "$w/c"); expect "issue certificate C" 201 "$c"
C_NOT_AFTER="$(cert_epoch -enddate "$w/c.cert.pem")"
COSIGN_PASSWORD="" "$COSIGN" import-key-pair --key "$w/c.key" --output-key-prefix "$w/ccs" >/dev/null 2>&1
if COSIGN_PASSWORD="" "$COSIGN" sign --key "$w/ccs.key" --certificate "$w/c.cert.pem" --tlog-upload=false --use-signing-config=false --yes "$IMAGE_PINNED" >"$w/cosign-img.log" 2>&1; then
  PASS "cosign sign <image@digest> --key --certificate --tlog-upload=false --use-signing-config=false"
else FAIL "cosign sign image: $(tail -3 "$w/cosign-img.log")"; fi
COSIGN_PASSWORD="" "$COSIGN" sign-blob --key "$w/ccs.key" --certificate "$w/c.cert.pem" --use-signing-config=false --tlog-upload=false --bundle "$w/sbom.bundle.json" "$RUN/sbom.cdx.json" >"$w/cosign-sbom.log" 2>&1 \
  && PASS "cosign sign-blob sbom.cdx.json --bundle" || FAIL "cosign sign-blob SBOM: $(tail -3 "$w/cosign-sbom.log")"
python3 -c "import json,base64,sys; sys.stdout.buffer.write(base64.b64decode(json.load(open('$w/sbom.bundle.json'))['messageSignature']['signature']))" >"$w/sbom.sig"
openssl ts -query -data "$w/sbom.sig" -sha256 -cert -out "$w/sq.tsq" 2>/dev/null
c=$(curl -sS -o "$w/sr.tsr" -w '%{http_code}' -H "Authorization: Bearer $T_alice" -H 'Content-Type: application/timestamp-query' --data-binary @"$w/sq.tsq" "$HUB/api/v1/tsa"); expect "timestamp the SBOM signature" 200 "$c"
python3 - "$w/sbom.bundle.json" "$w/sr.tsr" <<'PY'
import json, base64, sys
d = json.load(open(sys.argv[1]))
d["verificationMaterial"]["timestampVerificationData"] = {"rfc3161Timestamps": [{"signedTimestamp": base64.b64encode(open(sys.argv[2], "rb").read()).decode()}]}
json.dump(d, open(sys.argv[1], "w"))
PY
python3 - "$w" "$P" <<'PY'
import sys, json, re
w, P = sys.argv[1:3]
def ders(*paths):
    return [{"rawBytes": "".join(m.group(1).split())} for path in paths for m in re.finditer(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", open(path).read(), re.S)]
anchor = lambda uri, *paths: {"subject": {"organization": "Kryptkeeper UAT", "commonName": uri}, "uri": uri, "certChain": {"certificates": ders(*paths)}, "validFor": {"start": "2020-01-01T00:00:00Z"}}
json.dump({"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1", "tlogs": [], "ctlogs": [],
    "certificateAuthorities": [anchor("https://kk-cs-hub", w + "/c.chain.pem")],
    "timestampAuthorities": [anchor("https://kk-cs-hub/api/v1/tsa", P + "/tsa.pem", P + "/tsa-root.pem")]}, open(w + "/trusted_root.json", "w"))
PY
if "$COSIGN" verify --trusted-root "$w/trusted_root.json" --certificate-identity "https://github.com/$REPO@$REF" --certificate-oidc-issuer-regexp '.*' \
  --insecure-ignore-tlog --insecure-ignore-sct "$IMAGE_PINNED" >"$w/cosign-img-verify.log" 2>&1; then
  PASS "cosign verify <image@digest> (inside the certificate's window)"
else FAIL "cosign verify image: $(tail -3 "$w/cosign-img-verify.log")"; fi

STEP "C. refused tokens (run while A's certificate runs out)"
c=$(issue "$TOKA" "$w/a.csr" "$w/replay"); expect "replayed token refused" 401 "$c"
c=$(issue "$(idp_token evil/app $REF)" "$w/b.csr" "$w/x"); expect "token for another repo refused" 401 "$c"
c=$(issue "$(idp_token $REPO refs/heads/dev)" "$w/b.csr" "$w/x"); expect "token for another ref refused" 401 "$c"
if grep -q 'token refused' "$RUN/last.json" && ! grep -qiE 'no_matching_rule|replay|untrusted' "$RUN/last.json"; then PASS "401 body is generic"; else FAIL "401 body leaks a reason: $(cat "$RUN/last.json")"; fi
c=$(code "$T_alice" -X DELETE "$HUB/api/v1/codesign/oidc-trust-rules/no-such-rule"); expect "DELETE unknown rule" 404 "$c"

STEP "D. wait for certificate A to expire"
LAST_EXPIRY="$A_NOT_AFTER"; [ "$C_NOT_AFTER" -gt "$LAST_EXPIRY" ] && LAST_EXPIRY="$C_NOT_AFTER"
NOW="$(date +%s)"; WAIT=$(( LAST_EXPIRY - NOW + 2 ))
[ "$WAIT" -gt 0 ] && { echo "sleeping ${WAIT}s"; sleep "$WAIT"; }
openssl x509 -in "$w/a.cert.pem" -noout -checkend 0 >/dev/null 2>&1 && FAIL "certificate A has not expired" || PASS "certificate A has expired (openssl x509 -checkend 0 fails)"

STEP "E. verification after expiry"
openssl ts -verify -data "$w/blob.sig" -in "$w/r.tsr" -CAfile "$P/tsa-root.pem" >"$w/ts-verify2.log" 2>&1 && PASS "openssl ts -verify after expiry: $(cat "$w/ts-verify2.log")" || FAIL "openssl ts -verify after expiry: $(cat "$w/ts-verify2.log")"
openssl dgst -sha256 -verify "$w/a.pub" -signature "$w/blob.sig" "$w/blob.txt" >/dev/null && PASS "the signature itself verifies against the certificate key" || FAIL "signature"
# The chain check "as of the timestamp" is what a timestamp-aware verifier does.
openssl x509 -in "$w/a.chain.pem" -noout >/dev/null 2>&1 || true
GEN_EPOCH="$(python3 - "$GENTIME" <<'PY'
import sys, datetime
t = sys.argv[1].replace(" GMT", "")
fmt = "%b %d %H:%M:%S.%f %Y" if "." in t else "%b %d %H:%M:%S %Y"
print(int(datetime.datetime.strptime(t, fmt).replace(tzinfo=datetime.timezone.utc).timestamp()))
PY
)"
if openssl verify -attime "$GEN_EPOCH" -purpose codesign -CAfile "$w/a.chain.pem" "$w/a.cert.pem" >"$w/verify-at.log" 2>&1; then PASS "chain verifies as of the timestamp ($GENTIME): $(tail -1 "$w/verify-at.log")"; else FAIL "chain as of the timestamp: $(cat "$w/verify-at.log")"; fi
if openssl verify -purpose codesign -CAfile "$w/a.chain.pem" "$w/a.cert.pem" >"$w/verify-now.log" 2>&1; then FAIL "chain verified now WITHOUT a timestamp: the expired certificate should fail"; elif ! grep -qi "has expired" "$w/verify-now.log"; then FAIL "negative: verification failed now, but not because the certificate expired: $(cat "$w/verify-now.log")"; else PASS "negative: without the timestamp the expired certificate FAILS ($(grep -i error "$w/verify-now.log" | head -1))"; fi

STEP "F. cosign verification after expiry"
A_SERIAL="$(jget 'd["data"]["serial_number"]' <"$w/a.json")"
python3 - "$w" "$P" "$IDP_URL" <<'PY'
import sys, json, re
w, P, issuer = sys.argv[1:4]
def ders(*paths):
    out = []
    for path in paths:
        for m in re.finditer(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", open(path).read(), re.S):
            out.append({"rawBytes": "".join(m.group(1).split())})
    return out
anchor = lambda uri, *paths: {"subject": {"organization": "Kryptkeeper UAT", "commonName": uri}, "uri": uri,
    "certChain": {"certificates": ders(*paths)}, "validFor": {"start": "2020-01-01T00:00:00Z"}}
json.dump({"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1", "tlogs": [], "ctlogs": [],
    "certificateAuthorities": [anchor("https://kk-cs-hub", w + "/a.chain.pem")],
    "timestampAuthorities": [anchor("https://kk-cs-hub/api/v1/tsa", P + "/tsa.pem", P + "/tsa-root.pem")]}, open(w + "/trusted_root.json", "w"))
PY
IDENTITY="https://github.com/$REPO@$REF"
CV=("$COSIGN" verify-blob --trusted-root "$w/trusted_root.json" --certificate-identity "$IDENTITY" --certificate-oidc-issuer-regexp '.*' --insecure-ignore-tlog --insecure-ignore-sct)
if "${CV[@]}" --certificate-oidc-issuer "$IDP_URL" --use-signed-timestamps --bundle "$w/blob.bundle.json" "$w/blob.txt" >"$w/cv-strict.log" 2>&1; then
  FAIL "cosign accepted --certificate-oidc-issuer on a certificate without the Fulcio issuer extension"
else
  echo "INFO: with an exact --certificate-oidc-issuer cosign refuses: $(grep -i 'error' "$w/cv-strict.log" | head -1 | cut -c1-200)"
fi
if "${CV[@]}" --use-signed-timestamps --bundle "$w/blob.bundle.json" "$w/blob.txt" >"$w/cv-ok.log" 2>&1; then
  PASS "cosign verify-blob after expiry: trusted root + identity $IDENTITY + --use-signed-timestamps ($(tail -1 "$w/cv-ok.log"); cosign $(cosign version 2>&1 | grep GitVersion | awk '{print $2}'))"
else FAIL "cosign verify-blob after expiry: $(tail -3 "$w/cv-ok.log")"; fi
"${CV[@]}" --use-signed-timestamps --bundle "$w/blob.untimestamped.json" "$w/blob.txt" >"$w/cv-nots.log" 2>&1 \
  && FAIL "cosign verified the expired certificate WITHOUT a timestamp" || PASS "negative: without the RFC 3161 timestamp cosign refuses the expired certificate ($(grep -i error "$w/cv-nots.log" | head -1 | cut -c1-140))"
cp "$w/blob.txt" "$w/tampered.txt"; echo x >>"$w/tampered.txt"
"${CV[@]}" --use-signed-timestamps --bundle "$w/blob.bundle.json" "$w/tampered.txt" >/dev/null 2>&1 && FAIL "cosign verified a tampered blob" || PASS "cosign refuses a tampered blob"
"${CV[@]/$IDENTITY/https://github.com/evil/app@$REF}" --use-signed-timestamps --bundle "$w/blob.bundle.json" "$w/blob.txt" >/dev/null 2>&1 && FAIL "cosign accepted another repo's identity" || PASS "cosign refuses another repo's identity"

C_BUNDLE_CV=("$COSIGN" verify-blob --trusted-root "$w/trusted_root.json" --certificate-identity "$IDENTITY" --certificate-oidc-issuer-regexp '.*' --insecure-ignore-tlog --insecure-ignore-sct --use-signed-timestamps)
openssl x509 -in "$w/c.cert.pem" -noout -checkend 0 >/dev/null 2>&1 && FAIL "certificate C has not expired"
"${C_BUNDLE_CV[@]}" --bundle "$w/sbom.bundle.json" "$RUN/sbom.cdx.json" >"$w/cv-sbom.log" 2>&1 \
  && PASS "cosign verify-blob sbom.cdx.json after C expired ($(tail -1 "$w/cv-sbom.log"))" || FAIL "SBOM verification after expiry: $(tail -3 "$w/cv-sbom.log")"

STEP "G. jarsigner"
if java -version >/dev/null 2>&1 && command -v jarsigner >/dev/null 2>&1; then
  echo "INFO: a JDK is present but the jar path is exercised only by the documented README procedure"
  PASS "JDK present"
else
  echo "INFO: no JDK on this host (jarsigner is the macOS stub); the jarsigner -tsa path is NOT tested here"
fi

STEP "H. audit trail"
c=$(code "$T_alice" "$HUB/api/v1/audit?action=codesign.issue&limit=100"); expect "GET /audit?action=codesign.issue" 200 "$c"
python3 - "$RUN/last.json" "$REPO" "$REF" "$A_SERIAL" <<'PY' && PASS "codesign.issue success row carries repo, ref and the certificate serial; refusals are denied rows with issuer and reason" || FAIL "codesign.issue audit rows incomplete"
import json, sys
rows = json.load(open(sys.argv[1]))["data"]
repo, ref, serial = sys.argv[2:5]
ok = [r for r in rows if r["outcome"] == "success" and f'repo="{repo}"' in r["change_summary"] and f'ref="{ref}"' in r["change_summary"] and f"serial={serial}" in r["change_summary"]]
denied = [r for r in rows if r["outcome"] == "denied" and "issuer=" in r["change_summary"] and "reason=" in r["change_summary"]]
reasons = sorted({r["change_summary"].split("reason=")[1].split()[0] for r in denied})
print("success rows:", len(ok), "denied reasons:", reasons)
sys.exit(0 if ok and {"replay", "no_matching_rule"} <= set(reasons) else 1)
PY
DIGEST="$(openssl dgst -sha256 -hex "$w/blob.sig" | awk '{print $NF}')"
c=$(code "$T_alice" "$HUB/api/v1/audit?action=codesign.timestamp&limit=100"); expect "GET /audit?action=codesign.timestamp" 200 "$c"
grep -q "digest=$DIGEST" "$RUN/last.json" && PASS "codesign.timestamp row carries the digest of the timestamped signature" || FAIL "no codesign.timestamp row with digest $DIGEST"
c=$(code "$T_alice" "$HUB/api/v1/audit?action=codesign.trust_rule_create&limit=10"); expect "GET /audit?action=codesign.trust_rule_create" 200 "$c"
grep -q 'proposed_by=alice' "$RUN/last.json" && grep -q 'approved_by=bob' "$RUN/last.json" && PASS "trust rule creation audited with proposer alice and approver bob" || FAIL "trust rule audit lacks proposer/approver"

echo
if [ "$FAILED" = 0 ]; then echo "RESULT: all steps passed"; else echo "RESULT: FAILED"; fi
exit "$FAILED"
