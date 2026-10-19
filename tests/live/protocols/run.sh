#!/usr/bin/env bash
# W19-05: prove EST/SCEP/CMP issuance and OCSP/CRL-after-revocation against
# REAL third-party clients (not the fakes-only protocol test suite).
#
# W19-31: since W19-14 the hub self-issues a TLS listener by default
# whenever APP_CERTIFICATE_PROVIDER=ca, and it serves EST/SCEP/CMP/OCSP/CRL
# and the admin API all on that ONE listener -- there is no way to run part
# of the mux over plain HTTP and part over TLS. KRYPTKEEPER_TLS_DISABLE=true
# is no longer used here: it made EST fail by spec (RFC 7030 mandates TLS)
# while tests/live/tls/run.sh already proves EST works fine once the hub
# actually serves TLS. This fixture now runs the hub in the SAME
# self-issued TLS mode as tests/live/tls/run.sh and gives every real client
# the hub's own CA, exported the same way that fixture does (unauthenticated
# EST cacerts, PKCS#7-decoded to PEM) -- never an --insecure/-k flag past
# the initial bootstrap fetch, per CLAUDE.md's rule against loosening a
# verification path.
#
# Idempotent, PASS/FAIL per step, non-zero exit on any FAIL, cleans up its
# own hub process/state on exit (trap). No real key material is ever
# committed: every key is generated fresh into a temp dir per run.
#
# Podman only (no docker); containers reach the host hub at
# host.containers.internal:$HUB_PORT.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$(dirname "${BASH_SOURCE[0]}")/../podman-host.sh"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-protocols.XXXXXX)"
HUB_DIR="$WORK/hub"
HUB_PORT="${HUB_PORT:-8096}"
HUB_BASE="https://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
SCEP_CN=uat-scep-leaf.scep.uat.example
CMP_SECRET=uat-cmp-secret
CMP_REFERENCE=kk-uat
GOLANG_IMG=docker.io/library/golang:1.23-alpine
ALPINE_IMG=docker.io/library/alpine:latest

# W19-31/podman-macOS gotcha: podman machine on macOS only virtiofs-mounts
# $HOME (/Users), not /tmp -- any file bind-mounted into a container (the
# exported CA here) must live under $HOME, not under $WORK. Mirrors
# tests/live/agent/run.sh's CA_EXPORT_DIR.
CA_EXPORT_DIR="$(mktemp -d "$HOME/.kk-uat-protocols-ca.XXXXXX")"
CA_PEM="$CA_EXPORT_DIR/hub-ca.pem"

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

HUB_PID=""
cleanup() {
  STEP "cleanup"
  [ -n "$HUB_PID" ] && kill "$HUB_PID" >/dev/null 2>&1 || true
  [ -n "$HUB_PID" ] && wait "$HUB_PID" >/dev/null 2>&1 || true
  # On failure, the hub's own protocol log lines say why before $WORK goes.
  if [ "${FAILED:-0}" = 1 ] && [ -f "$WORK/hub.log" ]; then
    echo "--- hub.log (protocol lines, last 40) ---"
    grep -E "scep|est|cmp|SCEP|EST|CMP" "$WORK/hub.log" | tail -40
  fi
  rm -rf "$WORK" "$CA_EXPORT_DIR"
  rm -rf "$HERE"/.scep-out.*
}
trap cleanup EXIT

curlj() { curl -sS --cacert "$CA_PEM" -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
# curlc <token> curl-args...: prints the HTTP status, body in $WORK/last.json.
curlc() { local tok="$1"; shift; curl -sS --cacert "$CA_PEM" -o "$WORK/last.json" -w '%{http_code}' -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

# W26-11: one named pki-admin (alice) from APP_API_KEYS_JSON approves the CMP
# poll item. The bootstrap token can propose but never approve
# (internal/bootstrap/separation_of_duties.go), so it cannot stand in.
API_PEPPER="uat-pepper-32-characters-minimum!!"
ALICE_SECRET="$(openssl rand -hex 24)"
ALICE_VERIFIER="$(printf '%s' "$ALICE_SECRET" | openssl dgst -sha256 -hmac "$API_PEPPER" -hex | awk '{print $NF}')"
T_alice="kk_uatalice_${ALICE_SECRET}"

# ---------------------------------------------------------------------------
# 1. Build and start the hub, self-issuing TLS from its own default CA, with
#    EST/SCEP/CMP/OCSP/CRL mounted.
# ---------------------------------------------------------------------------
STEP "build hub"
mkdir -p "$HUB_DIR/data"
(cd "$REPO_ROOT" && go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper) \
  && PASS "hub built" || DIE "go build ./cmd/kryptkeeper failed"

STEP "start hub on :$HUB_PORT (TLS self-issued from the hub's own CA)"
export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file
export APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!'
export KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" APP_CA_FILE="$HUB_DIR/data/cas.json" \
  APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" \
  APP_AUDIT_FILE="$HUB_DIR/data/audit.json" APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json"
export KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA"
export APP_BIND_ADDR=0.0.0.0 PORT="$HUB_PORT" KRYPTKEEPER_BASE_URL="https://host.containers.internal:${HUB_PORT}"
export KRYPTKEEPER_TLS_SELF_ISSUE=true
# EST needs a credential (W20-14, D-112): the estcheck client enrolls with
# HTTP Basic from the test users fixture, then re-enrolls with the TLS client
# certificate it just received, which needs client-certificate requests.
export KRYPTKEEPER_EST_USERS_FILE="$(cd "$(dirname "$0")" && pwd)/est-users.json"
export KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT=true
export KRYPTKEEPER_TLS_SANS="host.containers.internal,localhost,127.0.0.1"
export KRYPTKEEPER_SCEP_ENABLED=true
export KRYPTKEEPER_CMP_SECRET="$CMP_SECRET" KRYPTKEEPER_CMP_REFERENCE="$CMP_REFERENCE"
export APP_API_KEY_AUTH_ENABLED=true APP_API_KEY_PEPPER="$API_PEPPER" \
  APP_API_KEYS_JSON="[{\"name\":\"alice\",\"kid\":\"uatalice\",\"secret_verifier\":\"$ALICE_VERIFIER\",\"principal_id\":\"alice\",\"role\":\"pki-admin\",\"active\":true}]"

"$WORK/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
for _ in $(seq 1 30); do
  curl -sSk -o /dev/null "$HUB_BASE/healthz" && break
  sleep 0.5
done
curl -sSk "$HUB_BASE/healthz" | grep -q '"status":"ok"' \
  && PASS "hub healthy over TLS (pid $HUB_PID, insecure curl -- socket speaks TLS at all)" \
  || DIE "hub did not come up, see $WORK/hub.log"

# W19-31: export the hub's self-issued CA the same way tests/live/tls/run.sh
# does -- unauthenticated EST cacerts (RFC 7030 bootstrap-of-trust-anchors),
# PKCS#7-decoded to a plain PEM -- so every client below can be given a real
# trust anchor instead of an --insecure/-k flag.
curl -sSk --max-time 3 -o "$WORK/cacerts.b64" "$HUB_BASE/.well-known/est/cacerts" \
  && openssl base64 -d -A -in "$WORK/cacerts.b64" -out "$WORK/cacerts.p7" \
  && openssl pkcs7 -inform der -in "$WORK/cacerts.p7" -print_certs -out "$CA_PEM" \
  && [ -s "$CA_PEM" ] \
  && PASS "exported the hub's self-issued CA via EST cacerts to $CA_PEM" \
  || DIE "could not fetch/decode the hub's CA cert via EST cacerts"
cp "$CA_PEM" "$WORK/ca.pem"

CA_ID="$(curlj "$HUB_BASE/api/v1/cas" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"][0]["id"])')"
[ -n "$CA_ID" ] && PASS "root CA id=$CA_ID" || DIE "could not resolve root CA id"

# ---------------------------------------------------------------------------
# 1b. W19-15: SCEP's PKCS#7 envelope key-wraps the CSR to the CA's public
#     key, which has no EC analogue -- the bootstrap default root above is
#     ECDSA P-256, so SCEP cannot use it (main.go refuses to enable SCEP on
#     a non-RSA CA at all, rather than silently degrading). Create a
#     dedicated RSA-2048 root via the live API and restart the hub with
#     KRYPTKEEPER_SCEP_CA_ID pointed at it -- same HUB_DIR, so the keystore,
#     existing CA and the self-issued TLS listener cert (persisted under
#     KRYPTKEEPER_DATA_DIR/tls/, reused since its SANs are unchanged)
#     survive the restart.
# ---------------------------------------------------------------------------
STEP "create RSA-2048 CA for SCEP"
SCEP_CA_ID="$(curlj -X POST "$HUB_BASE/api/v1/cas" -d '{"name":"uat-scep-rsa-root","type":"root","algorithm":"RSA-2048","validity":"10y","subject_cn":"UAT SCEP RSA Root"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])')"
[ -n "$SCEP_CA_ID" ] && PASS "RSA CA created id=$SCEP_CA_ID" || DIE "could not create RSA CA for SCEP"

STEP "restart hub with KRYPTKEEPER_SCEP_CA_ID=$SCEP_CA_ID"
kill "$HUB_PID" >/dev/null 2>&1
wait "$HUB_PID" 2>/dev/null
export KRYPTKEEPER_SCEP_CA_ID="$SCEP_CA_ID"
"$WORK/kryptkeeper" >>"$WORK/hub.log" 2>&1 &
HUB_PID=$!
for _ in $(seq 1 30); do
  curl -sSk -o /dev/null "$HUB_BASE/healthz" && break
  sleep 0.5
done
curl -sS --cacert "$CA_PEM" "$HUB_BASE/healthz" | grep -q '"status":"ok"' \
  && PASS "hub restarted with RSA SCEP CA (pid $HUB_PID, real chain verification, no -k)" \
  || DIE "hub did not come back up after restart, see $WORK/hub.log"
grep -q "SCEP endpoint: /scep" "$WORK/hub.log" \
  && PASS "SCEP enabled on restart (RSA CA accepted)" || DIE "SCEP did not enable against the RSA CA, see $WORK/hub.log"

curl -sS --cacert "$CA_PEM" "$HUB_BASE/scep?operation=getcacert" -o "$WORK/scep-ca.der"
openssl x509 -inform der -in "$WORK/scep-ca.der" -out "$WORK/scep-ca.pem" 2>/dev/null \
  && PASS "fetched SCEP (RSA) CA cert" || DIE "could not fetch/convert SCEP CA cert"

curlj "$HUB_BASE/api/v1/cas/$CA_ID/chain?format=pem" -o "$WORK/ca.pem"
openssl x509 -in "$WORK/ca.pem" -noout -subject >/dev/null 2>&1 \
  && PASS "fetched default (ECDSA) CA cert for OCSP/CRL" || DIE "could not fetch default CA cert"

# ---------------------------------------------------------------------------
# 2. EST -- real client: github.com/globalsign/est (the library cmd/estclient
#    wraps; the CLI itself fails to build today because its optional
#    crypto11/PKCS#11 path does not compile against the pkcs11 version
#    `go install @latest` resolves -- unrelated to Kryptkeeper, so we use the
#    library directly, which is the same RFC 7030 client code path).
#    estcheck/ bootstraps its own trust from an unverified cacerts fetch (see
#    estcheck/main.go), so it needs no CA file mounted here -- W19-31 only
#    changed EST_HOST to reach an https hub, unchanged since tests/live/tls.
# ---------------------------------------------------------------------------
STEP "EST: real client (globalsign/est) against /.well-known/est/ (TLS)"
podman run ${KK_PODMAN_HOST_ARGS} --rm \
  -v "$HERE/estcheck:/src:ro" -v "$HERE/est-run.sh:/est-run.sh:ro" \
  -e EST_HOST="host.containers.internal:${HUB_PORT}" -e EST_USER=uat-est -e EST_PASS=uat-est-password \
  "$GOLANG_IMG" sh /est-run.sh >"$WORK/est.log" 2>&1
cat "$WORK/est.log"
if grep -q "PASS enroll" "$WORK/est.log"; then
  PASS "EST enroll via globalsign/est"
else
  FAIL "EST: real client cannot complete (see $WORK/est.log)."
fi

# ---------------------------------------------------------------------------
# 2b. W26-11: EST label routes (W26-06). A label publishes
#     /.well-known/est/<label>/ bound to one template; the template's
#     enrollment_permissions must list the pseudo role protocol:est. The same
#     globalsign/est client enrolls on the label path (AdditionalPathSegment).
# ---------------------------------------------------------------------------
STEP "EST labels: bind labels to templates through POST /api/v1/est/labels"
mktpl_est() { # mktpl_est <name> <enroll roles json> -> prints template id
  curlj -X POST "$HUB_BASE/api/v1/templates" -d "{\"name\":\"$1\",\"display_name\":\"$1\",\"validity_period\":\"P365D\",\"key_usage\":[\"digitalSignature\"],\"extended_key_usage\":[\"clientAuth\"],\"allowed_algorithms\":[\"ECDSA\",\"RSA\"],\"active\":true,\"enrollment_permissions\":{\"enroll\":$2}}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])'
}
EST_LBL_TPL="$(mktpl_est est-label-tpl '["protocol:est"]')"
EST_DENY_TPL="$(mktpl_est est-denied-tpl '["pki-admin"]')"
[ -n "$EST_LBL_TPL" ] && [ -n "$EST_DENY_TPL" ] && PASS "templates created: est-label-tpl ($EST_LBL_TPL, allows protocol:est), est-denied-tpl ($EST_DENY_TPL, pki-admin only)" || DIE "could not create EST label templates"
c=$(curlc "$TOKEN" -X POST "$HUB_BASE/api/v1/est/labels" -d "{\"label\":\"uat-label\",\"template_id\":\"$EST_LBL_TPL\",\"description\":\"W26-11 live label\"}")
[ "$c" = 201 ] && PASS "label uat-label created (201)" || FAIL "create label uat-label -> $c $(cat "$WORK/last.json")"
c=$(curlc "$TOKEN" -X POST "$HUB_BASE/api/v1/est/labels" -d "{\"label\":\"uat-denied\",\"template_id\":\"$EST_DENY_TPL\"}")
[ "$c" = 201 ] && PASS "label uat-denied created (201)" || FAIL "create label uat-denied -> $c $(cat "$WORK/last.json")"
c=$(curlc "$TOKEN" "$HUB_BASE/api/v1/est/labels")
[ "$c" = 200 ] && [ "$(jget 'sorted(l["label"] for l in d["data"])' <"$WORK/last.json")" = "['uat-denied', 'uat-label']" ] \
  && PASS "GET /api/v1/est/labels lists both labels" || FAIL "label list -> $c $(cat "$WORK/last.json")"

est_label_run() { # est_label_run <logname> <label> <cn> <expect: ""|refuse>
  podman run ${KK_PODMAN_HOST_ARGS} --rm \
    -v "$HERE/estcheck:/src:ro" -v "$HERE/est-run.sh:/est-run.sh:ro" \
    -e EST_HOST="host.containers.internal:${HUB_PORT}" -e EST_USER=uat-est -e EST_PASS=uat-est-password \
    -e EST_LABEL="$2" -e EST_CN="$3" -e EST_EXPECT="$4" -e EST_REENROLL=0 \
    "$GOLANG_IMG" sh /est-run.sh >"$WORK/$1.log" 2>&1
  cat "$WORK/$1.log"
}
EST_LABEL_CN=uat-est-label.est.uat.example
STEP "EST labels: enroll on the label path with a name under the user's suffix"
est_label_run est-label uat-label "$EST_LABEL_CN" ""
grep -q "PASS enroll" "$WORK/est-label.log" && PASS "globalsign/est enrolled on /.well-known/est/uat-label/" || FAIL "EST label enroll failed (see $WORK/est-label.log)"
LBL_TPL_SEEN="$(curlj "$HUB_BASE/api/v1/certificates?q=$EST_LABEL_CN&limit=10" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; print(" ".join(c["template_id"]+"/"+c["source"] for c in d))')"
case "$LBL_TPL_SEEN" in *"$EST_LBL_TPL/est"*) PASS "the issued certificate is in inventory with template_id est-label-tpl, source=est" ;; *) FAIL "label-issued cert not tied to est-label-tpl: [$LBL_TPL_SEEN]" ;; esac

STEP "EST labels: refused outside the user's suffix, refused without protocol:est, unknown label 404"
est_label_run est-label-out uat-label uat-est-evil.other.example refuse
grep -q "PASS refused" "$WORK/est-label-out.log" && PASS "a name outside the allowed suffix is refused on the label path" || FAIL "outside-suffix enroll was not refused (see $WORK/est-label-out.log)"
est_label_run est-label-denied uat-denied uat-est-denied.est.uat.example refuse
grep -q "PASS refused" "$WORK/est-label-denied.log" && PASS "a label whose template does not list protocol:est refuses a valid name (403)" || FAIL "label without protocol:est enrolled (see $WORK/est-label-denied.log)"
c=$(curl -sS --cacert "$CA_PEM" -o /dev/null -w '%{http_code}' "$HUB_BASE/.well-known/est/nolabel/cacerts")
[ "$c" = 404 ] && PASS "an unknown label answers 404" || FAIL "unknown label -> $c, want 404"

# ---------------------------------------------------------------------------
# 3. SCEP -- real client: micromdm/scep (a maintained Go reimplementation of
#    Cisco's sscep protocol handling; builds cleanly, unlike sscep's autotools
#    build which needs libssl-dev headers not worth vendoring for one step).
#
#    W19-31: classic SCEP (RFC 8894) is a plain-HTTP protocol -- the message
#    itself carries its own PKCS#7 crypto -- but the hub serves everything,
#    SCEP included, on the single TLS listener above, so this client has to
#    speak HTTPS too. micromdm/scep's scepclient has NO flag for a custom CA
#    bundle or for skipping verification at all (checked: `scepclient -help`
#    lists no -cacert/-insecure/-tls-* option; scepclient.New ->
#    scepserver.MakeClientEndpoints uses Go's http.DefaultClient verbatim).
#    The one way to hand it our CA without an --insecure flag is the
#    supported Go/OS mechanism for this exact situation: SSL_CERT_FILE,
#    which crypto/x509's Unix SystemCertPool() reads to *replace* (not
#    append to) the root pool a bare http.Client verifies against -- this is
#    the same mechanism `update-ca-certificates` relies on, not a bypass.
# ---------------------------------------------------------------------------
STEP "SCEP: mint one-time challenges (W20-16)"
mint_scep() {
  curlj -X POST "$HUB_BASE/api/v1/scep/challenges" -d "{\"common_name\":\"$1\",\"dns_names\":[\"$1\"],\"ttl\":\"15m\"}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["challenge"])'
}
SCEP_CHALLENGE="$(mint_scep "$SCEP_CN")"
SCEP_BOUND_CN=uat-scep-bound.scep.uat.example
SCEP_CHALLENGE2="$(mint_scep "$SCEP_BOUND_CN")"
[ "${#SCEP_CHALLENGE}" -eq 64 ] && [ "${#SCEP_CHALLENGE2}" -eq 64 ] \
  && PASS "minted two one-time challenges via POST /api/v1/scep/challenges" || DIE "could not mint SCEP challenges"
LIST_JSON="$(curlj "$HUB_BASE/api/v1/scep/challenges")"
case "$LIST_JSON" in *"$SCEP_CHALLENGE"*) FAIL "GET /api/v1/scep/challenges exposes a challenge secret" ;; *) PASS "challenge list carries no secrets" ;; esac

STEP "SCEP: real client (micromdm/scep) against /scep (RSA CA, TLS)"
# scep-out lives under $HERE (inside the repo, under $HOME), not $WORK
# (/tmp) -- podman machine on macOS only bind-mounts $HOME into its VM.
SCEP_OUT="$HERE/.scep-out.$$"
mkdir -p "$SCEP_OUT"
podman run ${KK_PODMAN_HOST_ARGS} --rm \
  -v "$HERE/scep-run.sh:/scep-run.sh:ro" \
  -v "$SCEP_OUT:/out" \
  -v "$CA_PEM:/ca.pem:ro" \
  -e SCEP_URL="https://host.containers.internal:${HUB_PORT}/scep" \
  -e SCEP_CHALLENGE="$SCEP_CHALLENGE" -e SCEP_CHALLENGE2="$SCEP_CHALLENGE2" -e SCEP_CN="$SCEP_CN" \
  -e SSL_CERT_FILE=/ca.pem \
  "$GOLANG_IMG" sh /scep-run.sh >"$WORK/scep.log" 2>&1
grep -v -e "$SCEP_CHALLENGE" -e "$SCEP_CHALLENGE2" "$WORK/scep.log"
if grep -q "cacertlist count=1" "$WORK/scep.log"; then
  PASS "SCEP getcacert via micromdm/scep"
else
  FAIL "SCEP getcacert: real client could not fetch/parse the CA cert (see $WORK/scep.log)"
fi
scep_result() { grep "^RESULT $1 " "$WORK/scep.log" | head -1; }
case "$(scep_result first)" in
  *"issued subject=CN=$SCEP_CN "*)
    PASS "SCEP enroll via micromdm/scep with a one-time challenge (RSA CA, real PKCS#7 PKIOperation, over TLS)"
    if openssl verify -CAfile "$WORK/scep-ca.pem" "$SCEP_OUT/first.pem" >"$WORK/scep-verify.log" 2>&1; then
      PASS "SCEP-issued certificate chains to the RSA SCEP CA"
    else
      FAIL "SCEP-issued certificate does not chain to the RSA SCEP CA: $(cat "$WORK/scep-verify.log")"
    fi
    STEP "inventory: SCEP-issued cert appears with source=scep"
    SCEP_SOURCES="$(curlj "$HUB_BASE/api/v1/certificates?limit=25" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(c["source"] for c in d["data"]))')"
    case "$SCEP_SOURCES" in *scep*) PASS "GET /api/v1/certificates lists the SCEP issuance, source=scep" ;; *) FAIL "SCEP-issued cert missing from inventory (source=scep not found): [$SCEP_SOURCES]" ;; esac
    ;;
  *) FAIL "SCEP enroll with a fresh challenge: $(scep_result first) (see $WORK/scep.log)" ;;
esac
case "$(scep_result reuse)" in *refused*) PASS "SCEP: a used challenge is refused" ;; *) FAIL "SCEP: a used challenge enrolled again: $(scep_result reuse)" ;; esac
case "$(scep_result wrong)" in *refused*) PASS "SCEP: a challenge the hub never minted is refused" ;; *) FAIL "SCEP: an unminted challenge enrolled: $(scep_result wrong)" ;; esac
case "$(scep_result bound)" in
  *"issued subject=CN=$SCEP_BOUND_CN "*) PASS "SCEP: a CSR naming Administrator is issued the challenge's name ($SCEP_BOUND_CN)" ;;
  *) FAIL "SCEP: bound-name enrollment: $(scep_result bound)" ;;
esac
SCEP_AUDIT="$(curlj "$HUB_BASE/api/v1/audit?limit=50" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; rows=d if isinstance(d,list) else d.get("entries",d.get("items",[])); print(" ".join(r["action"]+":"+r["outcome"] for r in rows if r["action"].startswith("scep.")))')"
case "$SCEP_AUDIT" in
  *"scep.enroll:denied"*"scep.enroll:success"*|*"scep.enroll:success"*"scep.enroll:denied"*) PASS "SCEP enrollments audited, success and denied: [$SCEP_AUDIT]" ;;
  *) FAIL "SCEP audit rows missing: [$SCEP_AUDIT]" ;;
esac

STEP "SCEP renewal (W26-30): RenewalReq signed by the current certificate"
case "$(scep_result renew)" in
  *"issued old_serial="*"subject=CN=$SCEP_CN"*)
    PASS "SCEP renewal signed by the current cert is issued (same CN, new serial)"
    if openssl verify -CAfile "$WORK/scep-ca.pem" "$SCEP_OUT/renew.pem" >"$WORK/scep-verify2.log" 2>&1; then
      PASS "the renewed certificate chains to the RSA SCEP CA"
    else
      FAIL "renewed certificate does not chain to the SCEP CA: $(cat "$WORK/scep-verify2.log")"
    fi
    ;;
  *) FAIL "SCEP renewal: $(scep_result renew) (see $WORK/scep.log)" ;;
esac
case "$(scep_result renew-rogue)" in *refused*) PASS "SCEP renewal signed by an unrelated key is refused" ;; *) FAIL "SCEP renewal with an unrelated key: $(scep_result renew-rogue)" ;; esac
case "$(scep_result renew-foreign)" in *refused*) PASS "SCEP RenewalReq from a self-signed certificate the CA never issued is refused" ;; *) FAIL "SCEP renewal with a foreign cert: $(scep_result renew-foreign)" ;; esac
case "$(scep_result replay)" in *refused*) PASS "SCEP: the used challenge still fails after the renewal (replay refused)" ;; *) FAIL "SCEP: challenge replay after renewal: $(scep_result replay)" ;; esac
SCEP_RENEW_AUDIT="$(curlj "$HUB_BASE/api/v1/audit?limit=100" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; rows=d if isinstance(d,list) else d.get("entries",d.get("items",[])); print(" ".join(r["action"]+":"+r["outcome"] for r in rows if r["action"]=="scep.renew"))')"
case "$SCEP_RENEW_AUDIT" in
  *"scep.renew:success"*) case "$SCEP_RENEW_AUDIT" in *"scep.renew:denied"*) PASS "scep.renew audited, success and denied: [$SCEP_RENEW_AUDIT]" ;; *) FAIL "no scep.renew denied row: [$SCEP_RENEW_AUDIT]" ;; esac ;;
  *) FAIL "no scep.renew success row: [$SCEP_RENEW_AUDIT]" ;;
esac

# ---------------------------------------------------------------------------
# 4. CMP -- real client: OpenSSL 3's `openssl cmp` app (RFC 4210/6712).
#    W19-31: -tls_used enables the client's TLS connection options;
#    -tls_trusted is the actual trust-anchor flag (verified via `openssl cmp
#    -help` inside the alpine container this step runs in -- there is no
#    plain `-trusted` flag, that name only exists for CMP message-signer
#    verification, a separate concern from the transport).
# ---------------------------------------------------------------------------
STEP "CMP: real client (openssl cmp -cmd ir / kur / rr) against /cmp (TLS)"
CMP_OUT="$HERE/.scep-out.cmp.$$" # under $HOME like SCEP_OUT; removed with .scep-out.* in cleanup
mkdir -p "$CMP_OUT"
podman run ${KK_PODMAN_HOST_ARGS} --rm \
  -v "$HERE/cmp-run.sh:/cmp-run.sh:ro" \
  -v "$CMP_OUT:/out" \
  -v "$CA_PEM:/ca.pem:ro" \
  -e CMP_URL="https://host.containers.internal:${HUB_PORT}/cmp" \
  -e CMP_SECRET="$CMP_SECRET" \
  -e CMP_REFERENCE="$CMP_REFERENCE" \
  -e CMP_CA=/ca.pem \
  "$ALPINE_IMG" sh /cmp-run.sh >"$WORK/cmp.log" 2>&1
cat "$WORK/cmp.log"
if grep -q "IR_RC=0" "$WORK/cmp.log" && grep -q "leaf.pem (ir succeeded)" "$WORK/cmp.log"; then
  PASS "CMP ir via openssl cmp (protected with -secret/-ref, POPO verified, over TLS)"
else
  FAIL "CMP ir: real client's request is rejected (see $WORK/cmp.log)."
fi
if grep -q "WRONGSECRET_REJECTED=1" "$WORK/cmp.log"; then
  PASS "CMP ir with wrong -secret is rejected"
else
  FAIL "CMP ir with a wrong shared secret was not rejected -- see $WORK/cmp.log"
fi
if grep -q "UNPROTECTED_REJECTED=1" "$WORK/cmp.log"; then
  PASS "CMP ir with -unprotected_requests is rejected"
else
  FAIL "CMP ir with no message protection was not rejected -- see $WORK/cmp.log"
fi
if grep -q "KUR_RC=0" "$WORK/cmp.log" && grep -q "kur.pem (kur succeeded)" "$WORK/cmp.log"; then
  PASS "CMP kur via openssl cmp"
else
  echo "FINDING: CMP kur did not succeed with -secret/-ref alone -- see $WORK/cmp.log. internal/cmp only implements RFC 4210 section 5.1.3.1 PasswordBasedMac protection (see docs/STATUS.md W19-16); section 5.1.3.2 signature-based protection (the client's existing certificate+key, which is what a real kur normally authenticates with) is not implemented. This is a documented gap, not a fixture bug."
fi

STEP "CMP rr (W26-08): revoke with the shared secret, OCSP and CRL show it"
if grep -q "RR_BADSECRET_REJECTED=1" "$WORK/cmp.log"; then PASS "CMP rr with a wrong -secret is rejected"; else FAIL "CMP rr with a wrong secret was not rejected -- see $WORK/cmp.log"; fi
if grep -q "RR_RC=0" "$WORK/cmp.log"; then
  PASS "CMP rr via openssl cmp (PBM-protected, reason keyCompromise)"
  RR_SERIAL="$(openssl x509 -in "$CMP_OUT/rr-target.pem" -noout -serial | cut -d= -f2)"
  RR_STATUS=""
  for _ in $(seq 1 10); do
    RR_STATUS="$(openssl ocsp -issuer "$WORK/ca.pem" -cert "$CMP_OUT/rr-target.pem" -url "$HUB_BASE/ocsp" -CAfile "$WORK/ca.pem" -text 2>&1 | grep -i 'Cert Status' | head -1)"
    case "$RR_STATUS" in *revoked*) break ;; esac
    sleep 1
  done
  case "$RR_STATUS" in *revoked*) PASS "OCSP answers revoked for the rr'd certificate (serial $RR_SERIAL)" ;; *) FAIL "OCSP after CMP rr: [$RR_STATUS]" ;; esac
  curl -sS --cacert "$CA_PEM" "$HUB_BASE/crl/$CA_ID.crl" -o "$WORK/rr.crl"
  openssl crl -in "$WORK/rr.crl" -inform der -noout -text 2>&1 | grep -qi "$RR_SERIAL" \
    && PASS "the CRL lists the rr'd serial" || FAIL "CRL does not list the rr'd serial $RR_SERIAL"
  if grep -q "RR_AGAIN_REJECTED=1" "$WORK/cmp.log"; then PASS "a second rr for the same certificate is rejected"; else FAIL "a second CMP rr was not rejected"; fi
  RR_AUDIT="$(curlj "$HUB_BASE/api/v1/audit?limit=200" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; rows=d if isinstance(d,list) else d.get("entries",d.get("items",[])); print(" ".join(r["action"]+":"+r["outcome"] for r in rows if r["action"]=="cmp.rr"))')"
  case "$RR_AUDIT" in *"cmp.rr:success"*) PASS "cmp.rr success is audited" ;; *) FAIL "no cmp.rr success audit row: [$RR_AUDIT]" ;; esac
else
  FAIL "CMP rr did not succeed (RR_RC missing or non-zero; see $WORK/cmp.log)"
fi

# ---------------------------------------------------------------------------
# 5. Inventory recorder wiring -- W19-31 found this finding to be STALE: the
#    original W19-05/W18-18 write-up claimed cmd/kryptkeeper/main.go wires
#    est.NewServer/scep.NewServer/cmp.NewServer directly against the raw
#    ca.Service, bypassing bootstrap.CertificateProvider entirely. That is no
#    longer true for any of the three -- main.go now calls
#    estServer.WithIssuedRecorder/scepServer.WithIssuedRecorder/
#    cmpServer.WithIssuedRecorder for all of them, and this run's EST/SCEP
#    checks below empirically prove those two work (source=est, source=scep
#    both appear live). CMP alone still fails, but for a different and more
#    specific reason found by reading the hub's own log (grep "cmp:" on
#    KRYPTKEEPER_DATA_DIR's stdout during this run):
#    "cmp: issued certificate <fp> not recorded: ... was not written and is
#    not present -- the row was rejected, not deduplicated". The root cause
#    is a real, previously-undiscovered hub defect, not a wiring gap: the
#    `certificates` table's `source` column CHECK constraint
#    (internal/db/migrations/{sqlite,postgres}/000002_templates_ca_certs_
#    core.up.sql) enumerates 'api','acme','est','scep','discovery_*','ct_
#    log','import' -- 'cmp' was never added to that list in any migration,
#    even though internal/cmp/server.go has always called
#    RecordIssuedCertificate(..., "cmp"). SQLite's INSERT OR IGNORE (and
#    Postgres's ON CONFLICT DO NOTHING) silently swallow the resulting CHECK
#    violation, exactly the failure mode writeCertToDB's own comment warns
#    about. This ticket's write_scope is tests/live/ + docs only, so the fix
#    (add 'cmp' to both migrations' CHECK) is left for a follow-up ticket
#    rather than applied here.
# ---------------------------------------------------------------------------
STEP "inventory: EST-issued cert reaches /api/v1/certificates live"
EST_SOURCES="$(curlj "$HUB_BASE/api/v1/certificates?limit=25" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(c["source"] for c in d["data"]))')"
case "$EST_SOURCES" in *est*) PASS "GET /api/v1/certificates lists the EST issuance, source=est" ;; *) FAIL "EST-issued cert missing from inventory (source=est not found): [$EST_SOURCES]." ;; esac

STEP "inventory: CMP-issued cert reaches /api/v1/certificates live"
CMP_SOURCES="$(curlj "$HUB_BASE/api/v1/certificates?limit=25" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(c["source"] for c in d["data"]))')"
if grep -q "IR_RC=0" "$WORK/cmp.log" && grep -q "leaf.pem (ir succeeded)" "$WORK/cmp.log"; then
  case "$CMP_SOURCES" in *cmp*) PASS "GET /api/v1/certificates lists the CMP issuance, source=cmp" ;; *) FAIL "CMP-issued cert missing from inventory (source=cmp not found): [$CMP_SOURCES]. Real hub defect, not a fixture bug or wiring gap: the certificates table's source CHECK constraint (internal/db/migrations/{sqlite,postgres}/000002_templates_ca_certs_core.up.sql) never included 'cmp', so cmp.Server's RecordIssuedCertificate(..., \"cmp\") call is always silently rejected by the CHECK and swallowed by INSERT OR IGNORE/ON CONFLICT DO NOTHING -- confirmed via hub.log: 'cmp: issued certificate <fp> not recorded: ... was not written and is not present -- the row was rejected, not deduplicated'. Fix (add 'cmp' to both migrations' CHECK) is out of this ticket's write_scope." ;; esac
else
  echo "SKIP: CMP ir did not succeed -- inventory check for CMP not meaningful this run"
fi

# ---------------------------------------------------------------------------
# 6. OCSP / CRL / revocation -- issue two certs via the hub's own API (a real,
#    already-proven surface independent of EST/SCEP/CMP), revoke one, and
#    check both with REAL openssl ocsp / openssl crl clients.
# ---------------------------------------------------------------------------
STEP "issue two leaf certs via API for OCSP/CRL"
TPL_ID="$(curlj -X POST "$HUB_BASE/api/v1/templates" -d '{"name":"uat-basic","display_name":"UAT Basic","validity_period":"P365D","key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["RSA"],"active":true}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])')"
[ -n "$TPL_ID" ] && PASS "template created: $TPL_ID" || DIE "could not create issuance template"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$WORK/leaf1.key" >/dev/null 2>&1
openssl req -new -key "$WORK/leaf1.key" -subj "/CN=uat-ocsp-leaf1" -out "$WORK/leaf1.csr" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$WORK/leaf2.key" >/dev/null 2>&1
openssl req -new -key "$WORK/leaf2.key" -subj "/CN=uat-ocsp-leaf2" -out "$WORK/leaf2.csr" >/dev/null 2>&1

python3 - "$WORK" "$CA_ID" "$TPL_ID" <<'PYEOF'
import json, sys
work, ca_id, tpl_id = sys.argv[1], sys.argv[2], sys.argv[3]
for n in (1, 2):
    csr = open(f"{work}/leaf{n}.csr").read()
    json.dump({"ca_id": ca_id, "template_id": tpl_id, "csr_pem": csr}, open(f"{work}/issue{n}.json", "w"))
PYEOF

FP1="$(curlj -X POST "$HUB_BASE/api/v1/certificates" --data @"$WORK/issue1.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["fingerprint_sha256"])')"
FP2="$(curlj -X POST "$HUB_BASE/api/v1/certificates" --data @"$WORK/issue2.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["fingerprint_sha256"])')"
[ -n "$FP1" ] && [ -n "$FP2" ] && PASS "issued leaf1=$FP1 leaf2=$FP2" || DIE "certificate issuance via API failed"

STEP "inventory: API-issued certs appear with source=api"
LIST_SOURCES="$(curlj "$HUB_BASE/api/v1/certificates?limit=10" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(c["source"] for c in d["data"]))')"
case "$LIST_SOURCES" in *api*api*|*api*) PASS "GET /api/v1/certificates lists both, source=api" ;; *) FAIL "issued certs missing from inventory list: [$LIST_SOURCES]" ;; esac

STEP "revoke leaf1 via API"
curlj -X POST "$HUB_BASE/api/v1/certificates/$FP1/revoke" -d '{"reason_code":1,"reason_text":"uat key compromise test"}' >"$WORK/revoke.json"
grep -q '"renewal_status":"revoked"' "$WORK/revoke.json" && PASS "leaf1 revoked" || DIE "revoke API call failed: $(cat "$WORK/revoke.json")"

curlj "$HUB_BASE/api/v1/certificates/$FP1/download?format=pem" -o "$WORK/leaf1.pem"
curlj "$HUB_BASE/api/v1/certificates/$FP2/download?format=pem" -o "$WORK/leaf2.pem"

STEP "OCSP: real openssl ocsp against /ocsp (TLS)"
OCSP1="$(openssl ocsp -issuer "$WORK/ca.pem" -cert "$WORK/leaf1.pem" -url "$HUB_BASE/ocsp" -CAfile "$WORK/ca.pem" -text 2>&1)"
echo "$OCSP1" | grep -qi "Cert Status: revoked" && PASS "OCSP reports leaf1 revoked (signature verified, no -noverify)" \
  || FAIL "OCSP did not report leaf1 as revoked: $OCSP1"
OCSP2="$(openssl ocsp -issuer "$WORK/ca.pem" -cert "$WORK/leaf2.pem" -url "$HUB_BASE/ocsp" -CAfile "$WORK/ca.pem" -text 2>&1)"
echo "$OCSP2" | grep -qi "Cert Status: good" && PASS "OCSP reports leaf2 good" \
  || FAIL "OCSP did not report leaf2 as good: $OCSP2"

STEP "CRL: real openssl crl against /crl/<ca id>.crl (TLS)"
curl -sS --cacert "$CA_PEM" "$HUB_BASE/crl/$CA_ID.crl" -o "$WORK/ca.crl"
if openssl crl -in "$WORK/ca.crl" -inform der -CAfile "$WORK/ca.pem" -noout 2>"$WORK/crlverify.log"; then
  PASS "CRL signature verifies against CA (real chain, no bypass)"
else
  FAIL "CRL failed to verify: $(cat "$WORK/crlverify.log")"
fi
CRL_TEXT="$(openssl crl -in "$WORK/ca.crl" -inform der -noout -text 2>&1)"
LEAF1_SERIAL="$(openssl x509 -in "$WORK/leaf1.pem" -noout -serial | cut -d= -f2)"
echo "$CRL_TEXT" | grep -qi "$LEAF1_SERIAL" && PASS "CRL lists leaf1's serial ($LEAF1_SERIAL)" \
  || FAIL "CRL does not list leaf1's serial: $CRL_TEXT"
LEAF2_SERIAL="$(openssl x509 -in "$WORK/leaf2.pem" -noout -serial | cut -d= -f2)"
echo "$CRL_TEXT" | grep -qi "$LEAF2_SERIAL" && FAIL "CRL incorrectly lists non-revoked leaf2's serial" \
  || PASS "CRL correctly omits non-revoked leaf2"

# ---------------------------------------------------------------------------
# W26-11: CMP deferred issuance (W26-08). KRYPTKEEPER_CMP_TEMPLATE names the
# template whose require_approval gates EVERY CMP enrollment, so it is set only
# now, after the plain ir/kur/rr steps. openssl cmp gets `waiting`, then sends
# pollReq (the hub's checkAfter is 30 s) until a named approver approves the
# cmp_enroll item in the pending-actions queue.
# ---------------------------------------------------------------------------
STEP "CMP poll: ir against an approval-required template, pollReq until approved"
CMP_TPL_ID="$(curlj -X POST "$HUB_BASE/api/v1/templates" -d '{"name":"uat-cmp-approval","display_name":"UAT CMP approval","validity_period":"P365D","key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["RSA"],"active":true,"require_approval":true,"approval_roles":["pki-admin"]}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])')"
[ -n "$CMP_TPL_ID" ] && PASS "approval-required template created: $CMP_TPL_ID" || DIE "could not create the CMP approval template"
kill "$HUB_PID" >/dev/null 2>&1
wait "$HUB_PID" 2>/dev/null
export KRYPTKEEPER_CMP_TEMPLATE="$CMP_TPL_ID"
"$WORK/kryptkeeper" >>"$WORK/hub.log" 2>&1 &
HUB_PID=$!
for _ in $(seq 1 30); do curl -sSk -o /dev/null "$HUB_BASE/healthz" && break; sleep 0.5; done
curl -sS --cacert "$CA_PEM" "$HUB_BASE/healthz" | grep -q '"status":"ok"' && PASS "hub restarted with KRYPTKEEPER_CMP_TEMPLATE=$CMP_TPL_ID" || DIE "hub did not come back up, see $WORK/hub.log"
grep -q "CMP: enrollment waits for approval" "$WORK/hub.log" && PASS "hub logged that CMP enrollment waits for approval" || FAIL "hub did not log the CMP approval gate"

podman run ${KK_PODMAN_HOST_ARGS} --rm \
  -v "$HERE/cmp-run.sh:/cmp-run.sh:ro" -v "$CMP_OUT:/out" -v "$CA_PEM:/ca.pem:ro" \
  -e CMP_MODE=poll -e CMP_URL="https://host.containers.internal:${HUB_PORT}/cmp" \
  -e CMP_SECRET="$CMP_SECRET" -e CMP_REFERENCE="$CMP_REFERENCE" -e CMP_CA=/ca.pem \
  "$ALPINE_IMG" sh /cmp-run.sh >"$WORK/cmp-poll.log" 2>&1 &
POLL_PID=$!

CMP_ACT=""
for _ in $(seq 1 90); do
  CMP_ACT="$(curlj "$HUB_BASE/api/v1/pending-actions?status=pending" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; print(next((a["id"] for a in d if a["action_type"]=="cmp_enroll"), ""))' 2>/dev/null)"
  [ -n "$CMP_ACT" ] && break
  sleep 1
done
[ -n "$CMP_ACT" ] && PASS "a cmp_enroll item is pending in the approval queue ($CMP_ACT)" || { kill "$POLL_PID" 2>/dev/null; DIE "no cmp_enroll pending action appeared; client log: $(tail -5 "$WORK/cmp-poll.log")"; }
for _ in $(seq 1 30); do grep -qiE 'poll|waiting' "$WORK/cmp-poll.log" && break; sleep 1; done
grep -qiE 'poll|waiting' "$WORK/cmp-poll.log" && PASS "client log shows waiting/pollReq before approval" || FAIL "client log has no waiting/pollReq evidence (see $WORK/cmp-poll.log)"
grep -q "poll.pem (ir poll succeeded)" "$WORK/cmp-poll.log" && FAIL "the client already holds a certificate before approval" || PASS "no certificate issued before approval"
c=$(curlc "$TOKEN" -X POST "$HUB_BASE/api/v1/pending-actions/$CMP_ACT/approve")
[ "$c" = 403 ] && PASS "the bootstrap token cannot approve the item ($c)" || FAIL "bootstrap approve -> $c $(cat "$WORK/last.json")"
c=$(curlc "$T_alice" -X POST "$HUB_BASE/api/v1/pending-actions/$CMP_ACT/approve")
[ "$c" = 200 ] && PASS "alice (a second principal) approves the cmp_enroll item (200)" || FAIL "alice approve -> $c $(cat "$WORK/last.json")"
wait "$POLL_PID"
cat "$WORK/cmp-poll.log"
if grep -q "IR_POLL_RC=0" "$WORK/cmp-poll.log" && grep -q "poll.pem (ir poll succeeded)" "$WORK/cmp-poll.log"; then
  PASS "openssl cmp ir completes after approval (IR_POLL_RC=0, certificate issued)"
  openssl verify -CAfile "$WORK/ca.pem" "$CMP_OUT/poll.pem" >/dev/null 2>&1 && PASS "the polled certificate chains to the CMP CA" || FAIL "polled certificate does not chain to the CMP CA"
else
  FAIL "CMP poll flow did not end with a certificate (see $WORK/cmp-poll.log)"
fi
POLL_AUDIT="$(curlj "$HUB_BASE/api/v1/audit?limit=200" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; rows=d if isinstance(d,list) else d.get("entries",d.get("items",[])); print(" ".join(r["action"]+":"+r["outcome"] for r in rows if r["action"] in ("cmp.ir","cmp.poll")))')"
case "$POLL_AUDIT" in *"cmp.ir:pending_approval"*) PASS "cmp.ir pending_approval is audited" ;; *) FAIL "no cmp.ir pending_approval audit row: [$POLL_AUDIT]" ;; esac
unset KRYPTKEEPER_CMP_TEMPLATE

# ---------------------------------------------------------------------------
# W22-17: issuance-policy refusal reaches ACME and EST clients. Self-contained
# (own podman network and hub: ACME http-01 needs the hub to dial the client
# container, which this host-process hub cannot), so it runs after the
# host-hub steps and only contributes its exit status.
# ---------------------------------------------------------------------------
STEP "issuance-policy refusal (ACME + EST), tests/live/protocols/policy-refusal"
bash "$HERE/policy-refusal/run.sh" || FAILED=1

# ---------------------------------------------------------------------------
STEP "summary"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL STEPS PASSED"
else
  echo "ONE OR MORE STEPS FAILED -- see FAIL lines above"
fi
exit "$FAILED"
