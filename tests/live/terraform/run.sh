#!/usr/bin/env bash
# W26-15: Terraform provider acceptance tests against a live hub.
# Builds the hub from this checkout, runs it natively (plain HTTP, file stores,
# free loopback port, everything in a mktemp dir), starts two pki-admin
# identities (APP_API_KEYS_JSON, dual control needs two humans), then runs
# TestAcc_* in terraform-provider-kryptkeeper with the real provider binary
# driven by tofu or terraform. Tokens are never printed. No podman needed.
# Writes RESULTS.md next to this script. Not part of `go test`; CI runs it in the terraform-provider.yml acceptance job.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
RECORD="${RECORD:-$HERE/RESULTS.md}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kk-tfacc.XXXXXX")"
HUB_PID=""
FAILED=0
PEPPER="uat-pepper-32-characters-minimum!!"

say()  { echo "$*" | tee -a "$RECORD"; }
STEP() { say ""; say "=== $* ==="; }
PASS() { say "PASS: $*"; }
FAIL() { say "FAIL: $*"; FAILED=1; }
DIE()  { say "FAIL: $*"; FAILED=1; exit 1; }
cleanup() {
  [ -n "$HUB_PID" ] && kill "$HUB_PID" >/dev/null 2>&1 && wait "$HUB_PID" 2>/dev/null
  if [ "$FAILED" = 1 ] && [ -f "$WORK/hub.log" ]; then
    { echo; echo "--- hub log, last 30 lines ---"; tail -30 "$WORK/hub.log"; } | tee -a "$RECORD"
  fi
  if [ -n "${KK_ACC_KEEP:-}" ]; then echo "kept $WORK (KK_ACC_KEEP set)"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

ENTRIES=""
mkident() { # name -> sets T_<name>
  local name="$1" secret verifier
  secret="$(openssl rand -hex 24)"
  verifier="$(printf '%s' "$secret" | openssl dgst -sha256 -hmac "$PEPPER" -hex | awk '{print $NF}')"
  eval "T_$name=kk_acc${name}_${secret}"
  ENTRIES="${ENTRIES:+$ENTRIES,}{\"name\":\"$name\",\"kid\":\"acc$name\",\"secret_verifier\":\"$verifier\",\"principal_id\":\"$name\",\"role\":\"pki-admin\",\"active\":true}"
}
api() { # token method path -> prints body; status in $WORK/status
  local tok="$1" m="$2" p="$3"; shift 3
  curl -sS -o "$WORK/body" -w '%{http_code}' -X "$m" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@" "$HUBURL$p" >"$WORK/status"; cat "$WORK/body"
}

: >"$RECORD"
TFBIN="${KK_ACC_TF_BIN:-$(command -v tofu || command -v terraform || true)}"
say "# W26-15 live test: Terraform provider acceptance against a live hub"
say "date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "commit:  $(git -C "$REPO" rev-parse HEAD)"
say "machine: $(uname -srm), $(go version | awk '{print $3}'), $(openssl version | awk '{print $1" "$2}')"
say "cli:     ${TFBIN:+$("$TFBIN" version 2>/dev/null | head -1)}"
[ -n "$TFBIN" ] || DIE "neither tofu nor terraform is installed (run recorded as PENDING-RUN)"

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
HUBURL="http://127.0.0.1:$PORT"
mkident alice; mkident bob

STEP "build and start the hub (plain HTTP, 127.0.0.1:$PORT, state in a temp dir)"
mkdir -p "$WORK/data"
(cd "$REPO" && go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper) || DIE "go build failed"
PASS "hub built from this checkout"
D="$WORK/data"
env APP_BOOTSTRAP_TOKEN="acc-bootstrap-$(openssl rand -hex 6)" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file KRYPTKEEPER_TLS_DISABLE=true \
  APP_API_KEY_AUTH_ENABLED=true APP_API_KEY_PEPPER="$PEPPER" APP_API_KEYS_JSON="[$ENTRIES]" \
  APP_CREDENTIAL_STORE_PASSPHRASE='acc-cred-passphrase-32-bytes-long!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='acc-keystore-passphrase-32-bytes!' \
  KRYPTKEEPER_DATA_DIR="$D" APP_CA_FILE="$D/cas.json" APP_TEMPLATE_FILE="$D/templates.json" \
  APP_CERTIFICATE_FILE="$D/certificates.json" APP_AUDIT_FILE="$D/audit.json" APP_CERTS_SUMMARY_FILE="$D/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="acc bootstrap root" \
  APP_BIND_ADDR=127.0.0.1 PORT="$PORT" "$WORK/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
for _ in $(seq 1 40); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $T_alice" "$HUBURL/api/v1/cas")" = 200 ] && break
  kill -0 "$HUB_PID" 2>/dev/null || DIE "hub exited at startup"
  sleep 1
done
api "$T_alice" GET /api/v1/cas >/dev/null; [ "$(cat "$WORK/status")" = 200 ] && PASS "hub up; admins alice and bob authenticate" || DIE "hub never answered 200 for alice"
api "$T_bob" GET /api/v1/cas >/dev/null; [ "$(cat "$WORK/status")" = 200 ] || DIE "bob cannot authenticate"

STEP "go test -run TestAcc (real provider binary through $(basename "$TFBIN"))"
export TF_ACC=1 KK_ACC_HUB_URL="$HUBURL" KK_ACC_TOKEN="$T_alice" KK_ACC_APPROVER_TOKEN="$T_bob" KK_ACC_TF_BIN="$TFBIN"
(cd "$REPO/terraform-provider-kryptkeeper" && go test ./internal/provider/ -run TestAcc -count=1 -v 2>&1) | sed -e "s/$T_alice/<redacted>/g" -e "s/$T_bob/<redacted>/g" >"$WORK/go-test.log"
grep -E '^(=== RUN|--- |FAIL|ok |PASS)|residual=|warning|Warning: (Template|CA) ' "$WORK/go-test.log" | tee -a "$RECORD"
for t in TestAcc_CA_Template_Certificate_RoundTrip TestAcc_StateHasNoPrivateKey TestAcc_DestroyPendingApprovalFails TestAcc_ImportThenPlan TestAcc_PolicyViolationSurfacesRule; do
  if grep -q -- "^--- PASS: $t " "$WORK/go-test.log"; then PASS "$t"; else FAIL "$t did not pass"; tail -60 "$WORK/go-test.log" | tee -a "$RECORD"; fi
done

STEP "residuals through the API (tfacc- objects left behind)"
# The hub keeps a revoked CA's record (DELETE 409s on the FK from the CA's own certificate row), so a residual CA is one that is not revoked.
RES_CA="$(api "$T_alice" GET /api/v1/cas | jget 'len([c for c in d["data"] if c["name"].startswith("tfacc-") and c["status"]!="revoked"])')"
RES_TPL="$(api "$T_alice" GET /api/v1/templates | jget 'len([c for c in d["data"] if c["name"].startswith("tfacc-") and c.get("active")])')"
RES_CERT="$(api "$T_alice" GET "/api/v1/certificates?limit=500" | jget 'len([c for c in d["data"] if c["common_name"].startswith("tfacc-") and c.get("renewal_status")!="revoked"])')"
RESIDUAL=$((RES_CA + RES_TPL + RES_CERT))
say "residual=$RESIDUAL (non_revoked_cas=$RES_CA active_templates=$RES_TPL non_revoked_certs=$RES_CERT)"
[ "$RESIDUAL" = 0 ] && PASS "0 residual resources" || FAIL "residual resources remain"

say ""
if [ "$FAILED" = 0 ]; then say "ALL STEPS PASSED"; else say "ONE OR MORE STEPS FAILED"; fi
exit "$FAILED"
