#!/usr/bin/env bash
# W24-18: live cloud-certificate inventory UAT. Real hub (db mode) against an
# ACM emulator (moto by default; LocalStack via KK_CLOUD_EMULATOR_IMAGE and
# KK_CLOUD_EMULATOR_PORT_INNER=4566; AWS's own emulator with KK_AWS_EMULATOR=aws),
# plus Azure/GCP bad-credential cases.
# Cloud scan results live in scan_jobs.results_summary (not the certificates
# table), so assertions read that row and GET /discovery/scan-jobs.
set -u -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
CE="${CONTAINER_ENGINE:-podman}"
NAME=kk-uat-cloudinv
IMAGE="${KK_CLOUD_EMULATOR_IMAGE:-docker.io/motoserver/moto:latest}"
INNER="${KK_CLOUD_EMULATOR_PORT_INNER:-5000}"
PORT="${KK_CLOUD_EMULATOR_PORT:-5566}"
HUB_PORT="${KK_CLOUD_HUB_PORT:-8097}"
BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
# moto's ListCertificates omits SubjectAlternativeNameSummaries (real ACM and
# LocalStack return them), so dns_names is only asserted off moto.
EMU="${KK_AWS_EMULATOR:-moto}"
case "$EMU:$IMAGE" in aws:*) ASSERT_DNS_NAMES="${KK_ASSERT_DNS_NAMES:-1}" ;; *moto*) ASSERT_DNS_NAMES="${KK_ASSERT_DNS_NAMES:-0}" ;; *) ASSERT_DNS_NAMES="${KK_ASSERT_DNS_NAMES:-1}" ;; esac
PAGE_CERTS="${KK_CLOUD_PAGINATION_CERTS:-1100}"
WORK="$(mktemp -d /tmp/kk-uat-cloudinv.XXXXXX)"
DATA="$WORK/data"
HUB_PID=""
PASSED=0; FAILED=0; SKIPPED=0

PASS() { echo "PASS: $*"; PASSED=$((PASSED + 1)); }
FAIL() { echo "FAIL: $*"; FAILED=$((FAILED + 1)); }
SKIP() { echo "SKIP $*"; SKIPPED=$((SKIPPED + 1)); }
STEP() { echo; echo "== $* =="; }

stop_hub() { [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null && wait "$HUB_PID" 2>/dev/null; HUB_PID=""; }
cleanup() {
  stop_hub
  [ "$EMU" = aws ] && kk_aws_emulator_stop
  "$CE" rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
finish() {
  echo; echo "=== cloud-inventory: $PASSED passed, $FAILED failed, $SKIPPED skipped ==="
  [ "$FAILED" -eq 0 ] && { echo "ALL CHECKS PASSED"; exit 0; } || { echo "FAIL: see above"; exit 1; }
}
DIE() { FAIL "$*"; finish; }

curlj() { curl -sS --max-time 20 -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }

# ---- 1. emulator ---------------------------------------------------------
STEP "start ACM emulator ($EMU)"
if [ "$EMU" = aws ]; then
  # AWS's own emulator as a host process; the hub below inherits its
  # point-the-SDK environment (SigV4 keys file, AWS_CA_BUNDLE).
  . "$HERE/../lib/podman.sh"
  . "$HERE/../lib/aws-emulator.sh"
  kk_aws_emulator_start; rc=$?
  [ "$rc" -eq 2 ] && exit 0
  [ "$rc" -eq 0 ] || DIE "aws-emulator did not start"
  # Leak check below looks for this run's access key id, not a placeholder.
  LEAK_NEEDLE="$(awk -F' *= *' '$1=="aws_access_key_id"{print $2; exit}' "$AWS_SHARED_CREDENTIALS_FILE")"
  export KK_LIVE_CLOUD_INVENTORY=1
else
  "$CE" rm -f "$NAME" >/dev/null 2>&1 || true
  "$CE" image inspect "$IMAGE" >/dev/null 2>&1 || "$CE" pull "$IMAGE" >/dev/null || DIE "pull $IMAGE"
  "$CE" run -d --name "$NAME" -p "127.0.0.1:${PORT}:${INNER}" "$IMAGE" >/dev/null || DIE "start emulator"
  for _ in $(seq 1 60); do curl -s -o /dev/null "http://127.0.0.1:${PORT}/" && break; sleep 1; done
  curl -s -o /dev/null "http://127.0.0.1:${PORT}/" || DIE "emulator never answered on :${PORT}"
  PASS "emulator answering on :${PORT} ($IMAGE)"
  export AWS_ENDPOINT_URL="http://127.0.0.1:${PORT}" AWS_REGION=us-east-1 \
    AWS_ACCESS_KEY_ID=kk-uat AWS_SECRET_ACCESS_KEY=kk-uat KK_LIVE_CLOUD_INVENTORY=1
  LEAK_NEEDLE=kk-uat
fi
[ "$ASSERT_DNS_NAMES" = "1" ] || SKIP "dns_names assertion: emulator omits SubjectAlternativeNameSummaries in ListCertificates (common_name asserted instead)"

import_certs() { # region count prefix -> ARN lines
  (cd "$REPO_ROOT" && KK_IMPORT_COUNT="$2" KK_IMPORT_REGION="$1" KK_IMPORT_PREFIX="$3" \
    go test ./tests/live/cloud-inventory -run TestImportCerts -count=1 -v -timeout 30m 2>&1) | tee "$WORK/import-$1.log" | grep '^ARN=' | sed 's/^ARN=//'
}
helper() { # go test helper NAME -> its stdout lines
  (cd "$REPO_ROOT" && go test ./tests/live/cloud-inventory -run "^$1\$" -count=1 -v 2>&1) | tee "$WORK/$1.log"
}

# ---- 2. import K=5 certs ---------------------------------------------------
STEP "import 5 certs into us-east-1"
import_certs us-east-1 5 acm-uat >"$WORK/arns-us.txt"
[ "$(wc -l <"$WORK/arns-us.txt" | tr -d ' ')" = "5" ] && PASS "5 certificates imported (ARNs captured)" || { cat "$WORK/import-us-east-1.log"; DIE "import did not yield 5 ARNs"; }

# ---- hub helpers -----------------------------------------------------------
STEP "build hub"
(cd "$REPO_ROOT" && go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper) && PASS "hub built" || DIE "go build failed"
mkdir -p "$DATA"

start_hub() { # scopes_json [env assignments...]
  local scopes="$1"; shift
  stop_hub
  env -u AZURE_KEYVAULT_URL -u AZURE_TENANT_ID -u AZURE_CLIENT_ID -u AZURE_CLIENT_SECRET \
    -u GCP_PROJECT_ID -u GOOGLE_ACCESS_TOKEN -u KRYPTKEEPER_CLOUD_SCOPES \
    APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
    APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file KRYPTKEEPER_TLS_DISABLE=true \
    APP_CREDENTIAL_STORE_PASSPHRASE='uat-cloud-cred-passphrase-32bytes!' \
    KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-cloud-keystore-passphrase-32by' \
    KRYPTKEEPER_DATA_DIR="$DATA" KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Cloud Root CA" \
    APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT" KRYPTKEEPER_CLOUD_SCOPES="$scopes" "$@" \
    "$WORK/kryptkeeper" >>"$WORK/hub.log" 2>&1 &
  HUB_PID=$!
  local tries=60
  until curl -sf -o /dev/null -H "Authorization: Bearer ${TOKEN}" "$BASE/api/v1/cas"; do
    tries=$((tries - 1)); [ "$tries" -le 0 ] && { tail -20 "$WORK/hub.log"; DIE "hub never answered"; }
    sleep 1
  done
}

run_scan() { # scan_type max_wait_seconds -> sets JOB_ID, JOB_STATUS
  local resp; resp="$(curlj -X POST "$BASE/api/v1/discovery/scans" -d "{\"scan_type\":\"$1\"}")"
  JOB_ID="$(echo "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["scan_job"]["id"])' 2>/dev/null)"
  [ -n "$JOB_ID" ] || { echo "scan create response: $resp"; JOB_STATUS="rejected"; return; }
  local i; JOB_STATUS=""
  for i in $(seq 1 "$2"); do
    JOB_STATUS="$(job_field status)"
    case "$JOB_STATUS" in completed|completed_with_errors|failed|cancelled) return ;; esac
    sleep 1
  done
}

job_field() { # field of the job via the PUBLIC API (scan-jobs list)
  curlj "$BASE/api/v1/discovery/scan-jobs?limit=50" | python3 -c "
import json,sys
jobs=json.load(sys.stdin).get('data',{}).get('scan_jobs',[])
j=next((j for j in jobs if j.get('id')=='$JOB_ID'),{})
print(j.get('$1',''))" 2>/dev/null
}

CAP=200 # cloudScanMaxItems in internal/bootstrap/cloud_discovery.go
summary_row() { sqlite3 "$DATA/kryptkeeper.db" "SELECT results_summary FROM scan_jobs WHERE id='$JOB_ID'"; }

check_summary() { # label want_count arns_file(optional)  (reads summary_row)
  summary_row >"$WORK/summary.json"
  python3 - "$WORK/summary.json" "$2" "${3:-}" "$ASSERT_DNS_NAMES" "$CAP" <<'PY'
import json, sys
s = json.load(open(sys.argv[1])); want = int(sys.argv[2]); arns = sys.argv[3]; dns = sys.argv[4] == "1"; cap = int(sys.argv[5])
items = s.get("items") or []
ids = [i["resource_id"] for i in items]
errs = []
if s.get("provider") != "cloud_acm": errs.append("summary provider=%r (scan type recorded)" % s.get("provider"))
if s.get("certificates") != want: errs.append("certificates=%s want %d" % (s.get("certificates"), want))
if len(ids) != len(set(ids)): errs.append("duplicate resource_id values")
if len(ids) != min(want, cap): errs.append("items=%d want %d" % (len(ids), min(want, cap)))
for i in items:
    if i.get("provider") != "aws-acm": errs.append("item provider %r" % i.get("provider"))
    if not i.get("common_name"): errs.append("empty common_name for %s" % i["resource_id"])
    if dns and not i.get("dns_names"): errs.append("empty dns_names for %s" % i["resource_id"])
    # A PENDING_VALIDATION certificate has no body yet, so no validity.
    if i.get("status") == "ISSUED" and (not i.get("not_after") or i["not_after"].startswith("0001")): errs.append("empty not_after for %s" % i["resource_id"])
if arns:
    want_ids = set(l.strip() for l in open(arns) if l.strip())
    if set(ids) != want_ids: errs.append("ARN set mismatch: extra=%s missing=%s" % (sorted(set(ids)-want_ids), sorted(want_ids-set(ids))))
print("; ".join(errs) if errs else "OK")
sys.exit(1 if errs else 0)
PY
}

# ---- 3-4. first scan -----------------------------------------------------------
STEP "ACM scan: exactly 5 entries with ARN, names, expiry"
start_hub '[{"provider":"aws-acm","profile":"","region":"us-east-1"}]'
run_scan cloud_acm 30
[ "$JOB_STATUS" = "completed" ] && PASS "scan job $JOB_ID completed" || FAIL "scan job status=$JOB_STATUS error=$(job_field error)"
out="$(check_summary x 5 "$WORK/arns-us.txt")" && PASS "results_summary: 5 distinct ARNs equal to imported, common_name + not_after set" || FAIL "results_summary: $out"

# ---- 5. rerun --------------------------------------------------------------------
STEP "rerun adds 0 duplicates"
run_scan cloud_acm 30
[ "$JOB_STATUS" = "completed" ] && PASS "rerun job completed" || FAIL "rerun status=$JOB_STATUS"
out="$(check_summary x 5 "$WORK/arns-us.txt")" && PASS "rerun: still 5 certificates, same ARN set, no duplicate resource_id" || FAIL "rerun: $out"

# ---- 6. multi-scope isolation ---------------------------------------------------
STEP "multi-scope: second region, then one bad scope"
if [ "$EMU" = aws ]; then
SKIP "two-region merge: aws-emulator does not separate Regions (one Region per emulator), so this case stays on moto"
start_hub '[{"provider":"aws-acm","profile":"","region":"us-east-1"},{"provider":"aws-acm","region":"ap-south-1","profile":"does-not-exist"}]'
run_scan cloud_acm 30
msg="$(job_field error)"
[ "$JOB_STATUS" = "completed_with_errors" ] && PASS "bad scope: status completed_with_errors" || FAIL "bad scope: status=$JOB_STATUS (want completed_with_errors) error=$msg"
echo "$msg" | grep -q 'aws-acm/does-not-exist/ap-south-1' && PASS "error_message names the failing scope" || FAIL "error_message lacks scope key: $msg"
out="$(check_summary x 5 "$WORK/arns-us.txt")" && PASS "good scope's 5 certificates still listed" || FAIL "good scope lost: $out"
else
import_certs eu-west-1 2 acm-eu >"$WORK/arns-eu.txt"
[ "$(wc -l <"$WORK/arns-eu.txt" | tr -d ' ')" = "2" ] && PASS "2 certificates imported into eu-west-1" || DIE "eu-west-1 import failed"
cat "$WORK/arns-us.txt" "$WORK/arns-eu.txt" >"$WORK/arns-all.txt"
start_hub '[{"provider":"aws-acm","profile":"","region":"us-east-1"},{"provider":"aws-acm","profile":"","region":"eu-west-1"}]'
run_scan cloud_acm 30
out="$(check_summary x 7 "$WORK/arns-all.txt")" && [ "$JOB_STATUS" = "completed" ] && PASS "two scopes: 7 certificates, all ARNs present" || FAIL "two scopes: status=$JOB_STATUS $out"

start_hub '[{"provider":"aws-acm","profile":"","region":"us-east-1"},{"provider":"aws-acm","profile":"","region":"eu-west-1"},{"provider":"aws-acm","region":"ap-south-1","profile":"does-not-exist"}]'
run_scan cloud_acm 30
msg="$(job_field error)"
[ "$JOB_STATUS" = "completed_with_errors" ] && PASS "bad scope: status completed_with_errors" || FAIL "bad scope: status=$JOB_STATUS (want completed_with_errors) error=$msg"
echo "$msg" | grep -q 'aws-acm/does-not-exist/ap-south-1' && PASS "error_message names the failing scope" || FAIL "error_message lacks scope key: $msg"
out="$(check_summary x 7 "$WORK/arns-all.txt")" && PASS "good scopes' 7 certificates still listed" || FAIL "good scopes lost: $out"
fi

# ---- 6b. pending certificate ---------------------------------------------------------
STEP "pending: a requested (DNS-validated) certificate is listed as PENDING_VALIDATION"
pend="$(helper TestRequestPending | grep '^ARN=' | sed 's/^ARN=//')"
[ -n "$pend" ] && PASS "requested certificate $pend" || FAIL "RequestCertificate failed: $(tail -3 "$WORK/TestRequestPending.log")"
if [ -n "$pend" ]; then
  start_hub '[{"provider":"aws-acm","profile":"","region":"us-east-1"}]'
  run_scan cloud_acm 30
  [ "$JOB_STATUS" = "completed" ] && PASS "scan with a pending certificate completed" || FAIL "pending scan status=$JOB_STATUS error=$(job_field error)"
  { cat "$WORK/arns-us.txt"; echo "$pend"; } >"$WORK/arns-pending.txt"
  out="$(check_summary x 6 "$WORK/arns-pending.txt")" && PASS "results_summary: 6 certificates (5 imported + 1 pending)" || FAIL "pending summary: $out"
  st="$(python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print(next((i.get("status","") for i in s.get("items") or [] if i["resource_id"]==sys.argv[2]),"absent"))' "$WORK/summary.json" "$pend")"
  case "$st" in
    PENDING_VALIDATION) PASS "pending certificate listed with status PENDING_VALIDATION" ;;
    *) FAIL "pending certificate status=$st (want PENDING_VALIDATION)" ;;
  esac
fi

# ---- 6c. pagination --------------------------------------------------------------------
STEP "pagination: $PAGE_CERTS more certificates (real ACM pages at up to 1000)"
import_certs us-east-1 "$PAGE_CERTS" acm-page >"$WORK/arns-page.txt"
got="$(wc -l <"$WORK/arns-page.txt" | tr -d ' ')"
if [ "$got" != "$PAGE_CERTS" ]; then
  if grep -q 'emulator holds at most' "$WORK/import-us-east-1.log"; then
    SKIP "pagination over $PAGE_CERTS certificates: $(grep -o 'this emulator holds at most[^"]*' "$WORK/import-us-east-1.log" | head -1)"
  else
    FAIL "imported $got of $PAGE_CERTS certificates: $(grep -E 'Import|Error' "$WORK/import-us-east-1.log" | tail -2)"
  fi
else
  PASS "$PAGE_CERTS certificates imported"
  pages="$(helper TestCountPages | grep '^PAGES=' | head -1)"
  echo "  ListCertificates as the hub calls it: $pages"
  total=$((PAGE_CERTS + 5)); [ -n "$pend" ] && total=$((total + 1))
  case "$pages" in
    "PAGES=1 "*) SKIP "NextToken path: the emulator returned all certificates in one ListCertificates page ($pages); completeness still asserted" ;;
    PAGES=*) PASS "ListCertificates spans several pages ($pages)" ;;
    *) FAIL "page count helper failed: $(tail -3 "$WORK/TestCountPages.log")" ;;
  esac
  start_hub '[{"provider":"aws-acm","profile":"","region":"us-east-1"}]'
  run_scan cloud_acm 300
  [ "$JOB_STATUS" = "completed" ] && PASS "scan over $total certificates completed" || FAIL "pagination scan status=$JOB_STATUS error=$(job_field error)"
  out="$(check_summary x "$total")" && PASS "results_summary.certificates=$total, $CAP persisted items, no duplicate resource_id" || FAIL "pagination summary: $out"
fi

# ---- 7. AWS bad endpoint -----------------------------------------------------------
STEP "AWS unreachable endpoint -> failed job with readable message"
start_hub '[{"provider":"aws-acm","profile":"","region":"us-east-1"}]' AWS_ENDPOINT_URL=http://127.0.0.1:1
run_scan cloud_acm 90
msg="$(job_field error)"
[ "$JOB_STATUS" = "failed" ] && PASS "aws unreachable: job failed" || FAIL "aws unreachable: status=$JOB_STATUS"
echo "$msg" | grep -Eq 'list certificates|connector init' && PASS "message readable: ${msg:0:160}" || FAIL "message not readable: $msg"
echo "$msg" | grep -qF "$LEAK_NEEDLE" && FAIL "message leaks credential value" || PASS "message carries no credential value"
echo "$msg" | grep -Eq 'goroutine|\.go:[0-9]+' && FAIL "message looks like a stack trace" || PASS "message has no stack trace"

# ---- 8. Azure ------------------------------------------------------------------------
STEP "Azure: bad credentials"
start_hub '' AZURE_KEYVAULT_URL=https://kk-uat.vault.azure.net
run_scan cloud_azure_kv 30
msg="$(job_field error)"
[ "$JOB_STATUS" = "failed" ] && PASS "azure missing creds: job failed" || FAIL "azure missing creds: status=$JOB_STATUS"
echo "$msg" | grep -q 'AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET are required' && PASS "azure message readable: ${msg:0:160}" || FAIL "azure message: $msg"
if [ -n "${KK_LIVE_AZURE_KV_URL:-}" ] && [ -n "${AZURE_TENANT_ID:-}" ] && [ -n "${AZURE_CLIENT_ID:-}" ] && [ -n "${AZURE_CLIENT_SECRET:-}" ]; then
  start_hub '' AZURE_KEYVAULT_URL="$KK_LIVE_AZURE_KV_URL" AZURE_TENANT_ID="$AZURE_TENANT_ID" AZURE_CLIENT_ID="$AZURE_CLIENT_ID" AZURE_CLIENT_SECRET="$AZURE_CLIENT_SECRET"
  run_scan cloud_azure_kv 60
  [ "$JOB_STATUS" = "completed" ] && PASS "azure positive: completed" || FAIL "azure positive: status=$JOB_STATUS error=$(job_field error)"
else
  SKIP "azure positive: no test tenant (set KK_LIVE_AZURE_KV_URL, AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)"
fi

# ---- 9. GCP ----------------------------------------------------------------------------
STEP "GCP: bad credentials (waits out the metadata-server timeout)"
start_hub '' GCP_PROJECT_ID=kk-uat-proj
run_scan cloud_gcp_cm 40
msg="$(job_field error)"
[ "$JOB_STATUS" = "failed" ] && PASS "gcp no credentials: job failed" || FAIL "gcp no credentials: status=$JOB_STATUS"
echo "$msg" | grep -q 'gcp certmanager: get token' && PASS "gcp message readable: ${msg:0:160}" || FAIL "gcp message: $msg"
if [ -n "${KK_LIVE_GCP_PROJECT:-}" ] && [ -n "${GOOGLE_ACCESS_TOKEN:-}" ]; then
  start_hub '' GCP_PROJECT_ID="$KK_LIVE_GCP_PROJECT" GOOGLE_ACCESS_TOKEN="$GOOGLE_ACCESS_TOKEN"
  run_scan cloud_gcp_cm 60
  [ "$JOB_STATUS" = "completed" ] && PASS "gcp positive: completed" || FAIL "gcp positive: status=$JOB_STATUS error=$(job_field error)"
else
  SKIP "gcp positive: no test project (set KK_LIVE_GCP_PROJECT and GOOGLE_ACCESS_TOKEN)"
fi

finish
