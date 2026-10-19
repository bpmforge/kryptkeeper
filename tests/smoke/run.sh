#!/usr/bin/env bash
set -euo pipefail

# filename: tests/smoke/run.sh
# P0 runtime-oriented smoke checks:
# - local binary mode (if app source exists)
# - deployment smoke mode (env-driven, optional)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SKIP_EXIT_CODE=10
SMOKE_MODE="${KRYPTKEEPER_SMOKE_MODE:-auto}"
SMOKE_ASSERTIONS=0
SMOKE_ASSERTIONS_FAILED=0
# W19-24: an assertion whose precondition the environment genuinely lacks
# (a tool, a provider, a port) is counted here, separately from FAIL, and
# printed with a reason -- never silently dropped and never mixed into the
# pass/fail counts that gate the suite's exit code.
SMOKE_ASSERTIONS_SKIPPED=0
# W19-14: curl_expect_200 splices this into every request so the TLS pass
# (run_tls_smoke, below) can point it at a --cacert without touching every
# call site; empty for the existing plain-HTTP scenarios.
EXTRA_CURL_OPTS=()
# W22-42: per-request curl budget. 3s flaked (curl 28, HTTP 000) on a shared,
# heavily loaded dev host; a longer budget only waits longer for a response,
# every status/body assertion is unchanged.
CURL_MAX_TIME="${KRYPTKEEPER_SMOKE_CURL_MAX_TIME:-10}"

# W19-21: every background process/port/tmp-dir a scenario starts is
# tracked here in top-level arrays, not the per-function `local pid=""`
# style the scenarios below used to rely on. That style set `trap cleanup
# EXIT` from inside run_local_binary_smoke with `cleanup()` closing over
# `local pid`/`local oidc_provider_pid`/`local tmp_dir` -- but a bash EXIT
# trap fires only at the whole script's actual exit, long after
# run_local_binary_smoke has returned and those `local` bindings were
# popped, so `cleanup()` resolved `$pid` etc. to the (always-empty)
# top-level globals of the same name and silently killed nothing. Confirmed
# live: repeated runs left `kryptkeeper` hub processes (and python's OIDC
# discovery test server) running indefinitely. A single top-level trap over
# these arrays has no such scoping gap.
SMOKE_PIDS=()
SMOKE_PORTS=()
SMOKE_TMP_DIRS=()

track_pid() { [[ -n "${1:-}" ]] && SMOKE_PIDS+=("$1"); }
track_port() { [[ -n "${1:-}" ]] && SMOKE_PORTS+=("$1"); }
track_tmp_dir() { [[ -n "${1:-}" ]] && SMOKE_TMP_DIRS+=("$1"); }

kill_pid() {
  local target="${1:-}"
  if [[ -n "$target" ]] && kill -0 "$target" >/dev/null 2>&1; then
    kill "$target" >/dev/null 2>&1 || true
    wait "$target" >/dev/null 2>&1 || true
  fi
}

# kill_port is the belt-and-suspenders half of the fix: a process that
# double-forked, got reparented, or that kill_pid otherwise missed can
# still be listening on a port we allocated, so find and kill it that way
# too. lsof is optional -- skip quietly where it's not installed.
kill_port() {
  local port="${1:-}"
  [[ -n "$port" ]] || return 0
  command -v lsof >/dev/null 2>&1 || return 0
  local p
  for p in $(lsof -ti ":$port" 2>/dev/null || true); do
    kill "$p" >/dev/null 2>&1 || true
    wait "$p" >/dev/null 2>&1 || true
  done
}

cleanup_all() {
  local p
  for p in "${SMOKE_PIDS[@]:-}"; do
    kill_pid "$p"
  done
  for p in "${SMOKE_PORTS[@]:-}"; do
    kill_port "$p"
  done
  SMOKE_PIDS=()
  SMOKE_PORTS=()
  local d
  for d in "${SMOKE_TMP_DIRS[@]:-}"; do
    [[ -n "$d" ]] && rm -rf "$d"
  done
  SMOKE_TMP_DIRS=()
}
trap cleanup_all EXIT

allocate_free_port() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import socket
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
    return 0
  fi

  local candidate
  local attempt
  for attempt in {1..20}; do
    candidate=$((20000 + (RANDOM % 20000)))
    if command -v lsof >/dev/null 2>&1; then
      if ! lsof -iTCP:"$candidate" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "$candidate"
        return 0
      fi
    else
      echo "$candidate"
      return 0
    fi
  done

  return 1
}

skip_assertion() {
  local name="$1"
  local reason="$2"
  echo "[smoke] SKIP ${name} -- ${reason}"
  SMOKE_ASSERTIONS_SKIPPED=$((SMOKE_ASSERTIONS_SKIPPED + 1))
}

curl_expect_200() {
  local method="$1"
  local url="$2"
  local name="$3"
  local expected_code="$4"
  local expected_body_substring="${5:-}"
  local content_type_prefix="${6:-}"
  local auth_header="${7:-}"
  local extra_header="${8:-}"
  local request_body="${9:-}"

  if [[ -z "$request_body" && -n "$extra_header" ]]; then
    if [[ "$extra_header" == "{"* || "$extra_header" == "["* ]]; then
      request_body="$extra_header"
      extra_header=""
    fi
  fi

  local tmp_body
  tmp_body="$(mktemp "${TMPDIR:-/tmp}/kryptkeeper-smoke-body-XXXXXX")"

  local tmp_headers
  tmp_headers="$(mktemp "${TMPDIR:-/tmp}/kryptkeeper-smoke-headers-XXXXXX")"

  local code
  if [[ -n "$auth_header" ]]; then
    if [[ -n "$request_body" ]]; then
      if [[ -n "$extra_header" ]]; then
        code="$(curl -sS ${EXTRA_CURL_OPTS[@]+"${EXTRA_CURL_OPTS[@]}"} -X "$method" -H "$auth_header" -H "$extra_header" -H "Content-Type: application/json" -d "$request_body" -D "$tmp_headers" -o "$tmp_body" -w "%{http_code}" --max-time "$CURL_MAX_TIME" "$url" || true)"
      else
        code="$(curl -sS ${EXTRA_CURL_OPTS[@]+"${EXTRA_CURL_OPTS[@]}"} -X "$method" -H "$auth_header" -H "Content-Type: application/json" -d "$request_body" -D "$tmp_headers" -o "$tmp_body" -w "%{http_code}" --max-time "$CURL_MAX_TIME" "$url" || true)"
      fi
    else
      if [[ -n "$extra_header" ]]; then
        code="$(curl -sS ${EXTRA_CURL_OPTS[@]+"${EXTRA_CURL_OPTS[@]}"} -X "$method" -H "$auth_header" -H "$extra_header" -D "$tmp_headers" -o "$tmp_body" -w "%{http_code}" --max-time "$CURL_MAX_TIME" "$url" || true)"
      else
        code="$(curl -sS ${EXTRA_CURL_OPTS[@]+"${EXTRA_CURL_OPTS[@]}"} -X "$method" -H "$auth_header" -D "$tmp_headers" -o "$tmp_body" -w "%{http_code}" --max-time "$CURL_MAX_TIME" "$url" || true)"
      fi
    fi
  else
    if [[ -n "$request_body" ]]; then
      if [[ -n "$extra_header" ]]; then
        code="$(curl -sS ${EXTRA_CURL_OPTS[@]+"${EXTRA_CURL_OPTS[@]}"} -X "$method" -H "$extra_header" -H "Content-Type: application/json" -d "$request_body" -D "$tmp_headers" -o "$tmp_body" -w "%{http_code}" --max-time "$CURL_MAX_TIME" "$url" || true)"
      else
        code="$(curl -sS ${EXTRA_CURL_OPTS[@]+"${EXTRA_CURL_OPTS[@]}"} -X "$method" -H "Content-Type: application/json" -d "$request_body" -D "$tmp_headers" -o "$tmp_body" -w "%{http_code}" --max-time "$CURL_MAX_TIME" "$url" || true)"
      fi
    else
      if [[ -n "$extra_header" ]]; then
        code="$(curl -sS ${EXTRA_CURL_OPTS[@]+"${EXTRA_CURL_OPTS[@]}"} -X "$method" -H "$extra_header" -D "$tmp_headers" -o "$tmp_body" -w "%{http_code}" --max-time "$CURL_MAX_TIME" "$url" || true)"
      else
        code="$(curl -sS ${EXTRA_CURL_OPTS[@]+"${EXTRA_CURL_OPTS[@]}"} -X "$method" -D "$tmp_headers" -o "$tmp_body" -w "%{http_code}" --max-time "$CURL_MAX_TIME" "$url" || true)"
      fi
    fi
  fi

  if [[ "$code" != "$expected_code" ]]; then
    echo "[smoke] ERROR ${name} (${method} ${url}): expected HTTP ${expected_code}, got ${code:-request_error}" >&2
    rm -f "$tmp_body" "$tmp_headers"
    SMOKE_ASSERTIONS=$((SMOKE_ASSERTIONS + 1))
    SMOKE_ASSERTIONS_FAILED=$((SMOKE_ASSERTIONS_FAILED + 1))
    return 0
  fi

  if [[ -n "$expected_body_substring" ]]; then
    local body
    body="$(<"$tmp_body")"
    if [[ "$body" != *"$expected_body_substring"* ]]; then
      echo "[smoke] ERROR ${name} (${method} ${url}): response body missing expected text: ${expected_body_substring}" >&2
      echo "[smoke] INFO response body: ${body}" >&2
      rm -f "$tmp_body" "$tmp_headers"
      SMOKE_ASSERTIONS=$((SMOKE_ASSERTIONS + 1))
      SMOKE_ASSERTIONS_FAILED=$((SMOKE_ASSERTIONS_FAILED + 1))
      return 0
    fi
  fi

  if [[ -n "$content_type_prefix" ]]; then
    local content_type_line
    local header_line
    content_type_line=""
    while IFS= read -r header_line || [[ -n "$header_line" ]]; do
      if [[ "$(printf '%s' "$header_line" | tr '[:upper:]' '[:lower:]')" == content-type:* ]]; then
        content_type_line="${header_line#*:}"
        content_type_line="${content_type_line//$'\r'/}"
        content_type_line="${content_type_line#${content_type_line%%[![:space:]]*}}"
        break
      fi
    done < "$tmp_headers"

    if [[ "$content_type_line" != "$content_type_prefix"* ]]; then
      echo "[smoke] ERROR ${name} (${method} ${url}): expected Content-Type prefix '${content_type_prefix}', got '${content_type_line}'" >&2
      rm -f "$tmp_body" "$tmp_headers"
      SMOKE_ASSERTIONS=$((SMOKE_ASSERTIONS + 1))
      SMOKE_ASSERTIONS_FAILED=$((SMOKE_ASSERTIONS_FAILED + 1))
      return 0
    fi
  fi

  echo "[smoke] PASS ${name} (${method} ${url})"
  SMOKE_ASSERTIONS=$((SMOKE_ASSERTIONS + 1))
  rm -f "$tmp_body" "$tmp_headers"
  return 0
}

run_local_binary_smoke() {
  set -e
  # W19-14: every local-binary launch below sets KRYPTKEEPER_TLS_DISABLE=true
  # explicitly (not left to default) -- otherwise an ambient
  # APP_CERTIFICATE_PROVIDER=ca in the calling shell/CI job would make the
  # hub self-issue TLS and silently break every plain http:// assertion
  # here. run_tls_smoke, below, is the one scenario that opts back in.

  if [[ ! -f "$ROOT_DIR/go.mod" || ! -d "$ROOT_DIR/cmd/kryptkeeper" ]]; then
    echo "[smoke] WARN local runtime prerequisites missing (need go.mod and cmd/kryptkeeper); skipping local mode"
    return "$SKIP_EXIT_CODE"
  fi

  if ! command -v go >/dev/null 2>&1; then
    echo "[smoke] WARN go toolchain not installed; skipping local mode"
    return "$SKIP_EXIT_CODE"
  fi

  if ! command -v curl >/dev/null 2>&1; then
    echo "[smoke] WARN curl not installed; skipping local mode"
    return "$SKIP_EXIT_CODE"
  fi

  local tmp_dir
  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/kryptkeeper-smoke-XXXXXX")"
  track_tmp_dir "$tmp_dir"
  local bin_path="$tmp_dir/kryptkeeper"
  local app_log="$tmp_dir/app.log"
  local summary_file="$tmp_dir/certs-summary.json"
  local audit_file="$tmp_dir/audit.json"
  local ca_file="$tmp_dir/cas.json"
  local template_file="$tmp_dir/templates.json"
  local certificate_file="$tmp_dir/certificates.json"
  local sqlite_db_file="$tmp_dir/certs-summary.db"
  local port
  local pid=""
  local oidc_provider_pid=""
  local bootstrap_token="${APP_BOOTSTRAP_TOKEN:-bootstrap-dev-token}"

  write_summary_fixture() {
    cat > "$summary_file" <<'EOF'
{"total":42,"expiring_30_days":7,"expired":2}
EOF
  }

  write_audit_fixture() {
    cat > "$audit_file" <<'EOF'
[{"id":1001,"timestamp":"2026-04-07T00:00:00Z","action":"certificate.issue","actor_type":"system","actor_id":"system","resource_type":"certificate","resource_id":"fp-1","trace_id":"trace-local-1","outcome":"success"}]
EOF
  }

  # W19-24: CAListItem.CertificatePEM ("certificate_pem" in the fixture) used
  # to be omitted entirely, so GET /cas/{id}/chain?format=pem always hit the
  # "no real PEM to serve" branch W19-01 added (handlers_cas.go) and 503'd --
  # not a product bug, a fixture gap: the file provider's job is to echo back
  # whatever CertificatePEM it was given, and it was never given one. Backed
  # by real openssl-issued self-signed certs so the assertion actually
  # exercises "-----BEGIN CERTIFICATE-----" bytes an x509 parser accepts, per
  # W19-01's own point (a fingerprint-hex string wrapped in PEM markers looks
  # right but isn't). ca_chain_pem_available gates the one assertion that
  # needs this on openssl being present (see below).
  local ca_chain_pem_available=""
  local ca_root_pem=""
  local ca_iss_pem=""
  if command -v openssl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    if ca_root_pem="$(openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -subj "/CN=Root 1" -days 3650 2>/dev/null)" \
      && ca_iss_pem="$(openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -subj "/CN=Issuing 1" -days 3650 2>/dev/null)" \
      && [[ -n "$ca_root_pem" && -n "$ca_iss_pem" ]]; then
      ca_chain_pem_available="1"
    else
      ca_root_pem=""
      ca_iss_pem=""
    fi
  fi

  write_ca_fixture() {
    if [[ -n "$ca_chain_pem_available" ]]; then
      python3 - "$ca_file" "$ca_root_pem" "$ca_iss_pem" <<'PY'
import json
import sys

ca_file, root_pem, iss_pem = sys.argv[1], sys.argv[2], sys.argv[3]

data = [
  {"id":"ca-root-1","name":"root-1","display_name":"Root 1","type":"root","parent_ca_id":None,"status":"active","active_issued_certificates":0,"key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-root-1","certificate_pem":root_pem,"certificate":{"fingerprint_sha256":"fp-root-1","subject_dn":"CN=Root 1","valid_from":"2026-04-01T00:00:00Z","valid_until":"2036-04-01T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":4096},"crl_distribution_points":[],"ocsp_service_url":None,"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"},
  {"id":"ca-iss-1","name":"iss-1","display_name":"Issuing 1","type":"issuing","parent_ca_id":"ca-root-1","status":"suspended","active_issued_certificates":0,"key_storage_type":"software","certificate_fingerprint_sha256":"fp-iss-1","certificate_pem":iss_pem,"certificate":{"fingerprint_sha256":"fp-iss-1","subject_dn":"CN=Issuing 1","valid_from":"2026-04-02T00:00:00Z","valid_until":"2031-04-02T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":2048},"crl_distribution_points":[],"ocsp_service_url":None,"created_at":"2026-04-02T00:00:00Z","updated_at":"2026-04-02T00:00:00Z"},
  {"id":"ca-revoked-empty","name":"revoked-empty","display_name":"Revoked Empty","type":"issuing","parent_ca_id":"ca-root-1","status":"revoked","active_issued_certificates":0,"key_storage_type":"software","certificate_fingerprint_sha256":"fp-revoked-empty","certificate":{"fingerprint_sha256":"fp-revoked-empty","subject_dn":"CN=Revoked Empty","valid_from":"2025-04-02T00:00:00Z","valid_until":"2030-04-02T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":2048},"crl_distribution_points":[],"ocsp_service_url":None,"created_at":"2026-04-02T00:00:00Z","updated_at":"2026-04-02T00:00:00Z"},
  {"id":"ca-revoked-empty-jwt","name":"revoked-empty-jwt","display_name":"Revoked Empty JWT","type":"issuing","parent_ca_id":"ca-root-1","status":"revoked","active_issued_certificates":0,"key_storage_type":"software","certificate_fingerprint_sha256":"fp-revoked-empty-jwt","certificate":{"fingerprint_sha256":"fp-revoked-empty-jwt","subject_dn":"CN=Revoked Empty JWT","valid_from":"2025-04-02T00:00:00Z","valid_until":"2030-04-02T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":2048},"crl_distribution_points":[],"ocsp_service_url":None,"created_at":"2026-04-02T00:00:00Z","updated_at":"2026-04-02T00:00:00Z"},
  {"id":"ca-revoked-busy","name":"revoked-busy","display_name":"Revoked Busy","type":"issuing","parent_ca_id":"ca-root-1","status":"revoked","active_issued_certificates":2,"key_storage_type":"software","certificate_fingerprint_sha256":"fp-revoked-busy","certificate":{"fingerprint_sha256":"fp-revoked-busy","subject_dn":"CN=Revoked Busy","valid_from":"2025-04-02T00:00:00Z","valid_until":"2030-04-02T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":2048},"crl_distribution_points":[],"ocsp_service_url":None,"created_at":"2026-04-02T00:00:00Z","updated_at":"2026-04-02T00:00:00Z"},
]

with open(ca_file, "w") as f:
    json.dump(data, f)
PY
      return 0
    fi
    cat > "$ca_file" <<'EOF'
[{"id":"ca-root-1","name":"root-1","display_name":"Root 1","type":"root","parent_ca_id":null,"status":"active","active_issued_certificates":0,"key_storage_type":"pkcs11","certificate_fingerprint_sha256":"fp-root-1","certificate":{"fingerprint_sha256":"fp-root-1","subject_dn":"CN=Root 1","valid_from":"2026-04-01T00:00:00Z","valid_until":"2036-04-01T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":4096},"crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"},{"id":"ca-iss-1","name":"iss-1","display_name":"Issuing 1","type":"issuing","parent_ca_id":"ca-root-1","status":"suspended","active_issued_certificates":0,"key_storage_type":"software","certificate_fingerprint_sha256":"fp-iss-1","certificate":{"fingerprint_sha256":"fp-iss-1","subject_dn":"CN=Issuing 1","valid_from":"2026-04-02T00:00:00Z","valid_until":"2031-04-02T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":2048},"crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-02T00:00:00Z","updated_at":"2026-04-02T00:00:00Z"},{"id":"ca-revoked-empty","name":"revoked-empty","display_name":"Revoked Empty","type":"issuing","parent_ca_id":"ca-root-1","status":"revoked","active_issued_certificates":0,"key_storage_type":"software","certificate_fingerprint_sha256":"fp-revoked-empty","certificate":{"fingerprint_sha256":"fp-revoked-empty","subject_dn":"CN=Revoked Empty","valid_from":"2025-04-02T00:00:00Z","valid_until":"2030-04-02T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":2048},"crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-02T00:00:00Z","updated_at":"2026-04-02T00:00:00Z"},{"id":"ca-revoked-empty-jwt","name":"revoked-empty-jwt","display_name":"Revoked Empty JWT","type":"issuing","parent_ca_id":"ca-root-1","status":"revoked","active_issued_certificates":0,"key_storage_type":"software","certificate_fingerprint_sha256":"fp-revoked-empty-jwt","certificate":{"fingerprint_sha256":"fp-revoked-empty-jwt","subject_dn":"CN=Revoked Empty JWT","valid_from":"2025-04-02T00:00:00Z","valid_until":"2030-04-02T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":2048},"crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-02T00:00:00Z","updated_at":"2026-04-02T00:00:00Z"},{"id":"ca-revoked-busy","name":"revoked-busy","display_name":"Revoked Busy","type":"issuing","parent_ca_id":"ca-root-1","status":"revoked","active_issued_certificates":2,"key_storage_type":"software","certificate_fingerprint_sha256":"fp-revoked-busy","certificate":{"fingerprint_sha256":"fp-revoked-busy","subject_dn":"CN=Revoked Busy","valid_from":"2025-04-02T00:00:00Z","valid_until":"2030-04-02T00:00:00Z","public_key_algorithm":"RSA","key_size_bits":2048},"crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-04-02T00:00:00Z","updated_at":"2026-04-02T00:00:00Z"}]
EOF
  }

  write_template_fixture() {
    cat > "$template_file" <<'EOF'
[{"id":"tpl-tls-90d","name":"tls-server-90d","display_name":"TLS Server Certificate (90 days)","oid":"1.3.6.1.4.1.99999.1.1","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","RSA"],"min_key_size":2048,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":true,"active":true,"revision":3,"schema_version":1,"issued_count":412,"created_at":"2026-01-10T08:00:00Z","updated_at":"2026-03-01T14:00:00Z"},{"id":"tpl-code-1y","name":"code-signing-1y","display_name":"Code Signing Certificate (1 year)","oid":"1.3.6.1.4.1.99999.1.4","key_usage":["digitalSignature"],"extended_key_usage":["codeSigning"],"allowed_algorithms":["RSA"],"min_key_size":3072,"validity_period":"P1Y","renewal_overlap":"P30D","auto_enroll":false,"active":false,"revision":1,"schema_version":1,"issued_count":3,"created_at":"2026-02-01T08:00:00Z","updated_at":"2026-02-01T08:00:00Z"},{"id":"tpl-unused-zero","name":"unused-zero","display_name":"Unused Zero","oid":"1.3.6.1.4.1.99999.1.99","key_usage":["digitalSignature"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["ECDSA"],"min_key_size":256,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":false,"active":true,"revision":1,"schema_version":1,"issued_count":0,"created_at":"2026-02-10T08:00:00Z","updated_at":"2026-02-10T08:00:00Z"},{"id":"tpl-unused-zero-jwt","name":"unused-zero-jwt","display_name":"Unused Zero JWT","oid":"1.3.6.1.4.1.99999.1.100","key_usage":["digitalSignature"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["ECDSA"],"min_key_size":256,"validity_period":"P90D","renewal_overlap":"P14D","auto_enroll":false,"active":true,"revision":1,"schema_version":1,"issued_count":0,"created_at":"2026-02-11T08:00:00Z","updated_at":"2026-02-11T08:00:00Z"}]
EOF
  }

  write_certificate_fixture() {
    cat > "$certificate_file" <<'EOF'
[
  {"fingerprint_sha256":"fp-prev","serial_number":"00","common_name":"api.example.com","subject_dn":"CN=api.example.com","subject_alt_names":["api.example.com"],"issuer_cn":"Issuing 1","issuer_dn":"CN=Issuing 1","ca_id":"ca-root-1","template_id":"tpl-tls-90d","team_id":"team-1","valid_from":"2025-10-01T00:00:00Z","valid_until":"2026-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["TLS Web Server Authentication"],"key_usage":["Digital Signature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":true,"risk_score":55,"risk_flags":["EXPIRING_7_DAYS"],"grade":"D","renewal_method":"acme","renewal_status":"renewed","source":"acme","successor_fingerprint":"fp-cur","etag":1,"created_at":"2025-10-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},
  {"fingerprint_sha256":"fp-cur","serial_number":"01","common_name":"api.example.com","subject_dn":"CN=api.example.com","subject_alt_names":["api.example.com","api-staging.example.com"],"issuer_cn":"Issuing 1","issuer_dn":"CN=Issuing 1","ca_id":"ca-root-1","template_id":"tpl-tls-90d","team_id":"team-1","valid_from":"2026-01-01T00:00:00Z","valid_until":"2026-04-11T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["TLS Web Server Authentication"],"key_usage":["Digital Signature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":true,"risk_score":35,"risk_flags":["EXPIRING_7_DAYS"],"grade":"C","renewal_method":"acme","renewal_status":"active","source":"acme","predecessor_fingerprint":"fp-prev","successor_fingerprint":"fp-next","etag":2,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-04-03T12:00:00Z"},
  {"fingerprint_sha256":"fp-next","serial_number":"02","common_name":"api.example.com","subject_dn":"CN=api.example.com","subject_alt_names":["api.example.com"],"issuer_cn":"Issuing 1","issuer_dn":"CN=Issuing 1","ca_id":"ca-root-1","template_id":"tpl-tls-90d","team_id":"team-1","valid_from":"2026-04-11T00:00:00Z","valid_until":"2026-07-11T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["TLS Web Server Authentication"],"key_usage":["Digital Signature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":false,"risk_score":5,"risk_flags":[],"grade":"A","renewal_method":"api","renewal_status":"active","source":"api","predecessor_fingerprint":"fp-cur","etag":1,"created_at":"2026-04-11T00:00:00Z","updated_at":"2026-04-11T00:00:00Z"},
  {"fingerprint_sha256":"fp-renew-bootstrap","serial_number":"03","common_name":"renew-bootstrap.example.com","subject_dn":"CN=renew-bootstrap.example.com","subject_alt_names":["renew-bootstrap.example.com"],"issuer_cn":"Issuing 1","issuer_dn":"CN=Issuing 1","ca_id":"ca-root-1","template_id":"tpl-tls-90d","team_id":"team-1","valid_from":"2026-02-01T00:00:00Z","valid_until":"2026-05-11T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["TLS Web Server Authentication"],"key_usage":["Digital Signature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":false,"risk_score":20,"risk_flags":[],"grade":"B","renewal_method":"api","renewal_status":"active","source":"api","etag":1,"created_at":"2026-02-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"},
  {"fingerprint_sha256":"fp-cur-jwt","serial_number":"04","common_name":"api-jwt.example.com","subject_dn":"CN=api-jwt.example.com","subject_alt_names":["api-jwt.example.com"],"issuer_cn":"Issuing 1","issuer_dn":"CN=Issuing 1","ca_id":"ca-root-1","template_id":"tpl-tls-90d","team_id":"team-1","valid_from":"2026-02-01T00:00:00Z","valid_until":"2026-05-11T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["TLS Web Server Authentication"],"key_usage":["Digital Signature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":false,"risk_score":25,"risk_flags":[],"grade":"C","renewal_method":"api","renewal_status":"active","source":"api","etag":1,"created_at":"2026-02-01T00:00:00Z","updated_at":"2026-04-01T00:00:00Z"}
]
EOF
  }

  write_sqlite_summary_fixture() {
    if ! command -v sqlite3 >/dev/null 2>&1; then
      return 1
    fi
    rm -f "$sqlite_db_file"
    # W19-24: sqliteCertSummaryStore.LoadSummary's query (certs_summary_db_
    # provider.go) references management_state (added by W11-01, docs/
    # STATUS.md 2026-08-18) in every SELECT -- this stand-alone fixture table
    # predates that column and lacked it entirely, so the query failed with
    # "no such column: management_state" and the handler answered 503. The
    # real query already COALESCEs a NULL management_state to 'managed', so
    # the column just needs to exist; leaving every row NULL matches "the
    # common case: an existing cert with no explicit state" and keeps the
    # total/expiring/expired counts below unchanged. revoked_at and
    # renewal_status back the active-certificate rule (certificate_active.go);
    # NULL in both means active, so the counts are again unchanged. is_ca
    # (migration 000077) keeps served-chain intermediates out of the leaf
    # counts; 0 = a leaf, so the counts are unchanged again. W22-42: owner_team
    # backs the unowned counter (unownedCertSQL); NULL = unowned, counts unchanged.
    sqlite3 "$sqlite_db_file" <<'SQL'
CREATE TABLE certificates (
  valid_until TEXT NOT NULL,
  management_state TEXT,
  revoked_at TEXT,
  renewal_status TEXT,
  is_ca INTEGER NOT NULL DEFAULT 0,
  owner_team TEXT
);
INSERT INTO certificates(valid_until) VALUES
  (datetime('now', '-1 day')),
  (datetime('now', '+2 day')),
  (datetime('now', '+10 day')),
  (datetime('now', '+60 day'));
SQL
  }

  write_summary_fixture
  write_audit_fixture
  write_ca_fixture
  write_template_fixture
  write_certificate_fixture

  generate_hs256_jwt() {
    local sub="$1"
    local secret="$2"
    local issuer="$3"
    local audience="$4"
    local role_claim="${5:-}"

    if command -v python3 >/dev/null 2>&1; then
      python3 - "$sub" "$secret" "$issuer" "$audience" "$role_claim" <<'PY'
import base64
import hashlib
import hmac
import json
import sys
import time

sub, secret, issuer, audience, role_claim = sys.argv[1:6]

header = {"alg": "HS256", "typ": "JWT"}
payload = {
  "sub": sub,
  "exp": int(time.time()) + 300,
}
if issuer:
  payload["iss"] = issuer
if audience:
  payload["aud"] = audience
if role_claim:
  payload["kk_role"] = role_claim

def b64url(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

header_part = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
payload_part = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
signing_input = f"{header_part}.{payload_part}".encode("ascii")
sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()

print(f"{header_part}.{payload_part}.{b64url(sig)}")
PY
      return 0
    fi

    if ! command -v openssl >/dev/null 2>&1; then
      return 1
    fi

    local now
    now="$(date +%s 2>/dev/null || true)"
    if [[ -z "$now" || ! "$now" =~ ^[0-9]+$ ]]; then
      return 1
    fi

    local exp=$((now + 300))
    local header_json='{"alg":"HS256","typ":"JWT"}'
    local payload_json
    payload_json="{\"sub\":\"${sub}\",\"exp\":${exp},\"iss\":\"${issuer}\",\"aud\":\"${audience}\"}"
    if [[ -n "$role_claim" ]]; then
      payload_json="{\"sub\":\"${sub}\",\"exp\":${exp},\"iss\":\"${issuer}\",\"aud\":\"${audience}\",\"kk_role\":\"${role_claim}\"}"
    fi

    local header_part
    local payload_part
    local signing_input
    local sig_part
    header_part="$(printf '%s' "$header_json" | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
    payload_part="$(printf '%s' "$payload_json" | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
    signing_input="${header_part}.${payload_part}"
    sig_part="$(printf '%s' "$signing_input" | openssl dgst -sha256 -hmac "$secret" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
    printf '%s\n' "${signing_input}.${sig_part}"
  }

  generate_rs256_oidc_token_and_jwks() {
    local sub="$1"
    local issuer="$2"
    local audience="$3"
    local kid="$4"

    if ! command -v python3 >/dev/null 2>&1; then
      return 1
    fi

    python3 - "$sub" "$issuer" "$audience" "$kid" <<'PY'
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sub, issuer, audience, kid = sys.argv[1:5]
openssl_path = shutil.which("openssl")
if not openssl_path:
  sys.exit(2)

def b64url(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def run(args, **kwargs):
  return subprocess.run(args, check=True, **kwargs)

with tempfile.TemporaryDirectory(prefix="kryptkeeper-oidc-") as tmp_dir:
  private_key_path = os.path.join(tmp_dir, "private.pem")
  public_key_path = os.path.join(tmp_dir, "public.pem")

  run([openssl_path, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", private_key_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  run([openssl_path, "rsa", "-in", private_key_path, "-pubout", "-out", public_key_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

  public_text = subprocess.check_output([openssl_path, "rsa", "-pubin", "-in", public_key_path, "-text", "-noout"], text=True)
  lines = public_text.splitlines()

  modulus_parts = []
  capture_modulus = False
  exponent_int = None

  for line in lines:
    stripped = line.strip()
    if stripped.startswith("Modulus:"):
      capture_modulus = True
      continue
    if capture_modulus and stripped.startswith("Exponent:"):
      capture_modulus = False
      exp_match = re.search(r"Exponent:\s+([0-9]+)", stripped)
      if exp_match:
        exponent_int = int(exp_match.group(1))
      continue
    if capture_modulus:
      modulus_parts.append(stripped.replace(":", ""))

  if not modulus_parts or exponent_int is None:
    raise RuntimeError("unable to parse RSA public key components")

  modulus_hex = "".join(modulus_parts)
  modulus_int = int(modulus_hex, 16)
  modulus_len = max(1, (modulus_int.bit_length() + 7) // 8)
  n = modulus_int.to_bytes(modulus_len, "big")

  exponent_len = max(1, (exponent_int.bit_length() + 7) // 8)
  e = exponent_int.to_bytes(exponent_len, "big")

  jwks = {
    "keys": [
      {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": b64url(n),
        "e": b64url(e),
      }
    ]
  }

  now = int(time.time())
  header = {"alg": "RS256", "typ": "JWT", "kid": kid}
  payload = {
    "sub": sub,
    "iss": issuer,
    "aud": audience,
    "iat": now,
    "exp": now + 300,
  }

  header_part = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
  payload_part = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
  signing_input = f"{header_part}.{payload_part}".encode("ascii")

  signature = subprocess.check_output([openssl_path, "dgst", "-sha256", "-sign", private_key_path], input=signing_input)
  token = f"{header_part}.{payload_part}.{b64url(signature)}"

  print(token)
  print(json.dumps(jwks, separators=(",", ":")))
PY
  }

  # W19-21: no per-function trap/cleanup() here anymore -- every pid/port
  # this function starts is registered with the top-level track_pid/
  # track_port helpers (see each `pid="$!"` and `port="$(allocate_free_port)"`
  # below) and reaped by the single script-wide cleanup_all trap, which
  # doesn't have the local-variable-scoping gap the old per-function
  # trap had.

  echo "[smoke] Building local binary for runtime smoke"
  if ! go build -o "$bin_path" ./cmd/kryptkeeper; then
    echo "[smoke] ERROR go build failed for ./cmd/kryptkeeper" >&2
    return 1
  fi

  if ! port="$(allocate_free_port)"; then
    echo "[smoke] WARN unable to allocate a free local port; skipping local mode"
    return "$SKIP_EXIT_CODE"
  fi

  echo "[smoke] Starting local binary on port $port"
  # W19-24: S-70 made discovery's seed endpoints/scan-jobs opt-in
  # (APP_DISCOVERY_DEMO_SEEDS, docs/STATUS.md 2026-08-18) so a fresh
  # environment doesn't show fabricated data against zeroed counters -- this
  # launch predates that change and never set it, so ListEndpoints/
  # ListScanJobs always saw an empty seed slice and the filter/pagination
  # assertions below failed on every run, not just this machine. The four
  # APP_DISCOVERY_* count overrides keep GetSummary's counters at the
  # pre-existing zero baseline (discovery/dashboard summary assertions below
  # assert 0 across the board) -- GetSummary derives its defaults from the
  # same seed slices (fileDiscoveryProvider.GetSummary), so turning seeds on
  # without these would change those already-passing assertions too.
  PORT="$port" AUTH_MODE="bootstrap" APP_BOOTSTRAP_TOKEN="$bootstrap_token" APP_DISCOVERY_PROVIDER="file" APP_DISCOVERY_DEMO_SEEDS="true" APP_DASHBOARD_ACTION_DEMO="true" APP_DISCOVERY_DISCOVERED_ENDPOINTS="0" APP_DISCOVERY_MAPPED_CERTIFICATES="0" APP_DISCOVERY_RISKY_ENDPOINTS="0" APP_DISCOVERY_ACTIVE_SCAN_JOBS="0" APP_CERTS_SUMMARY_FILE="$summary_file" APP_AUDIT_FILE="$audit_file" APP_CA_FILE="$ca_file" APP_TEMPLATE_FILE="$template_file" APP_CERTIFICATE_FILE="$certificate_file" APP_AUTH_LOGIN_ENABLED="true" APP_AUTH_LOGIN_EMAIL="admin@example.com" APP_AUTH_LOGIN_PASSWORD_HASH="13eb3cd84e895d9aec00db8145ebbe377915bfa0dfb2be8295b82443aecb332d" APP_AUTH_LOGIN_PASSWORD_PEPPER="smoke-login-pepper" APP_AUTH_LOGIN_SUBJECT="team-1" APP_AUTH_LOGIN_SIGNING_SECRET="smoke-login-signing-secret-0123456789abcdef" APP_API_KEY_AUTH_ENABLED="true" APP_API_KEY_PEPPER="dev-api-key-pepper" APP_API_KEYS_JSON='[{"kid":"smoke","secret_verifier":"e27bf9a5fbc3ffad1c1a9ee77707f9b2d2998f98e89ac3270572aa34565363af","principal_id":"team-1","role":"service-account","scopes":["*"],"active":true}]' KRYPTKEEPER_TLS_DISABLE="true" "$bin_path" >"$app_log" 2>&1 &
  pid="$!"
  track_pid "$pid"
  track_port "$port"

  local base_url="http://127.0.0.1:$port"
  local attempt
  for attempt in {1..40}; do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "[smoke] ERROR local binary exited before health checks completed" >&2
      if [[ -f "$app_log" ]]; then
        echo "[smoke] INFO local binary logs:" >&2
        cat "$app_log" >&2
      fi
      return 1
    fi

    if curl -sS -o /dev/null --max-time 1 "$base_url/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done

  curl_expect_200 "GET" "$base_url/healthz" "healthz returns ok json" "200" '"status":"ok"' "application/json"
  curl_expect_200 "GET" "$base_url/readyz" "readyz returns ready json" "200" '"status":"ready"' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/meta" "meta returns service/version json" "200" '"service":"kryptkeeper"' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/meta" "meta includes version field" "200" '"version":"' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/auth/login" "auth login returns tokens for valid local user" "200" '"access_token":"' "application/json" "" '{"email":"admin@example.com","password":"bootstrap-dev-password"}'
  curl_expect_200 "POST" "$base_url/api/v1/auth/login" "auth login rejects invalid password" "401" '{"error":"unauthorized","message":"invalid credentials"}' "application/json" "" '{"email":"admin@example.com","password":"wrong"}'
  curl_expect_200 "POST" "$base_url/api/v1/auth/refresh" "auth refresh rejects invalid token" "401" '{"error":"unauthorized","message":"invalid refresh token"}' "application/json" "" '{"refresh_token":"bad-token"}'
  curl_expect_200 "GET" "$base_url/api/v1/authz-check" "authz-check rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/authz-check" "authz-check returns principal for valid bearer token" "200" '"authenticated":true,"principal":"bootstrap"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/protocols/status" "protocol status bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protocols/status" "protocol status bootstrap mode returns protocol flags" "200" '"resource":"protocol-status","principal":"bootstrap","protocols":{"acme":false,"est":false,"scep":false,"ocsp":false,"crl":false}' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/protocols/readiness" "protocol readiness bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protocols/readiness" "protocol readiness bootstrap mode returns readiness envelope" "200" '"resource":"protocol-readiness","principal":"bootstrap","protocols":{"acme":{"enabled":false,"healthy":false,"last_checked_at":null}' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/protocols/conformance" "protocol conformance bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protocols/conformance" "protocol conformance bootstrap mode returns suite status envelope" "200" '"resource":"protocol-conformance","principal":"bootstrap","suites":{"acme":{"state":"pass"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/protocols/conformance/recheck" "protocol conformance recheck bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"suite":"acme","reason":"smoke recheck"}'
  curl_expect_200 "POST" "$base_url/api/v1/protocols/conformance/recheck" "protocol conformance recheck bootstrap mode queues job" "202" '"resource":"protocol-conformance-recheck"' "application/json" "Authorization: Bearer $bootstrap_token" '{"suite":"acme","reason":"smoke recheck"}'
  curl_expect_200 "GET" "$base_url/api/v1/discovery/summary" "discovery summary bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/summary" "discovery summary bootstrap mode returns summary counts" "200" '"resource":"discovery-summary","principal":"bootstrap","discovered_endpoints":0,"mapped_certificates":0,"risky_endpoints":0,"active_scan_jobs":0' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/endpoints" "discovery endpoints bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/endpoints?protocol=tls&risky_only=true&limit=1&cursor=0" "discovery endpoints bootstrap mode returns filtered risky endpoint page" "200" '"resource":"discovery-endpoints","principal":"bootstrap","endpoints":[{"id":"ep-risky-1"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/endpoints?protocol=tls&risky_only=true&limit=1&cursor=0" "discovery endpoints bootstrap mode returns pagination metadata" "200" '"meta":{"total":1,"limit":1,"next_cursor":null,"prev_cursor":null}' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/scan-jobs" "discovery scan-jobs bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/scan-jobs?status=running&q=10.0.0&limit=1&cursor=0" "discovery scan-jobs bootstrap mode returns filtered page" "200" '"resource":"discovery-scan-jobs","principal":"bootstrap","scan_jobs":[{"id":"scan-1700000000000000001"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/scan-jobs?status=running&q=10.0.0&limit=1&cursor=0" "discovery scan-jobs bootstrap mode returns pagination metadata" "200" '"meta":{"total":1,"limit":1,"next_cursor":null,"prev_cursor":null}' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scan-jobs/cancel" "discovery scan-job cancel bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"scan_job_id":"scan-1700000000000000001","reason":"smoke cancel"}'
  # W19-24: the file discovery provider has no scan runner and deliberately
  # refuses every write with 422 (discovery_file_provider.go's
  # errDiscoveryScanUnsupported) -- it used to fabricate a 202/201 success
  # for a scan it then discarded, a real defect fixed and documented in
  # docs/STATUS.md's 2026-08-20 entry ("the default file discovery provider
  # fabricated a 201 'queued' job it then discarded ... now refuses with
  # directions, surfaced as 422"). These three assertions still expected the
  # pre-fix 202/201 shape; the local-binary smoke launch above only ever
  # pins the file provider explicitly (APP_DISCOVERY_PROVIDER=file; the
  # code default is db since 2026-10), so 422 with the documented message
  # is the correct, permanent expectation for file mode, not an environment
  # gap. Without the pin these POSTs would start a real /24 scan.
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scan-jobs/cancel" "discovery scan-job cancel bootstrap mode refuses on file provider (no scan runner)" "422" '"error":"unprocessable_entity","message":"network scans need the database-backed discovery provider' "application/json" "Authorization: Bearer $bootstrap_token" '{"scan_job_id":"scan-1700000000000000001","reason":"smoke cancel"}'
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scan-jobs/requeue" "discovery scan-job requeue bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"scan_job_id":"scan-1700000000000000001","reason":"smoke requeue"}'
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scan-jobs/requeue" "discovery scan-job requeue bootstrap mode refuses on file provider (no scan runner)" "422" '"error":"unprocessable_entity","message":"network scans need the database-backed discovery provider' "application/json" "Authorization: Bearer $bootstrap_token" '{"scan_job_id":"scan-1700000000000000001","reason":"smoke requeue"}'
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scans" "discovery scan create bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"scan_type":"full","target":"10.0.0.0/24"}'
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scans" "discovery scan create bootstrap mode refuses on file provider (no scan runner)" "422" '"error":"unprocessable_entity","message":"network scans need the database-backed discovery provider' "application/json" "Authorization: Bearer $bootstrap_token" '{"scan_type":"full","target":"10.0.0.0/24"}'
  curl_expect_200 "GET" "$base_url/api/v1/notifications/summary" "notification summary bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/notifications/summary" "notification summary bootstrap mode returns summary counts" "200" '"resource":"notification-summary","principal":"bootstrap","pending_notifications":0,"ownership_escalations":0,"delivery_failures_24h":0' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/notifications/deliveries" "notification deliveries bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/notifications/deliveries?status=failed&channel=email&limit=1&cursor=0" "notification deliveries bootstrap mode returns filtered page" "200" '"resource":"notification-deliveries","principal":"bootstrap","deliveries":[{"id":"notif-failed-1"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/notifications/deliveries?status=failed&channel=email&limit=1&cursor=0" "notification deliveries bootstrap mode returns pagination metadata" "200" '"meta":{"total":1,"limit":1,"next_cursor":null,"prev_cursor":null}' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/notifications/deliveries/ack" "notification delivery ack bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"delivery_id":"notif-failed-1","note":"ack smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/notifications/deliveries/ack" "notification delivery ack bootstrap mode accepts acknowledgement" "202" '"resource":"notification-delivery-ack"' "application/json" "Authorization: Bearer $bootstrap_token" '{"delivery_id":"notif-failed-1","note":"ack smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/notifications/deliveries/retry" "notification delivery retry bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"delivery_id":"notif-failed-1","reason":"retry smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/notifications/deliveries/retry" "notification delivery retry bootstrap mode queues retry" "202" '"resource":"notification-delivery-retry"' "application/json" "Authorization: Bearer $bootstrap_token" '{"delivery_id":"notif-failed-1","reason":"retry smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/notifications/test-delivery" "notification test-delivery bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"channel":"email","target":"ops@example.com","message":"smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/notifications/test-delivery" "notification test-delivery bootstrap mode queues delivery" "202" '"resource":"notification-test-delivery","principal":"bootstrap","delivery":{"id":"notif-' "application/json" "Authorization: Bearer $bootstrap_token" '{"channel":"email","target":"ops@example.com","message":"smoke"}'
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/summary" "dashboard summary bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/summary" "dashboard summary bootstrap mode returns resource and principal" "200" '"resource":"dashboard-summary","principal":"bootstrap"' "application/json" "Authorization: Bearer $bootstrap_token"
  # W19-24: W11-01 (docs/STATUS.md 2026-08-18) inserted managed/external/
  # unmanaged fields between expired and source in the certificates block
  # (handlers_dashboard.go's response struct field order); this assertion
  # was written before that field order changed and never updated.
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/summary" "dashboard summary bootstrap mode returns certificate counts" "200" '"certificates":{"total":42,"revoked":0,"expiring_30_days":7,"expired":2,"managed":0,"external":0,"unmanaged":0,"unowned":0,"source":"file-store"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/summary" "dashboard summary bootstrap mode returns discovery counts" "200" '"discovery":{"discovered_endpoints":0,"risky_endpoints":0,"active_scan_jobs":0' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/summary" "dashboard summary bootstrap mode returns discovery finding funnel" "200" '"findings":{"raw":0,"deduped":0,"in_scope":0,"effective":0,"suppressed":0' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/summary" "dashboard summary bootstrap mode returns notification counts" "200" '"notifications":{"pending_notifications":0,"escalations":0' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/actions" "dashboard actions bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/actions" "dashboard actions bootstrap mode returns prioritized actions" "200" '"resource":"dashboard-actions","principal":"bootstrap","actions":[{"category":"certificate","count":7,"id":"act-expiring-certs"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/actions/history" "dashboard actions history bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/actions/history?status=open&category=certificate&limit=1&cursor=0" "dashboard actions history bootstrap mode returns filtered page" "200" '"resource":"dashboard-actions-history","principal":"bootstrap","history":[{"action_id":"act-expired-certs"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/actions/history?status=open&category=certificate&limit=1&cursor=0" "dashboard actions history bootstrap mode returns pagination metadata" "200" '"meta":{"total":1,"limit":1,"next_cursor":null,"prev_cursor":null}' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/actions/ack" "dashboard action ack bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"action_id":"act-expiring-certs","note":"ack from smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/actions/ack" "dashboard action ack bootstrap mode accepts acknowledgement" "202" '"resource":"dashboard-action-ack","principal":"bootstrap","action_id":"act-expiring-certs","status":"acknowledged"' "application/json" "Authorization: Bearer $bootstrap_token" '{"action_id":"act-expiring-certs","note":"ack from smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/actions/resolve" "dashboard action resolve bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"action_id":"act-expiring-certs","note":"resolved from smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/actions/resolve" "dashboard action resolve bootstrap mode accepts resolution" "202" '"resource":"dashboard-action-resolve"' "application/json" "Authorization: Bearer $bootstrap_token" '{"action_id":"act-expiring-certs","note":"resolved from smoke"}'
  curl_expect_200 "GET" "$base_url/api/v1/authz-check" "authz-check accepts configured api key bearer token" "200" '"authenticated":true,"principal":"team-1"' "application/json" "Authorization: Bearer kk_smoke_smoke-secret"
  curl_expect_200 "GET" "$base_url/api/v1/api-keys" "api keys list bootstrap mode returns configured key" "200" '"kid":"smoke"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/api-keys" "api keys create bootstrap mode returns token" "201" '"token":"kk_' "application/json" "Authorization: Bearer $bootstrap_token" '{"name":"smoke-created","principal_id":"smoke-created-svc","role":"service-account","scopes":["*"]}'
  curl_expect_200 "DELETE" "$base_url/api/v1/api-keys/smoke" "api keys delete bootstrap mode removes key" "204" "" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/authz-check" "authz-check rejects deleted api key" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "Authorization: Bearer kk_smoke_smoke-secret"
  curl_expect_200 "GET" "$base_url/api/v1/protected/ping" "protected ping bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protected/ping" "protected ping bootstrap mode returns ok and principal for valid token" "200" '"resource":"protected-ping","status":"ok","principal":"bootstrap"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/whoami" "protected whoami bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protected/whoami" "protected whoami bootstrap mode returns resource principal auth_mode and timestamp for valid token" "200" '"resource":"protected-whoami","principal":"bootstrap","auth_mode":"bootstrap","timestamp":"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/config" "protected config bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protected/config" "protected config bootstrap mode returns auth mode and expected config booleans" "200" '"resource":"protected-config","auth_mode":"bootstrap","config":{"oidc_enabled":false,"discovery_enabled":false,"jwt_mode_enabled":false}' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary bootstrap mode returns resource for valid token" "200" '"resource":"protected-certs-summary"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary bootstrap mode returns principal for valid token" "200" '"principal":"bootstrap"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary bootstrap mode returns deterministic summary values" "200" '"total":42,"expiring_30_days":7,"expired":2' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary bootstrap mode reports file-store source" "200" '"source":"file-store"' "application/json" "Authorization: Bearer $bootstrap_token"
  rm -f "$summary_file"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary bootstrap mode falls back to default source when summary file is missing" "200" '"source":"file-store-default"' "application/json" "Authorization: Bearer $bootstrap_token"
  write_summary_fixture
  curl_expect_200 "GET" "$base_url/" "root returns bootstrap text" "200" "kryptkeeper bootstrap app" "text/plain"
  curl_expect_200 "POST" "$base_url/healthz" "healthz rejects non-GET" "405" "method not allowed"
  curl_expect_200 "POST" "$base_url/api/v1/meta" "meta rejects non-GET" "405" "method not allowed"
  curl_expect_200 "POST" "$base_url/api/v1/authz-check" "authz-check rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/authz-check" "authz-check rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/protocols/status" "protocol status bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protocols/status" "protocol status bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/protocols/readiness" "protocol readiness bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protocols/readiness" "protocol readiness bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/protocols/conformance" "protocol conformance bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protocols/conformance" "protocol conformance bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/protocols/conformance/recheck" "protocol conformance recheck bootstrap mode rejects non-POST" "405" "method not allowed"
  curl_expect_200 "POST" "$base_url/api/v1/discovery/summary" "discovery summary bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/discovery/summary" "discovery summary bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/discovery/endpoints" "discovery endpoints bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/discovery/endpoints" "discovery endpoints bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scan-jobs" "discovery scan-jobs bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scan-jobs" "discovery scan-jobs bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/scan-jobs/cancel" "discovery scan-job cancel bootstrap mode rejects unauthenticated non-POST before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/scan-jobs/cancel" "discovery scan-job cancel bootstrap mode rejects non-POST" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/scan-jobs/requeue" "discovery scan-job requeue bootstrap mode rejects unauthenticated non-POST before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/scan-jobs/requeue" "discovery scan-job requeue bootstrap mode rejects non-POST" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/scans" "discovery scan create bootstrap mode rejects unauthenticated non-POST before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/scans" "discovery scan create bootstrap mode rejects non-POST" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/notifications/summary" "notification summary bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/notifications/summary" "notification summary bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/notifications/deliveries" "notification deliveries bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/notifications/deliveries" "notification deliveries bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/notifications/deliveries/ack" "notification delivery ack bootstrap mode rejects unauthenticated non-POST before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/notifications/deliveries/ack" "notification delivery ack bootstrap mode rejects non-POST" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/notifications/deliveries/retry" "notification delivery retry bootstrap mode rejects unauthenticated non-POST before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/notifications/deliveries/retry" "notification delivery retry bootstrap mode rejects non-POST" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/notifications/test-delivery" "notification test-delivery bootstrap mode rejects unauthenticated non-POST before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/notifications/test-delivery" "notification test-delivery bootstrap mode rejects non-POST" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/summary" "dashboard summary bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/summary" "dashboard summary bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/actions" "dashboard actions bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/actions" "dashboard actions bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/actions/history" "dashboard actions history bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/actions/history" "dashboard actions history bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/actions/ack" "dashboard action ack bootstrap mode rejects unauthenticated non-POST before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/actions/ack" "dashboard action ack bootstrap mode rejects non-POST" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/actions/resolve" "dashboard action resolve bootstrap mode rejects unauthenticated non-POST before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/actions/resolve" "dashboard action resolve bootstrap mode rejects non-POST" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/protected/ping" "protected ping bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protected/ping" "protected ping bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/protected/whoami" "protected whoami bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protected/whoami" "protected whoami bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/protected/config" "protected config bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protected/config" "protected config bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/protected/certs/summary" "protected certs summary bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protected/certs/summary" "protected certs summary bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/audit" "audit bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/audit" "audit bootstrap mode returns principal" "200" '"principal":"bootstrap"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/audit" "audit bootstrap mode returns protected resource audit records" "200" '"resource_type":"protected_resource"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/audit?action=protected.ping.read&limit=1&cursor=0&order=desc" "audit bootstrap mode supports action filter and cursor pagination params" "200" '"limit":1' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/audit?actor_id=system&resource_id=fp-1&after=2026-04-06T00:00:00Z&before=2026-04-08T00:00:00Z" "audit bootstrap mode supports actor/resource/time filters" "200" '"resource_id":"fp-1"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/audit" "audit bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/audit" "audit bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/cas" "ca list bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/cas?type=root&status=active&limit=1&cursor=0" "ca list bootstrap mode returns filtered row" "200" '"id":"ca-root-1"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/cas?type=root&status=active&limit=1&cursor=0" "ca list bootstrap mode returns limit metadata" "200" '"limit":1' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/cas/ca-root-1" "ca get bootstrap mode returns ca by id" "200" '"id":"ca-root-1"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/cas/ca-iss-1/chain" "ca chain bootstrap mode returns json chain" "200" '"ca_id":"ca-iss-1"' "application/json" "Authorization: Bearer $bootstrap_token"
  if [[ -n "$ca_chain_pem_available" ]]; then
    curl_expect_200 "GET" "$base_url/api/v1/cas/ca-iss-1/chain?format=pem" "ca chain bootstrap mode returns pem chain" "200" "-----BEGIN CERTIFICATE-----" "application/x-pem-file" "Authorization: Bearer $bootstrap_token"
  else
    skip_assertion "ca chain bootstrap mode returns pem chain" "openssl/python3 unavailable to mint a real self-signed CA cert for the fixture; handlers_cas.go (W19-01) correctly refuses to fabricate placeholder PEM bytes, so this needs a real one"
  fi
  curl_expect_200 "PATCH" "$base_url/api/v1/cas/ca-root-1" "ca patch bootstrap mode updates mutable fields" "200" '"display_name":"Root 1 Updated"' "application/json" "Authorization: Bearer $bootstrap_token" '{"display_name":"Root 1 Updated"}'
  curl_expect_200 "PATCH" "$base_url/api/v1/cas/ca-root-1" "ca patch bootstrap mode rejects immutable fields" "422" '{"error":"unprocessable_entity","message":"attempt to modify immutable field"}' "application/json" "Authorization: Bearer $bootstrap_token" '{"name":"immutable"}'
  curl_expect_200 "PATCH" "$base_url/api/v1/cas/ca-root-1" "ca patch bootstrap mode rejects invalid fields" "400" '{"error":"bad_request","message":"invalid request body"}' "application/json" "Authorization: Bearer $bootstrap_token" '{"unknown_field":"x"}'
  curl_expect_200 "DELETE" "$base_url/api/v1/cas/ca-root-1" "ca delete bootstrap mode rejects active status" "422" '{"error":"unprocessable_entity","message":"ca must be revoked or expired before deletion"}' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "DELETE" "$base_url/api/v1/cas/ca-revoked-busy" "ca delete bootstrap mode rejects active certificate conflict" "409" '{"error":"conflict","message":"ca has active certificates"}' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "DELETE" "$base_url/api/v1/cas/ca-revoked-empty" "ca delete bootstrap mode deletes revoked empty CA" "204" "" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/cas/ca-root-1/suspend" "ca suspend bootstrap mode updates status" "200" '"status":"suspended"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/cas/ca-root-1/suspend" "ca suspend bootstrap mode returns conflict when already suspended" "409" '{"error":"conflict","message":"ca state conflict"}' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/cas/ca-root-1/activate" "ca activate bootstrap mode updates status" "200" '"status":"active"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/cas/not-found" "ca get bootstrap mode returns not found" "404" '{"error":"not_found","message":"ca not found"}' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/cas/ca-root-1" "ca get bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/cas" "ca list bootstrap mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "DELETE" "$base_url/api/v1/cas" "ca list bootstrap mode rejects unsupported method" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/certificates" "certificate list bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/certificates?status=active&grade=C&ca_id=ca-root-1&limit=1&cursor=0" "certificate list bootstrap mode returns filtered row" "200" '"fingerprint_sha256":"fp-cur"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/certificates/fp-cur" "certificate get bootstrap mode returns certificate by fingerprint" "200" '"common_name":"api.example.com"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/certificates/fp-cur/chain" "certificate chain bootstrap mode returns current fingerprint" "200" '"current_fingerprint":"fp-cur"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/certificates/fp-cur/download?format=pem" "certificate download bootstrap mode returns pem" "200" "-----BEGIN CERTIFICATE-----" "application/x-pem-file" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/certificates" "certificate issue bootstrap mode creates certificate" "201" '"source":"api"' "application/json" "Authorization: Bearer $bootstrap_token" '{"ca_id":"ca-root-1","template_id":"tpl-tls-90d","csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\nbootstrap\n-----END CERTIFICATE REQUEST-----"}'
  curl_expect_200 "POST" "$base_url/api/v1/certificates/fp-renew-bootstrap/renew" "certificate renew bootstrap mode creates successor" "201" '"predecessor_fingerprint":"fp-renew-bootstrap"' "application/json" "Authorization: Bearer $bootstrap_token" '{"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\nrenew-bootstrap\n-----END CERTIFICATE REQUEST-----"}'
  curl_expect_200 "POST" "$base_url/api/v1/certificates/fp-renew-bootstrap/renew" "certificate renew bootstrap mode returns conflict when successor exists" "409" '{"error":"conflict","message":"certificate already has an active successor"}' "application/json" "Authorization: Bearer $bootstrap_token" '{"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\nrenew-bootstrap\n-----END CERTIFICATE REQUEST-----"}'
  curl_expect_200 "POST" "$base_url/api/v1/certificates/import" "certificate import bootstrap mode imports external cert" "201" '"source":"import"' "application/json" "Authorization: Bearer $bootstrap_token" '{"certificate_pem":"-----BEGIN CERTIFICATE-----\nbootstrap-import\n-----END CERTIFICATE-----","team_id":"team-1"}'
  curl_expect_200 "POST" "$base_url/api/v1/certificates/fp-cur/revoke" "certificate revoke bootstrap mode updates status" "200" '"renewal_status":"revoked"' "application/json" "Authorization: Bearer $bootstrap_token" '{"reason_code":1,"reason_text":"test"}'
  curl_expect_200 "POST" "$base_url/api/v1/certificates/fp-cur/revoke" "certificate revoke bootstrap mode returns conflict when already revoked" "409" '{"error":"conflict","message":"certificate is already revoked or expired"}' "application/json" "Authorization: Bearer $bootstrap_token" '{"reason_code":1,"reason_text":"test"}'
  curl_expect_200 "POST" "$base_url/api/v1/certificates/fp-cur" "certificate get bootstrap mode rejects non-GET" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/certificates" "certificate list bootstrap mode rejects non-GET/POST issue payload" "400" '{"error":"bad_request","message":"invalid request body"}' "application/json" "Authorization: Bearer $bootstrap_token" '{"ca_id":"ca-root-1"}'
  curl_expect_200 "GET" "$base_url/api/v1/templates" "template list bootstrap mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/templates?active=true&q=tls&limit=1&cursor=0" "template list bootstrap mode returns filtered row" "200" '"id":"tpl-tls-90d"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/templates" "template create bootstrap mode creates new template" "201" '"display_name":"Template Created Bootstrap"' "application/json" "Authorization: Bearer $bootstrap_token" '{"name":"created-bootstrap","display_name":"Template Created Bootstrap","oid":"1.3.6.1.4.1.99999.1.201","key_usage":["digitalSignature"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P90D","auto_enroll":false,"active":true}'
  curl_expect_200 "POST" "$base_url/api/v1/templates" "template create bootstrap mode rejects duplicate name" "409" '{"error":"conflict","message":"template name or oid already exists"}' "application/json" "Authorization: Bearer $bootstrap_token" '{"name":"tls-server-90d","display_name":"Duplicate","key_usage":["digitalSignature"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P90D"}'
  curl_expect_200 "GET" "$base_url/api/v1/templates/tpl-tls-90d" "template get bootstrap mode returns template by id" "200" '"name":"tls-server-90d"' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "PATCH" "$base_url/api/v1/templates/tpl-tls-90d" "template patch bootstrap mode updates mutable fields" "200" '"display_name":"TLS Bootstrap Updated"' "application/json" "Authorization: Bearer $bootstrap_token" '{"display_name":"TLS Bootstrap Updated","auto_enroll":false}'
  curl_expect_200 "PUT" "$base_url/api/v1/templates/tpl-tls-90d" "template replace bootstrap mode replaces template with if-match" "200" '"display_name":"TLS Bootstrap Replaced"' "application/json" "Authorization: Bearer $bootstrap_token" "If-Match: 4" '{"name":"tls-server-90d","display_name":"TLS Bootstrap Replaced","oid":"1.3.6.1.4.1.99999.1.1","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","RSA"],"min_key_size":2048,"validity_period":"P180D","renewal_overlap":"P30D","auto_enroll":true,"active":true}'
  curl_expect_200 "PUT" "$base_url/api/v1/templates/tpl-tls-90d" "template replace bootstrap mode enforces if-match precondition" "412" '{"error":"precondition_failed","message":"if-match revision mismatch"}' "application/json" "Authorization: Bearer $bootstrap_token" "If-Match: 1" '{"name":"tls-server-90d","display_name":"TLS Bootstrap Replaced","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P180D"}'
  curl_expect_200 "POST" "$base_url/api/v1/templates/tpl-tls-90d/clone" "template clone bootstrap mode creates inactive clone" "201" '"display_name":"TLS Bootstrap Clone"' "application/json" "Authorization: Bearer $bootstrap_token" '{"name":"tls-server-90d-clone-bootstrap","display_name":"TLS Bootstrap Clone"}'
  curl_expect_200 "POST" "$base_url/api/v1/templates/tpl-tls-90d/clone" "template clone bootstrap mode rejects duplicate clone name" "409" '{"error":"conflict","message":"template name or oid already exists"}' "application/json" "Authorization: Bearer $bootstrap_token" '{"name":"tls-server-90d","display_name":"Dup"}'
  curl_expect_200 "PATCH" "$base_url/api/v1/templates/tpl-tls-90d" "template patch bootstrap mode rejects immutable fields" "422" '{"error":"unprocessable_entity","message":"attempt to modify immutable field"}' "application/json" "Authorization: Bearer $bootstrap_token" '{"name":"immutable"}'
  curl_expect_200 "PATCH" "$base_url/api/v1/templates/tpl-tls-90d" "template patch bootstrap mode rejects invalid fields" "400" '{"error":"bad_request","message":"invalid request body"}' "application/json" "Authorization: Bearer $bootstrap_token" '{"unknown_field":"x"}'
  curl_expect_200 "DELETE" "$base_url/api/v1/templates/tpl-tls-90d" "template delete bootstrap mode rejects issued certificate conflict" "409" '{"error":"conflict","message":"template has issued certificates"}' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "DELETE" "$base_url/api/v1/templates/tpl-unused-zero" "template delete bootstrap mode deletes unused template" "204" "" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "GET" "$base_url/api/v1/templates/missing" "template get bootstrap mode returns not found" "404" '{"error":"not_found","message":"template not found"}' "application/json" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "DELETE" "$base_url/api/v1/templates" "template list bootstrap mode rejects non-GET/POST" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"
  curl_expect_200 "POST" "$base_url/api/v1/templates/tpl-tls-90d" "template detail bootstrap mode rejects non-GET/PUT/PATCH/DELETE" "405" "method not allowed" "" "Authorization: Bearer $bootstrap_token"

  if command -v sqlite3 >/dev/null 2>&1; then
    if ! write_sqlite_summary_fixture; then
      echo "[smoke] WARN sqlite3 fixture generation failed; skipping db provider smoke checks"
    else
      if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
        kill "$pid" >/dev/null 2>&1 || true
        wait "$pid" >/dev/null 2>&1 || true
        pid=""
      fi

      if ! port="$(allocate_free_port)"; then
        echo "[smoke] WARN unable to allocate a free local port for db sqlite checks; skipping db provider smoke"
      else
        echo "[smoke] Starting local binary in db sqlite provider mode on port $port"
        PORT="$port" AUTH_MODE="bootstrap" APP_BOOTSTRAP_TOKEN="$bootstrap_token" APP_CERTS_SUMMARY_PROVIDER="db" APP_AUDIT_PROVIDER="db" KRYPTKEEPER_DB_MODE="sqlite" APP_CERTS_SUMMARY_DB_DSN="file:${sqlite_db_file}?cache=shared&_fk=1&_journal_mode=WAL" APP_AUDIT_DB_DSN="file:${sqlite_db_file}?cache=shared&_fk=1&_journal_mode=WAL" KRYPTKEEPER_TLS_DISABLE="true" "$bin_path" >"$app_log" 2>&1 &
        pid="$!"
        track_pid "$pid"
        track_port "$port"
        base_url="http://127.0.0.1:$port"

        for attempt in {1..40}; do
          if ! kill -0 "$pid" >/dev/null 2>&1; then
            echo "[smoke] ERROR local db-sqlite-mode binary exited before health checks completed" >&2
            if [[ -f "$app_log" ]]; then
              echo "[smoke] INFO local binary logs:" >&2
              cat "$app_log" >&2
            fi
            return 1
          fi

          if curl -sS -o /dev/null --max-time 1 "$base_url/healthz" >/dev/null 2>&1; then
            break
          fi
          sleep 0.25
        done

        curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary db sqlite mode returns db source" "200" '"source":"db-store-sqlite"' "application/json" "Authorization: Bearer $bootstrap_token"
        curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary db sqlite mode returns computed counters" "200" '"total":4,"expiring_30_days":2,"expired":1' "application/json" "Authorization: Bearer $bootstrap_token"

        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
          kill "$pid" >/dev/null 2>&1 || true
          wait "$pid" >/dev/null 2>&1 || true
          pid=""
        fi

        if ! port="$(allocate_free_port)"; then
          echo "[smoke] WARN unable to allocate a free local port for db postgres fail-closed checks; skipping"
        else
          echo "[smoke] Starting local binary in db postgres mode (no DSN) on port $port"
          PORT="$port" AUTH_MODE="bootstrap" APP_BOOTSTRAP_TOKEN="$bootstrap_token" APP_CERTS_SUMMARY_PROVIDER="db" APP_AUDIT_PROVIDER="file" APP_AUDIT_FILE="$audit_file" KRYPTKEEPER_DB_MODE="postgres" APP_CERTS_SUMMARY_DB_DSN="" APP_AUDIT_DB_DSN="" KRYPTKEEPER_DB_DSN="" DATABASE_URL="" KRYPTKEEPER_TLS_DISABLE="true" "$bin_path" >"$app_log" 2>&1 &
          pid="$!"
          track_pid "$pid"
          track_port "$port"
          base_url="http://127.0.0.1:$port"

          for attempt in {1..40}; do
            if ! kill -0 "$pid" >/dev/null 2>&1; then
              echo "[smoke] ERROR local db-postgres-mode binary exited before health checks completed" >&2
              if [[ -f "$app_log" ]]; then
                echo "[smoke] INFO local binary logs:" >&2
                cat "$app_log" >&2
              fi
              return 1
            fi

            if curl -sS -o /dev/null --max-time 1 "$base_url/healthz" >/dev/null 2>&1; then
              break
            fi
            sleep 0.25
          done

          curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary db postgres mode fails closed without DSN" "503" '{"error":"service_unavailable","message":"certificate summary unavailable"}' "application/json" "Authorization: Bearer $bootstrap_token"
        fi
      fi
    fi
  else
    echo "[smoke] WARN sqlite3 not available; skipping db provider smoke checks"
  fi

  local jwt_secret="local-smoke-jwt-secret-0123456789abcdef"
  local jwt_sub="team-1"
  local jwt_other_sub="team-2"
  local jwt_issuer="local-smoke-issuer"
  local jwt_audience="local-smoke-audience"
  # Bearer tokens are read-only (viewer) unless their kk_role claim is mapped
  # (APP_AUTH_ROLE_MAP_JSON below). jwt_token / jwt_other_token carry the
  # claim and act as service-accounts; jwt_readonly_token does not.
  local jwt_role_value="kk-issuer"
  local jwt_token
  local jwt_other_token
  local jwt_readonly_token
  if ! jwt_token="$(generate_hs256_jwt "$jwt_sub" "$jwt_secret" "$jwt_issuer" "$jwt_audience" "$jwt_role_value")"; then
    echo "[smoke] WARN unable to generate local JWT token (python3/openssl tooling unavailable); skipping jwt mode auth checks"
    echo "[smoke] PASS local runtime smoke"
    return 0
  fi
  if ! jwt_readonly_token="$(generate_hs256_jwt "$jwt_sub" "$jwt_secret" "$jwt_issuer" "$jwt_audience")"; then
    echo "[smoke] WARN unable to generate read-only local JWT token; skipping jwt mode authz checks"
    echo "[smoke] PASS local runtime smoke"
    return 0
  fi
  if ! jwt_other_token="$(generate_hs256_jwt "$jwt_other_sub" "$jwt_secret" "$jwt_issuer" "$jwt_audience" "$jwt_role_value")"; then
    echo "[smoke] WARN unable to generate secondary local JWT token; skipping jwt mode authz checks"
    echo "[smoke] PASS local runtime smoke"
    return 0
  fi

  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
    pid=""
  fi

  if ! port="$(allocate_free_port)"; then
    echo "[smoke] WARN unable to allocate a free local port for jwt mode checks; skipping local jwt smoke"
    echo "[smoke] PASS local runtime smoke"
    return 0
  fi

  echo "[smoke] Starting local binary in jwt auth mode on port $port"
  PORT="$port" AUTH_MODE="jwt" APP_AUTH_UNMAPPED_ROLE="read-only" APP_AUTH_ROLE_CLAIM="kk_role" APP_AUTH_ROLE_MAP_JSON="[{\"claim_value\":\"${jwt_role_value}\",\"role\":\"service-account\"}]" APP_JWT_HS256_SECRET="$jwt_secret" APP_JWT_ISSUER="$jwt_issuer" APP_JWT_AUDIENCE="$jwt_audience" APP_CERTS_SUMMARY_FILE="$summary_file" APP_AUDIT_FILE="$audit_file" APP_CA_FILE="$ca_file" APP_TEMPLATE_FILE="$template_file" APP_CERTIFICATE_FILE="$certificate_file" KRYPTKEEPER_TLS_DISABLE="true" "$bin_path" >"$app_log" 2>&1 &
  pid="$!"
  track_pid "$pid"
  track_port "$port"
  base_url="http://127.0.0.1:$port"

  for attempt in {1..40}; do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "[smoke] ERROR local jwt-mode binary exited before health checks completed" >&2
      if [[ -f "$app_log" ]]; then
        echo "[smoke] INFO local binary logs:" >&2
        cat "$app_log" >&2
      fi
      return 1
    fi

    if curl -sS -o /dev/null --max-time 1 "$base_url/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done

  curl_expect_200 "GET" "$base_url/api/v1/authz-check" "authz-check jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/authz-check" "authz-check jwt mode accepts valid HS256 token" "200" "\"authenticated\":true,\"principal\":\"$jwt_sub\"" "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/protocols/status" "protocol status jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protocols/status" "protocol status jwt mode allows service-account read" "200" '"resource":"protocol-status"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/protocols/readiness" "protocol readiness jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protocols/readiness" "protocol readiness jwt mode allows service-account read" "200" '"resource":"protocol-readiness"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/protocols/conformance" "protocol conformance jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protocols/conformance" "protocol conformance jwt mode allows service-account read" "200" '"resource":"protocol-conformance"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/protocols/conformance/recheck" "protocol conformance recheck jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"suite":"acme","reason":"smoke recheck"}'
  curl_expect_200 "POST" "$base_url/api/v1/protocols/conformance/recheck" "protocol conformance recheck jwt mode denies non-ops write role" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"suite":"acme","reason":"smoke recheck"}'
  curl_expect_200 "GET" "$base_url/api/v1/discovery/summary" "discovery summary jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/summary" "discovery summary jwt mode allows service-account read" "200" '"resource":"discovery-summary"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/endpoints" "discovery endpoints jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/endpoints" "discovery endpoints jwt mode allows service-account read" "200" '"resource":"discovery-endpoints"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/scan-jobs" "discovery scan-jobs jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/discovery/scan-jobs" "discovery scan-jobs jwt mode allows service-account read" "200" '"resource":"discovery-scan-jobs"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scan-jobs/cancel" "discovery scan-job cancel jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"scan_job_id":"scan-1700000000000000001","reason":"smoke cancel"}'
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scan-jobs/cancel" "discovery scan-job cancel jwt mode denies non-ops write role" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"scan_job_id":"scan-1700000000000000001","reason":"smoke cancel"}'
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scan-jobs/requeue" "discovery scan-job requeue jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"scan_job_id":"scan-1700000000000000001","reason":"smoke requeue"}'
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scan-jobs/requeue" "discovery scan-job requeue jwt mode denies non-ops write role" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"scan_job_id":"scan-1700000000000000001","reason":"smoke requeue"}'
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scans" "discovery scan create jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"scan_type":"full","target":"10.0.0.0/24"}'
  curl_expect_200 "POST" "$base_url/api/v1/discovery/scans" "discovery scan create jwt mode denies non-ops write role" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"scan_type":"full","target":"10.0.0.0/24"}'
  curl_expect_200 "GET" "$base_url/api/v1/notifications/summary" "notification summary jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/notifications/summary" "notification summary jwt mode allows service-account read" "200" '"resource":"notification-summary"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/notifications/deliveries" "notification deliveries jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/notifications/deliveries" "notification deliveries jwt mode allows service-account read" "200" '"resource":"notification-deliveries"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/notifications/deliveries/ack" "notification delivery ack jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"delivery_id":"notif-failed-1","note":"ack smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/notifications/deliveries/ack" "notification delivery ack jwt mode denies non-ops write role" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"delivery_id":"notif-failed-1","note":"ack smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/notifications/deliveries/retry" "notification delivery retry jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"delivery_id":"notif-failed-1","reason":"retry smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/notifications/deliveries/retry" "notification delivery retry jwt mode denies non-ops write role" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"delivery_id":"notif-failed-1","reason":"retry smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/notifications/test-delivery" "notification test-delivery jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"channel":"email","target":"ops@example.com","message":"smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/notifications/test-delivery" "notification test-delivery jwt mode denies non-ops write role" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"channel":"email","target":"ops@example.com","message":"smoke"}'
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/summary" "dashboard summary jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/summary" "dashboard summary jwt mode allows service-account read" "200" '"resource":"dashboard-summary"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/actions" "dashboard actions jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/actions" "dashboard actions jwt mode allows service-account read" "200" '"resource":"dashboard-actions"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/actions/history" "dashboard actions history jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/dashboard/actions/history" "dashboard actions history jwt mode allows service-account read" "200" '"resource":"dashboard-actions-history"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/actions/ack" "dashboard action ack jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"action_id":"act-expiring-certs","note":"ack from smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/actions/ack" "dashboard action ack jwt mode denies non-ops write role" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"action_id":"act-expiring-certs","note":"ack from smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/actions/resolve" "dashboard action resolve jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json" "" '{"action_id":"act-expiring-certs","note":"resolved from smoke"}'
  curl_expect_200 "POST" "$base_url/api/v1/dashboard/actions/resolve" "dashboard action resolve jwt mode denies non-ops write role" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"action_id":"act-expiring-certs","note":"resolved from smoke"}'
  curl_expect_200 "GET" "$base_url/api/v1/api-keys" "api keys list jwt mode returns scoped empty list when no keys match principal" "200" '"data":[]' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/ping" "protected ping jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protected/ping" "protected ping jwt mode accepts valid HS256 token" "200" "\"resource\":\"protected-ping\",\"status\":\"ok\",\"principal\":\"$jwt_sub\"" "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/whoami" "protected whoami jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protected/whoami" "protected whoami jwt mode returns resource principal auth_mode and timestamp for valid token" "200" "\"resource\":\"protected-whoami\",\"principal\":\"$jwt_sub\",\"auth_mode\":\"jwt\",\"timestamp\":\"" "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/config" "protected config jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protected/config" "protected config jwt mode returns auth mode and expected config booleans" "200" '"resource":"protected-config","auth_mode":"jwt","config":{"oidc_enabled":false,"discovery_enabled":false,"jwt_mode_enabled":true}' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary jwt mode returns resource for valid token" "200" '"resource":"protected-certs-summary"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary jwt mode returns principal for valid token" "200" "\"principal\":\"$jwt_sub\"" "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary jwt mode returns deterministic summary values" "200" '"total":42,"expiring_30_days":7,"expired":2' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary jwt mode reports file-store source" "200" '"source":"file-store"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/audit" "audit jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/audit" "audit jwt mode refuses a service-account token (no audit.read)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/audit" "audit jwt mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/audit" "audit jwt mode refuses a service-account token (no write rule: admin only)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/cas" "ca list jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/cas?type=root&status=active&limit=1&cursor=0" "ca list jwt mode returns filtered row" "200" '"id":"ca-root-1"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/cas/ca-root-1" "ca get jwt mode returns ca by id" "200" '"id":"ca-root-1"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/cas/ca-iss-1/chain" "ca chain jwt mode returns json chain" "200" '"ca_id":"ca-iss-1"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "PATCH" "$base_url/api/v1/cas/ca-root-1" "ca patch jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"display_name":"Root 1 JWT Updated"}'
  curl_expect_200 "DELETE" "$base_url/api/v1/cas/ca-revoked-busy" "ca delete jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "DELETE" "$base_url/api/v1/cas/ca-revoked-empty-jwt" "ca delete jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/cas/ca-root-1/suspend" "ca suspend jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/cas/ca-root-1/activate" "ca activate jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/cas/ca-root-1" "ca get jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/cas" "ca list jwt mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "DELETE" "$base_url/api/v1/cas" "ca list jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/certificates" "certificate list jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/certificates?q=api-jwt&status=active&grade=C&ca_id=ca-root-1&limit=1&cursor=0" "certificate list jwt mode returns filtered row" "200" '"fingerprint_sha256":"fp-cur-jwt"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/certificates?team_id=team-1" "certificate list jwt mode allows matching team scope" "200" '"total":' "application/json" "Authorization: Bearer $jwt_token"
  # W19-24: S-37 (docs/STATUS.md 2026-08-19) replaced the generic
  # {"error":"forbidden","message":"forbidden"} body with reason-specific
  # messages so a caller/operator can tell a team-scope denial from a
  # tenant-visibility one (handlers_certificates.go's
  # certificateTeamScopeDeniedMessage); these two assertions predate that
  # change.
  curl_expect_200 "GET" "$base_url/api/v1/certificates?team_id=team-1" "certificate list jwt mode denies non-matching team scope" "403" '{"error":"forbidden","error_code":"team_scope_mismatch","message":"forbidden: certificate does not belong to your team"}' "application/json" "Authorization: Bearer $jwt_other_token"
  curl_expect_200 "GET" "$base_url/api/v1/certificates/fp-cur-jwt" "certificate get jwt mode returns certificate by fingerprint" "200" '"common_name":"api-jwt.example.com"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/certificates/fp-cur-jwt" "certificate get jwt mode denies non-owner team" "403" '{"error":"forbidden","error_code":"team_scope_mismatch","message":"forbidden: certificate does not belong to your team"}' "application/json" "Authorization: Bearer $jwt_other_token"
  curl_expect_200 "GET" "$base_url/api/v1/certificates/fp-cur-jwt/chain" "certificate chain jwt mode returns current fingerprint" "200" '"current_fingerprint":"fp-cur-jwt"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "GET" "$base_url/api/v1/certificates/fp-cur-jwt/download?format=der" "certificate download jwt mode returns der" "200" "DER:fp-cur-jwt" "application/pkix-cert" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/certificates" "certificate issue jwt mode creates certificate" "201" '"source":"api"' "application/json" "Authorization: Bearer $jwt_token" '{"ca_id":"ca-root-1","template_id":"tpl-tls-90d","csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\njwt\n-----END CERTIFICATE REQUEST-----"}'
  curl_expect_200 "POST" "$base_url/api/v1/certificates" "certificate issue jwt mode refuses a token without the mapped role claim (read-only viewer)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_readonly_token" '{"ca_id":"ca-root-1","template_id":"tpl-tls-90d","csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\njwt\n-----END CERTIFICATE REQUEST-----"}'
  curl_expect_200 "GET" "$base_url/api/v1/authz-check" "authz-check jwt mode still lets a read-only token read" "200" "\"authenticated\":true,\"principal\":\"$jwt_sub\"" "application/json" "Authorization: Bearer $jwt_readonly_token"
  curl_expect_200 "POST" "$base_url/api/v1/certificates/fp-cur-jwt/renew" "certificate renew jwt mode creates successor" "201" '"predecessor_fingerprint":"fp-cur-jwt"' "application/json" "Authorization: Bearer $jwt_token" '{"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\nrenew-jwt\n-----END CERTIFICATE REQUEST-----"}'
  curl_expect_200 "POST" "$base_url/api/v1/certificates/fp-cur-jwt/renew" "certificate renew jwt mode returns conflict when successor exists" "409" '{"error":"conflict","message":"certificate already has an active successor"}' "application/json" "Authorization: Bearer $jwt_token" '{"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\nrenew-jwt\n-----END CERTIFICATE REQUEST-----"}'
  curl_expect_200 "POST" "$base_url/api/v1/certificates/import" "certificate import jwt mode imports external cert" "201" '"source":"import"' "application/json" "Authorization: Bearer $jwt_token" '{"certificate_pem":"-----BEGIN CERTIFICATE-----\njwt-import\n-----END CERTIFICATE-----","team_id":"team-1"}'
  curl_expect_200 "POST" "$base_url/api/v1/certificates/fp-cur-jwt/revoke" "certificate revoke jwt mode refuses a service-account token (certificate.revoke)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"reason_code":1,"reason_text":"test"}'
  curl_expect_200 "POST" "$base_url/api/v1/certificates/fp-cur-jwt/revoke" "certificate revoke jwt mode refuses a service-account token again" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"reason_code":1,"reason_text":"test"}'
  curl_expect_200 "POST" "$base_url/api/v1/certificates/fp-cur-jwt" "certificate get jwt mode refuses a service-account token (no write rule: admin only)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/certificates" "certificate list jwt mode rejects non-GET/POST issue payload" "400" '{"error":"bad_request","message":"invalid request body"}' "application/json" "Authorization: Bearer $jwt_token" '{"ca_id":"ca-root-1"}'
  curl_expect_200 "GET" "$base_url/api/v1/templates" "template list jwt mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/templates?active=true&q=tls&limit=1&cursor=0" "template list jwt mode returns filtered row" "200" '"id":"tpl-tls-90d"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/templates" "template create jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"name":"created-jwt","display_name":"Template Created JWT","oid":"1.3.6.1.4.1.99999.1.202","key_usage":["digitalSignature"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P90D","auto_enroll":false,"active":true}'
  curl_expect_200 "POST" "$base_url/api/v1/templates" "template create jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"name":"oid-conflict-jwt","display_name":"OID Conflict","oid":"1.3.6.1.4.1.99999.1.1","key_usage":["digitalSignature"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P90D"}'
  curl_expect_200 "GET" "$base_url/api/v1/templates/tpl-tls-90d" "template get jwt mode returns template by id" "200" '"name":"tls-server-90d"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "PATCH" "$base_url/api/v1/templates/tpl-tls-90d" "template patch jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"display_name":"TLS JWT Updated","active":false}'
  curl_expect_200 "PUT" "$base_url/api/v1/templates/tpl-tls-90d" "template replace jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" "If-Match: 6" '{"name":"tls-server-90d","display_name":"TLS JWT Replaced","oid":"1.3.6.1.4.1.99999.1.1","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","RSA"],"min_key_size":2048,"validity_period":"P180D","renewal_overlap":"P30D","auto_enroll":true,"active":true}'
  curl_expect_200 "PUT" "$base_url/api/v1/templates/tpl-tls-90d" "template replace jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" "If-Match: 1" '{"name":"tls-server-90d","display_name":"TLS JWT Replaced","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P180D"}'
  curl_expect_200 "POST" "$base_url/api/v1/templates/tpl-tls-90d/clone" "template clone jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"name":"tls-server-90d-clone-jwt","display_name":"TLS JWT Clone"}'
  curl_expect_200 "POST" "$base_url/api/v1/templates/tpl-tls-90d/clone" "template clone jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"name":"tls-server-90d","display_name":"Dup"}'
  curl_expect_200 "PATCH" "$base_url/api/v1/templates/tpl-tls-90d" "template patch jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"name":"immutable"}'
  curl_expect_200 "PATCH" "$base_url/api/v1/templates/tpl-tls-90d" "template patch jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token" '{"unknown_field":"x"}'
  curl_expect_200 "DELETE" "$base_url/api/v1/templates/tpl-tls-90d" "template delete jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "DELETE" "$base_url/api/v1/templates/tpl-unused-zero-jwt" "template delete jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "DELETE" "$base_url/api/v1/templates" "template list jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/templates/tpl-tls-90d" "template detail jwt mode refuses a service-account token (ca.manage)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/authz-check" "authz-check jwt mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/authz-check" "authz-check jwt mode refuses a service-account token (no write rule: admin only)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/protected/ping" "protected ping jwt mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protected/ping" "protected ping jwt mode refuses a service-account token (no write rule: admin only)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/protected/whoami" "protected whoami jwt mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protected/whoami" "protected whoami jwt mode refuses a service-account token (no write rule: admin only)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/protected/config" "protected config jwt mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protected/config" "protected config jwt mode refuses a service-account token (no write rule: admin only)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"
  curl_expect_200 "POST" "$base_url/api/v1/protected/certs/summary" "protected certs summary jwt mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protected/certs/summary" "protected certs summary jwt mode refuses a service-account token (no write rule: admin only)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $jwt_token"

  # W19-14: run here, not at the very end of this function -- several OIDC
  # sub-scenarios below warn-and-return-early when optional tooling
  # (python3/openssl RSA JWK generation) is unavailable, which would skip a
  # TLS pass placed after them even though it has no OIDC dependency itself.
  run_tls_smoke "$bin_path" "$tmp_dir"
  run_estate_import_smoke "$bin_path" "$tmp_dir"
  run_governance_smoke "$bin_path" "$tmp_dir"
  run_reports_smoke "$bin_path" "$tmp_dir"

  local oidc_sub="team-1"
  local oidc_issuer="https://local-smoke.example/issuer"
  local oidc_audience="kryptkeeper-local-smoke"
  local oidc_bundle
  local oidc_token
  local oidc_jwks_json
  local -a oidc_lines=()
  if ! oidc_bundle="$(generate_rs256_oidc_token_and_jwks "$oidc_sub" "$oidc_issuer" "$oidc_audience" "local-smoke-oidc-kid")"; then
    echo "[smoke] WARN unable to generate OIDC RS256 token/JWKS (python3 and openssl required); skipping oidc mode auth checks"
    echo "[smoke] PASS local runtime smoke"
    return 0
  fi

  mapfile -t oidc_lines <<<"$oidc_bundle"
  oidc_token="${oidc_lines[0]:-}"
  oidc_jwks_json="${oidc_lines[1]:-}"
  if [[ -z "$oidc_token" || -z "$oidc_jwks_json" ]]; then
    echo "[smoke] WARN oidc token generation produced incomplete output; skipping oidc mode auth checks"
    echo "[smoke] PASS local runtime smoke"
    return 0
  fi

  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
    pid=""
  fi

  if ! port="$(allocate_free_port)"; then
    echo "[smoke] WARN unable to allocate a free local port for oidc mode checks; skipping local oidc smoke"
    echo "[smoke] PASS local runtime smoke"
    return 0
  fi

  echo "[smoke] Starting local binary in oidc auth mode on port $port"
  PORT="$port" AUTH_MODE="oidc" APP_AUTH_UNMAPPED_ROLE="read-only" APP_OIDC_ISSUER="$oidc_issuer" APP_OIDC_AUDIENCE="$oidc_audience" APP_OIDC_JWKS_JSON="$oidc_jwks_json" APP_CERTS_SUMMARY_FILE="$summary_file" APP_AUDIT_FILE="$audit_file" APP_CA_FILE="$ca_file" APP_TEMPLATE_FILE="$template_file" APP_CERTIFICATE_FILE="$certificate_file" KRYPTKEEPER_TLS_DISABLE="true" "$bin_path" >"$app_log" 2>&1 &
  pid="$!"
  track_pid "$pid"
  track_port "$port"
  base_url="http://127.0.0.1:$port"

  for attempt in {1..40}; do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "[smoke] ERROR local oidc-mode binary exited before health checks completed" >&2
      if [[ -f "$app_log" ]]; then
        echo "[smoke] INFO local binary logs:" >&2
        cat "$app_log" >&2
      fi
      return 1
    fi

    if curl -sS -o /dev/null --max-time 1 "$base_url/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done

  curl_expect_200 "GET" "$base_url/api/v1/authz-check" "authz-check oidc mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/authz-check" "authz-check oidc mode accepts valid RS256 token" "200" "\"authenticated\":true,\"principal\":\"$oidc_sub\"" "application/json" "Authorization: Bearer $oidc_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/ping" "protected ping oidc mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protected/ping" "protected ping oidc mode accepts valid RS256 token" "200" "\"resource\":\"protected-ping\",\"status\":\"ok\",\"principal\":\"$oidc_sub\"" "application/json" "Authorization: Bearer $oidc_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/whoami" "protected whoami oidc mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protected/whoami" "protected whoami oidc mode returns resource principal auth_mode and timestamp for valid token" "200" "\"resource\":\"protected-whoami\",\"principal\":\"$oidc_sub\",\"auth_mode\":\"oidc\",\"timestamp\":\"" "application/json" "Authorization: Bearer $oidc_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/config" "protected config oidc mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protected/config" "protected config oidc mode returns auth mode and expected config booleans" "200" '"resource":"protected-config","auth_mode":"oidc","config":{"oidc_enabled":true,"discovery_enabled":false,"jwt_mode_enabled":false}' "application/json" "Authorization: Bearer $oidc_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary oidc mode rejects missing bearer token" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary oidc mode returns resource for valid token" "200" '"resource":"protected-certs-summary"' "application/json" "Authorization: Bearer $oidc_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary oidc mode returns principal for valid token" "200" "\"principal\":\"$oidc_sub\"" "application/json" "Authorization: Bearer $oidc_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary oidc mode returns deterministic summary values" "200" '"total":42,"expiring_30_days":7,"expired":2' "application/json" "Authorization: Bearer $oidc_token"
  curl_expect_200 "GET" "$base_url/api/v1/protected/certs/summary" "protected certs summary oidc mode reports file-store source" "200" '"source":"file-store"' "application/json" "Authorization: Bearer $oidc_token"
  curl_expect_200 "POST" "$base_url/api/v1/authz-check" "authz-check oidc mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/authz-check" "authz-check oidc mode refuses a service-account token (no write rule: admin only)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $oidc_token"
  curl_expect_200 "POST" "$base_url/api/v1/protected/ping" "protected ping oidc mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protected/ping" "protected ping oidc mode refuses a service-account token (no write rule: admin only)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $oidc_token"
  curl_expect_200 "POST" "$base_url/api/v1/protected/whoami" "protected whoami oidc mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protected/whoami" "protected whoami oidc mode refuses a service-account token (no write rule: admin only)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $oidc_token"
  curl_expect_200 "POST" "$base_url/api/v1/protected/config" "protected config oidc mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protected/config" "protected config oidc mode refuses a service-account token (no write rule: admin only)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $oidc_token"
  curl_expect_200 "POST" "$base_url/api/v1/protected/certs/summary" "protected certs summary oidc mode rejects unauthenticated non-GET before revealing allowed methods" "401" '{"error":"unauthorized","message":"invalid or missing bearer token"}' "application/json"
  curl_expect_200 "POST" "$base_url/api/v1/protected/certs/summary" "protected certs summary oidc mode refuses a service-account token (no write rule: admin only)" "403" '"error":"forbidden"' "application/json" "Authorization: Bearer $oidc_token"

  local oidc_discovery_mode="${KRYPTKEEPER_SMOKE_OIDC_DISCOVERY_MODE:-auto}"
  case "$oidc_discovery_mode" in
    off)
      echo "[smoke] INFO skipping OIDC discovery/JWKS rotation smoke (KRYPTKEEPER_SMOKE_OIDC_DISCOVERY_MODE=off)"
      ;;
    auto|on)
      if ! command -v python3 >/dev/null 2>&1; then
        echo "[smoke] WARN python3 not available; skipping OIDC discovery/JWKS rotation smoke"
      else
        local oidc_provider_port
        if ! oidc_provider_port="$(allocate_free_port)"; then
          echo "[smoke] WARN unable to allocate local port for OIDC discovery provider; skipping discovery/JWKS rotation smoke"
        else
          local oidc_discovery_issuer="http://127.0.0.1:${oidc_provider_port}"
          local oidc_discovery_url="${oidc_discovery_issuer}/.well-known/openid-configuration"
          local oidc_discovery_audience="kryptkeeper-local-smoke-oidc-discovery"
          local oidc_primary_bundle
          local oidc_rotated_bundle
          local oidc_primary_token
          local oidc_primary_jwks
          local oidc_rotated_token
          local oidc_rotated_jwks
          local -a oidc_primary_lines=()
          local -a oidc_rotated_lines=()

          if ! oidc_primary_bundle="$(generate_rs256_oidc_token_and_jwks "$oidc_sub" "$oidc_discovery_issuer" "$oidc_discovery_audience" "local-smoke-oidc-kid-1")"; then
            echo "[smoke] WARN unable to generate primary OIDC discovery token/JWKS; skipping discovery/JWKS rotation smoke"
          elif ! oidc_rotated_bundle="$(generate_rs256_oidc_token_and_jwks "$oidc_sub" "$oidc_discovery_issuer" "$oidc_discovery_audience" "local-smoke-oidc-kid-2")"; then
            echo "[smoke] WARN unable to generate rotated OIDC discovery token/JWKS; skipping discovery/JWKS rotation smoke"
          else
            mapfile -t oidc_primary_lines <<<"$oidc_primary_bundle"
            mapfile -t oidc_rotated_lines <<<"$oidc_rotated_bundle"
            oidc_primary_token="${oidc_primary_lines[0]:-}"
            oidc_primary_jwks="${oidc_primary_lines[1]:-}"
            oidc_rotated_token="${oidc_rotated_lines[0]:-}"
            oidc_rotated_jwks="${oidc_rotated_lines[1]:-}"

            if [[ -z "$oidc_primary_token" || -z "$oidc_primary_jwks" || -z "$oidc_rotated_token" || -z "$oidc_rotated_jwks" ]]; then
              echo "[smoke] WARN incomplete discovery/JWKS rotation artifacts; skipping discovery smoke"
            else
              local discovery_server_dir="$tmp_dir/oidc-discovery-server"
              mkdir -p "$discovery_server_dir/.well-known"
              cat > "$discovery_server_dir/.well-known/openid-configuration" <<EOF
{"issuer":"$oidc_discovery_issuer","jwks_uri":"$oidc_discovery_issuer/jwks.json"}
EOF
              printf '%s' "$oidc_primary_jwks" > "$discovery_server_dir/jwks.json"

              echo "[smoke] Starting local OIDC discovery provider on port $oidc_provider_port"
              python3 -m http.server "$oidc_provider_port" --bind 127.0.0.1 --directory "$discovery_server_dir" >"$tmp_dir/oidc-provider.log" 2>&1 &
              oidc_provider_pid="$!"
              track_pid "$oidc_provider_pid"
              track_port "$oidc_provider_port"

              sleep 0.25
              if ! kill -0 "$oidc_provider_pid" >/dev/null 2>&1; then
                echo "[smoke] WARN local OIDC discovery provider exited early; skipping discovery/JWKS rotation smoke"
              else
                if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
                  kill "$pid" >/dev/null 2>&1 || true
                  wait "$pid" >/dev/null 2>&1 || true
                  pid=""
                fi

                local oidc_refresh_seconds="${KRYPTKEEPER_SMOKE_OIDC_REFRESH_SECONDS:-1}"
                if [[ ! "$oidc_refresh_seconds" =~ ^[0-9]+$ || "$oidc_refresh_seconds" -le 0 ]]; then
                  echo "[smoke] WARN invalid KRYPTKEEPER_SMOKE_OIDC_REFRESH_SECONDS='$oidc_refresh_seconds'; defaulting to 1"
                  oidc_refresh_seconds="1"
                fi

                if ! port="$(allocate_free_port)"; then
                  echo "[smoke] WARN unable to allocate local port for OIDC discovery-mode app; skipping discovery/JWKS rotation smoke"
                else
                  echo "[smoke] Starting local binary in oidc discovery mode on port $port"
                  PORT="$port" AUTH_MODE="oidc" APP_AUTH_UNMAPPED_ROLE="read-only" APP_OIDC_ISSUER="$oidc_discovery_issuer" APP_OIDC_AUDIENCE="$oidc_discovery_audience" APP_OIDC_DISCOVERY_URL="$oidc_discovery_url" APP_OIDC_JWKS_TTL_SEC="$oidc_refresh_seconds" KRYPTKEEPER_TLS_DISABLE="true" "$bin_path" >"$app_log" 2>&1 &
                  pid="$!"
                  track_pid "$pid"
                  track_port "$port"
                  base_url="http://127.0.0.1:$port"

                  for attempt in {1..40}; do
                    if ! kill -0 "$pid" >/dev/null 2>&1; then
                      echo "[smoke] ERROR local oidc discovery-mode binary exited before health checks completed" >&2
                      if [[ -f "$app_log" ]]; then
                        echo "[smoke] INFO local binary logs:" >&2
                        cat "$app_log" >&2
                      fi
                      return 1
                    fi

                    if curl -sS -o /dev/null --max-time 1 "$base_url/healthz" >/dev/null 2>&1; then
                      break
                    fi
                    sleep 0.25
                  done

                  curl_expect_200 "GET" "$base_url/api/v1/authz-check" "authz-check oidc discovery mode accepts initial token" "200" "\"authenticated\":true,\"principal\":\"$oidc_sub\"" "application/json" "Authorization: Bearer $oidc_primary_token"
                  curl_expect_200 "GET" "$base_url/api/v1/protected/ping" "protected ping oidc discovery mode accepts initial token" "200" "\"resource\":\"protected-ping\",\"status\":\"ok\",\"principal\":\"$oidc_sub\"" "application/json" "Authorization: Bearer $oidc_primary_token"
                  curl_expect_200 "GET" "$base_url/api/v1/protected/config" "protected config oidc discovery mode reports active discovery enabled" "200" '"resource":"protected-config","auth_mode":"oidc","config":{"oidc_enabled":true,"discovery_enabled":true,"jwt_mode_enabled":false}' "application/json" "Authorization: Bearer $oidc_primary_token"

                  printf '%s' "$oidc_rotated_jwks" > "$discovery_server_dir/jwks.json"
                  sleep $((oidc_refresh_seconds + 1))

                  curl_expect_200 "GET" "$base_url/api/v1/authz-check" "authz-check oidc discovery mode accepts rotated token after JWKS refresh" "200" "\"authenticated\":true,\"principal\":\"$oidc_sub\"" "application/json" "Authorization: Bearer $oidc_rotated_token"
                  curl_expect_200 "GET" "$base_url/api/v1/protected/ping" "protected ping oidc discovery mode accepts rotated token after JWKS refresh" "200" "\"resource\":\"protected-ping\",\"status\":\"ok\",\"principal\":\"$oidc_sub\"" "application/json" "Authorization: Bearer $oidc_rotated_token"
                fi
              fi
            fi
          fi
        fi
      fi
      ;;
    *)
      echo "[smoke] WARN unsupported KRYPTKEEPER_SMOKE_OIDC_DISCOVERY_MODE='${oidc_discovery_mode}'; expected auto|on|off; skipping discovery/JWKS rotation smoke"
      ;;
  esac

  echo "[smoke] PASS local runtime smoke"
}

run_tls_smoke() {
  # W19-14: the hub previously had no TLS listener at all (UAT W19-05) --
  # this reuses the binary run_local_binary_smoke already built and starts a
  # second instance with KRYPTKEEPER_TLS_SELF_ISSUE=true, checking /healthz
  # and /readyz first with -k (proves the socket actually speaks TLS) and
  # then against the hub's own self-issued CA cert via --cacert (proves a
  # real chain verifies, no bypass -- the style tests/live/protocols/run.sh
  # uses for OCSP/CRL).
  local bin_path="$1"
  local base_tmp_dir="$2"

  echo "[smoke] --- TLS pass (KRYPTKEEPER_TLS_SELF_ISSUE=true) ---"

  if ! command -v openssl >/dev/null 2>&1; then
    echo "[smoke] WARN openssl not installed; skipping TLS pass"
    return 0
  fi

  local tls_dir="$base_tmp_dir/tls-pass"
  mkdir -p "$tls_dir/data"
  local tls_app_log="$tls_dir/app.log"
  local tls_port
  if ! tls_port="$(allocate_free_port)"; then
    echo "[smoke] WARN unable to allocate a free local port for the TLS pass; skipping"
    return 0
  fi

  APP_BOOTSTRAP_TOKEN="tls-smoke-token" AUTH_MODE="bootstrap" APP_CERTIFICATE_PROVIDER="ca" \
    APP_DISCOVERY_PROVIDER="db" APP_NOTIFICATION_PROVIDER="file" \
    APP_CREDENTIAL_STORE_PASSPHRASE="tls-smoke-cred-passphrase-32-bytes!!" \
    KRYPTKEEPER_KEYSTORE_PASSPHRASE="tls-smoke-keystore-passphrase-32b!!" \
    KRYPTKEEPER_DATA_DIR="$tls_dir/data" KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT="true" \
    KRYPTKEEPER_CA_NAME="TLS Smoke Root CA" KRYPTKEEPER_TLS_SELF_ISSUE="true" \
    PORT="$tls_port" "$bin_path" >"$tls_app_log" 2>&1 &
  local tls_pid="$!"
  track_pid "$tls_pid"
  track_port "$tls_port"

  local https_base="https://127.0.0.1:${tls_port}"
  local attempt up=""
  # 120 x 0.25s: migrations plus root-CA and TLS self-issue took >10s on a
  # busy shared CI runner.
  for attempt in {1..120}; do
    if ! kill -0 "$tls_pid" >/dev/null 2>&1; then
      echo "[smoke] ERROR TLS pass: local binary exited before health checks completed" >&2
      [[ -f "$tls_app_log" ]] && cat "$tls_app_log" >&2
      return 1
    fi
    if curl -sSk -o /dev/null --max-time 1 "$https_base/healthz" >/dev/null 2>&1; then
      up=1
      break
    fi
    sleep 0.25
  done
  if [[ -z "$up" ]]; then
    echo "[smoke] ERROR TLS pass: hub never came up on $https_base" >&2
    [[ -f "$tls_app_log" ]] && cat "$tls_app_log" >&2
    kill "$tls_pid" >/dev/null 2>&1 || true
    wait "$tls_pid" >/dev/null 2>&1 || true
    return 1
  fi

  EXTRA_CURL_OPTS=(-k)
  curl_expect_200 "GET" "$https_base/healthz" "TLS: healthz returns ok json (insecure, proves the socket speaks TLS)" "200" '"status":"ok"' "application/json"
  curl_expect_200 "GET" "$https_base/readyz" "TLS: readyz returns ready json (insecure, proves the socket speaks TLS)" "200" '"status":"ready"' "application/json"

  # SCEP is disabled by default here (needs KRYPTKEEPER_SCEP_ENABLED), so
  # fetch the CA the same way a real RFC 7030 client would: the EST cacerts
  # endpoint, unauthenticated per spec, now a real PKCS#7 certs-only
  # SignedData (fixed alongside this ticket -- see internal/est/server.go).
  local ca_b64="$tls_dir/cacerts.b64"
  local ca_p7="$tls_dir/cacerts.p7"
  local ca_pem="$tls_dir/ca.pem"
  if curl -sSk --max-time 3 -o "$ca_b64" "$https_base/.well-known/est/cacerts" \
    && openssl base64 -d -A -in "$ca_b64" -out "$ca_p7" 2>/dev/null \
    && openssl pkcs7 -inform der -in "$ca_p7" -print_certs -out "$ca_pem" 2>/dev/null; then
    EXTRA_CURL_OPTS=(--cacert "$ca_pem")
    curl_expect_200 "GET" "$https_base/healthz" "TLS: healthz verifies against the hub's own self-issued CA (real chain, no bypass)" "200" '"status":"ok"' "application/json"
    curl_expect_200 "GET" "$https_base/readyz" "TLS: readyz verifies against the hub's own self-issued CA (real chain, no bypass)" "200" '"status":"ready"' "application/json"
  else
    echo "[smoke] ERROR TLS pass: could not fetch/convert the hub's self-issued CA cert for real chain verification" >&2
    SMOKE_ASSERTIONS=$((SMOKE_ASSERTIONS + 1))
    SMOKE_ASSERTIONS_FAILED=$((SMOKE_ASSERTIONS_FAILED + 1))
  fi
  EXTRA_CURL_OPTS=()

  kill "$tls_pid" >/dev/null 2>&1 || true
  wait "$tls_pid" >/dev/null 2>&1 || true
  return 0
}

# W22-42: governance helpers. curl_expect_200 does not hand back bodies or
# headers, which the ownership/dual-control chains below need, so these keep
# the last response in GOV_CODE / GOV_BODY / GOV_HEADERS.
GOV_CODE=""
GOV_BODY=""
GOV_HEADERS=""

gov_curl() {
  local method="$1" url="$2" auth="${3:-}" body="${4:-}" xff="${5:-}"
  local args=(-sS -X "$method" -D - -o - --max-time 5 -w $'\n__GOVCODE__%{http_code}')
  [[ -n "$auth" ]] && args+=(-H "Authorization: $auth")
  [[ -n "$xff" ]] && args+=(-H "X-Forwarded-For: $xff")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" -d "$body")
  local raw
  raw="$(curl "${args[@]}" "$url" 2>/dev/null || true)"
  GOV_CODE="${raw##*__GOVCODE__}"
  raw="${raw%$'\n'__GOVCODE__*}"
  # -D - puts headers before the body, separated by a blank line; with a 100
  # Continue or redirects there could be several blocks, the last is ours.
  GOV_HEADERS="${raw%%$'\r\n\r\n'*}"
  GOV_BODY="${raw#*$'\r\n\r\n'}"
  [[ "$GOV_BODY" == "$raw" ]] && GOV_BODY=""
  return 0
}

gov_assert() {
  local name="$1" expected="$2" substr="${3:-}"
  SMOKE_ASSERTIONS=$((SMOKE_ASSERTIONS + 1))
  if [[ "$GOV_CODE" != "$expected" ]]; then
    echo "[smoke] ERROR ${name}: expected HTTP ${expected}, got ${GOV_CODE:-request_error}" >&2
    echo "[smoke] INFO response body: ${GOV_BODY:0:400}" >&2
    SMOKE_ASSERTIONS_FAILED=$((SMOKE_ASSERTIONS_FAILED + 1))
    return 0
  fi
  if [[ -n "$substr" && "$GOV_BODY" != *"$substr"* && "$GOV_HEADERS" != *"$substr"* ]]; then
    echo "[smoke] ERROR ${name}: response missing expected text: ${substr}" >&2
    echo "[smoke] INFO response body: ${GOV_BODY:0:400}" >&2
    SMOKE_ASSERTIONS_FAILED=$((SMOKE_ASSERTIONS_FAILED + 1))
    return 0
  fi
  echo "[smoke] PASS ${name}"
}

gov_assert_not() {
  local name="$1" forbidden="$2"
  SMOKE_ASSERTIONS=$((SMOKE_ASSERTIONS + 1))
  if [[ -z "$GOV_CODE" || "$GOV_CODE" == "000" || "$GOV_CODE" == "$forbidden" ]]; then
    echo "[smoke] ERROR ${name}: got HTTP ${GOV_CODE:-request_error}, which must not be ${forbidden}" >&2
    SMOKE_ASSERTIONS_FAILED=$((SMOKE_ASSERTIONS_FAILED + 1))
    return 0
  fi
  echo "[smoke] PASS ${name}"
}

# gov_json KEY: top-level field, falling back to data.KEY.
gov_json() {
  printf '%s' "$GOV_BODY" | python3 -c '
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(0)
k=sys.argv[1]
v=d.get(k) if isinstance(d,dict) else None
if v is None and isinstance(d,dict) and isinstance(d.get("data"),dict):
    v=d["data"].get(k)
if v is not None:
    print(v)
' "$1"
}

run_governance_smoke() {
  # W22-42: one fresh plain-HTTP hub with three API-key principals (two
  # admins, one viewer) exercising roles, the write gate, ownership, the
  # transparency log, key-export dual control and the protocol rate limit.
  local bin_path="$1"
  local base_tmp_dir="$2"

  echo "[smoke] --- Governance pass (roles, write gate, ownership, transparency, dual control, 429) ---"

  if ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    skip_assertion "governance smoke" "needs python3 and openssl"
    return 0
  fi

  local dir="$base_tmp_dir/gov-pass"
  mkdir -p "$dir/data"
  local log="$dir/app.log"
  local port
  if ! port="$(allocate_free_port)"; then
    skip_assertion "governance smoke" "unable to allocate a free local port"
    return 0
  fi

  local pepper="gov-smoke-pepper"
  local v1 v2 vv
  v1="$(python3 -c 'import hmac,hashlib,sys;print(hmac.new(sys.argv[1].encode(),sys.argv[2].encode(),hashlib.sha256).hexdigest())' "$pepper" gov-admin1-secret)"
  v2="$(python3 -c 'import hmac,hashlib,sys;print(hmac.new(sys.argv[1].encode(),sys.argv[2].encode(),hashlib.sha256).hexdigest())' "$pepper" gov-admin2-secret)"
  vv="$(python3 -c 'import hmac,hashlib,sys;print(hmac.new(sys.argv[1].encode(),sys.argv[2].encode(),hashlib.sha256).hexdigest())' "$pepper" gov-viewer-secret)"
  local keys_json
  keys_json="[{\"kid\":\"gadm1\",\"principal_id\":\"admin-1\",\"role\":\"pki-admin\",\"scopes\":[\"*\"],\"active\":true,\"secret_verifier\":\"$v1\"},{\"kid\":\"gadm2\",\"principal_id\":\"admin-2\",\"role\":\"pki-admin\",\"scopes\":[\"*\"],\"active\":true,\"secret_verifier\":\"$v2\"},{\"kid\":\"gview\",\"principal_id\":\"viewer-1\",\"role\":\"viewer\",\"scopes\":[],\"active\":true,\"secret_verifier\":\"$vv\"}]"

  # APP_TRUSTED_PROXY_CIDRS and KRYPTKEEPER_KEY_DUAL_CONTROL stay unset on
  # purpose: the XFF assertion needs an untrusted peer, and dual control must
  # be the (default-on) behaviour under test.
  APP_BOOTSTRAP_TOKEN="gov-smoke-token" AUTH_MODE="bootstrap" APP_CERTIFICATE_PROVIDER="ca" \
    APP_DISCOVERY_PROVIDER="db" APP_NOTIFICATION_PROVIDER="file" \
    APP_CREDENTIAL_STORE_PASSPHRASE="gov-smoke-cred-passphrase-32-bytes!!" \
    KRYPTKEEPER_KEYSTORE_PASSPHRASE="gov-smoke-keystore-passphrase-32b!!" \
    KRYPTKEEPER_DATA_DIR="$dir/data" KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT="true" \
    KRYPTKEEPER_CA_NAME="Gov Smoke Root" KRYPTKEEPER_TLS_DISABLE="true" \
    APP_API_KEY_AUTH_ENABLED="true" APP_API_KEY_PEPPER="$pepper" APP_API_KEYS_JSON="$keys_json" \
    PORT="$port" "$bin_path" >"$log" 2>&1 &
  local pid="$!"
  track_pid "$pid"
  track_port "$port"

  local base="http://127.0.0.1:${port}"
  local attempt up=""
  for attempt in {1..120}; do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "[smoke] ERROR governance pass: local binary exited before health checks completed" >&2
      [[ -f "$log" ]] && cat "$log" >&2
      return 1
    fi
    if curl -sS -o /dev/null --max-time 1 "$base/healthz" >/dev/null 2>&1; then
      up=1
      break
    fi
    sleep 0.25
  done
  if [[ -z "$up" ]]; then
    echo "[smoke] ERROR governance pass: hub never came up on $base" >&2
    [[ -f "$log" ]] && cat "$log" >&2
    kill_pid "$pid"
    return 1
  fi

  local A1="Bearer kk_gadm1_gov-admin1-secret"
  local A2="Bearer kk_gadm2_gov-admin2-secret"
  local V="Bearer kk_gview_gov-viewer-secret"

  # 1. Roles (UC-E03)
  gov_curl GET "$base/api/v1/roles" "$A1"
  gov_assert "governance: roles list includes pki-admin" 200 '"name":"pki-admin"'
  gov_curl POST "$base/api/v1/roles" "$A1" '{"name":"smoke-reader","description":"smoke","permissions":["certificate.read"]}'
  gov_assert "governance: custom role create" 201 'smoke-reader'
  gov_curl GET "$base/api/v1/roles" "$A1"
  gov_assert "governance: roles list includes the new custom role" 200 'smoke-reader'

  # 2. Write gate (UC-E03): the gate answers before the handler, so {} suffices.
  gov_curl POST "$base/api/v1/certificates" "$V" '{}'
  gov_assert "governance: viewer cannot issue certificates" 403 '"error":"forbidden"'
  gov_curl POST "$base/api/v1/cas" "$V" '{}'
  gov_assert "governance: viewer cannot create CAs" 403 '"error":"forbidden"'
  gov_curl POST "$base/api/v1/templates" "$V" '{}'
  gov_assert "governance: viewer cannot create templates" 403 '"error":"forbidden"'
  gov_curl POST "$base/api/v1/users/invite" "$V" '{}'
  gov_assert "governance: viewer cannot invite users" 403 '"error":"forbidden"'
  gov_curl DELETE "$base/api/v1/tenants/x" "$V"
  gov_assert "governance: viewer cannot delete tenants" 403 '"error":"forbidden"'
  gov_curl POST "$base/api/v1/users/invite" "$A1" '{}'
  gov_assert_not "governance: admin control passes the write gate on user invite" 403

  # 3. Ownership (UC-E06)
  local cert_pem fp import_body
  cert_pem="$(openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /dev/null -subj "/CN=gov-smoke.example.test" -days 30 2>/dev/null || true)"
  if [[ -z "$cert_pem" ]]; then
    skip_assertion "governance: ownership" "openssl could not generate a certificate"
  else
    fp="$(printf '%s\n' "$cert_pem" | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f')"
    import_body="$(printf '%s' "$cert_pem" | python3 -c 'import json,sys;print(json.dumps({"certificate_pem":sys.stdin.read()}))')"
    gov_curl POST "$base/api/v1/certificates/import" "$A1" "$import_body"
    gov_assert "governance: certificate import" 201
    local loc
    loc="$(printf '%s\n' "$GOV_HEADERS" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}' | tail -1)"
    [[ -n "$loc" ]] && fp="${loc##*/}"
    local own='{"owner_email":"owner@example.test","owner_team":"platform","service_name":"gov-smoke"}'
    gov_curl PATCH "$base/api/v1/certificates/${fp}/ownership" "$A1" "$own"
    gov_assert "governance: ownership PATCH by admin" 200 '"owner_team":"platform"'
    gov_curl PATCH "$base/api/v1/certificates/${fp}/ownership" "$V" "$own"
    gov_assert "governance: ownership PATCH by viewer is refused" 403
  fi

  # 4. Transparency (UC-E07): a 503 here means the seed was not auto-provisioned.
  gov_curl GET "$base/api/v1/audit/transparency/checkpoint" "$A1"
  gov_assert "governance: transparency checkpoint is signed" 200 '"signature"'
  gov_assert "governance: transparency checkpoint carries the public key" 200 '"public_key"'
  gov_curl GET "$base/api/v1/audit/transparency/inclusion?index=0" "$A1"
  gov_assert "governance: transparency inclusion proof" 200 '"tree_size"'
  gov_curl GET "$base/api/v1/audit/transparency/consistency?from=1" "$A1"
  gov_assert "governance: transparency consistency proof" 200 '"from_size":1'

  # 5. Key export dual control (UC-E02, FR-P50). Grants bind to the PROPOSER
  # and need a different APPROVER (key_dual_control.go), so the proposer
  # redeems; the second admin approving is what's asserted.
  local pass="gov-export-passphrase-0123456789" aid
  gov_curl POST "$base/api/v1/keys" "$A1" '{"id":"gov-key","algorithm":"ECDSA-P256"}'
  gov_assert "governance: key create" 201
  gov_curl POST "$base/api/v1/keys/gov-key/export" "$A1" "{\"passphrase\":\"$pass\"}"
  gov_assert "governance: key export is held for approval" 202
  aid="$(gov_json action_id)"
  if [[ -z "$aid" ]]; then
    echo "[smoke] ERROR governance: no action_id in export response" >&2
    SMOKE_ASSERTIONS=$((SMOKE_ASSERTIONS + 1))
    SMOKE_ASSERTIONS_FAILED=$((SMOKE_ASSERTIONS_FAILED + 1))
  else
    local redeem="{\"passphrase\":\"$pass\",\"approved_action_id\":\"$aid\"}"
    gov_curl POST "$base/api/v1/keys/gov-key/export" "$A1" "$redeem"
    gov_assert "governance: redeem before approval is refused" 403
    gov_curl POST "$base/api/v1/pending-actions/${aid}/approve" "$A1"
    gov_assert "governance: self-approval is refused" 403
    gov_curl POST "$base/api/v1/pending-actions/${aid}/approve" "$A2"
    gov_assert "governance: second admin approves" 200
    gov_curl POST "$base/api/v1/keys/gov-key/export" "$A2" "$redeem"
    gov_assert "governance: grant is bound to the proposing credential" 403
    gov_curl POST "$base/api/v1/keys/gov-key/export" "$A1" "$redeem"
    gov_assert "governance: proposer redeems the approved grant" 200 'BEGIN'
    gov_assert "governance: export is served as PEM" 200 'application/x-pem-file'
    gov_curl POST "$base/api/v1/keys/gov-key/export" "$A1" "$redeem"
    gov_assert "governance: grant is single use" 403
  fi

  # 6. Protocol burst + XFF spoofing (UC-M22) -- LAST: it exhausts the
  # loopback IP's unauthenticated bucket. The peer is untrusted, so rotating
  # X-Forwarded-For must not mint fresh buckets.
  local n
  for n in $(seq 1 30); do
    gov_curl GET "$base/acme/directory" "" "" "203.0.113.$n"
    gov_assert "governance: acme burst request $n" 200 >/dev/null
  done
  gov_curl GET "$base/acme/directory" "" "" "203.0.113.200"
  gov_assert "governance: 31st protocol request is rate limited despite a spoofed XFF" 429 'Retry-After'
  gov_curl GET "$base/healthz"
  gov_assert "governance: healthz is outside the protocol limiter" 200

  kill_pid "$pid"
  return 0
}

# W24-26: own CA-provider hub (clean data dir); asserts 500-cert bulk-import
# scale, idempotent rerun, per-row CSV failure, private-key rejection and the
# estate (origin,management_state) bucket sums.
smoke_assert() {
  local name="$1"
  local ok="$2"
  SMOKE_ASSERTIONS=$((SMOKE_ASSERTIONS + 1))
  if [[ "$ok" != "true" ]]; then
    SMOKE_ASSERTIONS_FAILED=$((SMOKE_ASSERTIONS_FAILED + 1))
    echo "[smoke] ERROR ${name}" >&2
  fi
}

# smoke_json_post <base_url> <token> <path> <json-file>: prints "<http_code> <body-file>".
smoke_json_post() {
  local base="$1" token="$2" path="$3" file="$4"
  local out="${file}.resp"
  local code
  code="$(curl -sS --max-time 120 -o "$out" -w "%{http_code}" -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" -d @"$file" "$base$path" 2>/dev/null || true)"
  echo "${code:-000} $out"
}

# smoke_jq <file> <python-expr over d>: evaluates against parsed JSON, prints result.
smoke_jq() {
  python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
print(eval(sys.argv[2]))' "$1" "$2" 2>/dev/null || echo "ERR"
}

# estate_gen_certs <start> <count> <outdir> <bundle-file>: one EC key, distinct CN+serial per cert.
estate_gen_certs() {
  local start="$1" count="$2" outdir="$3" bundle="$4"
  local key="$outdir/ec.key" i
  mkdir -p "$outdir"
  openssl ecparam -name prime256v1 -genkey -noout -out "$key" 2>/dev/null
  : >"$bundle"
  for ((i = start; i < start + count; i++)); do
    openssl req -x509 -new -key "$key" -subj "/CN=smoke-$i.example.test" -set_serial "$i" -days 30 \
      -out "$outdir/c$i.pem" 2>/dev/null
    cat "$outdir/c$i.pem" >>"$bundle"
  done
}

estate_total() {
  local base="$1" token="$2" origin="$3" state="$4"
  curl -sS --max-time 10 -H "Authorization: Bearer $token" \
    "$base/api/v1/certificates?origin=${origin}&management_state=${state}&limit=1" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["meta"]["total"])' 2>/dev/null || echo "ERR"
}

estate_dash_sum() {
  local base="$1" token="$2"
  # the db cert-summary provider caches for 2s (certSummaryCacheTTL); wait it
  # out so a read after an import never returns the pre-import snapshot.
  sleep 2.5
  curl -sS --max-time 10 -H "Authorization: Bearer $token" "$base/api/v1/dashboard/summary" 2>/dev/null \
    | python3 -c 'import json,sys; c=json.load(sys.stdin)["data"]["certificates"]; print(c["managed"]+c["external"]+c["unmanaged"])' 2>/dev/null || echo "ERR"
}

run_estate_import_smoke() {
  local bin_path="$1"
  local base_tmp_dir="$2"
  local P="estate smoke:"

  echo "[smoke] --- estate import pass (500-cert bulk import, bucket sums) ---"

  local tool
  for tool in openssl python3 curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      skip_assertion "estate import smoke" "$tool not installed"
      return 0
    fi
  done

  local dir="$base_tmp_dir/estate-pass"
  mkdir -p "$dir/data"
  local port
  if ! port="$(allocate_free_port)"; then
    echo "[smoke] ERROR estate pass: unable to allocate a free port" >&2
    SMOKE_ASSERTIONS=$((SMOKE_ASSERTIONS + 1))
    SMOKE_ASSERTIONS_FAILED=$((SMOKE_ASSERTIONS_FAILED + 1))
    return 0
  fi
  local token="smoke-estate-token"
  local base="http://127.0.0.1:${port}"

  # APP_CERTS_SUMMARY_PROVIDER=db: the file-backed summary reports zero
  # managed/external/unmanaged buckets, so the dashboard sums need the db one.
  APP_BOOTSTRAP_TOKEN="$token" AUTH_MODE="bootstrap" APP_CERTIFICATE_PROVIDER="ca" \
    APP_DISCOVERY_PROVIDER="db" APP_NOTIFICATION_PROVIDER="file" APP_CERTS_SUMMARY_PROVIDER="db" \
    APP_CREDENTIAL_STORE_PASSPHRASE="estate-smoke-cred-passphrase-32-bytes!" \
    KRYPTKEEPER_KEYSTORE_PASSPHRASE="estate-smoke-keystore-passphrase-32b!" \
    KRYPTKEEPER_DATA_DIR="$dir/data" KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT="true" \
    KRYPTKEEPER_CA_NAME="Estate Smoke Root CA" KRYPTKEEPER_TLS_DISABLE="true" \
    PORT="$port" "$bin_path" >"$dir/app.log" 2>&1 &
  local pid="$!"
  track_pid "$pid"
  track_port "$port"

  local attempt up=""
  for attempt in {1..120}; do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "[smoke] ERROR estate pass: hub exited early" >&2
      cat "$dir/app.log" >&2
      smoke_assert "$P hub started" false
      return 0
    fi
    if curl -sS -o /dev/null --max-time 1 "$base/healthz" >/dev/null 2>&1; then up=1; break; fi
    sleep 0.25
  done
  if [[ -z "$up" ]]; then
    smoke_assert "$P hub reachable" false
    kill_pid "$pid"
    return 0
  fi

  # Fixtures: A=1..500 (bulk), B=501..550, C=551..600 (ADCS export dir), D=601..602 (CSV).
  estate_gen_certs 1 500 "$dir/a" "$dir/a.pem"
  estate_gen_certs 501 50 "$dir/b" "$dir/b.pem"
  estate_gen_certs 551 50 "$dir/c" "$dir/c.pem"
  estate_gen_certs 601 2 "$dir/d" "$dir/d.pem"

  local jpy='import json,sys; print(json.dumps({"format":"pem","bundle":open(sys.argv[1]).read()}))'
  python3 -c "$jpy" "$dir/a.pem" >"$dir/a.json"
  python3 -c "$jpy" "$dir/b.pem" >"$dir/b.json"

  local code resp
  # a. 500 in one call
  read -r code resp < <(smoke_json_post "$base" "$token" /api/v1/certificates/bulk-import "$dir/a.json")
  smoke_assert "$P 500-cert bulk import (http=$code imported=$(smoke_jq "$resp" 'd["data"]["imported"]'))" \
    "$([[ "$code" == "200" && "$(smoke_jq "$resp" 'd["data"]["imported"]==500 and d["data"]["failed"]==[]')" == "True" ]] && echo true || echo false)"
  # b. rerun
  read -r code resp < <(smoke_json_post "$base" "$token" /api/v1/certificates/bulk-import "$dir/a.json")
  smoke_assert "$P rerun reports 0 imported and 500 duplicates (http=$code)" \
    "$([[ "$code" == "200" && "$(smoke_jq "$resp" 'd["data"]["imported"]==0 and d["data"]["skipped_duplicates"]==500')" == "True" ]] && echo true || echo false)"
  # c. CSV with a bad middle row
  python3 - "$dir/d/c601.pem" "$dir/d/c602.pem" "$dir" <<'PY'
import base64, json, re, sys
def der_b64(path):
    pem = open(path).read()
    return "".join(re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S).group(1).split())
rows = ["cert_b64,owner_email,owner_team,service_name",
        der_b64(sys.argv[1]) + ",a@example.test,team,svc",
        # valid base64 that is not a certificate: the importer fails this row
        # only (a non-base64 cell is a whole-request 400 by design).
        base64.b64encode(b"this is not a certificate").decode() + ",b@example.test,team,svc",
        der_b64(sys.argv[2]) + ",c@example.test,team,svc"]
json.dump({"format": "csv", "bundle": "\n".join(rows) + "\n"}, open(sys.argv[3] + "/csv.json", "w"))
PY
  read -r code resp < <(smoke_json_post "$base" "$token" /api/v1/certificates/bulk-import "$dir/csv.json")
  smoke_assert "$P CSV bad row fails only that row (http=$code)" \
    "$([[ "$code" == "200" && "$(smoke_jq "$resp" 'd["data"]["imported"]==2 and len(d["data"]["failed"])==1')" == "True" ]] && echo true || echo false)"
  # d. private key rejected, nothing imported
  local before_total after_total
  before_total="$(estate_dash_sum "$base" "$token")"
  openssl ecparam -name prime256v1 -genkey 2>/dev/null >"$dir/pk.pem"
  openssl req -x509 -new -key "$dir/a/ec.key" -subj "/CN=smoke-pk.example.test" -set_serial 900 -days 30 \
    >"$dir/pk-cert.pem" 2>/dev/null || true
  cat "$dir/pk-cert.pem" "$dir/pk.pem" >"$dir/pk-bundle.pem"
  python3 -c "$jpy" "$dir/pk-bundle.pem" >"$dir/pk.json"
  read -r code resp < <(smoke_json_post "$base" "$token" /api/v1/certificates/bulk-import "$dir/pk.json")
  after_total="$(estate_dash_sum "$base" "$token")"
  echo "[smoke] estate pass: private-key import returned HTTP $code"
  smoke_assert "$P private key input rejected with 400/422 and nothing imported (http=$code)" \
    "$([[ ( "$code" == "400" || "$code" == "422" ) && "$before_total" == "$after_total" && "$before_total" != "ERR" ]] && echo true || echo false)"

  # e. baselines
  local summary0 iu0 im0 se0
  summary0="$(estate_dash_sum "$base" "$token")"
  iu0="$(estate_total "$base" "$token" imported unmanaged)"
  im0="$(estate_total "$base" "$token" imported managed)"
  se0="$(estate_total "$base" "$token" synced external)"
  smoke_assert "$P baseline snapshots readable (dashboard=$summary0)" \
    "$([[ "$summary0" != "ERR" && "$iu0" != "ERR" && "$im0" != "ERR" && "$se0" != "ERR" ]] && echo true || echo false)"

  # f. B imported + 20 taken over; ADCS export dir C synced
  read -r code resp < <(smoke_json_post "$base" "$token" /api/v1/certificates/bulk-import "$dir/b.json")
  smoke_assert "$P import 50 mixed-origin certs (B) (http=$code)" \
    "$([[ "$code" == "200" && "$(smoke_jq "$resp" 'd["data"]["imported"]==50')" == "True" ]] && echo true || echo false)"
  local takeover_ok=true fp n=0
  for fp in $(smoke_jq "$resp" '" ".join(d["data"]["fingerprints"][:20])'); do
    printf '{"fingerprint":"%s","renewal_path":{"mode":"internal"}}' "$fp" >"$dir/take.json"
    local tcode tresp
    read -r tcode tresp < <(smoke_json_post "$base" "$token" /api/v1/estate/takeover "$dir/take.json")
    [[ "$tcode" == "200" ]] || takeover_ok=false
    n=$((n + 1))
  done
  [[ "$n" == "20" ]] || takeover_ok=false
  smoke_assert "$P 20 takeovers each return 200 (n=$n)" "$takeover_ok"

  mkdir -p "$dir/adcs"
  cp "$dir"/c/c*.pem "$dir/adcs/"
  python3 -c 'import json,sys; print(json.dumps({"name":"smoke-adcs","type":"adcs_export","config_json":json.dumps({"export_path":sys.argv[1]})}))' "$dir/adcs" >"$dir/src.json"
  local scode sresp
  read -r scode sresp < <(smoke_json_post "$base" "$token" /api/v1/inventory-sources "$dir/src.json")
  local sid
  sid="$(smoke_jq "$sresp" 'd["data"]["id"]')"
  echo '{}' >"$dir/empty.json"
  read -r code resp < <(smoke_json_post "$base" "$token" "/api/v1/inventory-sources/${sid}/sync" "$dir/empty.json")
  smoke_assert "$P ADCS export source over 50 files synced=50 (create=$scode sync=$code)" \
    "$([[ "$scode" =~ ^20 && "$code" == "200" && "$(smoke_jq "$resp" 'd["data"]["synced"]==50')" == "True" ]] && echo true || echo false)"

  # g. bucket deltas
  local iu1 im1 se1
  iu1="$(estate_total "$base" "$token" imported unmanaged)"
  im1="$(estate_total "$base" "$token" imported managed)"
  se1="$(estate_total "$base" "$token" synced external)"
  smoke_assert "$P bucket deltas imported/unmanaged +30, imported/managed +20, synced/external +50 (got $((iu1 - iu0)),$((im1 - im0)),$((se1 - se0)))" \
    "$([[ "$iu1" != "ERR" && "$im1" != "ERR" && "$se1" != "ERR" && $((iu1 - iu0)) -eq 30 && $((im1 - im0)) -eq 20 && $((se1 - se0)) -eq 50 ]] && echo true || echo false)"
  # h. dashboard
  local summary1
  summary1="$(estate_dash_sum "$base" "$token")"
  smoke_assert "$P dashboard managed+external+unmanaged grew by exactly 100 (got $((summary1 - summary0)))" \
    "$([[ "$summary1" != "ERR" && "$summary0" != "ERR" && $((summary1 - summary0)) -eq 100 ]] && echo true || echo false)"

  kill_pid "$pid"
  return 0
}

run_reports_smoke() {
  local bin_path="$1"
  local base_tmp_dir="$2"
  local P="reports smoke:"

  echo "[smoke] --- reports pass (/reports/* contract operations, /cbom, per-framework evidence PDFs) ---"

  local tool
  for tool in openssl python3 curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      skip_assertion "reports smoke" "$tool not installed"
      return 0
    fi
  done

  local dir="$base_tmp_dir/reports-pass"
  mkdir -p "$dir/data"
  local port
  if ! port="$(allocate_free_port)"; then
    echo "[smoke] ERROR reports pass: unable to allocate a free port" >&2
    SMOKE_ASSERTIONS=$((SMOKE_ASSERTIONS + 1))
    SMOKE_ASSERTIONS_FAILED=$((SMOKE_ASSERTIONS_FAILED + 1))
    return 0
  fi
  local token="smoke-reports-token"
  local base="http://127.0.0.1:${port}"

  APP_BOOTSTRAP_TOKEN="$token" AUTH_MODE="bootstrap" APP_CERTIFICATE_PROVIDER="ca" \
    APP_DISCOVERY_PROVIDER="db" APP_NOTIFICATION_PROVIDER="file" APP_CERTS_SUMMARY_PROVIDER="db" \
    APP_CREDENTIAL_STORE_PASSPHRASE="reports-smoke-cred-passphrase-32-bytes!" \
    KRYPTKEEPER_KEYSTORE_PASSPHRASE="reports-smoke-keystore-passphrase-32b!" \
    KRYPTKEEPER_DATA_DIR="$dir/data" KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT="true" \
    KRYPTKEEPER_CA_NAME="Reports Smoke Root CA" KRYPTKEEPER_TLS_DISABLE="true" \
    PORT="$port" "$bin_path" >"$dir/app.log" 2>&1 &
  local pid="$!"
  track_pid "$pid"
  track_port "$port"

  local attempt up=""
  for attempt in {1..120}; do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "[smoke] ERROR reports pass: hub exited early" >&2
      cat "$dir/app.log" >&2
      smoke_assert "$P hub started" false
      return 0
    fi
    if curl -sS -o /dev/null --max-time 1 "$base/healthz" >/dev/null 2>&1; then up=1; break; fi
    sleep 0.25
  done
  if [[ -z "$up" ]]; then
    smoke_assert "$P hub reachable" false
    kill_pid "$pid"
    return 0
  fi

  # Seed a non-empty estate so every report body is non-trivial.
  estate_gen_certs 1 30 "$dir/a" "$dir/a.pem"
  local jpy='import json,sys; print(json.dumps({"format":"pem","bundle":open(sys.argv[1]).read()}))'
  python3 -c "$jpy" "$dir/a.pem" >"$dir/a.json"
  local code resp
  read -r code resp < <(smoke_json_post "$base" "$token" /api/v1/certificates/bulk-import "$dir/a.json")
  smoke_assert "$P seed 30-cert bulk import (http=$code)" \
    "$([[ "$code" == "200" && "$(smoke_jq "$resp" 'd["data"]["imported"]==30')" == "True" ]] && echo true || echo false)"

  # Operation list comes from the contract so the count never goes stale.
  python3 - "$ROOT_DIR/docs/openapi.yaml" >"$dir/report-ops.tsv" <<'PY'
import re,sys
cur=None
for l in open(sys.argv[1]):
    m=re.match(r'^  (/\S+):\s*$',l)
    if m: cur=m.group(1); continue
    m=re.match(r'^    (get|post|put|patch|delete):\s*$',l)
    if m and cur and cur.startswith('/reports/'): print(m.group(1).upper()+"\t"+cur)
PY
  local nops
  nops="$(wc -l <"$dir/report-ops.tsv" | tr -d ' ')"
  smoke_assert "$P openapi lists >=31 /reports operations (got $nops)" \
    "$([[ "$nops" -ge 31 ]] && echo true || echo false)"
  smoke_assert "$P openapi lists /reports/crypto-posture" \
    "$(if grep -q $'\t/reports/crypto-posture$' "$dir/report-ops.tsv"; then echo true; else echo false; fi)"

  local method path rcode concrete
  while IFS=$'\t' read -r method path; do
    if [[ "$method" == "GET" ]]; then
      if [[ "$path" == *"{"* ]]; then
        skip_assertion "$P GET $path" "path parameter"
        continue
      fi
      rcode="$(curl -sS --max-time "${CURL_MAX_TIME:-10}" -o "$dir/body" -w '%{http_code}' \
        -H "Authorization: Bearer $token" "$base/api/v1$path" 2>/dev/null || true)"
      smoke_assert "$P GET $path 200 non-empty (http=$rcode)" \
        "$([[ "$rcode" == "200" && -s "$dir/body" ]] && echo true || echo false)"
    else
      concrete="$(printf '%s' "$path" | sed -E 's/\{[^}]*\}/smoke-none/g')"
      rcode="$(curl -sS --max-time "${CURL_MAX_TIME:-10}" -o /dev/null -w '%{http_code}' -X "$method" \
        "$base/api/v1$concrete" 2>/dev/null || true)"
      smoke_assert "$P $method $path unauthenticated 401 (http=$rcode)" \
        "$([[ "$rcode" == "401" ]] && echo true || echo false)"
    fi
  done <"$dir/report-ops.tsv"

  # CycloneDX CBOM.
  rcode="$(curl -sS --max-time "${CURL_MAX_TIME:-10}" -o "$dir/cbom.json" -w '%{http_code}' \
    -H "Authorization: Bearer $token" "$base/api/v1/cbom" 2>/dev/null || true)"
  smoke_assert "$P GET /cbom 200 CycloneDX 1.6 (http=$rcode)" \
    "$(if [[ "$rcode" == "200" && -s "$dir/cbom.json" ]] && grep -q '"bomFormat"' "$dir/cbom.json" \
        && grep -Eq '"specVersion": ?"1\.6"' "$dir/cbom.json"; then echo true; else echo false; fi)"

  # Per-framework evidence PDFs.
  local fw today today2 isodate ok
  for fw in soc2 pci nist dora nis2 fedramp; do
    today="$(date -u +%Y%m%d)"
    isodate="$(date -u +%Y-%m-%d)"
    rcode="$(curl -sS --max-time 60 -D "$dir/h-$fw" -o "$dir/$fw.pdf" -w '%{http_code}' \
      -H "Authorization: Bearer $token" \
      "$base/api/v1/reports/compliance-evidence?framework=$fw&format=pdf" 2>/dev/null || true)"
    today2="$(date -u +%Y%m%d)"
    ok=true
    [[ "$rcode" == "200" ]] || ok=false
    [[ -f "$dir/$fw.pdf" && "$(head -c 4 "$dir/$fw.pdf" 2>/dev/null)" == "%PDF" ]] || ok=false
    [[ -f "$dir/$fw.pdf" && "$(wc -c <"$dir/$fw.pdf" | tr -d ' ')" -gt 1000 ]] || ok=false
    if ! { grep -a -q "/CreationDate (D:${today}" "$dir/$fw.pdf" 2>/dev/null \
        || grep -a -q "/CreationDate (D:${today2}" "$dir/$fw.pdf" 2>/dev/null; }; then ok=false; fi
    if ! grep -i -q "content-disposition:.*compliance-$fw-$isodate" "$dir/h-$fw" 2>/dev/null; then ok=false; fi
    smoke_assert "$P $fw evidence PDF (%PDF, generated date) (http=$rcode)" "$ok"
  done

  rcode="$(curl -sS --max-time 60 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" \
    "$base/api/v1/reports/compliance-evidence?framework=bogus&format=pdf" 2>/dev/null || true)"
  smoke_assert "$P framework=bogus format=pdf returns 400 (http=$rcode)" \
    "$([[ "$rcode" == "400" ]] && echo true || echo false)"

  kill_pid "$pid"
  return 0
}

run_deployment_smoke() {
  if [[ ! -f "$ROOT_DIR/scripts/deploy/smoke.sh" ]]; then
    echo "[smoke] WARN scripts/deploy/smoke.sh not found; skipping deployment smoke mode"
    return "$SKIP_EXIT_CODE"
  fi

  if [[ -z "${KRYPTKEEPER_SMOKE_TARGET_ENV:-}" ]]; then
    echo "[smoke] WARN KRYPTKEEPER_SMOKE_TARGET_ENV not set; skipping deployment smoke mode"
    echo "[smoke] INFO Set KRYPTKEEPER_SMOKE_TARGET_ENV=staging|production to enable"
    return "$SKIP_EXIT_CODE"
  fi

  if [[ -z "${KRYPTKEEPER_SMOKE_BASE_URL:-}" ]]; then
    case "${KRYPTKEEPER_SMOKE_TARGET_ENV}" in
      staging)
        if [[ -z "${KRYPTKEEPER_SMOKE_BASE_URL_STAGING:-}" ]]; then
          echo "[smoke] WARN no staging smoke URL configured; skipping deployment smoke mode"
          return "$SKIP_EXIT_CODE"
        fi
        ;;
      production)
        if [[ -z "${KRYPTKEEPER_SMOKE_BASE_URL_PRODUCTION:-}" ]]; then
          echo "[smoke] WARN no production smoke URL configured; skipping deployment smoke mode"
          return "$SKIP_EXIT_CODE"
        fi
        ;;
      *)
        echo "[smoke] WARN unsupported KRYPTKEEPER_SMOKE_TARGET_ENV='${KRYPTKEEPER_SMOKE_TARGET_ENV}'; expected staging|production"
        return "$SKIP_EXIT_CODE"
        ;;
    esac
  fi

  echo "[smoke] Running deployment smoke checks"
  bash "$ROOT_DIR/scripts/deploy/smoke.sh" "$KRYPTKEEPER_SMOKE_TARGET_ENV"
}

run_mode_with_skip_semantics() {
  local mode="$1"
  local rc

  case "$mode" in
    local)
      rc=0
      set +e
      run_local_binary_smoke
      rc=$?
      set -e
      if [[ "$rc" -eq 0 ]]; then
        return 0
      fi
      [[ "$rc" -eq "$SKIP_EXIT_CODE" ]] && return 0
      return "$rc"
      ;;
    deploy)
      rc=0
      set +e
      run_deployment_smoke
      rc=$?
      set -e
      if [[ "$rc" -eq 0 ]]; then
        return 0
      fi
      [[ "$rc" -eq "$SKIP_EXIT_CODE" ]] && return 0
      return "$rc"
      ;;
    auto)
      rc=0
      set +e
      run_local_binary_smoke
      rc=$?
      set -e
      if [[ "$rc" -eq 0 ]]; then
        return 0
      fi
      if [[ "$rc" -ne "$SKIP_EXIT_CODE" ]]; then
        return "$rc"
      fi

      rc=0
      set +e
      run_deployment_smoke
      rc=$?
      set -e
      if [[ "$rc" -eq 0 ]]; then
        return 0
      fi
      [[ "$rc" -eq "$SKIP_EXIT_CODE" ]] && return 0
      return "$rc"
      ;;
    *)
      echo "[smoke] WARN unsupported KRYPTKEEPER_SMOKE_MODE='${mode}'; expected auto|local|deploy; skipping"
      return 0
      ;;
  esac
}

ensure_assertions_executed() {
  if [[ "$SMOKE_ASSERTIONS" -le 0 ]]; then
    echo "[smoke] ERROR no smoke assertions executed" >&2
    return 1
  fi
  return 0
}

# W19-21: verify every pid THIS RUN tracked is actually dead after
# cleanup_all -- not a system-wide `pgrep kryptkeeper`, which would give a
# false failure the moment any other concurrent ticket/session on the same
# host (this conductor runs several kk/* branches in parallel, per
# CLAUDE.md) happens to have its own hub up at the same moment. Snapshot
# which tracked pids are alive *before* cleanup_all runs (the last hub of a
# normal run always is -- that's expected, not a leak) and confirm
# cleanup_all's kill actually took for every one of them. A system-wide
# pgrep is still logged, informationally only, since a human skimming the
# log benefits from it even though it can't gate the assertion.
assert_no_leftover_hub_processes() {
  local before_pids=()
  local p
  for p in "${SMOKE_PIDS[@]:-}"; do
    [[ -n "$p" ]] && kill -0 "$p" >/dev/null 2>&1 && before_pids+=("$p")
  done

  cleanup_all

  local rc=0
  for p in "${before_pids[@]:-}"; do
    if kill -0 "$p" >/dev/null 2>&1; then
      echo "[smoke] ERROR pid $p (a hub this run started) survived cleanup_all" >&2
      rc=1
    fi
  done

  if command -v pgrep >/dev/null 2>&1; then
    local system_wide
    system_wide="$(pgrep -x kryptkeeper 2>/dev/null || true)"
    if [[ -n "$system_wide" ]]; then
      echo "[smoke] INFO kryptkeeper process(es) still present system-wide (may belong to a concurrent run, not necessarily this one): $system_wide"
    fi
  fi

  return "$rc"
}

echo "[smoke] mode=${SMOKE_MODE}"
run_mode_with_skip_semantics "$SMOKE_MODE"
ensure_assertions_executed

smoke_passed=$((SMOKE_ASSERTIONS - SMOKE_ASSERTIONS_FAILED))
echo "[smoke] SUMMARY ${SMOKE_ASSERTIONS} assertion(s) run, ${smoke_passed} passed, ${SMOKE_ASSERTIONS_FAILED} failed, ${SMOKE_ASSERTIONS_SKIPPED} skipped"

leftover_rc=0
assert_no_leftover_hub_processes || leftover_rc=$?

if [[ "$SMOKE_ASSERTIONS_FAILED" -gt 0 || "$leftover_rc" -ne 0 ]]; then
  [[ "$SMOKE_ASSERTIONS_FAILED" -gt 0 ]] && echo "[smoke] FAIL ${SMOKE_ASSERTIONS_FAILED} of ${SMOKE_ASSERTIONS} assertion(s) failed" >&2
  exit 1
fi
