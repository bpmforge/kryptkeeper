#!/usr/bin/env bash
set -euo pipefail

# Smoke-test Kryptkeeper deployment endpoints.
#
# Usage:
#   scripts/deploy/smoke.sh <target_env>
#
# URL resolution:
#   - If KRYPTKEEPER_SMOKE_BASE_URL is set, use it.
#   - Otherwise use env-specific:
#       staging    -> KRYPTKEEPER_SMOKE_BASE_URL_STAGING
#       production -> KRYPTKEEPER_SMOKE_BASE_URL_PRODUCTION

TARGET_ENV="${1:-}"

if [[ -z "$TARGET_ENV" ]]; then
  echo "Usage: $0 <target_env>" >&2
  exit 2
fi

BASE_URL="${KRYPTKEEPER_SMOKE_BASE_URL:-}"
if [[ -z "$BASE_URL" ]]; then
  case "$TARGET_ENV" in
    staging) BASE_URL="${KRYPTKEEPER_SMOKE_BASE_URL_STAGING:-}" ;;
    production) BASE_URL="${KRYPTKEEPER_SMOKE_BASE_URL_PRODUCTION:-}" ;;
    *)
      echo "ERROR: unsupported target_env '$TARGET_ENV' (expected staging|production)" >&2
      exit 2
      ;;
  esac
fi

if [[ -z "$BASE_URL" ]]; then
  echo "ERROR: smoke base URL not configured for env '$TARGET_ENV'" >&2
  exit 3
fi

if [[ ! "$BASE_URL" =~ ^https?:// ]]; then
  echo "ERROR: base URL must include scheme (http/https): $BASE_URL" >&2
  exit 2
fi

HTTP_TIMEOUT="${SMOKE_HTTP_TIMEOUT_SECONDS:-10}"

check_endpoint() {
  local url="$1"
  local name="$2"

  local code
  code=$(curl -ksS -o /tmp/kryptkeeper_smoke_body.txt -w "%{http_code}" --max-time "$HTTP_TIMEOUT" "$url") || {
    echo "[smoke] FAIL $name ($url): request error" >&2
    return 1
  }

  if [[ "$code" != "200" ]]; then
    echo "[smoke] FAIL $name ($url): expected 200, got $code" >&2
    return 1
  fi

  echo "[smoke] PASS $name ($url)"
}

echo "[smoke] env=$TARGET_ENV base_url=$BASE_URL"

check_endpoint "$BASE_URL/healthz" "live"
check_endpoint "$BASE_URL/readyz" "ready"

# Optional OCSP endpoint smoke check (if configured)
if [[ -n "${KRYPTKEEPER_OCSP_SMOKE_URL:-}" ]]; then
  check_endpoint "$KRYPTKEEPER_OCSP_SMOKE_URL" "ocsp"
fi

echo "[smoke] all checks passed"
