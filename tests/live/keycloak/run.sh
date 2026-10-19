#!/usr/bin/env bash
# W33-07: nightly wrapper over tests/live/sso (W22-21/22). Exit 0 only if every part passes.
set -u
set -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
OUT="${KK_KC_RESULTS:-$HERE/last-run.md}"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
start=$(date -u +%FT%TZ)
bash "$REPO_ROOT/tests/live/sso/run.sh" 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
end=$(date -u +%FT%TZ)
# harness prints: === RESULT: N passed, M failed ===
summary="$(grep -E '^=== RESULT:' "$LOG" | tail -1)"
oidc="$(grep -c '^PASS: .*whoami role' "$LOG")"
saml="$(grep -c '^PASS: .* via SAML: whoami role' "$LOG")"
sha="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
image="$(grep -E '^KC_IMAGE=' "$REPO_ROOT/tests/live/sso/lib.sh" | sed -E 's/^KC_IMAGE="\$\{KK_SSO_KC_IMAGE:-([^}]*)\}".*/\1/')"
{
  echo "# Keycloak SSO live run"
  echo
  echo "- start: $start"
  echo "- end: $end"
  echo "- git SHA: $sha"
  echo "- Keycloak image: $image"
  echo "- summary: ${summary:-(none)}"
  echo "- OIDC role PASS lines: $oidc"
  echo "- SAML role PASS lines: $saml"
  echo "- exit code: $rc"
  echo
  echo '## PASS/FAIL lines'
  echo '```'
  grep -E '^(PASS|FAIL):' "$LOG"
  echo '```'
} > "$OUT"
if [ -z "$summary" ] || [ "$oidc" -eq 0 ] || [ "$saml" -eq 0 ]; then
  echo "FAIL: harness produced no OIDC/SAML pass lines"
  exit 1
fi
exit "$rc"
