#!/usr/bin/env bash
# Issue one certificate per hub profile (plus CA certs, CRLs, OCSP responses),
# then lint them with pkilint and zlint (gap T6). Exit 1 on any finding that is
# not in scripts/lint/allowlist.json.
#
# Tools (pinned in CI, see .github/workflows/ci-pr.yml):
#   pkilint 0.13.3  (MIT)         pip install pkilint==0.13.3
#   zlint   v3.7.2  (Apache-2.0)  go install github.com/zmap/zlint/v3/cmd/zlint@v3.7.2
# Both are used as CLIs only; neither is a Go module dependency of kryptkeeper.
# Locate them with PKILINT_BIN_DIR / ZLINT_BIN, or put them on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CORPUS="${KK_LINT_CORPUS_DIR:-$(mktemp -d)}"
export KK_LINT_CORPUS_DIR="$CORPUS"

cd "$ROOT"
go test ./internal/bootstrap -run '^TestProfileLintCorpus$' -count=1
exec python3 -I "$ROOT/scripts/lint/profile_lint.py" "$CORPUS" "$ROOT/scripts/lint/allowlist.json" "$@"
