# WS-10 CI Workflow Re-Audit (Post Fail-Closed Changes)

## Summary
- Re-audited `scripts/test/run.sh`, `.github/workflows/ci-pr.yml`, and `.github/workflows/ci-main.yml` after fail-closed updates.
- Prior HIGH fail-open findings are **mostly resolved** at harness/suite presence checks and main protocol/integration missing-directory behavior.
- **CRITICAL findings: 0**
- **HIGH findings: 2 (remaining blind spots)**

## Subtasks
1. [DONE] Re-validate prior HIGH findings against current files.
2. [DONE] Re-check gate/failure/skip semantics for protocol/integration/smoke.
3. [DONE] Identify and severity-rank remaining blind spots.

## Prior HIGH Findings Status

### HIGH-1 (previous): Missing `scripts/test/run.sh` allowed skip-success
**Status: RESOLVED**
- `ci-pr.yml` now runs harness when `go.mod` exists without a harness-exists guard (`run: bash scripts/test/run.sh ...`), so missing harness fails the step.
- `ci-main.yml` smoke job does the same.

### HIGH-2 (previous): Harness missing suite script was warning-only
**Status: RESOLVED**
- `scripts/test/run.sh` now marks missing suite script as failure:
  - `echo "[test-harness] FAIL ..."` + increments `failures` (lines 60-63)
  - exits non-zero when failures > 0 (lines 76-78).

### HIGH-3 (previous): `ci-main` protocol-conformance skipped success with no suites
**Status: RESOLVED**
- `ci-main.yml` now fails when suite list is empty:
  - prints missing required protocol suites
  - `exit 1` (lines 137-140).

### HIGH-4 (previous): `ci-main` integration-full skipped success if `tests/integration` missing
**Status: RESOLVED**
- `ci-main.yml` now explicitly fails if directory is missing (lines 109-112).

## Remaining Findings

### HIGH-R1: Global `go.mod` skip semantics still allow required gates to pass without execution
**Where**
- `ci-pr.yml`: protocol/integration/smoke jobs skip-success if `hashFiles('go.mod') == ''` (lines 31-34, 52-54).
- `ci-main.yml`: smoke job skip-success if `go.mod` missing (lines 34-36); integration/protocol steps are guarded by `if: hashFiles('go.mod') != ''`, so jobs can no-op succeed.

**Risk**
- In a Go service repo, deleting/renaming `go.mod` can make required protocol/integration/smoke gates green without executing.
- This is a branch-protection bypass pattern via skip semantics.

**Recommendation**
- For this repository type, fail closed when `go.mod` is absent in required jobs:
  - replace skip markers with `exit 1`, or
  - add a dedicated early "repo invariant" job that fails if `go.mod` is missing and gate all required jobs on it.

---

### HIGH-R2: Smoke suite still has internal skip-to-success path for missing local runtime prerequisites
**Where**
- `tests/smoke/run.sh` local mode returns `SKIP_EXIT_CODE` when prerequisites missing (e.g., no `cmd/kryptkeeper`, missing `go`, missing `curl`; lines 146-159), then converts skip to success in `run_mode_with_skip_semantics` for local mode (lines 992-993).

**Risk**
- Required smoke gate can report success while running no assertions if local runtime prerequisites disappear.
- This is still fail-open at suite level (even though harness-level fail-closed improved).

**Recommendation**
- Add CI strict mode for smoke (e.g., `KRYPTKEEPER_SMOKE_STRICT=1`):
  - in CI strict mode, prerequisite-missing should fail non-zero instead of skip-success.

## Confidence Scores
- [1] Prior finding resolution check: **9/10**
- [2] Remaining skip/failure semantic audit: **8/10**
- [3] Severity classification of remaining blind spots: **8/10**
