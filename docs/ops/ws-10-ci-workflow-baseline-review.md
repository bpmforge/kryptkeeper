# WS-10 CI Workflow Baseline Review (ci-pr.yml, ci-main.yml)

## Summary
- Reviewed gate coverage and execution semantics for protocol, integration, and smoke checks across PR and main workflows.
- **CRITICAL findings: 0**
- **HIGH findings: 4**
- Primary risk theme: several "required" gates are currently **fail-open** (skip = success), allowing green CI without actually executing target suites.

## Scope
- `.github/workflows/ci-pr.yml`
- `.github/workflows/ci-main.yml`
- Runtime semantics validated against harness scripts:
  - `scripts/test/run.sh`
  - `tests/protocol/run.sh`
  - `tests/integration/run.sh`
  - `tests/smoke/run.sh`

## Findings

### HIGH-1: Harness/file deletion can bypass protocol+integration and smoke gates (fail-open)
**Where**
- `ci-pr.yml`:
  - protocol/integration harness skip on missing harness: lines 34-36
  - smoke harness skip on missing harness: lines 58-60
- `ci-main.yml`:
  - smoke harness skip on missing harness: lines 37-39

**Why this is risky**
- If `go.mod` exists but `scripts/test/run.sh` is removed/renamed, the jobs still pass with a skip marker.
- This enables an easy accidental or intentional bypass of core gates while keeping PR checks green.

**Failure semantics today**
- Missing harness => `echo` skip => job success.

**Recommended fix**
- For required suites, switch to fail-closed:
  - If `go.mod` exists and harness is missing, `exit 1`.
  - Keep soft-skip only for explicitly optional jobs.

---

### HIGH-2: Harness treats missing suite scripts as warning-only, still exits success
**Where**
- `scripts/test/run.sh`: lines 60-63 (missing suite script => WARN + continue)

**Why this is risky**
- In `ci-pr.yml`, `protocol-integration-harness` runs `--suite protocol --suite integration`.
- If `tests/protocol/run.sh` or `tests/integration/run.sh` is missing, harness reports WARN and continues.
- Combined with no hard assertion on executed suite count, the job can pass with zero real suite execution.

**Failure semantics today**
- Missing suite script is non-fatal.

**Recommended fix**
- Add strict mode for CI-required suites:
  - Missing requested suite script => fail (`exit 1`).
  - Emit executed suite count and fail if count is 0 for required jobs.

---

### HIGH-3: `ci-main` protocol-conformance can pass with no conformance tests executed
**Where**
- `ci-main.yml` protocol job lines 135-143.
- If none of `tests/acme`, `tests/ocsp`, `tests/crl`, `tests/est`, `tests/scep` exist, workflow prints "No protocol suites found; skipping" and exits 0.

**Why this is risky**
- Main branch can remain green while protocol conformance coverage is effectively zero.
- Current repository state has no matching protocol test files under those directories.

**Failure semantics today**
- Missing suites => explicit success (`exit 0`).

**Recommended fix**
- For baseline gate, require at least one protocol suite package and at least one `_test.go` file.
- If none found, fail with actionable message.

---

### HIGH-4: `ci-main` integration-full can pass without integration tests
**Where**
- `ci-main.yml` integration job lines 112-116 (`tests/integration` missing => skip success)
- Also no assertion that `go test ./tests/integration/...` executed test files.

**Why this is risky**
- Gate may pass when directory is absent or contains no real tests.
- Current repository state has no `tests/integration/**/*_test.go`, so coverage appears nominal but may be empty.

**Failure semantics today**
- Missing test dir => success.
- Empty packages may still produce successful `go test` with no meaningful coverage.

**Recommended fix**
- Enforce non-empty integration test inventory before running:
  - Check for `tests/integration/**/*_test.go` count > 0.
  - Fail if count is zero for main branch required gate.

---

## Medium/Low Observations
- `tests/smoke/run.sh` has explicit skip-to-success behavior (`SKIP_EXIT_CODE=10`) and unsupported mode returns success (lines 1023-1025). In current workflows mode is pinned to `local`, so this is mostly controlled but still a latent fail-open pattern.
- PR coverage now improved by adding `protocol-integration-harness`, but semantics remain vulnerable to bypass unless strict assertions are added.

## Operational Recommendation (short-term hardening)
1. Fail closed for required jobs when harness/scripts are missing.
2. Add explicit "minimum executed tests" assertions for protocol/integration/smoke gates.
3. Publish a CI summary artifact with:
   - suites requested
   - suites executed
   - suites skipped (and reason)
   - tests discovered count
4. Keep optional checks optional, but separate them from required branch-protection gates.

## Confidence Scores
- [1] Workflow semantic review (ci-pr/ci-main): **9/10**
- [2] Harness behavior verification: **9/10**
- [3] Risk severity assessment: **8/10**
- [4] Blind-spot identification against current repo state: **8/10**
