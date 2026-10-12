# WS-10 CI Workflow Re-Audit (Latest)

## Summary
- Re-audited latest changes in:
  - `.github/workflows/ci-pr.yml`
  - `.github/workflows/ci-main.yml`
  - `tests/smoke/run.sh`
- Prior HIGH finding **(2) smoke skip-success / zero assertions** is **resolved**.
- Prior HIGH finding **(1) go.mod-based skip semantics on required gates** is **resolved**.
- Follow-up HIGH findings on `ci-main` protocol/integration fail-open semantics were remediated and re-audited.
- **CRITICAL findings: 0**
- **HIGH findings: 0**

## Subtasks
1. [DONE] Verify current gate/skip/failure semantics in PR workflow.
2. [DONE] Verify current gate/skip/failure semantics in main workflow.
3. [DONE] Verify smoke suite zero-assertion protections.
4. [DONE] Re-assess prior HIGH findings and severity.

## Re-check of Prior HIGH Findings

### 1) go.mod-based skip semantics on required gates
**Status: RESOLVED**

**Resolved portions**
- `ci-pr.yml` protocol+integration harness and runtime smoke harness no longer use `if: hashFiles('go.mod') != ''` and no longer include skip markers; they now run directly and fail if Go module/toolchain prerequisites are missing.
- `ci-main.yml` runtime smoke harness similarly runs unconditionally.

**Resolution evidence**
- Removed `if: ${{ hashFiles('go.mod') != '' }}` guards from required `ci-main` jobs:
  - `integration-full` setup and run steps now execute unconditionally.
  - `protocol-conformance` setup and run steps now execute unconditionally.
- Missing Go module/toolchain now fails closed rather than skipping required checks.

**Re-audit follow-up (now resolved)**
- `protocol-conformance` now requires all protocol suite directories (`acme`, `ocsp`, `crl`, `est`, `scep`) and fails if any are missing.
- `integration-full` now fails if no `*_test.go` files exist under `tests/integration`.
- `protocol-conformance` now fails if no `*_test.go` files exist under any required suite directory.

---

### 2) smoke suite skip-success risk (zero assertions)
**Status: RESOLVED**

**Evidence**
- `tests/smoke/run.sh` now tracks assertion execution via `SMOKE_ASSERTIONS`.
- `curl_expect_200` increments assertion count on success.
- New terminal guard `ensure_assertions_executed` fails if `SMOKE_ASSERTIONS <= 0`.
- Script flow now ends with:
  - `run_mode_with_skip_semantics "$SMOKE_MODE"`
  - `ensure_assertions_executed`

**Operational effect**
- Even if mode logic returns success via skip semantics, run exits non-zero when no assertions actually executed.
- This closes the prior “green smoke gate with zero checks” blind spot.

## Remaining Findings

- No remaining CRITICAL/HIGH findings in the audited scope.

## Confidence Scores
- [1] PR workflow reassessment: **9/10**
- [2] Main workflow reassessment: **10/10**
- [3] Smoke zero-assertion reassessment: **9/10**
- [4] Severity and residual risk classification: **9/10**
