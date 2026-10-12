# CI Harness Gates Contract (WS-10)

Status: Phase 4 (WS-10 incremental)

## Scope

Defines required harness-gated checks in GitHub Actions for PR/main pipelines.

## PR Pipeline Requirements

Workflow: `.github/workflows/ci-pr.yml`

- Must run `scripts/test/run.sh --suite protocol --suite integration`
- Must run `scripts/test/run.sh --suite smoke`

Fail-closed requirement:

- Missing harness file or missing requested suite scripts must fail the job.
- `go.mod` is required for these jobs; missing module is a hard failure (no skip path).

These checks ensure migration/workflow integrity and runtime baseline health before merge.

## Main Pipeline Requirements

Workflow: `.github/workflows/ci-main.yml`

- Must execute protocol/integration validations (via existing jobs/suites)
- Must execute runtime smoke harness

Fail-closed requirement:

- Missing required integration/protocol test directories must fail the job.
- Missing required integration/protocol `*_test.go` files must fail the job.
- Missing any required protocol suite directory (`tests/acme`, `tests/ocsp`, `tests/crl`, `tests/est`, `tests/scep`) must fail the job.
- Smoke suite must execute at least one assertion; zero-assertion runs fail.
- Required integration/protocol setup/run paths must not be gated behind `hashFiles('go.mod')` skip guards.

## Compatibility Notes

- Harness gates are additive to existing lint/unit/security jobs.
- If `go.mod` or harness script is missing, workflows fail closed with explicit non-zero exits.
