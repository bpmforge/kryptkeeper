# Contributor dry run on a clean machine - v0.20

Status: **PENDING-RUN**. The timed stranger-style run and the fork PR are human activities on machines and a GitHub account that were not available to the build host. Every measured field below is the literal `PENDING-RUN` until an operator replaces it. Only the "pre-checks" in section 3a were executed locally; nothing here is an invented timing, count or URL. Status flips to `RECORDED` only when sections 3 to 8 hold real values (then `grep -c PENDING-RUN` must print 0).

## 1. Header

| Field | Value |
|---|---|
| Version / commit of CONTRIBUTING.md used | PENDING-RUN (at authoring time CONTRIBUTING.md last changed in `60558730`; branch tip `b2ab5631`; re-record at run time) |
| Date | PENDING-RUN |
| Operator (must not be a maintainer) | PENDING-RUN |

Runbook for the operator: on each clean machine below, start a stopwatch, open only `CONTRIBUTING.md` and the files it links, and follow it literally from `git clone` to green `go test ./...` and green UI tests, then `make gate`. Record each step in section 3 (minutes elapsed and cumulative). Log anything not literally in the text as a gap (section 4 rule). Then do the fork PR (section 5) from a non-maintainer GitHub account and the edge cases (section 6). Do NOT run this on a machine that already has the toolchain.

## 2. Environment

| Field | (a) Apple Silicon Mac, fresh user, no Docker | (b) Ubuntu 24.04 x86_64 VM, fresh image | (c) Windows 11 (optional, agent build tags) |
|---|---|---|---|
| OS / version | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| CPU / RAM | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| Go version installed from CONTRIBUTING text only | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| Node version (repo wants 24, `ui/.nvmrc`) | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| Docker / Podman present | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| Network | PENDING-RUN | PENDING-RUN | PENDING-RUN |

## 3. Timeline

Pass line: cumulative <= 60 min to green `go test ./...` AND green UI tests. Record the actual total; do not round.

| Step (per CONTRIBUTING) | Mac min | Mac cum | Linux min | Linux cum | Result / counts |
|---|---|---|---|---|---|
| clone | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| install Go | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| install Node 24 + npm | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| `golangci-lint` install | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| `go build ./...` | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| `go test ./...` | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | pass count: PENDING-RUN |
| `npm --prefix ui ci` | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| `npm --prefix ui run test` | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | pass count: PENDING-RUN |
| `make gate` | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | pass/fail and failing step: PENDING-RUN |
| **Total to green go test + ui tests** | | PENDING-RUN | | PENDING-RUN | |

### 3a. Pre-checks (executed locally on the build host, NOT part of the timed run)

Run on a developer machine with the toolchain, so they say nothing about the clean-machine time.

```
$ go build -o /dev/null ./cmd/kryptkeeper-agent        -> exit 0
$ GOOS=windows go build -o /dev/null ./cmd/kryptkeeper-agent   -> exit 0
$ GOOS=windows go vet ./cmd/kryptkeeper-agent          -> exit 0
$ make -n gate   (dry run) -> go build ./..., go test ./..., make lint (golangci-lint run ./...),
                  make plugins-check, bash scripts/validate-openapi.sh, bash tests/protocol/run.sh,
                  cd ui && npm run lint && npm test -- --run
$ grep -c 'secrets\.' .github/workflows/ci-pr.yml      -> 0
$ grep -c 'pull_request_target' .github/workflows/ci-pr.yml -> 0
$ go.mod: go 1.26.0 ; ui/.nvmrc: 24
```

Observation for the operator to confirm or refute: `make gate` also needs `golangci-lint`, `tests/protocol/run.sh` prerequisites and the WASM plugin vet targets (Go with `wasip1`), and the UI step in `make gate` needs `npm ci` to have been run first; check CONTRIBUTING states each.

## 4. Rules of the run

The operator may use only CONTRIBUTING.md and the files it links. Any web search, prior knowledge or tribal command is logged here as a gap with the step that caused it. Result: PENDING-RUN.

## 5. Fork PR (acceptance 2)

| Field | Value |
|---|---|
| Fork account (non-maintainer) | PENDING-RUN |
| PR URL (one-line docs change to `main`) | PENDING-RUN |
| `ci-pr` run URL | PENDING-RUN |
| Per-job result | PENDING-RUN |
| Repository/organisation secrets required | PENDING-RUN (expected 0) |
| `grep -c 'secrets\.' .github/workflows/ci-pr.yml` | 0 (local pre-check; re-paste at run time: PENDING-RUN) |

Fork PRs get a read-only `GITHUB_TOKEN` and no secrets. Any job that needs a secret, or uses `pull_request_target`, and shows skipped or failing is a failing gap, not a note.

## 6. Edge cases

| Case | Result (PASS/FAIL/GAP) | Evidence |
|---|---|---|
| Apple Silicon: arm64 build and tests, any amd64-only assumption | PENDING-RUN | PENDING-RUN |
| No Docker: what `make gate` / `go test` skip or fail; container-needing tests must self-skip, list those that do not | PENDING-RUN | PENDING-RUN |
| Windows agent: `GOOS=windows go build ./cmd/kryptkeeper-agent` from Linux/macOS | PENDING-RUN on a clean machine (local pre-check on the build host: exit 0) | PENDING-RUN |
| Windows agent: `go vet` with the windows tag | PENDING-RUN on a clean machine (local pre-check: exit 0) | PENDING-RUN |

## 7. Gaps

| Id | Description | Step | Severity | Issue link (`good first issue` where scoped) | CONTRIBUTING needs fix? (re-run only the affected step) |
|---|---|---|---|---|---|
| PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |

Do not edit CONTRIBUTING.md in this ticket; file the fix as an issue.

## 8. Sign-off

| Acceptance | Result | Numbers |
|---|---|---|
| 1. Clean-machine run from CONTRIBUTING only reaches green `go test` and UI tests in under 60 minutes | PENDING-RUN | total: PENDING-RUN |
| 2. Fork PR passes `ci-pr.yml` with 0 secrets | PENDING-RUN | PR/run URLs: PENDING-RUN |

The board item is complete only when this record flips to `RECORDED` with real numbers.
