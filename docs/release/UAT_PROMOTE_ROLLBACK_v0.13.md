# UAT: promote and rollback by digest in kind (W25-19, FR-P55)

Run 2026-10-15, kind v0.33.0 on podman, helm v4.3.0. Harness `tests/live/promote-rollback/run.sh`
drives `scripts/deploy/by-digest.sh` (the script both workflows call) with `DEPLOY_METHOD=helm`.
Digest A and B are two real hub builds from this tree (`--build-arg VERSION=0.0.1-promote-a` /
`0.0.2-promote-b`) pushed to a local registry `localhost:5001`; the pods pull them by `@sha256`
through a containerd mirror. Hub runs `config.dbMode=sqlite`, one replica.

## Verdict

**Acceptance 1 and 2 met. `run.sh`: ALL PASS (0 FAIL). `workflow-gate_test.sh`: ALL PASS.**

| Test | Result |
|---|---|
| `baseline_smoke_green` | PASS: deploy A (`sha256:a0fe92dc...`), `smoke.sh` live + ready 200 |
| `promote_B_smoke_green` | PASS: deploy B; pod `imageID` = `localhost:5001/kryptkeeper@sha256:e47095c5...` (ends with B); smoke 200/200 |
| `rollback_A_smoke_green` | PASS: deploy A again; pod `imageID` ends with A; smoke 200/200 |
| `zero_smoke_failures` | PASS: `[smoke] FAIL` appears 0 times across the 3 runs |
| `bad_digest_rejected` | PASS: `by-digest.sh staging repo:latest` exits 2 |
| `workflow_environment_bound` | PASS: `deploy-target` (promote) and `deploy-rollback` (rollback) both have `environment: ${{ inputs.target_env }}` |
| `workflow_no_push_trigger` | PASS: `on` is `workflow_dispatch` only in both; the test fails (3 FAIL lines) when a copy is edited to add `push:` and drop `environment:` |
| deploy job needs its gate | PASS: `deploy-target` needs `verify-signature`; `deploy-rollback` needs `precheck` |

## Defects found in `scripts/deploy/by-digest.sh` (fixed in this change)

1. **Helm driver could not deploy the chart at all.** `helm upgrade --install` ran with only
   `image.repository` and `image.digest`; no way to give secrets or `dbMode`, and no
   `--reuse-values`, so a promote would also reset every value the release was installed with
   (`helm template` of that command: `secrets.bootstrapToken is required`). Now it passes
   `--reset-then-reuse-values` (helm 3.14+) and an optional `HELM_VALUES_FILE` for the first install.
2. **Digest regex rejected any registry with a port** (`localhost:5001/x@sha256:...`,
   `registry.internal:5000/...`): the repo part did not allow `:`. Now `[a-zA-Z0-9._:/-]`.
   `repo:latest` is still rejected (no `@sha256:`).

## Not fixed, outside this ticket's files (report)

- `.github/workflows/promote-by-digest.yml` and `rollback-by-digest.yml` still use the old regex
  without `:` in their own digest validation (lines ~60 / ~51), so a digest in a registry with a
  port is rejected by the workflow before `by-digest.sh` runs.
- Both workflows call `cosign verify --key cosign.pub`, which cannot verify keyless (OIDC)
  release signatures; it works only for key-signed images. This test does not exercise it.
- Both deploy jobs refuse to run unless the `DEPLOY_CMD_STAGING` / `DEPLOY_CMD_PRODUCTION` secret is
  non-empty, so the script's default helm/kubectl driver (the path tested here) is unreachable from
  the workflows as written.

## Limits of the evidence

- `smoke.sh` uses `curl -ksS` (skip-verify) by design; acceptable for smoke only. The shared
  `/tmp/kryptkeeper_smoke_body.txt` was not flaky in this sequential run, so `smoke.sh` is unchanged.
- The YAML cannot prove GitHub environment protection rules. the owner runs, against the real repo:
  `gh api repos/bpmforge/kryptkeeper/environments/production --jq '.protection_rules[].type'`
  and expects `required_reviewers`. **Pending (not run here).**
- This host has no PyYAML, so `workflow-gate_test.sh` falls back to Ruby's bundled YAML parser
  (same data); nothing was installed.
