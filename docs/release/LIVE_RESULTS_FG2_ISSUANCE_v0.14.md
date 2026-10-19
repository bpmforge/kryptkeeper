# Live validation W26-16: approval-gated issuance and policy rejection - v0.14

Date: 2026-10-16. Hub commit: not recorded by the log (PENDING-RUN). Harness:
`tests/live/issuance-approval/run.sh`. Host: not recorded by the log. OpenSSH (container):
version not recorded by the log; a real sshd container was used.
Source log: `uat16-pass.log`, real run 2026-10-16, ends `ALL STEPS PASSED`, `EXIT 0`.

## Verdict: PASS - validated (all 18 steps passed live, 2026-10-16)

Root CA 45e6ad20-5e80-4eba-ae4b-87a7a0d3e556; templates `tpl-rsa-direct-1792171002236496000`
and `tpl-rsa-approval-1792171002265470000`, both `min_key_size` 2048.

| Step | Expected | Result | Evidence |
|---|---|---|---|
| RSA-1024 refused 422 policy_violation, message names key_size | 422 | PASS | HTTP 422 `policy_violation`, `policy violation [key_size]: key size 1024 bits is below template minimum 2048` |
| refused CSR signed nothing | count unchanged | PASS | nothing signed |
| approval template answers 202 pending_approval + approval_id | 202 | PASS | 202, `apr-e37dfdf935de35be17049433a7dae31d` |
| no certificate listed while pending | 0 | PASS | 0 |
| alice self-approve | 403 | PASS | 403; still no cert afterwards |
| bootstrap token approve | 403 | PASS | 403 |
| bob approves | 201 | PASS | 201 |
| certificate listed, source=api | 1 | PASS | serial 222534785222025844971158823293309073349 |
| second approve | 409 | PASS | 409 (not pending) |
| same CSR again returns same serial (approval template) | same serial | PASS | HTTP 200, serial 222534785222025844971158823293309073349 (W26-32 reuse) |
| same CSR twice on direct template returns same serial | same serial | PASS | first 201, second 200, serial 164546542006333102622561214438302625904 |
| SSH approval template answers 202 | 202 | PASS | 202, `pending_approval` |
| no SSH record while pending; sshd refuses bare key | none | PASS | none; bare key refused |
| SSH self-approve | 403 | PASS | 403 |
| bob approves SSH | 201 + record | PASS | 201 |
| sshd accepts approved cert, key ID logged | login as deploy | PASS | logged in as `deploy`, host verified via @cert-authority, key ID logged |
| 25 h user cert | 400 | PASS | 400 (template ceiling 24h), before any approval row |
| audit: ssh pending_approval row, 2 approval.approve success | >=1, >=2 | PASS | measured 1 and 2 |

Board acceptance 3 (`docs/ops/SSH_CA.md` states v1.0 SSH revocation is TTL-only) is met by the
doc's Revocation section (no KRL; wait out the TTL or rotate the CA key); it is a doc check, not a log line.

## Product fixes this run drove

- Same-key idempotency (US-010 AC4) was fixed via W26-32 (same key + template returns the
  existing serial with HTTP 200); it now passes. The earlier HANDOFF note is closed.
- SSH issuance honours `require_approval` (W26-31); the approval path passes end to end against real sshd.
- Policy refusal is HTTP 422 `policy_violation` (the owner, 2026-10-16), rule `key_size`.
- Migration 000196: the Baseline policy allows RSA-3072; the policy API, openapi and UI accept RSA-3072.
- X.509 approval templates now dry-run the engine policy before queueing (W26-32 commit), so a
  non-compliant CSR is refused 422 instead of being queued.
- osslsigncode 2.5 signs a PE via the engine by name (see W26-24).
