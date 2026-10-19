# W26-16: approval-gated issuance and policy rejection, live

One hub on the host plus a real OpenSSH server in podman. alice and bob are two
named pki-admin humans (`APP_API_KEYS_JSON`); the bootstrap token cannot approve
(proposer != approver is decided on the human behind the credential).

Proves:

1. RSA-1024 CSR against a `min_key_size` 2048 template: HTTP 422
   `policy_violation`, message names `key_size`, nothing signed.
2. Approval-required template: 202 `pending_approval`, no certificate listed;
   self-approval and bootstrap approval 403; bob approves 201; listed with
   `source=api`; a second approve is 409.
3. Same CSR again (same key + template): recorded as the product answers. The
   board wants the same serial; a different answer stays FAIL with a HANDOFF.
4. SSH from an approval-required template: 202, bare key refused by sshd, alice
   cannot self-approve, bob approves 201 with the cert record, sshd accepts it
   (host verified through `@cert-authority`).
5. TTL 25 h on a 24 h template: 400. Audit rows for pending and approved.

## Run

```
bash tests/live/issuance-approval/run.sh
```

Env: `HUB_PORT` (default 8101), `SSH_PORT` (default 2225). Needs podman, go,
openssl, ssh, python3, curl. Container `kk-uat-issapp`; cleans up on exit.
Ends with `ALL STEPS PASSED` only when there is no FAIL.

Results: `docs/release/LIVE_RESULTS_FG2_ISSUANCE_v0.14.md`.
