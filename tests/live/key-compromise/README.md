# W23-41: live key-compromise drill

A CA C with key K issues three leaves: L1 on a reachable managed ssh target
(re-issuable), L2 with no managed target (deferred), L3 on an unreachable
managed target (failed). A proposes `POST /api/v1/keys/K/compromise`, B
approves. The drill checks rotate-before-flag-before-revoke, 100% revocation
in OCSP and CRL, per-bucket re-issue reporting, the audit trail and alerts, and
that a compromise whose rotation fails (suspended CA) has zero side effects.

```
bash tests/live/key-compromise/run.sh
KK_KEEP_GOING=1 bash tests/live/key-compromise/run.sh   # run on past a FAIL
```

Prerequisites: as `tests/live/ca-revoke/README.md`, plus the sshd/nginx image
built from `tests/live/ssh-install` (built once and cached as
`localhost/kkw23cmp-ssh:latest`; the SSH key is generated per run and copied in
at start, never baked into the image). `HUB_PORT` defaults to 18438.

Output: `RESULTS.md`, stamped with date, git SHA of the checkout under test,
machine, and tool versions. Tokens are never written to it.

Notes:
- The CA API does not return the CA's key id (the spec assumed `key_id`), so K
  is derived as `key-<CA id>` (`internal/ca/engine.go`) and confirmed with
  `GET /api/v1/keys/K`.
- The rotation-failure leg uses a suspended CA (`CA ... is not active`), the
  first option in the spec that works.
- OCSP is asked with the leaf's real issuer, the pre-rotation certificate C0,
  and the response must verify against C0. A diagnostic query against the
  post-rotation certificate is printed only to explain a failure.

Not part of `go test ./...` and not wired into CI.
