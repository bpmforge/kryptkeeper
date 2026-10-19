# Ceremony and dual-control live UAT (W23-09)

```
bash tests/live/ceremony/run.sh
```

Needs `go`, `podman` (running machine), `openssl`, `curl`, `python3`. Builds the
hub from this checkout, starts a throwaway `postgres:16-alpine` container
(`kkw23cer-pg`, 127.0.0.1:55439), runs the hub on 127.0.0.1:8239 (override with
`HUB_PORT`, `PG_PORT`), writes `run-record.txt` here (untracked;
paste it into `RUN_RECORD.md`), and cleans up on exit. Exit code is non-zero on
any FAIL.

## What it proves
- A. 2-of-3 root-CA ceremony with distinct identities from `APP_API_KEYS_JSON`
  (alice, bob, carol: pki-admin; agent: mcp-agent). Quorum 1 and 4 are refused;
  the parked CA refuses issuance before quorum and issues after the 2nd
  approval, with a leaf that `openssl verify`s against the CA chain.
  Bootstrap-token, mcp-agent, repeat and post-completion approvals are refused;
  an aborted ceremony's CA stays unusable.
- B. D-122 dual control: key delete and export are proposals (202); the
  proposer, the bootstrap token and an mcp-agent cannot approve; a second human
  can. Export grants are bound to the proposing credential and single-use.
- C. With Postgres stopped, a key delete answers 503 and deletes nothing.
- D. `KRYPTKEEPER_KEY_DUAL_CONTROL=false` logs the loud WARNING.

## What it does not prove
- Browser/UI behaviour (see `ui/src/pages/Ceremonies.test.tsx`).
- Ceremony expiry sweeping (unit-tested), HSM backends, multi-node hubs.
- A sqlite-only queue outage; that path is `TestDualControlFailsClosedWithoutQueue`.
- Bearer secrets and the pepper are random per run and never printed.
