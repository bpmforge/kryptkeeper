# Live MCP E2E (W29-08)

Drives the real `kryptkeeper-mcp` binary with the official `mark3labs/mcp-go`
client over **stdio** and **StreamableHTTP** against a real hub process (host
process, no containers; needs `go`, `curl`, `python3`).

```bash
bash tests/live/mcp/run.sh
```

Without `KK_LIVE_MCP=1` (which `run.sh` sets) the Go tests skip, so
`go test ./...` is unaffected.

## What it proves

- Tool list carries no approve/execute tool; `blast_radius` is readable.
- All five propose tools (`propose_revoke`, `propose_bulk_revoke`,
  `propose_issue`, `propose_renew`, `propose_rotate`): propose, human approval
  (named administrator via `/auth/login`), then the action is executed. Both
  transports.
- An `mcp-agent` key can never approve or reject (403 from the hub).
- `kryptkeeper-mcp` refuses to boot with a `pki-admin` key or the bootstrap token.
- The audit log shows each proposal with its rationale and the proposing agent.

## Observed result (2026-10-16, branch kk/w29-b)

`22 passed, 0 failed` (4 top-level tests; the `--- PASS` count includes subtests).

## Notes

Hub setup needs `APP_API_KEY_AUTH_ENABLED=true` plus `APP_API_KEY_PEPPER`, or
`POST /api/v1/api-keys` answers a misleading 400 and minted keys 401. The
approver login token is cached per test process because `/auth/login` is
rate-limited.
