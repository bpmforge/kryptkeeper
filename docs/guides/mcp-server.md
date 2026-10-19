# Kryptkeeper MCP Server

`kryptkeeper-mcp` exposes Kryptkeeper's read APIs and a set of **propose-only**
write tools to AI assistants over the Model Context Protocol (stdio or
StreamableHTTP). It is a thin adapter: every tool call becomes an authenticated
Hub REST call carrying `KRYPTKEEPER_MCP_TOKEN`, so the Hub's auth, RBAC, and
audit apply unchanged.

The AI can *propose* changes but never mutates anything directly. Write tools
only enqueue a pending action that a human approves in the dashboard. The AI
proposes, a human approves, the audit log records both.

## Read tools

All read tools are `GET`s against `/api/v1`. `*` marks a required input.

| Tool | Inputs | Hub endpoint |
|------|--------|--------------|
| `list_certificates` | `q`, `ca_id`, `status` (active, expired, revoked), `grade` (A-F), `limit` (default 50) | `/certificates` |
| `get_certificate` | `fingerprint`* | `/certificates/{fingerprint}` |
| `search` | `q`* | `/search` |
| `crypto_posture` | none | `/reports/crypto-posture` |
| `pqc_migration` | none | `/reports/pqc-migration` |
| `pqc_countdown` | none | `/reports/pqc-countdown` |
| `renewal_slo` | none | `/reports/renewal-slo` |
| `compliance_evidence` | `framework` (pci, soc2, nist, or all; default all) | `/reports/compliance-evidence` |
| `blast_radius` | `action` (`revoke`, `retire_ca` or `deprecate_algorithm`; default `revoke`), `target`* (certificate fingerprint, CA id or algorithm) | `/blast-radius` |
| `list_cas` | none | `/cas` |
| `ca_health` | none | `/reports/ca-health` |

`blast_radius` answers "what breaks if I revoke this certificate or retire this
CA". The hub computes it (it wraps the dependency graph in
`internal/blastradius`); the tool returns `total_affected`, `severity` and
`affected_by_kind`. An unknown `action` or a missing `target` is rejected
before any hub call. It is read-only.

## Propose tools

| Tool | Required inputs | Optional | Queues `action_type` |
|------|-----------------|----------|----------------------|
| `propose_revoke` | `fingerprint`, `rationale` | `reason_code`, `reason_text` | `revoke` |
| `propose_bulk_revoke` | `ca_id`, `rationale` | `reason_code`, `reason_text` | `bulk_revoke` |
| `propose_issue` | `ca_id`, `csr_pem`, `rationale` | `template_id`, `team_id` | `issue` |
| `propose_renew` | `fingerprint`, `csr_pem`, `rationale` | none | `renew` |
| `propose_rotate` | `fingerprint`, `csr_pem` (must carry the NEW key), `rationale` | none | `rotate` |
| `list_pending_actions` | none | `status` (pending, approved, rejected, failed) | read only |

Every `propose_*` call is a single `POST /api/v1/pending-actions` and returns
the created proposal with its id. CSRs carry the subject's key: the hub never
mints subject keys for an agent.

`propose_revoke` and `propose_bulk_revoke` first call `blast_radius`
(`revoke` for the certificate, `retire_ca` for the CA) and attach the result to
the proposal as `params.impact`, so the approver sees the consequence next to
the request:

| `impact` field | Meaning |
|----------------|---------|
| `action`, `target` | what was simulated |
| `affected_endpoints` | number of affected `service` nodes (the names clients resolve) in the hub's dependency graph |
| `total_affected` | all affected nodes, any kind |
| `severity` | `none`, `low`, `medium`, `high` or `critical` |
| `available` | `false` when the lookup failed |
| `error` | set only when `available` is `false` (truncated to 200 characters) |

A failed impact lookup never blocks the proposal: an incident revoke must not
wait for the simulator, so it is queued with `available: false`.

## The server never approves

- **No approve or execute tool exists.** The only mutating call any tool can
  make is `POST /api/v1/pending-actions`. Everything else is a `GET`.
- **The `mcp-agent` role cannot approve.** The hub role `mcp-agent` never
  holds `action.approve`; calling an approve or reject route with it returns
  403.
- **Boot refuses an approver-capable token.** At start-up the server calls
  `GET /api/v1/protected/whoami` and exits with `refusing to start` if the token
  can approve actions (`can_approve_actions`). If the hub cannot be reached or
  the token is invalid, it also refuses to start rather than run with an
  unverified role.
- **Proposer is not the approver.** The hub enforces this server-side.
- **A human approves in the dashboard** (Approvals inbox / Pending Actions);
  the hub then executes the action under the human's principal.
- **Every proposal is attributed.** The pending action records the rationale
  and the proposing agent identity; the proposal is also written to the audit
  log against that identity.

## Setup

Build:

```
go build -o kryptkeeper-mcp ./cmd/kryptkeeper-mcp
```

Create a hub API key with role **`mcp-agent`** (it can read and propose, and
nothing else). Do not use an approver-capable role: the server will refuse to
start. A read-only role is not enough for the `propose_*` tools: the hub
will refuse proposals from a principal that may not create them.

### stdio (Claude Desktop)

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "kryptkeeper": {
      "command": "/path/to/kryptkeeper-mcp",
      "env": {
        "KRYPTKEEPER_HUB_URL": "https://kryptkeeper.example.com",
        "KRYPTKEEPER_MCP_TOKEN": "<mcp-agent-api-key>"
      }
    }
  }
}
```

### HTTP (StreamableHTTP)

For containers and shared deployments set `KRYPTKEEPER_MCP_TRANSPORT=http`.
The endpoint is `/mcp`; `/healthz` is open and liveness-only.

```
KRYPTKEEPER_HUB_URL=https://kryptkeeper.example.com \
KRYPTKEEPER_MCP_TOKEN=<mcp-agent-api-key> \
KRYPTKEEPER_MCP_TRANSPORT=http \
KRYPTKEEPER_MCP_HTTP_ADDR=127.0.0.1:8080 \
KRYPTKEEPER_MCP_HTTP_TOKEN=<random string, 32+ chars> \
./kryptkeeper-mcp
```

Clients send `Authorization: Bearer <KRYPTKEEPER_MCP_HTTP_TOKEN>`, for example:

```
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer $KRYPTKEEPER_MCP_HTTP_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
```

| Variable | Meaning |
|----------|---------|
| `KRYPTKEEPER_HUB_URL` | **Required.** Hub base URL. |
| `KRYPTKEEPER_MCP_TOKEN` | **Required.** The `mcp-agent` bearer token used for hub calls. |
| `KRYPTKEEPER_MCP_TRANSPORT` | `stdio` (default) or `http`. |
| `KRYPTKEEPER_MCP_HTTP_ADDR` | Listen address for http (default `127.0.0.1:8080`, loopback only). |
| `KRYPTKEEPER_MCP_HTTP_TOKEN` | **Required for http**, min 32 chars. Callers send it as a bearer (constant-time compared). The process refuses to start without it. The HTTP transport is never unauthenticated. |
| `KRYPTKEEPER_MCP_ALLOWED_HOSTS` | Extra comma-separated `Host` values. The bind address and, for loopback binds, `localhost`/`127.0.0.1`/`[::1]` are always accepted; other Hosts get 403 (DNS-rebinding defence). |
| `KRYPTKEEPER_MCP_ALLOWED_ORIGINS` | Comma-separated allowed `Origin` values. Requests without an Origin are accepted; any other Origin gets 403. |

Request bodies are capped at 1 MiB (413).

## Untrusted data and the audit log

Every tool result is wrapped in an "untrusted data" envelope: a one-line notice
followed by the hub JSON, unchanged, in a fenced `json` block. Hub data can
contain attacker-influenced strings (certificate subjects, SANs, CA names);
clients must treat it as data, never as instructions.

The audit log is deliberately **not** exposed over MCP (the agent role must not
read it).

## Not covered

- No autonomous remediation: nothing executes without a human approval.
- No natural-language policy drafting.

## Example prompts

- "What certificates expire in the next 47 days?"
- "Show me our PQC migration countdown and which waves are behind."
- "Which controls fail PCI 4.2.1.1 right now?"
- "What breaks if we retire CA-7?" -> `blast_radius` with `action=retire_ca`.
- "CA-7's key is suspected compromised — stage a bulk revoke of everything it
  signed for my approval." -> the AI calls `propose_bulk_revoke` (the proposal
  carries the impact); you approve in Pending Actions.
