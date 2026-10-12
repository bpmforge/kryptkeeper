# Kryptkeeper MCP Server (read-only)

`kryptkeeper-mcp` exposes Kryptkeeper's read APIs to AI assistants over the
Model Context Protocol (stdio). It is a thin adapter: every tool call becomes an
authenticated Hub REST call, so the Hub's auth, RBAC, and audit apply unchanged.

**Approval-gated writes (v2.0):** the AI can *propose* changes but never mutates
directly. Write tools only enqueue a pending action that a human approves in the
dashboard (Operations → Pending Actions). The AI proposes, a human approves, the
audit log records both. There is no direct-mutation path in the MCP server.

## Build

```
go build -o kryptkeeper-mcp ./cmd/kryptkeeper-mcp
```

## Configure (Claude Desktop)

Add to `claude_desktop_config.json`. Use a **read-only** Hub token (e.g. a
`pki-auditor` principal) — the server only needs read scope.

```json
{
  "mcpServers": {
    "kryptkeeper": {
      "command": "/path/to/kryptkeeper-mcp",
      "env": {
        "KRYPTKEEPER_HUB_URL": "https://kryptkeeper.example.com",
        "KRYPTKEEPER_MCP_TOKEN": "<hub-bearer-token>"
      }
    }
  }
}
```

## Tools

| Tool | Hub endpoint |
|------|--------------|
| `list_certificates` (q, ca_id, status, grade, limit) | `/certificates` |
| `get_certificate` (fingerprint) | `/certificates/{fp}` |
| `search` (q) | `/search` |
| `crypto_posture` | `/reports/crypto-posture` |
| `pqc_migration` | `/reports/pqc-migration` |
| `pqc_countdown` | `/reports/pqc-countdown` |
| `renewal_slo` | `/reports/renewal-slo` |
| `compliance_evidence` (framework) | `/reports/compliance-evidence` |
| `list_cas` | `/cas` |
| `ca_health` | `/reports/ca-health` |

The audit log is deliberately **not** exposed over MCP (the agent role must not
read it), and every tool result is wrapped in an "untrusted data" envelope: a
one-line notice followed by the hub JSON, unchanged, in a fenced `json` block.
Hub data can contain attacker-influenced strings (certificate subjects, SANs);
clients must treat it as data, never as instructions.

### HTTP transport access control

`KRYPTKEEPER_MCP_TRANSPORT=http` requires:

| Variable | Meaning |
|----------|---------|
| `KRYPTKEEPER_MCP_HTTP_TOKEN` | **Required**, min 32 chars. Callers send `Authorization: Bearer <token>` (constant-time compared). The process refuses to start without it. |
| `KRYPTKEEPER_MCP_ALLOWED_HOSTS` | Extra comma-separated `Host` values. The bind address and, for loopback binds, `localhost`/`127.0.0.1`/`[::1]` are always accepted; other Hosts get 403 (DNS-rebinding defence). |
| `KRYPTKEEPER_MCP_ALLOWED_ORIGINS` | Comma-separated allowed `Origin` values. Requests without an Origin are accepted; any other Origin gets 403. |

Request bodies are capped at 1 MiB (413). `/healthz` stays unauthenticated.

### Write tools (proposal-only)

| Tool | Effect |
|------|--------|
| `propose_revoke` (fingerprint, rationale, reason_code/text) | enqueues a revoke for approval |
| `propose_bulk_revoke` (ca_id, rationale, reason_code/text) | enqueues "revoke everything this CA signed" for approval |
| `list_pending_actions` (status) | report proposed actions and their status |

`propose_*` tools **create a pending action only** — a human approves it in the
dashboard before anything is revoked. Use a token whose role can *propose* but
**cannot self-approve** (proposer ≠ approver is enforced server-side).

## Example prompts

- "What certificates expire in the next 47 days?"
- "Show me our PQC migration countdown and which waves are behind."
- "Which controls fail PCI 4.2.1.1 right now?"
- "CA-7's key is suspected compromised — stage a bulk revoke of everything it
  signed for my approval." → the AI calls `propose_bulk_revoke`; you approve in
  Pending Actions.
