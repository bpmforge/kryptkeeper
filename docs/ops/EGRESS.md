# Outbound egress and discovery limits

Operator-configured URLs are untrusted input. Three features make outbound
HTTP requests to them and share one guarded client (`internal/egress`):

| Feature | Findings |
|---|---|
| Notification webhooks (generic, Slack, PagerDuty) | SEMGREP-001 |
| Inventory sources (DigiCert, Sectigo, Entrust, GCP CAS, AWS PCA) | SEMGREP-002 |
| ACME upstream connector (health probe and issuance) | OWASP-A10-002 |

The guard checks the address actually dialled, after DNS resolution and on
every redirect hop:

- Always refused: link-local (169.254.0.0/16 incl. 169.254.169.254, fe80::/10),
  0.0.0.0/8 and unspecified, multicast, loopback, and IPv4-mapped/NAT64 forms
  of those.
- Allowed by default: RFC1918, ULA fc00::/7 and CGNAT 100.64.0.0/10 (internal
  chat servers, vendor appliances, internal CAs).
- Redirects: at most 3, only to the same host. An inventory credential is a
  custom header, which net/http would otherwise replay to a redirect target.
- Environment proxy settings are ignored.

## Switch

`KRYPTKEEPER_EGRESS_DENY_PRIVATE=true` also refuses private space for all
three features. Use it when the hub talks only to public SaaS. A webhook to an
internal host then fails with "destination blocked" in the delivery error.

## Discovery scans (OWASP-A10-003, A04-005)

`POST /api/v1/discovery/scans` returns 400 when the target is a literal IP or
CIDR inside the deny list, or when it expands to more than the cap
(addresses x ports per address).

| Variable | Default | Meaning |
|---|---|---|
| `KRYPTKEEPER_DISCOVERY_DENY_CIDRS` | empty | extra CIDRs/IPs, added to link-local (always denied) |
| `KRYPTKEEPER_DISCOVERY_MAX_TARGETS` | 65536 | per-scan expanded probe cap |

Hostnames are not resolved at creation time, so a name pointing into a denied
range is not caught by the deny list.
