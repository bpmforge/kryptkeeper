# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | ✅ Yes (latest release) |
| < 1.1   | ❌ No: upgrade to the latest 1.1.x release |

Security fixes land in the latest minor release only. The supported row moves forward with each tagged release; the table is checked against the newest git tag by `scripts/check-security-txt.mjs`.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security vulnerabilities via one of these channels:

1. **GitHub Private Security Advisory** (preferred):
   go to [Report a vulnerability](https://github.com/bpmforge/kryptkeeper/security/advisories/new)
   (Security → Report a vulnerability). GitHub keeps the report confidential
   until a fix is released.

2. **Email:** [security@kryptkeeper.io](mailto:security@kryptkeeper.io).
   We do not publish a PGP key. If your report needs encryption, ask for a
   private advisory or another secure channel in a first, detail-free email.

### What to include

- Description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code if available)
- Affected versions
- Any known mitigations

### Response timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | 3 business days |
| Initial assessment | 5 business days |
| Fix + coordinated disclosure | 90 days (may be extended for complex issues) |
| CVE assignment | Within 7 days of fix release |

We follow [responsible disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html).
Reporters who follow this policy will be credited in the release notes unless they prefer anonymity.

## Security Model

### Trust boundaries

- **Hub API**: All endpoints require authentication (JWT or API key).
  Unauthenticated requests return HTTP 401.
- **Satellite Agent**: Agents authenticate with a 32-byte random token issued at registration.
  Tokens are not logged or included in audit events.
- **PKCS#11/HSM**: Private key bytes never leave the HSM when using the `pkcs11` backend.
  The hub's software key store encrypts keys at rest using the OS secret store.
- **Template Policy**: Certificates cannot be issued outside the parameters defined in the
  template (algorithm, max validity, EKU, min key size). Violations return HTTP 422.

### Known limitations (v0.9)

This list is from the v0.9 release and is kept for history. Current open
findings are in [docs/security/V1.1_SCAN_2026-10-27.md](docs/security/V1.1_SCAN_2026-10-27.md)
and [docs/ROADMAP.md](docs/ROADMAP.md).

Open LOW findings from the RC2 scan
([docs/security/rc2/02-findings.md](docs/security/rc2/02-findings.md)); none is
a known bypass of authentication or separation of duties.

- B-03 residual: 19 JSON request decoders still have no body cap (authenticated, bounded by the 15 s read timeout).
- A-05 HA lease can be shorter than a renewal scan; A-06 successor-creation race; A-07 some agent installers use `http.DefaultClient`; A-08 privilege-elevation deny-list; A-09 discovery scanner deny-list matches literal IPs only.
- B-05 SIEM "test" returns the raw `url.Error`; B-06 SAML login CSRF; B-07 pending-SAML table capped at 4096; B-08 some pre-checks fail open on a store error.
- C-03 key-size floor enforced only in ACME and CMP; C-04/B-09 `/inventory/keys` readable by viewer; C-05 ACME http-01 allows RFC1918 by design; C-06 MCP error wrapper.
- I-1 OCSP answers "good" with no store configured; I-2 OCSP cache race; M-3 nginx CSP is `frame-ancestors` only (no HSTS or script-src).
- RC2-N-04 report endpoints materialise the whole inventory per request; RC2-N-05 arming a target checks `certificate.renew`, not certificate ownership (custom roles holding both `discovery.manage` and `certificate.renew` are admin-equivalent).
- RC2-N-06 `token:` egress stamps (external jwt/oidc bearers) are never re-verified; RC2-N-08 file-mode audit store is O(file) per read and single-node.
- Multi-tenancy (v0.10): tenant isolation is enforced and covered by the tenant IDOR suite; the remaining limits (one hub-wide SSH CA key, SCIM users landing in the default tenant, instance-global settings being super-admin only) are listed in [docs/design/TENANCY_POSTURE.md](docs/design/TENANCY_POSTURE.md). The v0.9 experimental start-up gate is lifted; `KRYPTKEEPER_MULTI_TENANCY_GATE=enforce` restores it.

Open findings from the RC5 delta review (an internal review); the
review's other items (S-L8 validity sum, the fail-open key-consistency check, the
README provider docs, the rule burst cap) were fixed before rc.7.

- RC5 S-M2 (MEDIUM, multi-tenant only, FIXED in v0.10 by L-10: rules and silences carry a tenant): notification rules were hub-global. They carry no tenant, and the renewal scan walks every tenant's certificates. With multi-tenancy on, a principal holding `notification.manage` can create an `email` rule to an external address and receive the common name, fingerprint and days-to-expiry of other tenants' certificates (no key material). Do not grant `notification.manage` to tenant-scoped principals. Multi-tenancy is experimental (above), so this is not a boundary in v0.9; tenant-isolation fixes are scheduled for v0.10.
- RC5 S-L2b: migration auto-tolerance accepts a column that already exists without comparing its type, default or CHECK, so a store that self-created a column with a different shape is not detected at runtime (covered by tests only). The self-heal exhaustiveness test checks file names, not that each store is constructed.
- RC5 S-L7: a notification rule's email target is not syntax-checked; a malformed address is stored and fails at send time (logged only).
- RC5 A-2: for the `delivery` provider "sent" means queued. A permanent failure (bad SMTP, webhook 500) is not audited as failed, and the cooldown suppresses a retry for its window.
- The review's code-health and test-coverage items (rule validation only in the HTTP handler, the in-memory `file` notification provider, PostgreSQL store tests that skip without `KRYPTKEEPER_TEST_POSTGRES_DSN`) are listed in the review, not repeated here.
- Residual risks accepted for v0.9 are listed in [docs/security/final-report.md](docs/security/final-report.md) and `docs/security/OWASP_TRACKER.md`.

Operational:

- The satellite agent ACME renewal executor requires either CAP_NET_BIND_SERVICE (for the
  in-process :80 listener) or write access to the webroot directory.
- The cert-manager issuer controller requires RBAC access to patch `CertificateRequest/status`.
  It does not need access to Secrets or ConfigMaps.

### Telemetry

Kryptkeeper does not phone home. There is no built-in analytics, usage telemetry, or
crash-reporting client, and no background process sends data to a Kryptkeeper-operated
or third-party endpoint. The only network egress the hub and agent initiate is traffic
you explicitly configure:

- Protocol traffic to devices/clients you manage (ACME, EST, SCEP, CMP, OCSP, WSTEP/XCEP).
- Integrations you turn on: notification channels (SMTP, Slack, PagerDuty, generic webhook),
  a SIEM webhook/syslog target (`SIEM_WEBHOOK_URL`/`SIEM_SYSLOG_ADDR`), an OIDC provider's
  JWKS endpoint, cloud inventory APIs, and hub↔agent/satellite communication.
- Certificate Transparency monitoring, when `KRYPTKEEPER_CT_DOMAINS` is set: queries to
  `crt.sh` (and `api.certspotter.com` unless `KRYPTKEEPER_CT_SECOND_SOURCE=off`) carrying the
  monitored domain names.
- ACME upstream connectors, when you configure one: requests to the ACME directory you choose
  (for example Let's Encrypt) and, for DNS-01, to your DNS provider.
- `govulncheck`/dependency tooling you run yourself (see below) — not run automatically
  by the product at runtime.

All certificate data, audit logs, and configuration stay in your database and object
storage; nothing is uploaded to Kryptkeeper or any third party as part of normal operation.

The complete per-feature list, with defaults, is in `docs/ops/DATA_RESIDENCY.md`.

### Dependency security

Run `go list -m -json all | nancy sleuth` or `govulncheck ./...` to check for known CVEs
in dependencies. We run `govulncheck` in CI on every pull request.
