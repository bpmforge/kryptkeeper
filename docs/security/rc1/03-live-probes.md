# Live probes (local hub, plain HTTP, random secrets, file keystore, no Postgres)

Hub built from `d74edf3`, run with `KRYPTKEEPER_TLS_DISABLE=true`, Argon2id login hash, API keys per role. Stopped afterwards.
Roles probed with API keys: viewer, auditor, mcp-agent, service-account, pki-operator, discovery-operator, plus admin login.

| Probe | Result |
|---|---|
| viewer/auditor/service-account/pki-operator/mcp-agent POST /targets | 403 (needs discovery.manage; mcp-agent propose-only) |
| same roles POST /credentials | 403 (pki-admin only) |
| viewer/auditor/mcp-agent POST /renewal/execute, /targets/{id}/renew | 403 |
| **discovery-operator POST /targets** ssh, auto_renew=true, credential_ref=nonexistent, verify_host_port in {169.254.169.254:80, 127.0.0.1:22, [::1]:443, localhost:8080, 10.0.0.1:443} | **201 for all** (no credential check, no egress check at create). Supports RC1-A-01/A-04 |
| discovery-operator/viewer/pki-operator GET /credentials | 403 |
| GET /inventory/keys: mcp-agent, service-account | 403; viewer, auditor, pki-operator, admin 200; none 401 |
| Body caps (2 MiB and 70 KiB JSON): /auth/login (unauth), /api-keys, /pending-actions | 413 |
| /targets, /credentials, /certificates, /templates oversized | 400 (rejected, but not 413; cosmetic) |
| Security headers (all responses) | nosniff, X-Frame-Options DENY, CSP `frame-ancestors 'none'`, Referrer-Policy no-referrer; `/api` also Cache-Control no-store. No HSTS on plain HTTP (correct) |
| Login cookie | `kk_token; HttpOnly; SameSite=Strict`, no Secure on plain HTTP; X-Forwarded-Proto from untrusted peer ignored (correct) |
| Spoofed X-Forwarded-For / X-Real-IP / Forwarded | audit `source_ip` stayed 127.0.0.1 (clientip works) |
| Login limiter with rotating XFF | 429 after 9 attempts (cannot bypass); correct password also 429 while limited (IP-keyed) |
| Dual control (default) admin POST /admin/backup, /keys/escrow | 202 proposed, no key bytes |
| API-key mint: pki-operator/viewer asking for pki-admin | 403 |
| GET /audit: viewer, mcp-agent, service-account | 403; auditor 200 |
| Path tricks on write gate (`//`, `/./`, `%2F`, case, method override, PATCH) as viewer | 307/403, no bypass |
| GET /users as viewer and mcp-agent | **200** (user directory readable by any authenticated principal) -> U-1 |
| Bootstrap token as bearer | accepted as pki-admin (documented) |
| ACME directory unauthenticated | 200 (EAB off by default, expected; FG-1 constraints covered by tests) |

Not live-testable here (needs Postgres/cloud/devices): custom roles, SCIM, SAML/OIDC, actual scheduler pushes, SIEM sinks.
