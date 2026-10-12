# OWASP A01 supplement (2026-10-09)

A second, independent A01 pass (a helper started by the first, interrupted
OWASP run) probed a live hub built at 0236b86 with MULTI_TENANCY on and two
tenants (`acme`, `beta`). It was read-only and cleaned up its hub and scratch
dir. Its findings are kept here so the attack chainer and the fix backlog see
them; overlaps with `OWASP_A01_FINDINGS_2026-10-09.md` are cross-referenced.
It also notes that docs/design/TENANCY_POSTURE.md (2026-07-16) is stale: CA,
certificate, template and approval reads and writes are tenant-scoped now
(acme-admin got 403 revoking a beta cert, reading a beta CA, downloading a
beta cert, and on /tenants/ca-mapping).

## Only in this pass

**A01S-3 (HIGH, REAL, live): the key store ignores tenants; a tenant admin exports another tenant's CA private key.**
`internal/bootstrap/handlers_keys.go:149-160` (admin-role check only; no tenant reference in the file), export at `:273-335`. acme-admin listed `key-<beta CA id>` and `ssh-ca`, then `POST /keys/key-<beta CA>/export` with its own passphrase returned beta's root CA key as a backup PEM. Delete is blocked by KeyInUseByCA; export is not. The global `ssh-ca` key is exportable the same way.
Preconditions: MULTI_TENANCY on; pki-admin in any tenant; key dual control off (the default). Yields: another tenant's CA private key; the shared SSH CA key.
Fix: map key to CA and apply caVisibleToTenant; restrict unmapped/global keys (ssh-ca) to unscoped super-admins. (Overlaps A01-006 in the focused pass, which showed the listing; this pass completed the export.)

**A01S-4 (HIGH, REAL, live for pki-operator; jwt/oidc part code-traced): SSH certificates have no principal or template policy.**
`internal/bootstrap/handlers_ssh_certs.go:150-156,251-257`. Any `principals` list is signed; FR-P70 says SSH certs are issued against a template. A pki-operator got a user cert for `["root","admin"]` (201). The SSH CA is one global signer, so a tenant-A cert is trusted wherever tenant B trusts it. In AUTH_MODE=jwt/oidc every valid token is a service-account, which holds certificate.issue, so any IdP user for the hub's audience could mint root SSH certificates (worse with an empty audience: see A02-4 in the A02/A07 supplement).
Fix: per-role or per-template allowed principals and host patterns enforced in the handler; do not give jwt/oidc tokens an issuing role by default.

**A01S-6 (MEDIUM, REAL, DELETE only): the user directory is shared across tenants.**
`handlers_users.go:90-135`; user records carry no tenant. acme-admin listed and deleted a pki-admin invited into beta. Fix: tenant on user records; scope list/patch/delete.

**A01S-7 (LOW, not exploitable today): the write gate matches the decoded path while the mux routes on the escaped one.**
`authz_write_gate.go:128-149,252-258`. With acme-op, `DELETE /api/v1/keys/somekey` was refused by the gate (key.manage), but `DELETE /api/v1/keys/byok/%2e%2e/somekey` and `/keys/byok/..%2Fsomekey` matched `keys/byok/**` (action.approve), passed the gate, and were stopped only by the handler's admin check. Today only keys/byok sits inside a broader subtree, and that handler re-checks.
Fix: under /api/v1, reject requests whose RawPath or segments contain `.`, `..` or an encoded `/`, or match the gate on the cleaned escaped path.

**A01S-8 (LOW, by design): the MCP HTTP transport has no authentication** (separate binary, default 127.0.0.1:8080, refuses approver-capable tokens at boot). Same as LLM-004.

## Shared with the focused pass

- A01S-1 tenant admin mints API keys in any tenant = A01-001 (focused pass: CRITICAL; this pass: HIGH). Also: GET/DELETE /api-keys are not tenant-filtered.
- A01S-2 approval executes against other tenants' certificates and CAs = A01-002. This pass also proved cross-tenant **issue** (an attacker CSR issued from beta's CA and template), not only revoke.
- A01S-5 cross-tenant reads via /search, /cbom, /audit = A01-004/A01-005, plus **GET /ssh/certificates** ignores its tenant column.

## SEMGREP resolutions (agrees with the focused pass)

SEMGREP-008 FP (every method switch defaults to 405; no GET handler writes; custom methods never write). SEMGREP-009 mostly FP, residual is A01S-7. SEMGREP-011 FP as a default (enrollment closed unless configured; an enabled agent is confined to its own rows).

Confidence reported: A01 7/10. Not covered: per-id tenant probes on credentials, connectors, notifications, targets, inventory sources, SCEP challenges; jwt/oidc live; MCP tool surface; delivery-plugins/config/ceremonies/nhi handler bodies; team_id ownership checks.
