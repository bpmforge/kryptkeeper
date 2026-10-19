# Kryptkeeper v0.10.0

This release makes multi-tenancy a real isolation boundary and adds the
governance layer: approvals with quorum, expiry and delegation; issuance
policy administration; risk exceptions; ownership tracking; access reviews;
and break-glass accounts. It is feature group W22 of the v1.0 release train.

## Upgrade notes (read first)

- **Baseline issuance policy.** If your hub has no issuance policy, the
  upgrade creates `pol-baseline`: RSA below 3072 bits is refused, leaf
  validity is capped at 398 days, and CA certificates cannot be issued
  through the leaf path. ACME clients now get `badCSR` and EST clients a 403
  naming the policy and rule. To opt out, disable or delete `pol-baseline`.
- **Unmapped SSO users are denied.** An OIDC/SAML user whose groups map to no
  role now gets 403 instead of silently becoming a read-only viewer; bearer
  tokens with no mapping get 401. Set `APP_AUTH_UNMAPPED_ROLE=read-only` to
  keep the old behaviour. `APP_SCIM_DEFAULT_ROLE` no longer defaults to
  `pki-viewer`.
- **Refresh tokens expire when idle** after `APP_AUTH_IDLE_TIMEOUT_SEC`
  (default 1800).
- **Multi-tenancy no longer needs the acknowledgement.**
  `KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk` is no longer required.
  `KRYPTKEEPER_MULTI_TENANCY_GATE=enforce` restores the v0.9 refusal.
- **Audit CSV export columns changed:** a `tenant` column is added and
  `resource_name` is removed.
- Migrations 000080-000099 run on upgrade (both engines). Migration 000090
  drops the legacy `users.role` CHECK; rolling it back maps roles outside the
  old set to `pki-viewer`.

## Tenant isolation

- All 21 cross-tenant leaks found by the v0.9.3 live validation are fixed,
  each with a named regression test (`TestLeakL*`). Users and custom roles
  carry a tenant; audit rows take the tenant from the authenticated
  principal; instance-wide settings are platform super-admin only while
  multi-tenancy is on.
- `bash scripts/test/run.sh --suite tenant-idor` replays every OpenAPI route
  as four roles of one tenant against another tenant's data, on SQLite and
  PostgreSQL. It reports 0 leaks for this release. Its limits are listed in
  `docs/release/MULTI_TENANCY_GATE_DECISION.md`.
- Enforced boundary and remaining limits: `docs/design/TENANCY_POSTURE.md`.

## Governance

- **Approvals:** auto-reject after `APPROVAL_TTL_HOURS` (default 72); n-of-m
  quorum per action type via `APPROVAL_QUORUM_POLICY`; dated delegation (max
  30 days); one approvals inbox (`/inbox`) for certificate approvals and
  pending actions.
- **Issuance policy:** `/api/v1/policies` with dry-run and a Policies page;
  loosening needs a second approver, tightening applies at once; version
  history and revert.
- **Risk exceptions:** accept-risk on Discovery and Crypto Posture findings,
  behind the approval queue, tenant scoped, with expiry warnings and
  auto-reopen; accepted risks appear in compliance evidence packs; a
  five-stage finding funnel with persistent finding identity.
- **Ownership:** ownership source, an unowned filter and dashboard card, CMDB
  ownership import, and orphaned-owner detection with bulk reassignment.
- **Access governance:** API key last-used time, an access review report,
  recertification campaigns with a signed close, a Roles page with SoD checks
  and SSO role-map preview.
- **Break-glass:** two-person activation, 4-hour windows, alert and review
  task on every use, local login while the IdP is down, and a quorum override
  for actions whose quorum can no longer be met.

## Audit

- `kryptkeeper-audit-verify` checks audit records and checkpoints offline;
  the transparency signing seed is auto-provisioned.
- Streamed, tenant-scoped audit export (CSV/JSON).
- Retention archive under dual control: rows are written to a signed,
  hash-chained archive before they are deleted. After an archive the live
  transparency log restarts over the remaining rows; the archive checkpoint
  is the trust anchor for the archived prefix.

## Hardening

- Per-credential protocol rate limits (ACME account, EST user) with
  configurable defaults. A credential is keyed before its signature is
  checked, so a known account id can exhaust that account's budget.
- Egress lint: user-supplied URLs must go through `internal/egress`.
- `docs/security/SECURITY_CLAIMS.md` lists each claim with its knob and the
  test that proves it.

## Validated live

- Keycloak OIDC and SAML login with group mapping, and SCIM create then
  deactivate: 39/39 (`tests/live/sso`). IdP TLS verification was not
  exercised (Keycloak on loopback HTTP).
- SIEM: Elasticsearch and syslog-ng (JSON and CEF over RFC 5424): 14/14
  (`tests/live/siem`). Splunk HEC was not exercised.
- ACME and EST clients receive the policy refusal text
  (`tests/live/protocols/policy-refusal`).
- Okta and Entra ID recipes are documented; their UAT rows are pending a
  human run (`docs/release/SSO_UAT_RECORD.md`). Entra over OIDC needs
  `email_verified`, which Entra does not send by default; use SAML.
