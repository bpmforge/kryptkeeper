# Kryptkeeper 1.0.0

Kryptkeeper 1.0.0 is the first stable release: a self-hosted machine-identity and
certificate-lifecycle hub with its own CAs, ACME, EST, SCEP, CMP and Windows (XCEP/WSTEP)
enrollment, agent and agentless discovery and renewal, and a review-gated MCP server.
Everything listed below was proven on the 1.0.0 lab pass; see
[LIVE_RESULTS_v1.0.0.md](LIVE_RESULTS_v1.0.0.md). What 1.0.0 deliberately does not do yet
is on the public [roadmap](../ROADMAP.md).

## New since 0.21.0

- **Discovery fingerprinting and install posture (W34).** Every discovered endpoint carries
  a fingerprinted technology with a confidence and evidence; certificates are classified
  managed, ours-unmanaged, authorized external, unknown issuer or self-signed, with an
  "Authorize this issuer" action. Non-standard installs are reported (privileged install
  path, service running as root, world-readable key, per-file accepted risk).
- **Privileged agentless Linux scans (W34).** SSH discovery, preflight and renewals run
  through one privilege layer: no sudo, passwordless sudo, sudo with a just-in-time
  password (never stored), or a hash-pinned helper.
- **Windows enroll lists are enforced (D-291).** WSTEP and XCEP now honour every template's
  enroll list, like EST, SCEP and ACME. A one-time upgrade keeps autoenrolled Windows
  templates working and logs any template that is now refused.
- **Approver role (decision of 2026-10-18).** The built-in approver role sees and decides
  certificate requests on templates whose approval roles name it; key and CA approvals stay
  with pki-admin and pki-operator.
- **Graceful shutdown.** On SIGTERM the hub reports not-ready, keeps serving for
  `KRYPTKEEPER_READINESS_DRAIN_SECONDS` (chart default 5), hands back its scheduler leases at
  once, then shuts down. The Helm chart sets a matching termination grace period.

## Fixed

- GPO machine autoenrollment was refused since 0.10: XCEP advertised 2048-bit keys under
  the Baseline 3072-bit policy, and ignored templates that allow an algorithm family. XCEP
  now advertises a key size the policy accepts; refusals carry the reason and are audited.
- Agentless Windows (WinRM) discovery and IIS installs failed on every host because of two
  argument-encoding bugs; arguments with quotes or line breaks are now refused before use.
- A hub on Postgres opened about 122 connections at start and silently ran some stores in
  memory; stores now share pools (about 40 connections).
- Agent, break-glass and access-review stores no longer fall back to memory when their
  database is down; they answer 503 and report not-ready (D-290). An invalid
  `APPROVAL_QUORUM_POLICY` now stops startup.
- A SQLite deadlock between inventory refresh and writes, and a refresh that could undo a
  takeover in memory, are fixed.
- Key operations answered 403 and leaked database details when the key-policy store was
  down; they now answer 503.
- The Windows agent now inventories `LocalMachine\My` and scans common Windows certificate
  folders by default; the Linux agent again discovers JKS, PKCS#12 and kubeconfig stores.
- ADCS migrations can no longer overwrite hub-native or admin-disabled templates, rollback
  restores the template exactly, and CA-infrastructure templates (OCSP signing, enrollment
  agent, key recovery) are never offered to workstations.
- Revoking a certificate that no hub CA issued now records it as revoked in inventory and
  says so (`revocation_scope: inventory_only`).
- File stores now default under `KRYPTKEEPER_DATA_DIR`; an existing `./var` file is still
  used, with a startup warning.
- About 25 UI issues from the user-guide screenshot tour (dialogs that did not fit the
  screen, unlabelled controls, raw timestamps and config keys, wrong credential types in
  the setup wizard, and more).

## Upgrade notes

- Windows: after upgrading, clear the client's enrollment policy cache
  (`certutil -f -PolicyServer * -PolicyCache delete`) or wait for it to expire so clients
  pick up the new key size. Templates whose enroll list names only API roles are now refused
  over WSTEP; add `protocol:wstep` if Windows should enroll.
- Postgres: no action. Two replicas now fit Postgres's default `max_connections=100`.
- Stores that silently ran in memory before now refuse until their database opens; set
  `APP_AGENT_STORE_PROVIDER`, `APP_BREAKGLASS_PROVIDER` or `APP_ACCESS_REVIEW_PROVIDER` to
  `memory` only if you want that explicitly.
- Migrations 000325, 000326 and 000340-000348 run automatically.

## Known limitations

See the [roadmap](../ROADMAP.md). Highlights: no install modes for SQL Server, Exchange
or RDP yet; F5, Citrix and real cloud KMS are proven against emulators only; a hub that
restarts while a CA is rate limiting it may send a few early requests.
