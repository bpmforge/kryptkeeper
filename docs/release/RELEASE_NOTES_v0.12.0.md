# Kryptkeeper v0.12.0

This release finishes discovery and inventory: per-target scan schedules,
agentless SSH discovery with pinned host keys, scan-diff alerts, CT findings
you can act on, multi-account cloud and multi-cluster Kubernetes discovery,
bulk takeover of the discovered estate, and template migration from ADCS,
Vault, Venafi, Keyfactor and DigiCert CertCentral. It is feature group W24 of
the v1.0 release train.

## Upgrade notes (read first)

- **First scan comes sooner.** A target that has never been scanned is due on
  the first scheduler tick, about a minute after startup, instead of after a
  full interval. Per-target intervals are set with `PUT /discovery/schedules`.
- **Agent poll default is 60s** (was 300s), below the 5-minute stale
  threshold, so healthy agents no longer flap to "stale". Set
  `KRYPTKEEPER_POLL_INTERVAL` to keep the old value.
- **Agents can be removed.** `DELETE /agents/{id}` (admin only) revokes the
  agent's token. Silent agents are pruned on `GET /agents` only when
  `KRYPTKEEPER_AGENT_PRUNE_AFTER` is set.
- **SSH host keys are pinned.** Targets accept `ssh_host_key`
  (`POST /targets/hostkey` fetches it for confirmation). Renewal and
  discovery refuse a host whose key does not match and audit
  `target.hostkey.mismatch`.
- **The CT monitor always runs.** With no domains it does nothing; domains
  come from `KRYPTKEEPER_CT_DOMAINS` or the `ct.domains` setting. Cert
  Spotter is a second source unless `KRYPTKEEPER_CT_SECOND_SOURCE=off`
  (this sends your monitored domain names to SSLMate). Findings are
  de-duplicated by serial, so crt.sh precert/cert pairs become one finding.
- **New settings** replace env-only configuration: `discovery.cloud_scopes`,
  `discovery.kube_clusters`, `discovery.saas_endpoints`, `ct.domains`.
- **Migration batches are not tenant-scoped yet.** Every authenticated
  principal can list import batches and reports (W24-53 tracks the fix).
- Migrations 000140-000145 run on upgrade (both engines).

## New

- **Discovery schedules:** per-target interval, skip-if-running, last and
  next run in the API and on the Discovery page.
- **Agentless SSH discovery:** an `ssh` scan type for SSH targets, on schedule
  and on demand, reading PEM, DER, JKS, PKCS#12 and PFX files; unreadable paths
  are reported; each certificate keeps its source path.
- **Scan-diff events:** `CERTIFICATE_REPLACED`, `CERTIFICATE_DISAPPEARED` and
  `KEY_DOWNGRADE` from network scans; agents raise `CERTIFICATE_REPLACED` on
  out-of-band changes and `AGENT_STALE`.
- **Protocols:** LDAP StartTLS probe; RDP NLA-only hosts are recorded as
  reachable.
- **Keystores:** JCEKS parsing; BCFKS detected and reported as password
  unknown.
- **CT findings:** list, acknowledge, mark known issuer, and a revoke link for
  certificates our CAs issued; leader-locked across replicas.
- **Cloud and Kubernetes:** fan-out across AWS accounts and regions, Azure
  vaults and GCP projects; cert-manager and mesh discovery across clusters.
- **Estate:** bulk takeover and revert-to-unmanaged, an estate board report
  (`GET /reports/estate`, JSON or PDF), SSH host and user keys in
  `/inventory/keys`, and PQC readiness of keys in the executive summary.
- **Migration:** dry-run diff, approval-gated apply with a batch id and audit,
  and undo that disables (never deletes) what a batch created. Importers for
  ADCS (export or read-only LDAP), Vault PKI roles, Venafi TPP policy trees,
  Keyfactor templates and CertCentral products.
- **UI:** Discovery schedules, host-key confirmation in target setup, CT
  Findings, Settings editors for discovery sources, Inventory Sources,
  bulk takeover and revert on Certificates, and a Migration page.
- `scripts/day-one-estate.sh` with a guide for a first-day estate run.

## Fixed

- GCP CAS and DigiCert inventory sources sent a credential stored as a JSON
  string with its quotes, so every live sync got 401.
- Inventory-source sync takes a per-source HA lease, so replicas no longer
  sync the same source twice.

## Proven live (records in each `tests/live/*` folder)

Seeded TLS corpus 43/43 found (recall 1.0, 0 false positives, /24 in about
85 s); 8/8 mail, database, directory, RDP and SSH protocols; SSH discovery
against nginx, Apache and JKS containers with host-key mismatch refusal;
agent JKS, PKCS#12 and kubeconfig inventory with an out-of-band replacement
alert in 8 s; two kind clusters (51/51); moto ACM and KMS plus Lowkey Vault;
Sectigo, Entrust, AWS PCA and GCP CAS fixtures; 500-certificate bulk import
smoke; 1,000 real inventory imports in 3.2 s (about 32 s projected for
10,000). Measured rates: `docs/release/DISCOVERY_RATES_v0.12.md`.

## Known gaps

- Not yet run by a human: Windows 11 store recall, ADCS against a Windows DC,
  the DigiCert sandbox, CT against a domain we control, the timed clean-VM
  day-one run, mesh discovery with linkerd/istio, and the Windows agent :80
  check. Each record is marked PENDING-RUN.
- Cloud scan results stay in scan summaries and do not reach the certificate
  inventory yet (W24-46).
- Importer field names are taken from vendor documentation and have not been
  checked against real exports.
- Follow-ups W24-45..53 are on the board.
