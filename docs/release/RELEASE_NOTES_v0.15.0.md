# Kryptkeeper v0.15.0

This release makes renewal and delivery explicit and survivable: certificates
renew only onto targets an operator bound to them, failed renewals land in a
durable queue you can retry, renewals are throttled per connector and drain on
shutdown, ACME gains dns-01 for the major DNS providers and fleet http-01,
DigiCert, SCEP, EST and WSTEP become hub connector types, Tomcat joins the
SSH install modes, ssh-mode groups roll out cluster-atomically, and seven
delivery plugins cover secret stores and cloud load balancers and CDNs. It is
feature group W27 of the v1.0 release train.

## Upgrade notes (read first)

- **Auto-renew now follows bindings, not host names.** A certificate is
  renewed only onto targets bound to it (`POST /targets/{id}/bindings`).
  The first renewal sweep after upgrade runs a one-time backfill that turns
  every existing CN/SAN-equals-host match into a binding (source `backfill`;
  migration 000200 adds the table), so renewals
  that worked before keep working. After the upgrade, a certificate whose
  CN/SAN matches a target host but has no binding is **no longer
  auto-renewed**; the skip reason is logged. Delete a backfilled binding and
  it stays deleted (the backfill never runs twice). Bind new pairs in the
  target wizard or through the API.
- **Credentialed upstream connectors require https.** DigiCert, EST and WSTEP
  refuse a plain `http` URL, because the API key or Basic credential would
  cross the wire in clear. SCEP carries no credential and still accepts
  `http`.
- **Bulk takeover is all-or-nothing and capped at 500.** `POST
  /estate/takeover` now rejects the whole call with 400 (nothing changed) on
  an empty or oversized list, a bad `renewal_path` or an unknown connector.
  Already-managed and other-tenant rows are skipped with a reason. Takeover
  stays audit-only (D-127).
- **Retry and backoff are configurable.** Failed scheduled renewals back off
  from 5 minutes up to a 6 hour cap. Tune with `renewal_policy.retry_base_minutes`
  and `renewal_policy.retry_cap_hours` (env `RENEWAL_RETRY_BASE_MINUTES`,
  `RENEWAL_RETRY_CAP_HOURS`).
- **New environment variables:** `KRYPTKEEPER_RENEWAL_WORKERS` (sweep worker
  pool, default 16), `KRYPTKEEPER_CONNECTOR_MAX_CONCURRENT` (per-connector
  cap, default 10), `KRYPTKEEPER_CONNECTOR_MIN_BACKOFF` (floor of the post-429
  backoff, default 30s), `KRYPTKEEPER_SHUTDOWN_DRAIN` (how long a stop waits
  for running renewals, default 8s), and `RENEWAL_TICK_JITTER_PERCENT`
  (default 10, 0 disables).
- **`POST /renewal/execute` answers differently.** A team- or tenant-forbidden
  certificate is now 403 (it was 503 "certificate unavailable"). A
  rate-limited connector is now 429 with `Retry-After`. A certificate that
  already has a successor is 409 with `successor_fingerprint`; roll that
  certificate out instead of renewing again. `install_detail` is redacted and
  capped at 1 KB.
- **New dependency:** `keystore-go` v4.5.0 (Tomcat keystores). Dev-only:
  `axe-core` 4.10.3 (shared with v0.14) for UI accessibility tests.
- **Agent upgrades** use your package manager, MSI, configuration management
  or image replacement; self-update is descoped (D-128). See the agent
  upgrade runbook in `packaging/README.md`.
- Migrations 000200-000203 and 000205 run on upgrade (both engines).

## New

- **Cert-to-target bindings:** explicit bindings drive auto-renew, so a
  wildcard or multi-SAN certificate bound to three targets renews to exactly
  those three. Create and delete are audited.
- **Fleet target groups:** a renewal threshold set on a group is inherited by
  its targets; the effective threshold shows on Renewal Policy.
- **Durable failure queue:** execute failures and notification dead letters
  are stored in the database (migration 000202) and survive restarts.
  `POST /renewal/retry` re-runs one now; the Automation page lists the queue
  with Retry, queue depth and ETA.
- **Throttling and scale:** per-connector concurrency cap, `Retry-After`
  handling, a connector-wide hold on a 429 that parks sibling orders, a worker
  pool for the sweep, deterministic per-certificate jitter and queue metrics.
  A stop now drains running renewals.
- **ACME dns-01:** Route53, Azure DNS, GCP DNS, RFC 2136 (TSIG) and
  acme-dns style CNAME delegation. **Fleet http-01:** a responder on target
  hosts. ACME order and authorization status are logged.
- **DCV tracker:** per-domain validation expiry, a reuse schedule and a
  warning event (migration 000203), with a panel showing days remaining.
- **Upstream connector types:** `digicert`, `scep`, `est` and `wstep` can be
  created through `/connectors` (migration 000205), imported and used for
  `renewal/execute`.
- **Tomcat installer:** builds a JKS or PKCS#12 keystore, swaps it, restarts
  and rolls back on failure.
- **Staged install and rollout groups:** ssh-mode nginx, Apache and HAProxy
  groups stage on every node before any flips; any failure returns all nodes
  to the old certificate (cluster-atomic). Canary, UTC window and per-node
  outcomes on a new Rollout Groups page. Other modes stay
  canary-then-sequential.
- **Delivery plugins:** HashiCorp Vault KV, Azure Key Vault, GCP Secret
  Manager, AWS (Secrets Manager; ACM import for ALB and CloudFront), Azure
  (Application Gateway and Front Door) and Cloudflare custom certificates.
  Plugin catalogue and an External Secrets Operator guide are in the docs.
- **Store read-back verification:** a secret-store plugin declaring
  `"verification": "readback"` is verified by the hub fingerprinting the PEM
  the store returns; a mismatch rolls back like a TLS mismatch.
- **`verify_propagation_seconds`** in a plugin manifest (0 to 1800) extends
  verification for CDNs that take minutes to serve the new certificate.
- **Estate:** bulk takeover with per-certificate owner suggestions
  (`GET /estate/takeover/suggestions`) and a Set up target hand-off on
  Discovery.
- **UI:** Rollout Groups, DCV panel, Automation failure queue, certificate
  bindings in the target wizard, groups and effective threshold on Renewal
  Policy.
- **Docs:** decisions D-127 and D-128, the agent upgrade runbook, and a
  corrected F4 in the pilot known gaps (the sweep covers ssh, keychain, f5,
  citrix, k8s, iis and plugin modes).

## Fixed

- ACME finalize no longer fails when the CA omits the order `Location`
  header.
- The EST client request body now ends with a newline; libest answered 400 to
  a single-line body without one.
- `renewal/execute` returned 503 for a team- or tenant-forbidden certificate;
  it returns 403.
- Long plugin verify windows no longer exceed the renewal execution budget or
  the rollout request deadline.

## Proven live (records in `docs/release/LIVE_RESULTS_*_v0.15.md`)

Index: `docs/release/LIVE_RESULTS_v0.15.md`. Rollout groups on three real
nginx nodes: 3 of 3 cases passed, including a node-3 flip failure that left
all three serving the old certificate. SSH install against nginx, Apache,
HAProxy and Tomcat: 43 checks passed, including config-test rollback with the
file restored byte for byte. Scheduler-driven renewal: plugin mode (15/15),
Kubernetes on kind (16/16) and a policy threshold change picked up on the next
tick (14/14). Upstream renewal against independent servers: SCEP (micromdm
scep v2.3.0) and EST (Cisco libest r3.2.0) renewed through the hub and nginx
served the new certificate. ACME dns-01 RFC 2136, a wildcard order and a
170 s wait against a local BIND and Pebble. The Vault delivery plugin
against a local Vault, including a forced failure that rolled back.
2,000-certificate renewal storm against a rate-limited stub CA: all 2,000
renewed before expiry with 0 duplicates and 0 late violations in the
uninterrupted and graceful-restart legs.

## Known gaps

- **Renewal storm: PARTIAL.** The strict zero-violation check fails (22
  violations uninterrupted, 105 with a graceful restart): up to 10 sibling
  orders are already on the wire when one draws a 429. Follow-up W27-39
  (rolling-window issuance budget) is unscheduled.
- Not yet run by a human: IIS (no Windows lab host), WSTEP against AD CS,
  DigiCert against a CertCentral sandbox, the cloud delivery plugins (AWS,
  Azure, GCP, Cloudflare) and the Route53, Azure, GCP, RFC 2136 and
  CNAME-delegation DNS legs against Let's Encrypt staging. Each record marks
  these PENDING-RUN or NOT RUN. The delivery plugins are not verified on real
  provider accounts.
- Azure Application Gateway: PEM versus PFX delivery is an open risk until
  the live leg runs. Front Door has no EC support in the plugin.
- Delivery plugins do not delete old ACM certificates or old Key Vault
  versions.
- The connector throttle (`DefaultThrottle`) is package-level, shared by all
  registries in a process.
- The acme-dns TXT record is not removed after validation.
- Tomcat `configtest` failures put the full stack trace (about 4 KB) in the
  install detail before the 1 KB cap trims it.
