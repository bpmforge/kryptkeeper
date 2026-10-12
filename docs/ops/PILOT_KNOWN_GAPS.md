# Pilot known gaps — honest disclosure

Companion to `PILOT_RUNBOOK.md`. Give this to a design partner **before** the
pilot, not after they hit one of these.

Two sections, and the split is the point:

- **Facts** — verified against the code, the board, or an executed run. Each
  carries its evidence (`file:line`, ticket id, or runbook).
- **Hypotheses** — believed but **not** verified here. Each states what would
  confirm or refute it. Nothing in this section may be relied on.

---

# Facts

## F1. Windows support is partial, and the boundary is sharp

Windows targets are reachable end to end over WinRM with an IIS installer
(W18-01/02/03 done, board `docs/board/plan.json`). What is **not** done:

| Ticket | State | What it means for a pilot |
|---|---|---|
| W18-06 WinRM over HTTPS | **done (2026-09-10)** | Live acceptance passed against a real Windows 11 host as a standard local user with `AllowUnencrypted=false`: agentless WinRM discovery over the verified HTTPS listener enumerated 28 certs; an IIS install as that user correctly failed as "authenticated but not a local Administrator" rather than a false success. Gated live suite `internal/agentdiscovery/live_winrm_test.go` (`KK_LIVE_WINRM=1`), 5/5 green. Enablement steps: `docs/ops/WINRM_ENABLEMENT.md`. |
| W18-07 Windows agent MSI | **done (2026-10-06)** | `make agent-windows-msi` builds an MSI that installs an auto-start service; verified end to end on a domain-joined Windows 11 Enterprise VM against a hub with closed enrollment: install, self-registration with `KRYPTKEEPER_AGENT_ENROLLMENT_SECRET`, reboot survival, prompt stop, a bad `agent.env` reported in Event Viewer, clean uninstall. Runbook: `docs/ops/WINDOWS_AGENT.md`. Still not code-signed (SmartScreen warns) and runs as LocalSystem. |
| W18-08 WSTEP autoenrollment | **GPO autoenrollment and renewal proven on the lab domain (machine context)** | Until 2026-10-06 MS-WSTEP/XCEP authenticated nobody; any caller could obtain a 1-year client-auth certificate for any subject. W20-08 (D-109) replaces that: enrollment and policy need a Kerberos ticket for the hub's SPN (keytab + SPN configured, otherwise the endpoints are not served), renewal needs a client certificate the hub issued, and the certificate subject comes from the authenticated identity, never the CSR. The unauthenticated lab override is deleted. A live Kerberos enrollment by a domain machine passed on the UAT lab on 2026-10-07 (see STATUS). GPO-driven machine autoenrollment and autoenrollment renewal passed on the same lab on 2026-10-07 (W18-08, runbook in `docs/ops/WSTEP_AUTOENROLLMENT.md`). Not yet proven: user-context autoenrollment, time-based renewal, and template policy enforcement on WSTEP (W20-09). Do not promise ADCS replacement in a pilot. |
| W20-14 EST enrollment | **authenticated (HTTP Basic or client certificate), off until configured** | Until 2026-10-07 EST authenticated nobody. Enrollment now needs HTTP Basic over TLS (per-user DNS suffixes) or a TLS client certificate from a configured anchor; re-enrollment needs the hub-issued certificate (D-112, runbook `docs/ops/EST_AUTH.md`). With no credential type configured, enrollment is refused; `cacerts`/`csrattrs` are still served. Not checked: revocation of client certificates from an external anchor. |
| W18-09 NTLM message encryption | **done (2026-10-06)** | Plain-HTTP WinRM (5985) with NTLM message sealing verified against real listeners on their defaults (`AllowUnencrypted=false`): Windows Server 2025 and Windows 11 Enterprise, both build 26100. Gated live test `internal/agentdiscovery/live_winrm_sealed_test.go` (`KK_LIVE_WINRM_HTTP=1`). Prefer HTTPS; see `docs/ops/WINRM_ENABLEMENT.md`. |
| W18-11 credential preflight | **done (2026-09-10)** | `POST /api/v1/credentials/{id}/preflight` opens one WinRM session and classifies a credential as unreachable/unauthenticated/no_shell/discover/install without changing anything on the host. Live-verified (6/6 live green); no UI button calls it yet (Credentials page follow-up). |

As of 2026-09-10 the install path itself is also proven live (W18-13): as a
local Administrator, the hub imported a renewed cert into IIS, rebound the
site, and verified it was serving — the full discover→issue→renew→install→
verify loop closed end to end against the lab host. What remains open per the
table above: agent MSI packaging (W18-07), WSTEP against a real domain-joined
client (W18-08), and NTLM message encryption for hosts with no HTTPS listener
(W18-09).

Source: `docs/ops/WINDOWS_ACCESS_MATRIX.md`, `docs/STATUS.md` 2026-08-20 →
2026-09-10.

## F2. Agentless Windows/IIS needs local Administrator, and Basic-over-HTTP is lab-only

Established by live capture against the internal Windows host (W18-10, closed
2026-08-27): **discovery works under a standard user; install requires a local
Administrator.** A failure for want of elevation is now reported as
insufficient privilege naming the operation, distinct from a bad credential.

The WinRM client speaks **HTTP Basic only**. Against a stock Windows listener
that is insufficient twice over: a default listener offers `Negotiate`, not
`Basic` (401 before anything happens), and `AllowUnencrypted=false` is a
*message-layer* requirement that rejects an unencrypted SOAP body even after
auth succeeds. Both are satisfied at once by **HTTPS on 5986** — which is
exactly what W18-06 is finishing.

Basic over HTTP with `AllowUnencrypted=true` sends the password in base64
cleartext and requires disabling two hardening defaults. **Lab only. Never
production.** CredSSP is declined outright — it delegates full credentials to
the remote host, unacceptable in a PKI product.
(`docs/ops/WINDOWS_ACCESS_MATRIX.md`.)

## F3. macOS is blocked, and the agent-mode wizard still offers it

W18-05 (macOS agentless Keychain install) is **blocked** on the board. There
is no macOS install code at all.

The wizard is *half* corrected. The **agentless** branch deliberately offers
only Linux and Windows — `type TargetOS = "linux" | "windows"`
(`ui/src/pages/TargetSetup.tsx:38`), with the reasoning stated in the comment
above it. The **agent** branch still lists macOS in its type picker
(`ui/src/pages/TargetSetup.tsx:22`), softened by inline copy reading "macOS is
agent-only for now — there is no agentless installer for it yet"
(`:552`). What actually exists behind that choice: generic POSIX filesystem
discovery (`internal/agentdiscovery/walk_other.go`) — **no Keychain read, no
Keychain install, and no shipped macOS agent artifact** (F1/W18-07). A
partner with a Mac fleet will find the picker promises more than the product
does.

## F4. The renewal *sweep* is SSH-only; the *push machinery* is not

Distinguish these or you will mis-set expectations both ways.

- The renewal **executor** can push to `f5`, `citrix`, `k8s` and `iis`
  (`internal/bootstrap/renewal_executor.go:150,523-575`).
- The scheduled **sweep** only *executes* a target that is
  `AutoRenew && InstallMode == "ssh" && CredentialRef != ""` with a complete
  install profile (`internal/bootstrap/renewal_scheduler.go:521`). Everything
  else — including every Windows/IIS target — is **notify-only**.

The wizard states this in the UI (`ui/src/pages/TargetSetup.tsx:713`) and the
API contract states it on the `auto_renew` field. Net effect for a pilot:
**unattended renewal is a Linux/SSH story today.**

## F5. Documentation drift you will hit on day one

All verified in this tree:

| Drift | Reality |
|---|---|
| `.env.example` | Does not exist. The file is **`env.example`** (no leading dot). |
| README: "bootstrap token printed to kryptkeeper container logs on first start" | False. Compose **hard-requires** it (`docker-compose.yml`: `${APP_BOOTSTRAP_TOKEN:?set APP_BOOTSTRAP_TOKEN}`) and the app only warns when it is missing (`internal/bootstrap/auth_config.go:254`). You set it; nothing generates it. |
| README config table: `APP_BOOTSTRAP_TOKEN` "generated if empty" | Same contradiction. Not generated. |
| README: "edit `POSTGRES_PASSWORD` … at minimum" | Compose does **not** start Postgres by default. `docker-compose.override.yml`'s `postgres` service sits behind an inactive profile; a plain `docker compose up` ignores the file entirely and stays on SQLite. |
| README config table: `APP_JWT_SECRET`, `APP_AUTH_MODE`, `KRYPTKEEPER_POSTGRES_DSN`, `APP_KEYSTORE_TYPE` | **No occurrence of any of these in the Go source.** The real names are `APP_JWT_HS256_SECRET`, `AUTH_MODE`, `DATABASE_URL`/`KRYPTKEEPER_DB_DSN`, `KRYPTKEEPER_KEY_BACKEND` (`env.example` is the accurate surface). |
| README first-run: `POST /api/v1/certificates` with `subject`/`sans` | The contract requires `ca_id`, `template_id`, `csr_pem` (`docs/openapi.yaml` `POST /certificates`). Issuance is CSR-in; there is no server-side subject-key generation. |
| README first-run: `POST /api/v1/cas` with `validity_str` | The spec's schema is `name`/`type`/`algorithm`/`subject_cn`, required `subject_cn` only. |

`PILOT_RUNBOOK.md` uses the verified shapes throughout. Treat the README's
Quick Start as stale until it is corrected.

## F6. SQLite pilots have no scripted database backup

`scripts/deploy/backup.sh` hard-requires `DATABASE_URL` and `pg_dump`; the
DR/restore drills were executed against Postgres and SQLite.
`docs/ops/DR_RUNBOOK.md` states plainly: **"Sqlite-mode deployments have no
DB-backup path today."** The keystore can still be exported via
`POST /api/v1/admin/backup`; the database file needs an ad-hoc file copy.
`PILOT_RUNBOOK.md` §7 gives the volume-tar procedure that fills the gap.

Also inherited from those drills: restore ordering is load-bearing (restore
into a database **no hub has ever booted against**), and `pg_dump`/`psql`
client major version must match the server — a mismatch aborts the restore.

## F7. Multi-tenancy is off by default

`MULTI_TENANCY=false` (`env.example`). A single-operator pilot is
single-tenant. Do not scope a pilot around tenant isolation; current
enforcement scope is `docs/design/TENANCY_POSTURE.md`.

## F8. The keystore passphrase defaults to the bootstrap token

`docker-compose.yml`:
`KRYPTKEEPER_KEYSTORE_PASSPHRASE: ${KRYPTKEEPER_KEYSTORE_PASSPHRASE:-${APP_BOOTSTRAP_TOKEN}}`.
Leaving it unset silently couples key encryption to the admin token; rotating
the token afterwards leaves an undecryptable keystore. Set both explicitly
before first boot (`PILOT_RUNBOOK.md` §2).

---


## F9. Compose+SQLite requires a pure-Go sqlite driver (fixed)

**Was (E1b 2026-09-09):** the container image built with `CGO_ENABLED=0` while
`go.mod` pulled in `github.com/mattn/go-sqlite3`. At runtime the driver is a
stub (`core DB unavailable`) and the API never becomes healthy on the default
Compose+SQLite path.

**Fix:** sqlite opens now use `modernc.org/sqlite` (pure Go, driver name
`sqlite`) so `CGO_ENABLED=0` + distroless remains valid. Default
`TARGETARCH` in the Dockerfile is `arm64` for Apple Silicon local builds;
override for amd64 CI as needed.

**Still true:** Postgres profile remains available via
`docker-compose.override.yml` profile `postgres`. Day-one root CA creation
needs `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true` passed into the container
(now wired in `docker-compose.yml`).



## F10. Day-one templates need a writable APP_TEMPLATE_FILE (fixed in compose)

**Was (E1e 2026-09-09):** container is `read_only` and the default template path
`./var/bootstrap-templates.json` is not writable, so `POST /api/v1/templates`
returned 503 (`template unavailable`) and issuance could not start (OpenAPI
requires `template_id`).

**Fix:** `docker-compose.yml` defaults `APP_TEMPLATE_FILE` to
`/var/kryptkeeper/data/templates.json` (on the `appdata` volume).

**Still true:** runbook §5b should create a template before first issue if the
file is empty. Prefer `openssl … -pkeyopt ec_param_enc:named_curve` (or RSA
with `RSA-2048` in `allowed_algorithms`); explicit-curve EC CSRs were rejected
as `invalid request body` in this session.

# Hypotheses

Not verified in this session. Each is labelled with what would settle it.

## H1. Published container images on GHCR

**Claim:** `ghcr.io/bpmforge/kryptkeeper` is a pullable image, so a partner
could skip the source build.

**On-disk evidence, both directions:** `.github/workflows/release.yml`,
`release-candidate.yml` and `promote-by-digest.yml` exist;
`charts/kryptkeeper/values.yaml:4` and `charts/kryptkeeper-certmanager-issuer/values.yaml:5`
default to `ghcr.io/bpmforge/*`; `docs/ops/AIRGAP_INSTALL.md` and
`deploy/terraform/README.md` document pulling it. Against: CI runner
registration (W0-06) is **done** on the board, but the Terraform registry
publish (S-04) remains **blocked**, and no evidence in this tree shows those
workflows have ever produced a published tag. *(Premise refresh: E1 dry-run
2026-09-09.)*

**Confirm/refute:** `docker pull ghcr.io/bpmforge/kryptkeeper:<tag>` from a
clean host, or `gh api /users/bpmforge/packages?package_type=container`. Until then the pilot builds
from source — which is why `PILOT_RUNBOOK.md` is written that way.

## H2. Supply-chain attestation and image signing

**Claim:** release images are signed and carry provenance/SBOM attestation.

**Evidence:** `packaging/SIGNING.md` describes signing
`ghcr.io/bpmforge/kryptkeeper` two ways and notes that images pulled other
than from a tagged release **lose Sigstore/Rekor** coverage.

**Confirm/refute:** `cosign verify` against a real published tag. Depends
entirely on H1 — an unpublished image cannot be a signed one. **A pilot image
built locally from tarball is unsigned by construction.** Say so rather than
implying supply-chain guarantees the pilot does not have.

## H3. Helm/Kubernetes as a viable partner path

**Claim:** a partner could deploy via the chart instead of Compose.

**Evidence:** `charts/kryptkeeper/` is complete (deployment, ingress, HPA,
PDB, NetworkPolicy, ServiceMonitor, ExternalSecret) and was rewritten against
its real values schema under W10-05. But it pulls the image from H1, `Chart.yaml`
declares **no bundled Postgres** (BYO), and `replicaCount` stays `1` by chart
default. Board item W6-01 (HA / scheduler leases) is **done**, so the older
"unsafe until W6-01" premise is stale — raise-replicas still needs a real
multi-node soak before a partner trusts it. *(Premise refresh: E1 dry-run
2026-09-09.)*

**Confirm/refute:** `helm install` against a real cluster with a resolvable
image and an external Postgres. Out of scope for a single-operator pilot;
`PILOT_RUNBOOK.md` deliberately does not offer it.

## H4. Protocol servers under a real client

**Claim:** ACME, EST, SCEP, OCSP, CRL, CMP work against third-party clients.

**Evidence:** all are implemented and covered by the protocol suite
(`scripts/test/run.sh --suite protocol`). What is *known* unverified is the
Windows pull side (F1/W18-08). For the rest, no evidence here establishes
verification against each vendor client a partner might bring.

**Confirm/refute:** run the partner's actual client (certbot, a specific F5,
a specific switch) against the pilot in week one. Treat any protocol beyond
ACME as unproven-for-their-client until it is.

---

## How to read this document

If a partner's blocking requirement lands in **Facts**, we know the size of
it. If it lands in **Hypotheses**, we do not yet know — and finding out is
work, not configuration. That distinction is kill-criterion **K7** in
`PILOT_RUNBOOK.md` §9.
