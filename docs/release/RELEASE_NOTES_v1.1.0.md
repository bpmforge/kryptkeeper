# Kryptkeeper 1.1.0

Kryptkeeper 1.1.0 is the first feature release after 1.0. Its headline is **CA choice**: you can keep the
CA you already use and issue through it from every Kryptkeeper protocol. It also adds a plugin
architecture for integrations, a five-minute trial, Windows service installs, and work ahead of the
standards (PQC delivery, device attestation, trust store push). Lab records are listed at the end;
what 1.1.0 still does not do is on the public [roadmap](../ROADMAP.md).

## Use your existing CA (W36)

- **External CAs.** Add HashiCorp Vault PKI, EJBCA, AWS Private CA, Google Cloud CAS, Sectigo,
  GlobalSign, Entrust, DigiCert or any ACME CA on the new **Issuers** page and create an external CA.
  ACME, EST, SCEP, CMP, Windows autoenrollment, the API, cert-manager and Terraform then issue
  through it, with Kryptkeeper's template policy applied first (D-304, D-305).
- **Every returned certificate is checked.** It must carry the requested key and names, no CA
  powers, no unrequested high-risk usages, and fit the validity cap. It must also chain to the trust
  bundle you supplied. Anything else is rejected and audited.
- **Revocation goes to the issuing CA first** and fails loudly if the CA refuses (D-306).
- **ACME presets** are available for Let's Encrypt, ZeroSSL, Google Trust Services, SSL.com,
  Sectigo and Buypass. Every built-in DNS-01 provider is now offered in the wizard.
- Proven live against Vault 1.18 and EJBCA CE 9.3, plus AWS Private CA on an emulator.

## Easy to adopt (W37)

- **Five-minute trial:** `docker compose -f deploy/try/compose.yaml up` starts a hub with labelled
  demo data, a demo banner and reset. `kryptkeeper demo seed` does the same for any empty,
  non-production hub. Helm demo values are included.
- **Signed Helm chart in ghcr** (`oci://ghcr.io/bpmforge/charts/kryptkeeper`).
- **Self-verifying releases:** every release now verifies what it published (D-309, D-312).
- **Ansible collection** `kryptkeeper.pki` with idempotent certificate, certificate_info and agent
  modules.

## Integrations on a plugin architecture (W38)

- **Plugin kinds (D-320, D-321):** signed WASM plugins now cover alerts (`notify`), ITSM
  (`ticket`), ACME DNS-01 (`dns01`) and credential sources (`credentials`), as well as delivery.
- **New plugins:**
  - Alerts: Microsoft Teams, PagerDuty, Opsgenie.
  - Tickets: Zendesk, Freshservice.
  - DNS-01: DigitalOcean, GoDaddy, NS1, Akamai.
  - Credentials: CyberArk CCP, Delinea Secret Server.
- **Signed plugin catalogue:** install plugins from kryptkeeper.io or offline, through the same
  checks and approvals as an upload (D-328).
- **Credential sources:** SSH, WinRM and device credentials can be fetched at use time from
  HashiCorp Vault or OpenBao (built in) instead of being stored in the hub (D-324).
- **Alerting:**
  - Alerts are routed by owner team, with an ownerless queue.
  - Every channel has a durable 8-attempt retry that survives restarts (D-322).
  - A failed manual renewal opens an ITSM ticket.
- **Cloud inventory:** certificates found in AWS ACM, Azure Key Vault and Google Certificate Manager
  become inventory rows, and there is a per-agent inventory API (D-323).
- **Reports:** eight reports can be scheduled as CSV, XLSX or PDF, and the executive summary gains
  a PQC key-readiness line.
- **Intune SCEP:** challenges are validated through Microsoft's Intune SCEP API. Validation fails
  closed, and the result is reported back to Intune (D-327).

## Windows and CA rate safety (W39)

- **New install modes:** `sqlserver`, `rdp` and `exchange` over WinRM. Each verifies what the
  service actually serves and rolls back on failure. A domain account can install over sealed
  NTLM on 5985.
- **RDP discovery** offers HYBRID, so hosts that require NLA hand over their certificate.
- **Port-80 check:** the Windows agent checks port 80 before an http-01 renewal.
- **Rate limits:** a CA's Retry-After hold is stored and shared across restarts and replicas
  (D-313). Each connector can also have a rolling-window issuance budget (D-314).
- Proven live in the lab on Server 2022 and Windows 11 (RDP) and SQL Server 2025 Express.

## Ahead of the standards (W40)

- **PQC waves** now install ML-DSA certificates on HAProxy and Kubernetes TLS Secrets (D-315).
  This is proven live with OpenSSL 3.5.
- **ACME device attestation** (`device-attest-01`) is available for Apple managed devices and TPM
  hosts. It requires operator-configured roots, a device allow-list and an opt-in template flag
  (D-316, D-317).
- **Trust store push:** CA-only bundles are pushed to hosts' trust stores through the agent. A
  second person must approve each push, and hosts must opt in (D-318, D-319).

## Upgrade notes

- **Migrations:** 000350–000388 run automatically.
- **Go toolchain:** 1.26.10 (GO-2026-6809).
- **Notification retries:** now 8 attempts with exponential backoff (were 3). The policy can be
  overridden with `KRYPTKEEPER_NOTIFY_RETRY_ATTEMPTS`, `_BASE` and `_CAP`.
- **New settings:**
  - `KRYPTKEEPER_PLUGIN_CATALOGUE_URL`: set it empty to disable the catalogue.
  - `KRYPTKEEPER_ENV`: set `production` to refuse demo seeding.
  - Agent `KRYPTKEEPER_TRUST_STORE_PUSH`: off by default. Install the separate sudoers drop-in
    with `--generate-trust-store-sudoers` to opt in.
- **Plugin `http` events** now log only the scheme and host, not the full URL.

## Known limitations

See the [roadmap](../ROADMAP.md). Highlights:

- **Fixture-only integrations:** Sectigo, GlobalSign, Entrust, DigiCert, Google CAS, Teams,
  PagerDuty, Opsgenie, Zendesk, Freshservice, the DNS plugins, CyberArk, Delinea and Intune are
  proven against recorded APIs or stand-ins, not real accounts.
- **Exchange and Windows-agent PQC delivery** are not proven on real servers.
- **Homebrew tap, apt/yum repositories, macOS notarization, Terraform registry and Galaxy
  publishing** await their accounts.

## Lab records

- [LIVE_RESULTS_UPSTREAM_CAS_v1.1.md](LIVE_RESULTS_UPSTREAM_CAS_v1.1.md)
- [LIVE_RESULTS_W39_WINDOWS_v1.1.md](LIVE_RESULTS_W39_WINDOWS_v1.1.md)
- [LIVE_RESULTS_PQC_W40_v1.1.md](LIVE_RESULTS_PQC_W40_v1.1.md)
- [LIVE_RESULTS_TRUST_STORE_v1.1.md](LIVE_RESULTS_TRUST_STORE_v1.1.md)
- [LIVE_RESULTS_CREDENTIAL_SOURCES_v1.1.md](LIVE_RESULTS_CREDENTIAL_SOURCES_v1.1.md)
- [LIVE_RESULTS_NOTIFY_PLUGINS_v1.1.md](LIVE_RESULTS_NOTIFY_PLUGINS_v1.1.md)
- [LIVE_RESULTS_DNS_PLUGINS_v1.1.md](LIVE_RESULTS_DNS_PLUGINS_v1.1.md)
- [LIVE_RESULTS_TICKET_PLUGINS_v1.1.md](LIVE_RESULTS_TICKET_PLUGINS_v1.1.md)
