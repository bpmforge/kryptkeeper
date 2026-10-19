# Kryptkeeper roadmap

This page lists what Kryptkeeper 1.0.0 does **not** do yet, and when we plan to do it.
Everything here was found during the 1.0.0 build, lab testing or security review and
was deliberately left out of the release, so it is written down rather than forgotten.

Each item has a target:

- **1.1**: planned for the next feature release.
- **Later**: planned, but not scheduled for 1.1. Some of these need a design decision first.
- **Needs partner hardware**: the feature is built and tested against emulators or stand-ins,
  but has not been proven against the real product or service. We need a customer, partner
  or vendor lab with that system to finish the proof.

The `Ref` column is our internal ticket or decision number, so you can ask about an item by
name. This page is updated in the same change that defers anything new
(see [ROADMAP_PROCESS.md](ROADMAP_PROCESS.md)).

Last updated: 2026-10-18.

## Windows and application installs

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Install renewed certificates into Microsoft SQL Server | Kryptkeeper finds SQL Server certificates on Windows hosts today, but you still renew them by hand. | 1.1 | W35-02 |
| Install renewed certificates into Microsoft Exchange | Same as above for Exchange: discovered today, renewed by hand. | 1.1 | W35-03 |
| Install renewed certificates on the RDP listener | Same as above for Remote Desktop: discovered today, renewed by hand. | 1.1 | W35-04 |
| Read certificates from RDP hosts that require Network Level Authentication | Hosts that only accept NLA do not hand over their certificate to the scanner today, so they can be missed. | 1.1 | W24-48 |
| Check that port 80 is free before the Windows agent answers an HTTP-01 challenge | Gives a clear error up front instead of a failed ACME renewal when IIS already owns port 80. | 1.1 | W24-50 |
| Windows autoenrollment proof on Windows 10 and Server 2019, plus a lab runbook | Autoenrollment is proven on Windows 11 and Server 2022; older versions and a step-by-step runbook are next. | 1.1 | W26-13, W26-14 |
| NSS certificate databases | Applications that keep certificates in an NSS database (for example some Firefox, Chrome-on-Linux and Red Hat directory server setups) are not discovered or updated today. | Later | lab coverage review, 2026-10-18 |
| Push renewals to nginx, Apache or Tomcat running on Windows through the Windows agent | The Windows agent discovers certificates (machine store, PEM and PFX files) but refuses install tasks; Windows installs go through agentless WinRM to IIS today. | Later | v1 lab, 2026-10-18 |
| Windows autoenrollment proof on Server 2025 as a member server | Proven on Windows 11 and Server 2022; the only Server 2025 machines in the lab are the domain controller and the CA, which the clock-skew test cannot use. | 1.1 | v1 lab, 2026-10-18 |
| Offer ECDSA keys to Windows clients over XCEP | XCEP advertises RSA key sizes the issuance policy accepts; templates whose policy allows only ECDSA are not offered to Windows yet. | Later | v1 lab, 2026-10-18 |

## Discovery and inventory

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Import cloud-discovered certificates into the main inventory | Certificates found in AWS, Azure and GCP show in the cloud scan but are not yet first-class inventory rows you can renew and report on. | 1.1 | W24-46 |
| Per-agent inventory in the API | Lets automation ask one agent what it found without filtering the whole inventory. | 1.1 | W24-45 |
| Inventory of SSH user keys | SSH host keys and SSH certificates are tracked; plain user keys are not yet collected. | 1.1 | W24-47 |
| Keep short-lived service-mesh certificates out of headline counts | Mesh certificates that live for hours inflate dashboard totals. | 1.1 | W24-51 |
| Quieter SSH discovery | Scanning an SSH port also logs a harmless TLS handshake error, which looks like a fault. | 1.1 | W24-52 |
| Keep custom ports when a scan is retried | A retried scan currently falls back to the default port list. | 1.1 | V1 scan 2026-10-17 |
| Fetch missing intermediate certificates | When a server sends an incomplete chain, Kryptkeeper reports it but does not download the missing intermediate to complete the picture. | Later | post-0.9.3 planning |
| Merge the IP and hostname views of the same server | A server scanned by IP and by name shows up as two endpoints. | Later | post-0.9.3 planning |
| Agent reports unreadable files and listening ports the same way agentless scans do | Today the agent silently skips files it cannot read, so a gap in coverage looks like nothing is there. Includes the live agent test for this report. | 1.1 | W34-09 |
| Browser test for a target blocked by a root-owned install path | Proves end to end that the dashboard explains why such a target is blocked and clears once the credential is switched to helper mode. | 1.1 | W33-26 |
| Key readiness line on the executive summary PDF | The one-page summary does not yet say how many keys are ready, not ready or unknown for migration. | 1.1 | W24-49 |

## Renewal, issuance and CA operations

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Remember a public CA's "slow down" signal across restarts and replicas | If the hub restarts while a CA is rate limiting it, it can send a few requests early and get refused again. | 1.1 | W35-01 |
| Rolling issuance budget per CA connector | Matches the CA's published rate limit so large renewal waves never trip it. | 1.1 | W27-39 |
| Test an SSH key credential before saving it | Catches a wrong key or host before the first scheduled renewal fails. | 1.1 | W33-30 |
| Show which delivery path each certificate uses | Makes it obvious whether a certificate is installed by the agent, over SSH, by a plugin or by hand. | 1.1 | W20-25 |
| Validate Intune SCEP challenges through the Intune API | Needed for Intune-managed devices to enroll through Kryptkeeper's SCEP service. | 1.1 | W20-23 |
| Tenant scoping for migration batches | Under multi-tenancy, migration batches are not yet limited to the tenant that created them. | 1.1 | W24-53 |
| Bulk reissue from the certificate list | Bulk reissue cannot yet rebuild certificates that were issued from a client's own CSR; it needs a design decision on which certificates can be reissued without one. | Later | W33-33 |
| Automatic destruction of retired CA keys | After a CA key rotation the old key is retired but not yet destroyed after the grace period; destroying key material needs a final owner decision. | Later | V1 scans 2026-10-17 and 2026-10-18 |
| Restore from an audit archive | Audit archives can be written but not yet restored through the API or CLI. | Later | V1 scan 2026-10-17 |
| Store rollout groups on the hub | Rollout groups are saved in the browser today, so they are not shared between operators or machines. | Later | UI review, 2026-10-18 |

## Post-quantum cryptography

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Automatic delivery of ML-DSA certificates during a PQC migration wave | Waves issue, verify and roll back today, but installing the new post-quantum certificate on the server is still a manual step until ML-DSA private-key export exists. | Later | D-175, W31-11 |
| IETF LAMPS composite signatures | Our hybrid certificates use their own documented encoding; we will move to the standard composite format once it is an RFC and mainstream verifiers accept it. | Later | D-172 |

## Notifications, ITSM and reports

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Microsoft Teams as a notification channel | Teams approvals work; plain Teams alerts are next. | 1.1 | W32-29 |
| Route notifications to the owning team, with a queue for ownerless certificates | Gets alerts to the people who can act, and shows what nobody owns. | 1.1 | W32-30 |
| Notification retries with backoff | A brief outage at the receiver should not lose an alert. | 1.1 | W32-31 |
| Open an ITSM ticket when a manual renewal fails | Puts failed renewals into the team's normal ticket queue. | 1.1 | W32-32 |
| Schedule any report as CSV, XLSX or PDF | Today only the evidence pack is scheduled by email. | 1.1 | W28-06 |

## Security and multi-tenancy

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Keep the dashboard sign-in refresh token in an httpOnly cookie | Removes the token from browser script storage as defence in depth. | 1.1 | V1 scan 2026-10-17 |
| Tenant name in structured logs | Makes log searches per tenant possible in multi-tenant installs. | 1.1 | V1 scans 2026-10-17 and 2026-10-18 |
| Pin container base images by digest | Today base images are pinned by tag; a digest makes builds fully repeatable. | 1.1 | V1 scan 2026-10-17 |
| Tenant ownership for agents, workload identities and imported certificates | Under multi-tenancy these are global-admin-only, and certificates without a hub CA belong to the default tenant, until they carry their own tenant. | Later | D-203, S-06 |
| Use a workload's SPIFFE identity to call the hub | Workload identity scopes are enforced in tests but nothing yet signs in to the hub with an SVID. | Later | D-150 |
| Remote plugin catalogue | Delivery plugins are uploaded and pinned by hash today; a hosted, signed catalogue comes after the repository is public. | Later | D-117 |
| Independent penetration test | Our own scans found no critical or high issues; an outside test is the next level of assurance. | Later | W33-29 |

## Packaging and distribution

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Container images and Helm chart published by every release | 1.0.0 ships binaries, packages and the Windows MSI; images and the chart repository need their own publishing step on our release pipeline. | 1.1 | D-210 |
| Homebrew tap | One command to install and update on macOS, instead of downloading the formula from the release. | 1.1 | D-210, W25-10 |
| Signed apt and yum repositories | Lets Debian, Ubuntu, RHEL and Rocky hosts install and update with their normal package manager. | 1.1 | D-210, W25-11 |
| Reproducible-build check and post-release signature verification | Proves anyone can rebuild the same binaries and that published signatures verify. | 1.1 | W33-09 |
| macOS notarization | Without it, Gatekeeper may quarantine a downloaded agent binary until you allow it. | Later | macOS agent guide |
| Terraform provider in a public registry | Today the provider is installed from the release; a registry entry makes `terraform init` just work. | Later | S-04 |

## Accessibility

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Screen-reader pass with VoiceOver and NVDA, and an updated accessibility conformance report | Automated WCAG checks pass; a manual screen-reader pass is what confirms the dashboard is usable without sight. | 1.1 | W33-15 |

## Proven against real partner systems

These features work against emulators, mock devices or stand-in services in our lab. We
will mark each one proven once it has run against the real system.

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| F5 BIG-IP and Citrix ADC certificate delivery | Proven against a mock appliance only. | Needs partner hardware | W32-06, W19-11, W20-22 |
| SCEP enrollment from F5 BIG-IP or Palo Alto appliances | Not yet run against a real appliance. | Needs partner hardware | W26-12 |
| AWS KMS, Azure Key Vault and Google Cloud KMS as CA key stores | Proven against emulators; real cloud permissions and HSM tiers are not yet proven. | Needs partner hardware | W19-12 |
| Disaster-recovery drill with CA keys in an external HSM or KMS | The drill passes with software and SoftHSM keys. | Needs partner hardware | W25-09 |
| YubiKey attestation for code-signing requests | The refusal path is proven; the success path needs a real YubiKey. | Needs partner hardware | code-signing live results |
| DigiCert inventory sync and upstream renewal | Proven with fixtures; the DigiCert sandbox run needs an account. | Needs partner hardware | inventory and upstream-renew live results |
| ServiceNow and Jira Cloud connectors | Proven against a stand-in service. | Needs partner hardware | W32-18 |
| Slack and PagerDuty alerts | Proven against local receivers. | Needs partner hardware | W30-19 |
| DNS-01 challenges in Route 53, Azure DNS and Google Cloud DNS | Proven with local DNS and with Cloudflare against Let's Encrypt staging. | Needs partner hardware | ACME DNS providers live results |
| Delivery to AWS, Azure and Google Cloud certificate services | Proven for HashiCorp Vault; the cloud legs need accounts. | Needs partner hardware | cloud delivery live results |
| Terraform deployment into a real AWS account | The Terraform module validates; apply and destroy in a sandbox account are not yet run. | Needs partner hardware | W25-16 |
| Service fingerprinting on Active Directory, F5 BIG-IP, Citrix ADC and other appliances | The fingerprint tells for these are tested against recorded fixtures only; real AD domain controllers, 389 Directory Server, F5, Citrix, Fortinet, Palo Alto, VMware, iDRAC/iLO and Exchange are needed to prove them. | Needs partner hardware | fingerprint recall v0.22 |
| Reference deployments | Named or anonymised customer deployments come from real customers, not from us. | Later | W33-28 |
