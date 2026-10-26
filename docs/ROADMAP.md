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

Last updated: 2026-10-25.

## Windows and application installs

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Windows autoenrollment proof on Windows 10 and Server 2019, plus a lab runbook | Autoenrollment is proven on Windows 11 and Server 2022; older versions and a step-by-step runbook are next. | 1.1 | W26-13, W26-14 |
| Alerts page form for plugin notification channels | A notify plugin is chosen with channel `plugin` and target `<plugin_id>/<credential_id>` through the API; the Alerts page rule form does not offer it yet. | 1.1 | W38-02 |
| Ticket plugins: find op and approval sync | Plugin connections cannot adopt a ticket made just before a hub crash (no `ticket.find`), and cannot carry approval sync, which stays native (ServiceNow, Jira). Both need their own design before third-party code gets them. | Later | D-326 |
| Plugin SDK and runtime renamed from "delivery" to "plugin" | The SDK module (`sdk/delivery-go`) and runtime package (`internal/plugins/delivery`) now serve every plugin kind but keep their delivery names, so no plugin go.mod or import had to change (D-321). A rename is a mechanical follow-up with a compatibility module. | Later | D-321 |
| NSS certificate databases | Applications that keep certificates in an NSS database (for example some Firefox, Chrome-on-Linux and Red Hat directory server setups) are not discovered or updated today. | Later | lab coverage review, 2026-10-18 |
| Push renewals to nginx, Apache or Tomcat running on Windows through the Windows agent | The Windows agent discovers certificates (machine store, PEM and PFX files) but refuses install tasks; Windows installs go through agentless WinRM to IIS today. | Later | v1 lab, 2026-10-18 |
| Windows autoenrollment proof on Server 2025 as a member server | Proven on Windows 11 and Server 2022; the only Server 2025 machines in the lab are the domain controller and the CA, which the clock-skew test cannot use. | 1.1 | v1 lab, 2026-10-18 |
| Offer ECDSA keys to Windows clients over XCEP | XCEP advertises RSA key sizes the issuance policy accepts; templates whose policy allows only ECDSA are not offered to Windows yet. | Later | v1 lab, 2026-10-18 |

## Discovery and inventory

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Show where a cloud certificate lives on its detail page, and retire ones removed at the source | Cloud certificates are inventory rows and each records its account, region and resource, but that is only in the database and the scan summary today. The certificate page does not show it, and a certificate whose cloud resource was deleted stays listed. | 1.1 | W38-05 |
| Real certificates for Key Vault and Certificate Manager keys that cannot be read, and for ACM certificates still pending | Without the certificate body only AWS ACM certificates with a known key become rows. Azure and GCP ones without a readable body are counted as skipped. | Later | W38-05 |
| Re-run the agent live harness against the inventory API | The W24-16 live agent checks now read GET /api/v1/agents/{id}/inventory instead of the hub database, but the edit has not been run against a real hub and agent yet. | 1.1 | W38-05 |
| Inventory of SSH user keys | SSH host keys and SSH certificates are tracked; plain user keys are not yet collected. | 1.1 | W24-47 |
| Keep short-lived service-mesh certificates out of headline counts | Mesh certificates that live for hours inflate dashboard totals. | 1.1 | W24-51 |
| Quieter SSH discovery | Scanning an SSH port also logs a harmless TLS handshake error, which looks like a fault. | 1.1 | W24-52 |
| Keep custom ports when a scan is retried | A retried scan currently falls back to the default port list. | 1.1 | V1 scan 2026-10-17 |
| Fetch missing intermediate certificates | When a server sends an incomplete chain, Kryptkeeper reports it but does not download the missing intermediate to complete the picture. | Later | post-0.9.3 planning |
| Merge the IP and hostname views of the same server | A server scanned by IP and by name shows up as two endpoints. | Later | post-0.9.3 planning |
| Agent reports unreadable files and listening ports the same way agentless scans do | Today the agent silently skips files it cannot read, so a gap in coverage looks like nothing is there. Includes the live agent test for this report. | 1.1 | W34-09 |
| Browser test for a target blocked by a root-owned install path | Proves end to end that the dashboard explains why such a target is blocked and clears once the credential is switched to helper mode. | 1.1 | W33-26 |

## Renewal, issuance and CA operations

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| More DNS-01 providers (Infoblox, PowerDNS) | Domain validation reuse drops to 10 days by 2029, so every renewal will need an automated DNS check wherever your zones live. DigitalOcean, GoDaddy, NS1 and Akamai Edge DNS now ship as DNS-01 plugins; the rest can be written the same way. | 1.1 | W40, W38-08 |
| GoDaddy DNS-01 on the v3 API with personal access tokens | The GoDaddy plugin uses the v1 API with a classic developer key, which GoDaddy lists as deprecated for Domains through 2026. | Later | W38-08 |
| Sectigo, GlobalSign, Entrust and DigiCert issuers as signed first-party plugins | Vendor API changes could then ship without a Kryptkeeper release; they are built in for 1.1. | Later | D-320 |
| Commercial CA order workflows beyond issue and revoke (OV/EV validation, organisation and domain pre-validation) | Kryptkeeper waits while the CA validates; that work still happens in the CA's own portal. | Later | W36-00-DESIGN §1.8 |
| Venafi and Keyfactor inventory import | Lets you see what another certificate manager already tracks during a migration. | Later | W36-00-DESIGN §1.8 |
| Test an SSH key credential before saving it | Catches a wrong key or host before the first scheduled renewal fails. | 1.1 | W33-30 |
| Show which delivery path each certificate uses | Makes it obvious whether a certificate is installed by the agent, over SSH, by a plugin or by hand. | 1.1 | W20-25 |
| Revoke on Intune's request (wipe, retire) | Intune queues revocations for the certificates it asked for; the hub does not yet download them through the Intune revocation API and revoke, so a wiped device's certificate stays valid until it expires. | Later | W20-23, D-327 |
| Tenant scoping for migration batches | Under multi-tenancy, migration batches are not yet limited to the tenant that created them. | 1.1 | W24-53 |
| Bulk reissue from the certificate list | Bulk reissue cannot yet rebuild certificates that were issued from a client's own CSR; it needs a design decision on which certificates can be reissued without one. | Later | W33-33 |
| Automatic destruction of retired CA keys | After a CA key rotation the old key is retired but not yet destroyed after the grace period; destroying key material needs a final owner decision. | Later | V1 scans 2026-10-17 and 2026-10-18 |
| Restore from an audit archive | Audit archives can be written but not yet restored through the API or CLI. | Later | V1 scan 2026-10-17 |
| Credential source management in the UI, and CyberArk client-certificate authentication | Sources are created through the API (Target Setup can pick and test one but not create one), and the CyberArk plugin supports AppID plus allowed-machines authentication only, not a client certificate. | Later | W38-07 |
| Store rollout groups on the hub | Rollout groups are saved in the browser today, so they are not shared between operators or machines. | Later | UI review, 2026-10-18 |

## Post-quantum cryptography

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| PQC wave delivery to F5, Citrix and plugin targets | Waves install ML-DSA certificates on SSH nginx, Apache and HAProxy servers and on Kubernetes TLS Secrets, and roll back on a failed check. F5 and Citrix targets and delivery plugins are still reported as "delivery unsupported": ML-DSA key import is not proven on those device APIs. | Needs partner hardware | D-300, D-315, W31F-06, W40-01 |
| PQC wave delivery to Tomcat | Tomcat is reported as "delivery unsupported" in a wave: our installer writes a PKCS#12 or JKS keystore, which we cannot build around an ML-DSA key, and it does not switch the connector to PEM files (which Tomcat supports). Needs a PEM install mode and a proof on Tomcat with JDK 24 or later. | Later | D-315, W40-01 |
| PQC wave delivery to Windows services (IIS, SQL Server, RDP, Exchange) | Reported as "delivery unsupported": these installers import a PFX file, we cannot build one around an ML-DSA key, and Microsoft documents ML-DSA certificate templates for AD CS (Windows Server 2025 with KB5087539 or later) but not Schannel serving ML-DSA certificates. Revisit once Microsoft documents it and a lab Windows host can prove it. | Needs partner hardware | D-315, W40-01 |
| Prove the PQC posture page against more certificate types | The posture page matched the API on a live mixed estate, but certificates expiring after 2030, unrecognised key types and RSA-2048 were not in that estate. | 1.1 | W31F-07 |
| MCP tool to propose a trust bundle | The hub API already lets the MCP agent propose a trust bundle (a human still approves); an MCP tool would let an assistant draft a CA rollover. | Later | W40-03 |
| Trust bundle targets by label and tenant | Agents carry neither today (D-203), so bundles target agent ids, a platform or all; labels would let you say "the web tier". | Later | W40-03 |
| Trust store push on SUSE and other distributions | Debian, Ubuntu and RHEL-family hosts are supported and proven live; SUSE uses a different anchor directory and refuses with a clear message today. | Later | W40-03 |
| Trust store push proven on Windows and macOS hosts | The Windows (certutil) and macOS (security) commands are covered by exact-command tests but have not run on real hosts. | Needs partner hardware | W40-03 |
| IETF LAMPS composite signatures | Our hybrid certificates use their own documented encoding; we will move to the standard composite format once it is an RFC and mainstream verifiers accept it. | Later | D-172 |

## Notifications, ITSM and reports

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Schedule the remaining reports and use cron-style timing | A schedule can deliver nine reports on a daily, weekly or monthly cadence. PQC migration, renewal SLO, key custody, revocation activity, issuance velocity, change audit, compliance evidence, PQC countdown and anomalies still need a flat-table shape of their own, and exact days or times need a cron expression. | Later | W38-06 |

## Security and multi-tenancy

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Keep the dashboard sign-in refresh token in an httpOnly cookie | Removes the token from browser script storage as defence in depth. | 1.1 | V1 scan 2026-10-17 |
| Tenant name in structured logs | Makes log searches per tenant possible in multi-tenant installs. | 1.1 | V1 scans 2026-10-17 and 2026-10-18 |
| Pin container base images by digest | Today base images are pinned by tag; a digest makes builds fully repeatable. | 1.1 | V1 scan 2026-10-17 |
| Tenant ownership for agents, workload identities and imported certificates | Under multi-tenancy these are global-admin-only, and certificates without a hub CA belong to the default tenant, until they carry their own tenant. | Later | D-203, S-06 |
| Use a workload's SPIFFE identity to call the hub | Workload identity scopes are enforced in tests but nothing yet signs in to the hub with an SVID. | Later | D-150 |
| Publish the plugin catalogue to the site automatically | The release workflow signs the catalogue and attaches it to the release, but copying it to kryptkeeper.io/plugins and deploying the site is still a manual step, and the workflow needs the plugin signing key added as repository secrets first. | 1.1 | W37-11, D-328 |
| Catalogue upgrade prompts and plugin removal notices | The Catalogue tab marks an installed older version as upgradable, but it does not say when a catalogue plugin is withdrawn or revoked, and there is no keyless-signed catalogue option. | Later | D-328 |
| Independent penetration test | Our own scans found no critical or high issues; an outside test is the next level of assurance. | Later | W33-29 |

## Packaging and distribution

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Container images and Helm chart published by every release | 1.0.0 ships binaries, packages and the Windows MSI; images and the chart repository need their own publishing step on our release pipeline. | 1.1 | D-210 |
| Homebrew tap | One command to install and update on macOS, instead of downloading the formula from the release. | 1.1 | D-210, W25-10 |
| Signed apt and yum repositories | Lets Debian, Ubuntu, RHEL and Rocky hosts install and update with their normal package manager. | 1.1 | D-210, W25-11 |
| Reproducible-build check and post-release signature verification | Proves anyone can rebuild the same binaries and that published signatures verify. | 1.1 | W33-09 |
| macOS notarization | Without it, Gatekeeper may quarantine a downloaded agent binary until you allow it. | 1.1 | macOS agent guide, W37 |
| Terraform provider in a public registry | Today the provider is installed from the release; a registry entry makes `terraform init` just work. | 1.1 | S-04, W37 |
| Ansible collection | Lets teams that run Ansible request, install and renew certificates from their playbooks. | 1.1 | W37 |
| Five-minute trial: one command brings up a hub with demo data | Evaluators should reach a working dashboard before they read a guide. | 1.1 | W37 |

## Website and walkthroughs

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Windows-side walkthrough screens: the Group Policy enrollment policy, a domain client enrolling, the certificate in certlm.msc, and the ADCS dual-issue and cutover view | The Windows and Active Directory pages show the Kryptkeeper side today; the client side is proven in the lab but not yet shown step by step. | 1.1 | SITE-01, SITE-02, SITE-03 |
| Linux host-side walkthrough screens: installing the agent and a certificate landing on disk with the service reloading | Same as above for Linux and macOS hosts. | 1.1 | SITE-04, SITE-05 |
| Search across the website walkthroughs | With 68 walkthroughs, finding one by keyword is faster than browsing the feature pages. | Later | SITE-06 |
| Short video versions of the main paths | Some evaluators would rather watch a two-minute run-through than read steps. | Later | SITE-07 |
| Dark-theme screenshots on the website | Walkthrough screens are captured in the light theme only, so they stand out on the dark site. | Later | SITE-08 |
| Crop dialog-only walkthrough steps, or merge the "fill X" steps | Long walkthroughs repeat a full-page capture for every field; the key ceremony page is about 11,900px tall and unreadable on phones. | 1.1 | SITE-10 |
| Walkthrough: use your existing CA (add an issuer, test it, create an external CA, issue over ACME) | The feature is documented in docs/ops/UPSTREAM_CAS.md; the screen-by-screen walkthrough on the website needs a capture run against a lab Vault. | 1.1 | W36-17 |
| Capture the install-plugin result step showing trust tier and capabilities | The walkthrough stops at the install dialog, so the signed tiers and declared capabilities are described but not shown. | 1.1 | SITE-11 |
| Recapture a dark 1.0 dashboard cover for "Getting around", and stronger covers for Windows and AD, Approvals and Build your own | The Getting around cover is from an older build, and the other three reuse screens that do not show the feature. | Later | SITE-12 |

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
| Intune SCEP enrollment against a real Intune tenant | Proven against a stand-in for Entra, Graph and the Intune service that follows Microsoft's published client; the exact scope string, the notification field formats (thumbprint case, serial, hResult sign) and the Intune checks have not run against a real tenant. | Needs partner hardware | W20-23, D-327 |
| AWS KMS, Azure Key Vault and Google Cloud KMS as CA key stores | Proven against emulators; real cloud permissions and HSM tiers are not yet proven. | Needs partner hardware | W19-12 |
| Disaster-recovery drill with CA keys in an external HSM or KMS | The drill passes with software and SoftHSM keys. | Needs partner hardware | W25-09 |
| YubiKey attestation for code-signing requests | The refusal path is proven; the success path needs a real YubiKey. | Needs partner hardware | code-signing live results |
| ACME device attestation on real devices | Proven with generated Apple-style and TPM attestation chains only; a real run needs an Apple MDM-managed device (Managed Device Attestation) and a TPM host with an AIK certificate issued by your attestation CA. | Needs partner hardware | W40-02 |
| DigiCert inventory sync and upstream renewal | Proven with fixtures; the DigiCert sandbox run needs an account. | Needs partner hardware | inventory and upstream-renew live results |
| ServiceNow, Jira Cloud, Zendesk and Freshservice connectors | Proven against stand-in services. Zendesk and Freshservice are ticket plugins; a run against a real Zendesk account and Freshservice domain (soft-delete behaviour, API-token auth, rate limits) needs those accounts. | Needs partner hardware | W32-18, W38-09 |
| Target credentials from CyberArk and Delinea | HashiCorp Vault and OpenBao are proven live; the CyberArk Central Credential Provider and Delinea Secret Server plugins pass the credentials conformance suite and an in-hub test against mocks only. A run needs a CCP with an AppID and a Secret Server with an application account. | Needs partner hardware | W38-07 |
| Slack, PagerDuty, Microsoft Teams and Opsgenie alerts | Proven against local receivers. PagerDuty and Opsgenie are also built as notify plugins, and Teams only as one (Workflows webhook); a run against a real Teams flow, PagerDuty service and Opsgenie team needs those tenants. | Needs partner hardware | W30-19, W38-02 |
| DNS-01 challenges in Route 53, Azure DNS and Google Cloud DNS | Proven with local DNS and with Cloudflare against Let's Encrypt staging. | Needs partner hardware | ACME DNS providers live results |
| DNS-01 through the DigitalOcean, GoDaddy, NS1 and Akamai Edge DNS plugins | Proven against local stand-ins shaped like each vendor's API (Akamai's EdgeGrid signature is checked against the vendor's test vectors); a run against a real account at each vendor, and against a public CA, needs those accounts. | Needs partner hardware | W38-08 |
| Delivery to AWS, Azure and Google Cloud certificate services | Proven for HashiCorp Vault; the cloud legs need accounts. | Needs partner hardware | cloud delivery live results |
| Terraform deployment into a real AWS account | The Terraform module validates; apply and destroy in a sandbox account are not yet run. | Needs partner hardware | W25-16 |
| Service fingerprinting on Active Directory, F5 BIG-IP, Citrix ADC and other appliances | The fingerprint tells for these are tested against recorded fixtures only; real AD domain controllers, 389 Directory Server, F5, Citrix, Fortinet, Palo Alto, VMware, iDRAC/iLO and Exchange are needed to prove them. | Needs partner hardware | fingerprint recall v0.22 |
| Issuance and revocation through Sectigo, GlobalSign, Entrust, DigiCert and Google CAS, and revocation through AWS Private CA | Built and tested against recorded API responses (AWS Private CA issuance also ran against the moto emulator, whose revoke is a no-op); a run against each real service needs an account. Vault PKI and EJBCA are proven against real containers. | Needs partner hardware | W36-07..W36-11, W36-16 |
| Reference deployments | Named or anonymised customer deployments come from real customers, not from us. | Later | W33-28 |
