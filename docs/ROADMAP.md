# Kryptkeeper roadmap

This page lists what Kryptkeeper 1.1.0 does **not** do yet, and when we plan to do it.
Everything here was found during the 1.0.0 and 1.1.0 builds, lab testing or security review
and was deliberately left out of the release, so it is written down rather than forgotten.

Each item has a target:

- **1.1**: planned for the next feature release.
- **Later**: planned, but not scheduled for 1.1. Some of these need a design decision first.
- **Needs an account**: the feature is built and tested against emulators or stand-ins. The
  real product or service is cheap or free to get (a trial, a free edition, a cloud or SaaS
  account), so the live run is waiting on us setting one up.
- **Needs partner or hardware**: the feature is built and tested against emulators or
  stand-ins, but finishing the proof needs a vendor, a customer or a purchase (an HSM, a
  hardware token, a sandbox contract, an appliance). We need that system in a lab.
- **Not planned**: we decided not to do it. The row says why.

The `Ref` column is our internal ticket or decision number, so you can ask about an item by
name. This page is updated in the same change that defers anything new
(see [ROADMAP_PROCESS.md](ROADMAP_PROCESS.md)).

Last updated: 2026-10-27.

## Windows and application installs

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Windows autoenrollment proof on Windows 10 and Server 2019, plus a lab runbook | Autoenrollment is proven on Windows 11, Server 2022 and Server 2025; Windows 10 and Server 2019 need ISOs the lab does not have (the owner-only); those versions and a step-by-step runbook are next. | 1.1 | W26-13, W26-14 |
| Alerts page form for plugin notification channels | A notify plugin is chosen with channel `plugin` and target `<plugin_id>/<credential_id>` through the API; the Alerts page rule form does not offer it yet. | 1.1 | W38-02 |
| Ticket plugins: find op and approval sync | Plugin connections cannot adopt a ticket made just before a hub crash (no `ticket.find`), and cannot carry approval sync, which stays native (ServiceNow, Jira). Both need their own design before third-party code gets them. | Later | D-326 |
| Plugin SDK and runtime renamed from "delivery" to "plugin" | The SDK module (`sdk/delivery-go`) and runtime package (`internal/plugins/delivery`) now serve every plugin kind but keep their delivery names, so no plugin go.mod or import had to change (D-321). A rename is a mechanical follow-up with a compatibility module. | Later | D-321 |
| NSS certificate databases | Applications that keep certificates in an NSS database (for example some Firefox, Chrome-on-Linux and Red Hat directory server setups) are not discovered or updated today. | Later | lab coverage review, 2026-10-18 |
| Push renewals to nginx, Apache or Tomcat running on Windows through the Windows agent | The Windows agent discovers certificates (machine store, PEM and PFX files) but refuses install tasks; Windows installs go through agentless WinRM to IIS today. | Later | v1 lab, 2026-10-18 |
| Server 2025 member: clock-skew refusal and the `wstep.renew` predecessor label | Autoenrollment and chain validation are proven on a Server 2025 member (lab-ws25, 2026-10-26). The Kerberos clock-skew test was not run there, and the last two renewals audited as `wstep.enroll`: Windows sent no old-certificate signature. | 1.1 | docs/release/LIVE_RESULTS_WINDOWS_KU_WS2025_v1.1.md |
| ECDSA machine templates through GPO autoenrollment | XCEP advertises RSA only, so an ECDSA-only template is withheld from Windows. ECDSA leaves are proven to be accepted by Windows (certreq, certutil, Schannel) when issued by CSR, not by autoenrollment. | 1.1 | docs/release/LIVE_RESULTS_WINDOWS_KU_WS2025_v1.1.md |
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
| PQC wave delivery to F5, Citrix and plugin targets | Waves install ML-DSA certificates on SSH nginx, Apache and HAProxy servers and on Kubernetes TLS Secrets, and roll back on a failed check. Proven live: HAProxy and a kind Secret (W40-01), and Apache httpd 2.4 on OpenSSL 3.5 with Apache and Kubernetes Secret rollback after a forced verify failure (docs/release/LIVE_RESULTS_PQC_APACHE_K8S_ROLLBACK_v1.1.md). Not yet live: Debian or RHEL httpd packages and real ingress controllers. F5 and Citrix targets and delivery plugins are still reported as "delivery unsupported": ML-DSA key import is not proven on those device APIs. | Needs partner or hardware | D-300, D-315, W31F-06, W40-01, P13 |
| Inventory-sources live harness uses the mTLS Entrust credential | W36-11 moved the Entrust source to client-certificate credentials; `tests/live/inventory-sources` still posts an API key to a plain-HTTP fixture, so the harness fails (docs/release/LIVE_RESULTS_v1.1.0_REGRESSION.md). Needs a TLS fixture with a client certificate. | 1.1 | P17 |
| S/MIME certificates carry the mailbox as an email SAN | The engine ignores CSR email addresses, so `emailProtection` templates issue certificates with no rfc822Name SAN (pkilint, allowlisted as known-defect in scripts/lint/allowlist.json). Needs a name policy for who may claim which mailbox. | Later | T6 |
| Kubernetes Secret rollback without a window of the unverified certificate | After a failed verify the hub restores the Secret byte for byte, but the workload can serve the unverified successor until the kubelet syncs the volume again (seen live, docs/release/LIVE_RESULTS_PQC_APACHE_K8S_ROLLBACK_v1.1.md). Staging the successor in a second Secret, or verifying before the swap, would close it. | Later | P13 |
| PQC wave delivery to Tomcat | Tomcat is reported as "delivery unsupported" in a wave: our installer writes a PKCS#12 or JKS keystore, which we cannot build around an ML-DSA key, and it does not switch the connector to PEM files (which Tomcat supports). Needs a PEM install mode and a proof on Tomcat with JDK 24 or later. | Later | D-315, W40-01 |
| PQC wave delivery to Windows services (IIS, SQL Server, RDP, Exchange) | Reported as "delivery unsupported": these installers import a PFX file, we cannot build one around an ML-DSA key, and Microsoft documents ML-DSA certificate templates for AD CS (Windows Server 2025 with KB5087539 or later) but not Schannel serving ML-DSA certificates. Revisit once Microsoft documents it and a lab Windows host can prove it. | Needs partner or hardware | D-315, W40-01 |
| Prove the PQC posture page against more certificate types | The posture page matched the API on a live mixed estate, but certificates expiring after 2030, unrecognised key types and RSA-2048 were not in that estate. | 1.1 | W31F-07 |
| MCP tool to propose a trust bundle | The hub API already lets the MCP agent propose a trust bundle (a human still approves); an MCP tool would let an assistant draft a CA rollover. | Later | W40-03 |
| Trust bundle targets by label and tenant | Agents carry neither today (D-203), so bundles target agent ids, a platform or all; labels would let you say "the web tier". | Later | W40-03 |
| Trust store push on SUSE and other distributions | Debian, Ubuntu and RHEL-family hosts are supported and proven live; SUSE uses a different anchor directory and refuses with a clear message today. | Later | W40-03 |
| Trust store push proven on Windows and macOS hosts | The Windows (certutil) and macOS (security) commands are covered by exact-command tests but have not run on real hosts. The Linux path is proven hub to agent in one run (debian:12, rockylinux:9; docs/release/LIVE_RESULTS_TRUST_STORE_E2E_v1.1.md). | Needs partner or hardware | W40-03 |
| IETF LAMPS composite signatures | Our hybrid certificates use their own documented encoding; we will move to the standard composite format once it is an RFC and mainstream verifiers accept it. | Later | D-172 |

## Notifications, ITSM and reports

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Opsgenie alerts plugin | The plugin is deprecated: Atlassian ends Opsgenie support on 2027-04-05, so we will not validate it against a real Opsgenie team. Use PagerDuty, Slack, Teams, email or a webhook. | Not planned | W38-02 |
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
| Client certificates for CyberArk CCP and other credential sources | CCP trusts the calling machine by AppID and allowed-machine list, so under multi-tenancy one tenant's admin can name another tenant's AppID. A per-source client certificate (or a per-tenant AppID allow-list) closes it. | 1.2 | A-01, D-330 |
| Per-credential use grants | Connectors and targets check that a credential belongs to the caller's tenant, but within one tenant anyone who can manage discovery can bind any of its credentials to an endpoint they choose. A use grant per credential (or binding limited to the credential's creator role) closes that. | 1.2 | C-02, D-330 |
| Allow-list for plugin `elevated_exec` | The gate is a deny-list of escalation and inline-shell forms; an allow-list of approved programs per plugin would make it a real boundary rather than a speed bump. | Later | A-04 |
| Credential-source and plugin-host reachability limits | Vault `base_url` and plugin credential URLs may name any private host and `/test` echoes the transport error; a per-tenant address allow-list and generic test errors stop it doubling as a port scanner. | 1.2 | A-07 |
| Require signed plugins, and refuse rollbacks | A hub setting to refuse community (unsigned) plugins, a minimum version per plugin id, a freshness check on the catalogue, and redaction of fetched values in credentials-plugin errors. | 1.2 | A-08, A-09 |
| Move PFX transfer off the WinRM command line | The encrypted PFX and its one-time password pass through PowerShell command lines and script text, which hosts with command-line or script-block logging record. A file-transfer channel (or WinRM file copy) with the password over stdin keeps them out of the logs. | 1.2 | B-03 |
| Root-owned trust-push state directory | The trust helper now writes its state symlink-safely, but the directory is still owned by the agent user; moving it to a root-owned path removes the agent user's say over which roots get removed. | 1.2 | B-04 |
| Windows install hardening | Import IIS and Exchange keys non-exportable, clean up machine-store keys when an early step fails, lock down the stage folder ACL, and report RollbackFailed for IIS and Exchange. | 1.2 | B-06, B-07, B-08, B-11 |
| Template policy on Intune, SCEP, EST and ACME issuance | These paths check enroll roles but not the template's key, SAN and validity policy or `require_approval`; Intune also fixes validity at 365 days. | 1.2 | C-04 |
| Device attestation hardening | Per-tenant device identifiers, a required non-exportable TPM key (fixedTPM, sensitiveDataOrigin), and a hub-side record of consumed Intune transactions. | Later | C-05, C-06, C-12 |
| External CA create and verify edge cases | Fail the create when the tenant mapping cannot be stored, and compare the upstream subject with the CSR when the request sets none. | 1.2 | C-08, C-09 |
| Scorecard hygiene on the public repository | Add a dependency-update tool and a SAST job, scope release-workflow write tokens, and stop shipping the historical 10-09 SBOM where OSV reads it as live dependencies (the public Scorecard is 4.6). | 1.2 | v1.1 scan 2026-10-27 |
| Independent penetration test | Our own scans found no critical or high issues; an outside test is the next level of assurance. | Later | W33-29 |

## Packaging and distribution

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Container images published by every release | 1.0.0 ships binaries, packages and the Windows MSI; 1.1.0 publishes a signed Helm chart at `oci://ghcr.io/bpmforge/charts/kryptkeeper`. Images still need their own publishing step on our release pipeline. | 1.1 | D-210 |
| Homebrew tap | One command to install and update on macOS, instead of downloading the formula from the release. | 1.1 | D-210, W25-10 |
| Signed apt and yum repositories | Lets Debian, Ubuntu, RHEL and Rocky hosts install and update with their normal package manager. | 1.1 | D-210, W25-11 |
| Reproducible-build check and post-release signature verification | Proves anyone can rebuild the same binaries and that published signatures verify. | 1.1 | W33-09 |
| macOS notarization | Without it, Gatekeeper may quarantine a downloaded agent binary until you allow it. | 1.1 | macOS agent guide, W37 |
| Terraform provider in a public registry | Today the provider is installed from the release; a registry entry makes `terraform init` just work. | 1.1 | S-04, W37 |
| Ansible collection published on Galaxy | The `kryptkeeper.pki` collection is built in 1.1.0; publishing it on Galaxy needs a Galaxy namespace. | Needs an account | W37 |
| Code and config comments cite docs/design/SECURITY_PRINCIPLES.md | About 25 Go, YAML and shell comments still name the private contributor rules file (`CLAUDE.md`) as the source of a rule; the public docs already point at the security principles page. | 1.2 | public cleanup 2026-10-27 |
| Five-minute trial: one command brings up a hub with demo data | Evaluators should reach a working dashboard before they read a guide. | 1.1 | W37 |
| Nightly fuzzing on a dedicated runner | The nightly fuzz workflow uses the same `ubuntu-latest` label as PR CI, so it lands on whichever shared Mac runner is free and competes with interactive dev work. It needs its own label and a dedicated (or cloud) runner. | 1.1 | M5 runner 2026-10-27 |

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

## Proven against real systems

These features work against emulators, mock devices or stand-in services in our lab. We
will mark each one proven once it has run against the real system. They are split by what
the proof needs, so you can see which ones are cheap to finish.

### Needs an account (cheap or free)

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| F5 BIG-IP and Citrix NetScaler certificate delivery | Proven against a mock appliance only. F5 offers a 30-day trial; NetScaler VPX Express is free. | Needs an account | W32-06, W19-11, W20-22 |
| SCEP enrollment from F5 BIG-IP | Not yet run against a real appliance (Palo Alto is in the next table). | Needs an account | W26-12 |
| Intune SCEP enrollment against a real Intune tenant | Proven against a stand-in for Entra, Graph and the Intune service that follows Microsoft's published client; the exact scope string, the notification field formats (thumbprint case, serial, hResult sign) and the Intune checks have not run against a real tenant. A trial tenant is enough. | Needs an account | W20-23, D-327 |
| AWS KMS, Azure Key Vault and Google Cloud KMS as CA key stores | Proven against emulators; real cloud permissions and HSM tiers are not yet proven. | Needs an account | W19-12 |
| Disaster-recovery drill with CA keys in a cloud KMS | The drill passes with software and SoftHSM keys; the KMS half needs a cloud account. | Needs an account | W25-09 |
| Delivery to AWS, Azure and Google Cloud certificate services | Proven for HashiCorp Vault; the cloud legs need accounts. | Needs an account | cloud delivery live results |
| ServiceNow, Jira Cloud, Zendesk and Freshservice connectors | Proven against stand-in services. A run against real instances (Zendesk and Freshservice soft-delete behaviour, API-token auth, rate limits) needs those accounts. | Needs an account | W32-18, W38-09 |
| Slack, PagerDuty and Microsoft Teams alerts | Proven against local receivers. PagerDuty is also built as a notify plugin, and Teams only as one (Workflows webhook); a run against a real Slack workspace, Teams flow and PagerDuty service needs those tenants. (Opsgenie is deprecated; see the Notifications section.) | Needs an account | W30-19, W38-02 |
| DNS-01 challenges in Route 53, Azure DNS and Google Cloud DNS | Proven with local DNS and with Cloudflare against Let's Encrypt staging. | Needs an account | ACME DNS providers live results |
| DNS-01 through the DigitalOcean, GoDaddy, NS1 and Akamai Edge DNS plugins | Proven against local stand-ins shaped like each vendor's API (Akamai's EdgeGrid signature is checked against the vendor's test vectors); a run against a real account at each vendor, and against a public CA, needs those accounts. | Needs an account | W38-08 |
| Terraform deployment into a real AWS account | The Terraform module validates; apply and destroy in a sandbox account are not yet run. | Needs an account | W25-16 |

### Needs partner or hardware

| Item | Why it matters | Target | Ref |
|---|---|---|---|
| Disaster-recovery drill with CA keys in a vendor HSM | The drill passes with software and SoftHSM keys; a vendor HSM is not in our lab. | Needs partner or hardware | W25-09 |
| YubiKey attestation for code-signing requests | The refusal path is proven; the success path needs a real YubiKey (a small purchase). | Needs partner or hardware | code-signing live results |
| ACME device attestation on real devices | Proven with generated Apple-style and TPM attestation chains only; a real run needs an Apple MDM-managed device (Managed Device Attestation) and a TPM host with an AIK certificate issued by your attestation CA. | Needs partner or hardware | W40-02 |
| SCEP enrollment from a Palo Alto appliance | Not yet run against a real appliance; it needs a Palo Alto VM-Series licence or a customer lab. | Needs partner or hardware | W26-12 |
| DigiCert inventory sync and upstream renewal | Proven with fixtures; the DigiCert sandbox run needs a sandbox contract. | Needs partner or hardware | inventory and upstream-renew live results |
| Target credentials from CyberArk and Delinea | HashiCorp Vault and OpenBao are proven live; the CyberArk Central Credential Provider and Delinea Secret Server plugins pass the credentials conformance suite and an in-hub test against mocks only. A run needs a CCP with an AppID and a Secret Server with an application account. | Needs partner or hardware | W38-07 |
| Service fingerprinting on Active Directory, F5 BIG-IP, Citrix ADC and other appliances | The fingerprint tells for these are tested against recorded fixtures only; real AD domain controllers, 389 Directory Server, F5, Citrix, Fortinet, Palo Alto, VMware, iDRAC/iLO and Exchange are needed to prove them. | Needs partner or hardware | fingerprint recall v0.22 |
| Issuance and revocation through Sectigo, GlobalSign, Entrust, DigiCert and Google CAS, and revocation through AWS Private CA | Built and tested against recorded API responses (AWS Private CA issuance also ran against the moto emulator, whose revoke is a no-op); a run against each real service needs a commercial account or contract. Vault PKI and EJBCA are proven against real containers. | Needs partner or hardware | W36-07..W36-11, W36-16 |
| Reference deployments | Named or anonymised customer deployments come from real customers, not from us. | Later | W33-28 |
