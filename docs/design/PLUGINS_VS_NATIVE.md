# What should be a plugin and what should be native (1.1)

the owner asked on 2026-10-25 which of the 1.1 integrations and features should be plugins and
which should be built into the hub. This is the recommendation. It is proposed until he picks.

## What exists today

- **One plugin kind, delivery** (`docs/design/DELIVERY_PLUGINS.md`, D-113..D-119).
  - **Runtime:** plugins run on the hub only (D-114), as WASM modules on wazero. They have no filesystem and no sockets. Their only
    network access is a brokered `http.do`, limited to https and the hosts the operator granted. A plugin is capped at 128 MiB and
    a deadline.
  - **Trust:** each manifest declares its capabilities. A cosign signature sets the trust tier (first-party, verified,
    community). Enabling a plugin with a High or Critical capability needs a second person's approval.
    A conformance kit tests every plugin before it ships.
- **First-party delivery plugins:** F5, Citrix, Cloudflare, AWS ACM, Azure, Vault, AWS Secrets Manager, Azure Key Vault and GCP
  Secret Manager. F5 and Citrix replaced built-in code (D-118).
- **Native today:** everything else. That covers the issuer connectors (including the seven W36 added),
  notification channels, ServiceNow and Jira, DNS-01 providers, inventory sources, cloud KMS and
  keystores, discovery, agent install modes and every enrollment protocol.

## The rule

**Native** when any of these is true:

1. **It is the trust path:** signing, the policy check, verifying what an upstream CA returns (D-304),
   revocation semantics (D-306), audit, tenancy and key custody. If a plugin bug breaks these, it breaks the security promise.
2. **It is a standard protocol** we serve or speak: ACME, EST, SCEP, CMP, WSTEP/XCEP, OCSP, CRL and
   RFC 2136. These are one implementation each, and they must be correct.
3. **It runs on the agent or needs OS access.** Windows store, IIS, SQL Server, Exchange, RDP, trust
   store push and discovery need these. D-114 keeps third-party code off the agent, because the agent's sudoers allowlist must not widen
   invisibly.
4. **Almost every customer needs it on day one, and we prove it ourselves**, for example ACME upstream,
   Vault PKI and generic webhooks.

**Plugin** when it is a **long-tail vendor HTTPS API**: the hub sends a request with a credential and
reads a reply, and the vendor can change that API without us releasing. The sandbox already
enforces the important parts: only https, only granted hosts, every key handover approved.

## The recommendation, by area

| Area | Native (built in) | Plugin (first-party, signed) | Plugin (community / verified) |
|---|---|---|---|
| **Issuing CAs** | Hub CA, ACME, EST, Vault PKI, EJBCA, AWS Private CA, Google CAS, ADCS (WSTEP) | Sectigo, GlobalSign, Entrust, DigiCert: move to first-party issuer plugins in 1.2 (built native in W36, so they stay native for 1.1) | HARICA, Certum, SSL.com API, Keyfactor or Venafi as an upstream, Microsoft Cloud PKI |
| **Response check and revoke rules** | always native (D-304, D-306): a plugin issuer's certificate is verified by the hub exactly like a native one | none | none |
| **Delivery** | agent installs (Linux services, IIS, SQL Server, Exchange, RDP, Windows store), SSH and WinRM, Kubernetes secrets, cert-manager | F5, Citrix, Cloudflare, AWS, Azure, GCP, Vault (already), plus A10, Fortinet, Palo Alto, Akamai, Imperva, Azure Front Door and Fastly | anything else |
| **Notifications** | email, signed generic webhook, the approval flows (Slack and Teams buttons, because they carry approvals) | Teams alerts, PagerDuty, Opsgenie, Google Chat, Webex | others |
| **ITSM** | the ticket bridge and approval sync (trust path for approvals) | ServiceNow and Jira move to first-party plugins in 1.2; Zendesk, Freshservice and BMC Helix as new plugins | others |
| **DNS-01** | Cloudflare, Route 53, Azure DNS, Google Cloud DNS, RFC 2136 (which already covers BIND, PowerDNS, Infoblox and Windows DNS with TSIG) | Akamai, GoDaddy, DigitalOcean, NS1, Gandi, OVH | the long tail |
| **Inventory sources** | ADCS, cloud certificate stores, CT logs | Sectigo, Entrust, GlobalSign and DigiCert inventory move with their issuers | Venafi and Keyfactor import for migrations |
| **Credential sources (PAM)** | HashiCorp Vault and OpenBao (we already speak them) | CyberArk, Delinea, 1Password, AWS Secrets Manager and Azure Key Vault as credential plugins with a new Critical capability, `provide_credentials` | others |
| **Keystores and KMS, PQC, discovery, device attestation, trust store push, reports** | native | none | none |

## What 1.1 needs so this works

1. **Plugin kinds, not just delivery.**
   - **Manifest:** gains `kind`: `delivery` (today), `issuer`, `notify`, `ticket`, `dns01`,
     `inventory` or `credentials`.
   - **Per kind:** each kind gets its own small operation set in the ABI, its own conformance suite, and its own
     capability rows.
     - **issuer:** returns a PEM bundle. The hub still runs the D-304 checks, so a bad plugin cannot get a certificate past them.
     - **credentials:** gets the Critical tier and second-person enable.
2. **Long-running issuer orders:** add a hub-held poll loop, so a plugin never holds a pending order in its own state (instances are fresh per call).
3. **Mutual TLS through `http.do`:** the host attaches the client certificate from the credential, so the plugin never sees the client key. This is the same rule as the egress fix in W36.
4. **Signed remote catalogue** (D-117 said "after the repo is public"; it is public). A first-party
   catalogue on kryptkeeper.io lists signed plugins, and the hub installs from it with the same pinned
   hash and approval rules.
5. **Docs and SDK:** the delivery SDK becomes `sdk/plugin-go` with one package per kind, and there is a
   "write a plugin" guide per kind.

## How it changes the 1.1 waves

- **W36 (CA choice):** no change. The issuers ship native in 1.1. Moving the commercial four to plugins is a
  1.2 roadmap row once issuer plugins exist.
- **W38 (fits your tools):** builds the plugin-kind framework first, then delivers Teams alerts,
  PagerDuty and Opsgenie as `notify` plugins, CyberArk and Delinea as `credentials` plugins, and the new
  ITSM systems as `ticket` plugins. The owner routing, retries and ticket-on-failure logic stay
  native, because they are hub behaviour, not vendor APIs.
- **W40 (standards):** the extra DNS-01 providers become `dns01` plugins instead of native code. Device
  attestation and trust store push stay native.
- **W37 (packaging):** adds the signed plugin catalogue next to the Helm repository and Homebrew tap.

## Trade-offs to know

- Plugins are slower to write than native Go (WASM, JSON ABI, no SDK reflection), but
  vendors and the community can ship them without a hub release, and the sandbox
  enforces what native code only promises.
- WASM has no raw sockets, so anything that is not HTTPS stays native: RFC 2136 (DNS over TCP and UDP),
  SMTP, LDAP and SSH.
- Every plugin kind adds conformance and review work. The recommendation keeps the number of kinds to the six
  that real 1.1 integrations need.
