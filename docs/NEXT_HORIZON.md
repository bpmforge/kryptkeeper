# Kryptkeeper — Next Horizon (V6 seed)

**Date:** 2026-08-19 · **Status:** Draft for adoption
**Basis:** V5/W11 complete (board: 193 done / 3 human-gated); fresh
competitive research 2026-08-19 (sources at bottom); code-verified gap
audit against `docs/research/CLM_LEADERSHIP_2026.md` (that checklist is
now essentially built — see §2).

## 1. What the market is complaining about (researched, not guessed)

**Venafi / CyberArk (now inside Palo Alto Networks, Feb 2026):**
- On-prem expects dedicated Windows Server + IIS + SQL Server; a typical
  rollout runs **3–6 months with professional services** before value.
- Organizations without dedicated PKI staff **pay for depth they never
  use**; two stacked acquisitions in 16 months leave renewal pricing,
  support continuity, and standalone-CLM roadmap all uncertain.

**Keyfactor Command / EJBCA:**
- Users report weakness precisely in **discovery and expiration
  monitoring**, a dated UI, deployment bugs, API configuration pain,
  and scalability complaints.

**The industry-wide pain (why budgets exist):**
- **83% of organizations had a certificate-related outage in the last
  24 months**; blind-spot certs obtained outside governance are the
  ones that fail quietly. Average enterprise: 25,000+ certs, still
  partly in spreadsheets; human error in manual renewal is the leading
  outage cause. The 47-day cliff (Mar 2029) makes all of this terminal.
- **Key management:** key sprawl across clouds with no accurate
  inventory; each cloud KMS has different APIs, rotation behavior, and
  audit formats; regulators levied **$2B+ in data-handling fines in
  Q1 2026 alone**, pushing documented key custody and crypto-agility
  ("one inventory of keys and algorithms") up the CISO stack.

**The synthesis:** incumbents sell visibility, charge for action, take
half a year to deploy, and still miss the blind spots. The winning
posture is: **day-one complete estate picture, zero-touch action, one
crypto inventory (certs AND keys), on a single self-hosted OSS binary.**

## 2. Where we already stand (code-verified)

The 2026-07 leadership checklist is built: five enrollment protocols
(ACME+EAB, SCEP, EST, CMP, XCEP/WSTEP-server), SAML SSO + SCIM, cloud
inventory (AWS ACM, Azure Key Vault, GCP Cert Manager), CT-log
monitoring, CBOM/CycloneDX, cross-signing, SPIFFE attestation +
NHI issuance, SLO-native ops, anomaly detection + NL policy drafts,
last-mile installers (nginx/Apache/HAProxy/IIS/F5/Citrix/K8s-Istio),
estate model + bulk import + ACME-upstream renewal + ADCS-export/
DigiCert sync + takeover flow + SSH CA. Key custody for our own CAs:
software/PKCS#11/Vault/AWS/Azure/GCP KMS, FIPS posture, dual-control
escrow, backup/destroy.

## 3. The gaps that close the category (V6 candidate waves)

### A. Drive every CA, not just be one (estate write-breadth)
1. **WSTEP/CES *client* to a running Windows ADCS** — submit CSRs to a
   customer's existing AD CS over its Certificate Enrollment Web
   Services. We already implement the protocol server-side; the client
   reuses our own SOAP/WS-Trust codec. Changes the story from "replace
   ADCS" to "replace *or* drive ADCS". Highest-value connector left.
2. **Commercial write adapters** behind the existing `IssuerConnector`:
   DigiCert issuance API first (read-side exists), then Sectigo,
   Entrust.
3. **SCEP + EST client modes** — drive any legacy CA speaking only
   those.
4. **Live ADCS sync** (DCOM/LDAP or a thin collector task) replacing
   the export-file workflow; more read-only sync sources (Sectigo,
   Entrust, AWS Private CA, Google CAS).

### B. See everything, with and without agents (discovery breadth)
5. **Agentless Linux/Unix scan** — reuse the hardened SSH executor
   (`internal/agentinstall/executor_ssh.go`, sudo-capable) for
   *discovery*: walk cert paths, parse keystores, capture SSH host
   keys. No new dependency.
6. **Agentless Windows scan via WinRM/PowerShell remoting** — WS-Man
   over HTTPS :5986 running `Get-ChildItem Cert:\` -class enumeration
   (the Lansweeper-style industry pattern). WinRM is SOAP/XML — the
   same family our WSTEP server already hand-rolls, so a stdlib
   implementation is plausible before reaching for a winrm dependency
   (dependency decision flagged if PSRP binary framing proves needed).
7. **Protocol-aware network scanning** — STARTTLS (SMTP/IMAP/POP/
   LDAP/Postgres), SSH host-key + algorithm capture, RDP; per-endpoint
   **crypto-posture probe** (TLS versions, cipher suites, weak groups)
   so "cert inventory" becomes the crypto inventory CBOM claims.
8. **Host keystore formats** — JKS and PKCS#12 parsing in the agent
   walk (where enterprise certs actually hide), kubeconfigs, cloud-CLI
   credential stores.

### C. One key plane (the KMS complaint, aimed)
9. **Unified key inventory across clouds** — enumerate keys in
   AWS/Azure/GCP KMS (we already hold connectors) into one risk-scored,
   algorithm-aware inventory with rotation status: the crypto-agility
   "one inventory of keys and algorithms" ask, and the PQC-readiness
   denominator for keys, not just certs.
10. **Key-custody evidence** — per-key custody/rotation/SoD report in
    the compliance-evidence pack (the $2B-fines driver).
11. **Opt-in leaf-key escrow** (DECISION REQUIRED): Venafi-parity
    central custody of endpoint keys conflicts with the house law
    ("private key material never leaves its boundary"). If adopted:
    per-tenant opt-in, reusing dual-control escrow, never default.
    **KMIP** stays deferred-until-pulled but is decided together with
    this (it would be the custody interface).
12. **BYOK workflows** to cloud KMS from our escrowed roots.

### D. Deployment speed as a weapon (their 3–6 months vs our day one)
13. **Day-one estate exercise productized**: quickstart → bulk import →
    agentless scan → ADCS sync → risk-scored estate report inside one
    day (this is V5 success-metric #1 turned into a guided flow +
    marketing artifact).
14. **W12 wiring wave** (small): CT-monitor start, SLO sweep ticker,
    anomaly notifier, mesh-discovery scheduler, pusher target-config
    wiring — turning landed seams into running defaults.

### E. Agentic maturity (extend the moat nobody has)
15. Auto-remediation proposals from anomaly findings (propose-only,
    approval-gated — the W7-04 → pending-actions bridge).
16. gRPC SPIFFE Workload API (pending the W7-01 dependency decision).

## 4. Deliberately not doing (carried forward, with triggers)
- KMIP — until a customer pulls it (revisit with §C-11).
- PGP/OpenPGP — out (D-106).
- Hosted SaaS — self-hosted *is* the differentiator; revisit with
  traction.
- ServiceNow/ITSM — webhook + SIEM until a real deployment asks.
- Mobile/IoT MDM — Intune SCEP covers the common case.

## 5. Suggested sequencing
- **W12** — wiring wave (§D-14) + the three human-gated decisions
  (gRPC dep, CI runner, terraform registry).
- **W13** — estate write-breadth (§A): WSTEP client, DigiCert write,
  live ADCS sync.
- **W14** — discovery breadth (§B): agentless SSH + WinRM scans,
  protocol-aware scanning, JKS/P12.
- **W15** — key plane (§C): unified key inventory, custody evidence;
  leaf-key-escrow decision gates the rest.
- Parallel: day-one exercise (§D-13) once W12 lands; validation of the
  V5 success metrics on a live install.

## 6. Research sources (2026-08-19 sweep)
- AxelSpire Venafi platform review + alternatives analyses (rollout
  time, infra expectations, post-acquisition uncertainty).
- IT Pro on CyberArk/Venafi integration; Palo Alto acquisition of
  CyberArk (Feb 2026).
- Gartner Peer Insights / G2 / PeerSpot on Keyfactor Command & EJBCA
  (discovery/expiry weakness, UI, deployment bugs).
- CyberArk/Palo Alto "machine identity sprawl" posts; Encryption
  Consulting outage-prevention (83% outage stat); Keyfactor discovery
  education page (blind spots).
- Help Net Security / NTT Data / Encryption Consulting on
  crypto-agility, multicloud KMS inconsistency, key sprawl; Q1-2026
  fines figure.
- Lansweeper / ITRS docs on WinRM-based agentless Windows certificate
  scanning (ports 5985/5986, PowerShell remoting pattern).
