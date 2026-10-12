# Kryptkeeper — User Personas

**Version:** 1.0
**Date:** 2026-04-05
**Phase:** 1 — Planning

---

## Persona 1 — The PKI Administrator ("Alex")

**Role:** Senior Security Engineer / PKI Lead
**Organization size:** 2,000–20,000 employees
**Industry:** Financial services, healthcare, or defense contractor

### Background
Alex has been managing PKI for 8 years. Their current environment runs on Windows ADCS,
which they inherited and have been maintaining with a mix of PowerShell scripts, manual
renewal processes, and tribal knowledge. They've been through two certificate expiry
incidents — one that took down an internal application for 4 hours, one that expired
a load balancer cert on a Friday night.

Alex knows X.509 cold. They understand the difference between root and issuing CAs,
can read a certificate dump from `openssl x509 -text`, and understand OCSP stapling.
They write PowerShell and Python, and they're comfortable reading Go code even if
they don't write it.

### Goals
- Get complete visibility into every certificate in the environment (they currently don't have it)
- Replace ADCS dependency — they're tired of the Windows Server license cost and the blast
  radius when Domain Admins do something unexpected
- Automate renewal before SC-081's 100-day mandate makes manual renewal impossible
- Have a clear answer for the auditor's question: "show me all certificates expiring in the next 90 days"

### Pain Points
- "I don't know what I don't know" — there are certs they've never seen because they weren't
  there when the service was deployed
- ADCS has no REST API — everything is through DCOM, PowerShell MMC snap-ins, or the GUI
- step-ca looked promising until they saw OCSP requires the commercial tier
- EJBCA is 3 weeks to deploy and requires a Java EE stack they don't want to run

### What Alex Needs from Kryptkeeper
- Discovery scanning that finds certs they didn't know existed
- OCSP responder free in OSS (not behind a paywall)
- REST API so they can integrate with their existing automation
- A clear path to ADCS replacement (V2) they can plan for
- Export to their SIEM (audit log in a parseable format)

### How Alex Evaluates Software
- Reads the GitHub repo before the website — code quality and commit history matter
- Checks the license carefully (LGPL is a dealbreaker, AGPL is a dealbreaker)
- Tests locally before pitching to management — wants Docker Compose that actually works
- Looks for OpenAPI spec — if there's no API docs, the API doesn't exist

---

## Persona 2 — The Platform Engineer ("Jordan")

**Role:** Senior Platform / DevOps Engineer
**Organization size:** 100–2,000 employees
**Industry:** SaaS, fintech, or cloud-native startup

### Background
Jordan runs Kubernetes at scale. Their team deploys 200+ microservices, and certificate
management is a pain point they inherited by accident — nobody else wanted to own it.
They use cert-manager for some services and ACME for others, but there's no central
inventory and they've had alerts fire for certificates they didn't know existed.

Jordan writes Go and TypeScript, lives in the terminal, and has strong opinions about
API design. They would rather write a 50-line Go program to solve a problem than click
through a GUI.

### Goals
- Self-service certificate issuance without a ticket to the security team
- Terraform provider to manage certificates as code
- K8s operator or cert-manager integration so certificate issuance is part of the deployment pipeline
- Visibility into what certs exist across the cluster without manual hunting

### Pain Points
- Cert-manager works but there's no central inventory of what was issued and when
- The security team's ADCS-based CA requires a ticket and 3 business days for a new cert
- Public cloud CAs (ACM, etc.) don't work for internal services
- Nobody knows who owns which certificate when something expires

### What Jordan Needs from Kryptkeeper
- ACME support — certbot and acme.sh must work without modification
- REST API with good docs — they'll write their own integrations
- Terraform provider (even basic) in V1 or a clear roadmap to it
- cert-manager ClusterIssuer integration
- Docker Compose quickstart that actually works in under 15 minutes

### How Jordan Evaluates Software
- Looks for OpenAPI spec on day 1 — if it's not there, they'll write their own CA
- Runs `docker compose up` and expects it to work — if it doesn't, they move on
- Checks GitHub stars and recent commit activity
- Reads the changelog to understand development velocity
- Has a strong aversion to Java/JVM-based tools ("I don't want to debug OutOfMemoryError at 3 AM")

---

## Persona 3 — The CISO / Security Leader ("Sam")

**Role:** CISO or VP of Security
**Organization size:** 1,000–50,000 employees
**Industry:** Regulated industries (finance, healthcare, government contractor)

### Background
Sam came up through security engineering 15 years ago but now spends most of their time
in meetings with auditors, boards, and regulators. They're preparing for a SOC 2 Type II
audit and their ADCS environment has been flagged as a risk in two pen tests — the testers
found expired certs and self-signed certificates on internal services.

Sam doesn't configure software, but they approve budget and sign off on tools. They need
to be able to explain to the board why a tool is safe, why it's better than alternatives,
and what the migration risk is.

### Goals
- Demonstrate cryptographic hygiene to auditors without building a custom report
- Know when they are at risk from certificate expiry before the NOC tells them
- Have a PQC readiness story to tell the board ahead of the 2030 mandate
- Reduce ADCS attack surface — ADCS is a high-value target, Domain Admin is a big blast radius

### Pain Points
- Venafi costs $500K+/year and requires a dedicated operator
- They can't answer "how many certificates do you have?" without significant manual effort
- The last pen test found self-signed certs on internal services that nobody owns
- Post-quantum is on the board's radar but they have no concrete plan

### What Sam Needs from Kryptkeeper
- Executive risk dashboard: expiry timeline, risk grade distribution, unowned cert count
- PQC vulnerability reporting (which certificates are RSA/ECDSA and will need migration)
- Audit log export for compliance evidence
- Clear licensing (Apache 2.0 = no legal landmines)
- A migration story from ADCS that doesn't require rearchitecting AD

### How Sam Evaluates Software
- Doesn't evaluate software directly — defers to Alex or Jordan's technical recommendation
- Does care about: vendor stability, license terms, support availability
- Asks: "What happens if this company disappears?" (open source Apache 2.0 answers this)
- Asks: "What data leaves our environment?" (telemetry opt-in policy must be clear)

---

## Persona 4 — The Network/Infrastructure Engineer ("Riley")

**Role:** Network Engineer or Systems Administrator
**Organization size:** Any
**Industry:** Any with network devices (firewalls, load balancers, routers)

### Background
Riley manages F5 BIG-IP, Palo Alto firewalls, and Citrix ADC. Certificates on these
devices are renewed manually, often by logging into each device individually. They're
not a PKI expert — they know enough to understand that a cert has an expiry date and
that SCEP is "the thing you use for network devices." They've been burned by expired
certs on load balancers and want to automate.

### Goals
- Automate certificate renewal on network devices without manual intervention
- Have visibility into when device certs expire before they cause outages
- Not have to call the PKI team every time they need a cert renewed

### What Riley Needs from Kryptkeeper
- SCEP support: F5, Palo Alto, Citrix, and Cisco devices use SCEP
- EST support: newer network devices support EST
- Discovery: scan network device management interfaces for existing certs
- Simple dashboard that shows expiry dates without PKI expertise required

---

## Persona 5 — The Open-Source Contributor ("Casey")

**Role:** Software Engineer (any level) with interest in PKI/security
**Organization size:** N/A (contributor, not user)

### Background
Casey is a Go developer who uses step-ca or Let's Encrypt at work and found Kryptkeeper
through Hacker News or a Reddit thread. They've never built CA software but they understand
Go well and care about security. They want to contribute to a project that matters.

### Goals
- Contribute code to a real, production-quality open-source security project
- Learn more about PKI by working on real protocol implementations
- See their changes used in production by real organizations

### What Casey Needs from Kryptkeeper
- Clear architecture documentation so they understand the module they're touching
- Contribution guidelines that explain how to run tests locally
- A public roadmap with issues labeled "good first issue" or "help wanted"
- A responsive maintainer who reviews PRs promptly
- Code that's modular enough that a contributor can own a specific module without
  understanding the entire codebase

---

## Persona Summary

| Persona | Primary Need | Key Feature | Anti-Pattern |
|---------|-------------|-------------|--------------|
| Alex (PKI Admin) | Visibility + ADCS escape | Discovery + OCSP + REST API | Paywalled OCSP, GUI-only management |
| Jordan (Platform Eng) | Self-service + automation | ACME + Terraform + cert-manager | Java stack, ticket-based issuance |
| Sam (CISO) | Compliance + risk reporting | Risk dashboard + PQC reporting | Opaque licensing, telemetry |
| Riley (Network Eng) | Device cert automation | SCEP + EST + device discovery | PKI expertise required |
| Casey (Contributor) | Learn + contribute | Modular architecture + docs | Monolith, undocumented code |
