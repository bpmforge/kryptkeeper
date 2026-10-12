> **Superseded (2026-09-10).** This June 2026 "Three Moats" plan was replaced by the estate-management direction in docs/DECISIONS.md D-106 and docs/sdlc/phase-0-ideation/VISION_V5.md. Kept for history.

# Kryptkeeper — Go-Forward Plan

**Date:** 2026-06-10
**Status:** Adopted — supersedes the Sprint 7 list in `STRATEGIC_GAP_ANALYSIS.md` §7
**Input:** Full product review 2026-06-10 (code-verified feature audit, UI coverage audit, competitive whitespace analysis)

---

## 1. Where We Are

v1.1.0 ships everything Sprints 5–6 built: compliance audit fields, 8 reports,
certificate ownership, renewal scheduler, ACME ARI, SIEM output, Vault transit,
key rotation/backup, approval workflow, bulk operations, short-lived profiles.
All 25 backend packages green. Staging live.

The review found the product was **ahead of its own story**: a month of
enterprise features sat unreleased and partially invisible in the UI. The
go-forward principle that follows from that:

> **Nothing counts until a user can see it, click it, and show it to an auditor.**
> Backend capability without UI surface and release notes is inventory, not product.

---

## 2. The Market Thesis (unchanged, accelerating)

1. **The 47-day cliff is no longer hypothetical.** The 200-day max took effect
   March 15, 2026 — three months ago. 100 days hits March 2027. Every org with
   >50 certs needs automation by next year, and only ~5% have it.
2. **PQC deadlines are regulatory, not aspirational.** CNSA 2.0 requires PQC
   software signing by 2030, all NSS by 2031. NIST 800-131A disallows RSA-2048
   and ECC-224 after 2030. Every federal-adjacent org needs a migration plan
   *with evidence of progress*.
3. **Compliance is the budget unlock.** PCI DSS 4.0 Req 4.2.1.1 (mandatory
   since March 2025) requires a searchable cert inventory. SOC 2 auditors ask
   "who owns this cert and when does it rotate?" Tools that *generate the
   evidence* get bought; tools that show dashboards get evaluated.

---

## 3. Competitive Whitespace — What Nobody Else Does

| Capability | Venafi/CyberArk | Keyfactor/EJBCA | step-ca | Vault PKI | **Kryptkeeper** |
|---|---|---|---|---|---|
| Free OCSP + full CA in OSS | ❌ $$$$ | Partial (CE crippled) | ❌ paywalled | ✅ (no OCSP) | ✅ |
| ADCS replacement (XCEP/WSTEP) | Paid add-on | ❌ | ❌ | ❌ | ✅ **only OSS** |
| PQC issuance (ML-DSA + hybrid) | "experimental" | Partial | ❌ | ❌ | ✅ |
| Discovery (network + agent + cloud) | ✅ $$$$ | Partial | ❌ | ❌ | ✅ |
| Close-the-loop renewal (discover→issue→**install**→verify) | ✅ $$$$ | Partial | ❌ | ❌ | ◐ → **Moat 1** |
| PQC *migration journey* product | ❌ | ❌ | ❌ | ❌ | **Moat 2 — nobody** |
| AI-native ops (MCP, agentic PKI) | ❌ | ❌ | ❌ | ❌ | **Moat 3 — nobody** |
| Auditor-ready evidence packs | Partial | ❌ | ❌ | ❌ | ◐ → v1.4 |

The pattern: incumbents sell visibility and charge for action; OSS alternatives
give you a CA and stop. **The whitespace is closed-loop action + the two
transitions (47-day, PQC) + AI-native operation — all in OSS.**

### Positioning statement

> **Kryptkeeper: the open-source machine identity platform for the
> post-quantum, 47-day world.** Discover every cert and key you own, renew
> them without humans, prove it to your auditor, and migrate to PQC on a
> schedule — for $0 in license fees.

---

## 4. The Three Moats

### Moat 1 — Renewal Autopilot (win the 47-day transition)

Today the agent *discovers* certs and runs ACME renewal; the Hub schedules and
notifies. The missing link is **install**: putting the renewed cert where the
workload reads it and proving it's serving. Nobody in OSS closes this loop.

Target experience: *"Point the agent at a server. Every cert on it renews,
installs, reloads, and verifies forever. The dashboard shows automation
coverage as an SLO."*

- Agent auto-install: nginx first (largest fleet, simplest reload), then
  Apache, HAProxy, IIS (Windows agent already exists)
- Verify-after-install: agent re-handshakes the endpoint, confirms the new
  fingerprint is serving, reports back — renewal isn't "done" until verified
- Renewal SLO on the dashboard: % of inventory on autopilot, mean time to
  renew, failed-renewal queue
- ARI-driven staggering (shipped in v1.1) prevents thundering herds

### Moat 2 — PQC Migration Copilot (own the narrative before 2030)

We already issue ML-DSA and hybrid certs — table stakes by 2028. The product
nobody has is the **journey**: a CISO can't buy "PQC support," they need a
plan with dates and proof of progress.

- **Classify**: score every cert/key for harvest-now-decrypt-later exposure
  (long-lived TLS on sensitive paths, code-signing keys, VPN/SSH)
- **Plan**: migration waves auto-generated from inventory (test → internal →
  customer-facing), each wave a tracked set with owners and deadlines
- **Execute**: hybrid-cert rollout per wave using existing issuance
- **Prove**: CNSA 2.0 / NIST 800-131A countdown report — "X of Y migrated,
  on track for 2030" — trending over time (requires v1.2 snapshots)

### Moat 3 — AI-Native PKI Operations (category creation)

PKI ops is conversational by nature ("what expires this month?", "rotate
everything that CA signed") and dangerous enough to need guardrails. We have
the guardrail already: the **approval workflow**. That combination — agentic
ops with human-in-the-loop approval built into the PKI itself — does not
exist anywhere.

- MCP server exposing read tools (inventory, posture, reports, audit) and
  write tools (issue, renew, revoke, rotate) — **every write routes through
  the approval queue**; the AI proposes, a human approves, the audit log
  records both
- Killer demos: "show me every cert that fails PCI 4.2.1.1 and draft the
  remediation plan" / "CA-7 is compromised — stage bulk revoke + re-issue
  for everything it signed, queue for my approval"
- This is also the wedge into every AI-tooling-curious security team, and it
  composes with everything above (Autopilot actions, PQC waves)

---

## 5. Release Train

| Release | Theme | Contents | Effort |
|---|---|---|---|
| **v1.1.0** ✅ now | Ship what exists | Changelog, version tag, README truth, repo hygiene (untrack runtime keys) | done |
| **v1.2** | Visibility complete | **Approvals UI** (footgun fix: approval-required templates currently unmanageable from UI), ownership editing, SIEM settings page, renewal-scheduler status panel, SSH-key + code-signing pages, remaining 4 risk signals, **posture snapshots + trend charts** (foundation for Moat 2 proof) | ~2 wks |
| **v1.3** | Renewal Autopilot | nginx/Apache auto-install + reload, verify-after-install, renewal SLO dashboard, failed-renewal queue; IIS next | ~3 wks |
| **v1.4** | Audit-ready | PDF evidence packs (per-framework: PCI, SOC 2, FedRAMP), scheduled email delivery, branded executive one-pager | ~2 wks |
| **v1.5** | PQC Migration Copilot | HNDL risk classification, migration waves, hybrid rollout tracking, CNSA 2.0 countdown report | ~3 wks |
| **v2.0** | AI-native + scale | MCP server (approval-gated writes), SPIFFE/SVID issuance, multi-tenancy (policy folders), deep K8s discovery (Ingress/Istio) | ~6 wks |

Sequencing logic: v1.2 makes everything visible (and snapshots must start
accumulating early so v1.5 has trend data). v1.3 delivers the core value
promise. v1.4 converts users into champions ("my auditor loved it"). v1.5–v2.0
are the moats competitors can't fast-follow.

### Test debt paydown (runs alongside, not a release)
- UI tests for Keys, Templates, Agents, all report pages, and each new v1.2 page
- Go tests for `internal/db`, `internal/discovery`, `internal/notifications`
- E2E smoke: issue → renew → revoke → report on staging

---

## 6. Deliberately Not Doing

| Item | Why not |
|---|---|
| ServiceNow/ITSM integration | Pull-driven only — build when a real deployment asks; webhook + SIEM covers the integration story until then |
| F5/NetScaler/load-balancer provisioning | Niche hardware fleet; agent web-server install covers 90% of demand |
| Mobile/IoT MDM | Different product; Intune SCEP already covers the common case |
| Hosted SaaS | Self-hosted *is* the differentiator vs Venafi; revisit only with traction |
| Deep K8s before v2.0 | cert-manager issuer already serves the K8s-native crowd |

---

## 7. Standing Out — the Story to Tell

1. **"Replace ADCS in a weekend"** — the only OSS XCEP/WSTEP. Windows shops
   stuck on neglected AD CS are the beachhead market; the guide already
   exists (`docs/guides/replace-adcs.md`). Lead with it.
2. **The comparison matrix** (§3) on the website/README — OSS users decide
   from feature tables; ours is genuinely favorable.
3. **The 47-day countdown** — content marketing writes itself: "1,000 certs ×
   47 days = 8,500 renewals/year. Here's the math, here's the autopilot."
4. **First PKI with an MCP server** — one demo video of an AI agent staging a
   CA-compromise response behind an approval gate will travel further than
   any feature list.
5. **Auditor empathy** — every report exports the evidence in the format the
   framework asks for. "Built for the person who has to sit in the audit."
