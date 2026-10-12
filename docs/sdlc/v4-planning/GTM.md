# Kryptkeeper — Go-to-Market Plan
**Date:** 2026-04-24
**Horizon:** 12 months post-launch

---

## Market Context

- CyberArk (Venafi) + Keyfactor dominate enterprise PKI/CLM — combined $100K–$1M+/yr
- 95% of orgs have not automated cert management — 47-day cert deadline forces action
- No open-source product covers: CA + CLM + ADCS replacement + PQC + crypto reporting
- TAM: $60B (CyberArk estimate at Venafi acquisition)
- ICP (Ideal Customer Profile): 500–10,000 employee enterprise; Windows shop or migrating; security-conscious; budget-constrained

---

## Positioning

**One-liner:**
> "Kryptkeeper: the open-source crypto trust platform. Replace ADCS, automate cert lifecycle, and issue quantum-safe certificates — all from a single binary."

**Tagline options:**
- "Guard your cryptographic trust."
- "The PKI your team can actually own."
- "Open-source ADCS replacement. PQC-ready."

**Why choose Kryptkeeper over:**

| Competitor | Our pitch |
|---|---|
| Venafi/CyberArk | Open-source core, no per-cert pricing, single Go binary vs complex enterprise stack |
| Keyfactor Command | EJBCA Community locks out ACME/EST/PQC; Kryptkeeper is full-featured OSS |
| step-ca | No Windows GPO autoenrollment, no OCSP in OSS, no discovery — Kryptkeeper does all of it |
| EJBCA Community | Java EE stack, weeks to deploy, PQC behind paywall — Kryptkeeper is one binary, PQC free |
| HashiCorp Vault PKI | A CA engine, not a platform — no discovery, no UI, no ADCS. Different tool. |
| Microsoft ADCS | Requires Windows Server + Domain Admin. Kryptkeeper runs on Linux, same GPO integration. |

---

## Distribution Channels

### Channel 1: Open Source (GitHub) — Primary
- Apache 2.0 license; all core features free
- GitHub Releases with signed binaries (amd64 + arm64)
- Docker Hub + GHCR images
- Helm chart on Artifact Hub
- GitHub Actions marketplace action
- **Goal:** 200 stars in 30 days of launch

### Channel 2: Content / SEO
High-value search queries to target:
- "ADCS replacement open source"
- "replace active directory certificate services linux"
- "certificate lifecycle management open source"
- "47 day ssl certificate automation"
- "post quantum certificate authority"
- "ML-DSA certificate issuance open source"

Content to produce:
- "Replace ADCS with Kryptkeeper" (blog + HN)
- "Issue your first PQC certificate in 5 minutes"
- "How to automate SSL renewal for 47-day certs"
- "Kryptkeeper vs. EJBCA vs. step-ca: The 2026 comparison"
- "Microsoft Intune BYOCA: replace NDES with Kryptkeeper"

### Channel 3: Community / Ecosystem
- cert-manager community: publish issuer plugin → get listed in cert-manager docs
- HashiCorp Registry: publish Terraform provider
- CNCF Slack: promote in #cert-manager, #security channels
- PKI Consortium: submit for inclusion in community resources
- r/netsec, r/sysadmin, r/devops launch posts
- HackerNews "Show HN" post on launch day

### Channel 4: Enterprise Direct (Month 6+)
- Inbound leads from OSS users hitting limits (multi-tenancy, HSM certifications, SLA support)
- Direct outreach to enterprises known to be migrating off ADCS
- Security conference presence (BSides, KubeCon)
- Partnership with HSM vendors (Thales, Utimaco) — list as compatible platform

---

## Launch Sequence

### T-minus 4 weeks (Week 10)
- [ ] Documentation site live (staging)
- [ ] Demo video recorded and edited
- [ ] Blog posts drafted and reviewed
- [ ] Social media assets ready

### T-minus 2 weeks (Week 12)
- [ ] Release candidates tested by 2–3 friendly beta users
- [ ] GitHub Discussions enabled; community welcome post ready
- [ ] HN post draft finalized
- [ ] Helm chart submitted to Artifact Hub review

### Launch Day (Week 14)
- [ ] `git tag v1.0.0` + GitHub Release published with signed binaries
- [ ] Docker images pushed
- [ ] Helm chart live on Artifact Hub
- [ ] HackerNews "Show HN" post published (aim for 9am EST Tuesday or Wednesday)
- [ ] Reddit posts in r/netsec and r/sysadmin
- [ ] LinkedIn + X posts
- [ ] Documentation site live on custom domain

### T-plus 1 week
- [ ] Respond to every GitHub issue and HN comment
- [ ] Blog post #2: "What we learned from the first week"
- [ ] Monitor stars, forks, Docker pulls

---

## Pricing (Commercial Tier)

### OSS — Free forever (Apache 2.0)
Everything in the platform. No feature gating. No cert limits. No node limits.

### Enterprise — Starting $15K/yr
What enterprise adds ON TOP of OSS:
- Multi-tenancy (org/team isolation, MSP deployments)
- Advanced reporting (custom branding, scheduled delivery, board-ready PDF templates)
- FIPS 140-3 validated deployment guide + testing support
- Air-gapped CA ceremony tooling + documentation
- SLA: 4-hour response for P1 issues
- Professional services: deployment, migration from ADCS, PKI architecture review
- FedRAMP-ready configuration templates (Year 2)

### Enterprise pricing tiers

| Tier | CAs | Users | Nodes | Price/yr |
|---|---|---|---|---|
| Startup | 3 | 10 | 500 | $15,000 |
| Business | 10 | 50 | 5,000 | $45,000 |
| Enterprise | Unlimited | Unlimited | Unlimited | $120,000+ |

*Pricing anchored below Keyfactor ($50K+) and Venafi ($100K+) at all tiers.*

---

## Metrics and Success Targets

### Launch Day + 30 days
- GitHub stars: 200+
- Docker pulls: 500+
- GitHub issues opened: 20+ (healthy indicator)
- HN upvotes: 100+ / front page

### Month 3 (after launch)
- GitHub stars: 500+
- Active installations: 50+ (via telemetry opt-in)
- Community contributors: 5+
- Enterprise inquiries: 3+

### Month 6
- GitHub stars: 1,000+
- Paying enterprise customers: 1
- cert-manager plugin: listed in official docs
- Terraform provider: published on HashiCorp Registry
- Blog posts indexed and driving organic traffic (track via GitHub referrers)

### Month 12
- GitHub stars: 2,000+
- Paying enterprise customers: 3–5
- ARR: $50K–$150K
- Recognized in analyst reports (Gartner, Forrester CLM coverage)

---

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Low launch traction | Prepare 3 launch channels simultaneously (HN + Reddit + Twitter); time for peak traffic day/time |
| Competitor OSS response (EJBCA adds PQC to community) | Kryptkeeper's single-binary UX + Go stack + ADCS integration still differentiates |
| Enterprise conversion slow | Free tier is generous enough to build trust; don't rush conversion; let product sell itself |
| Support overhead kills velocity | Clear CONTRIBUTING.md; templates for issues; auto-close stale issues after 60 days |
| Pricing too high | Start at $15K/yr as floor; negotiate up; publish pricing publicly to avoid enterprise friction |

---

## Immediate Next Actions (Pre-Launch Checklist)

1. Finish Sprint 3 (WS-01 through WS-07)
2. Start docs site skeleton in parallel (Week 6)
3. Record demo video (Week 10)
4. Publish to Artifact Hub + GHCR (Week 12)
5. Beta test with 2–3 volunteer users (Week 12)
6. Launch (Week 14)
