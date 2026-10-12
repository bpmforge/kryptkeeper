# Kryptkeeper — Product Vision V5
# "Manage the Whole Estate, Not Just Our Certs"

**Version:** 5.0
**Date:** 2026-08-18
**Phase:** V5 Planning — CA-agnostic estate management
**Status:** direction locked (D-106); wave W11 filed on the golden-state board

> "Every certificate a customer has — not just every certificate we issued —
> inventoried, risk-scored, and one click away from being managed."

---

## 1. What changed since V4

V4 made Kryptkeeper the **Crypto Trust Platform**: full CA, every enrollment
protocol, PQC issuance, discovery, key management, ADCS replacement. That
trajectory is ~28 tickets from its board-defined golden state, and it is the
*EJBCA-killer* shape: superb at managing certificates **Kryptkeeper issued**.

The gap V5 closes is the other half of the market. Venafi's category-defining
insight was never "be a CA" — it was **CA-agnostic management**: most
enterprises hold certificates from DigiCert, Entrust, Sectigo, Let's Encrypt,
ADCS, and three acquisitions' worth of forgotten issuers, and what they buy
first is *visibility and control over that mess*, long before they consider
switching CAs. Our own 2026 competitive brief lists "direct-CA import" inside
Tier-1 capability #1 — and until W11, no ticket implemented it.

**V5 = V4's platform + the estate layer.** Being a CA remains a strength (and
the eventual takeover destination); it stops being a prerequisite for being
useful.

## 2. The estate model (the conceptual core)

Every certificate in inventory carries two new first-class dimensions:

- **origin** — `internal` (our CA) · `imported` (operator-supplied) ·
  `discovered` (scanner/agent/CT found it) · `synced` (pulled from an
  external CA's own records)
- **management_state** — `managed` (we renew/install/govern it) ·
  `external` (another system manages it; we watch and report) ·
  `unmanaged` (nobody demonstrably manages it — the risk column)

The dashboard's headline becomes an **estate picture**: N certificates known,
X% managed, Y externally managed, Z unmanaged — with risk scoring, expiry
timelines, CBOM, and PQC readiness computed across *all* of them, not just
ours. That is the auditor/board answer no OSS product gives today.

## 3. The three capability pillars of V5

**Pillar 1 — See everything (inventory the other streams).**
Bulk import (PEM/PKCS#7/CSV/API). Direct-CA sync connectors that pull
inventory from the systems that issued it: ADCS first (largest install base,
already our migration story), then a commercial-CA adapter framework
(DigiCert/Sectigo/Entrust as adapters against one interface). CT-log
monitoring (W6-06) feeds the same funnel: a cert we didn't know about becomes
an `unmanaged` inventory row, not just a finding.

**Pillar 2 — A path to manage each of them (the takeover flow).**
From any unmanaged/external row: assign owner → choose a management path →
done. Paths: (a) **renew internally** — next renewal is issued by a
Kryptkeeper CA (the migration wedge V4 already built); (b) **renew upstream**
— Kryptkeeper drives renewal *at the original CA* through a connector (ACME
client with EAB covers Let's Encrypt and every RFC 8555 public CA; commercial
adapters cover the rest) and then runs our existing last-mile
install/verify/rollback machinery. The customer keeps their CA relationships;
we keep the automation loop. This is the "Venafi 2.0" mechanic.

**Pillar 3 — Govern the streams beyond TLS.**
SSH: we inventory keys today (V3); V5 adds an **SSH CA** — short-lived SSH
certificates with the same templates/approvals/audit spine, killing
authorized_keys sprawl. Scope decisions recorded rather than dodged: KMIP
deferred until a customer pulls it; PGP/OpenPGP explicitly out of scope
(signing needs are served by code-signing; nothing in the target market asks
Venafi-class tools for PGP).

## 4. Why this is still one product

The estate layer reuses the spine V1–V4 built: the same inventory tables,
risk scoring, ownership, approvals, audit log, notification channels,
discovery funnel, renewal scheduler, and last-mile installers. Connectors are
providers behind interfaces, exactly like keystores and certificate providers
today ("crypto.Signer is sacred" extends to "the issuer is an interface").
No second pane of glass, no separate agent.

## 5. Sequencing (W11 on the golden-state board)

Foundation first: the estate model + bulk import land before connectors, so
every connector has one place to write. Then the ACME upstream connector
(cheapest, covers the public-CA half of every estate), ADCS sync-in (largest
enterprise base, feeds the replacement story), the commercial adapter
framework, and the takeover-flow UI that ties it together. SSH CA rides in
parallel — it touches sshkeys + templates, not the connector layer.

W11 does not preempt W4–W10 exit criteria; it runs as its own lane. The two
tracks converge at the dashboard: one estate, one risk model, one report.

## 6. Success metrics (V5-specific)

- A customer with zero Kryptkeeper-issued certs gets a complete, risk-scored
  estate picture within one day of install (import + ADCS sync + discovery).
- One-click takeover: an unmanaged cert becomes managed-with-renewal-path in
  a single flow, both internal and upstream paths demonstrated end-to-end.
- Renewal through the ACME upstream connector survives the 47-day world:
  request→issue→install→verify with no human step.
- The estate report (managed/external/unmanaged split + PQC readiness across
  all origins) exports for the board — the number Venafi charged for.
