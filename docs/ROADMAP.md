# Kryptkeeper — Hardening Roadmap (design-review arc)

**Date:** 2026-07-15 · derived from `docs/work/IMPROVEMENT_RECOMMENDATIONS.md` (adopted) +
the G-x gap register. Waves gate on exit criteria; a wave opens when the prior wave's
non-infra tickets are `done`. Board: `docs/board/plan.json` (machine-validated by
`scripts/validate-plan.mjs` + `scripts/validate-traceability.mjs`).

This roadmap governs the **hardening track**, parallel to the product release train
(`vX.Y.Z`, DECISIONS D-018). It does not renumber releases; its output is likely a v2.2.x
hardening release + a v2.3 tenancy track.

> Release numbering changed 2026-10-09: the first public release is v0.9.0; the earlier
> vX.Y.Z names are internal milestones (tags `internal/vX.Y.Z`).

## W0 — Truth & CI integrity (unblock everything)
Make the gates real and the docs honest. **Exit:** UI CI lane executes and gates (FR-R1);
a runner is registered OR CI is explicitly declared local-only (NFR-R1/HP-2); multi-tenancy
doc claims corrected (R-B5); telemetry statement shipped (R-F2). Most doc-truth work landed
in the P1 fix pack; W0 tickets are the code/config + remaining honesty edits.

## W1 — Contract & agent hardening
**Exit:** OpenAPI matches routes + CI-validated (FR-R3); nightly gate runs real suites
(FR-R2); MCP identity structurally non-approving (FR-R8) + rate limits (FR-R9); alert
cooldown/silence (FR-R12); lint boundary config present (NFR-R5).

## W2 — Tenant enforcement + finding economics
**Exit:** tenant write-path/single-GET enforcement (FR-R5) + reports scoping (FR-R6) +
audit tenant context (FR-R7); dedup/staleness wired (FR-R11); alert lifecycle + renewal
failure handling (FR-R13) + migration-wave lifecycle (FR-R14); `FINDING_ECONOMICS.md`
design landed with the accepted-risk primitive (FR-R10 phase 1). **Status (v0.9):** the exception store exists but no API creates exceptions; finding exceptions / risk acceptance / suppression are **planned for v0.10** and are hidden in the UI until then. Security-adjacent
code-quality: plaintext agent tokens (FR-R16), UI SAN field (FR-R15).

## W3 — Identity-bound tenancy + funnel completion (v2.3 track)
**Exit:** identity-derived tenant binding, `X-Tenant` demoted to super-admin view-as, FKs
added (FR-R4); finding funnel effective-counts surfaced end-to-end (FR-R10 phase 2; **planned for v0.10** — suppressed is always 0 in v0.9);
MCP HTTP transport + image (FR-R17).

---

# Golden-state track (product + leadership) — W4–W7

Parallel to the hardening waves above. Basis: `docs/PRODUCT_SRS.md` (FR-P) + the 2026 competitive
brief (`docs/research/CLM_LEADERSHIP_2026.md`). Reaches CLM category leadership. Hardening (W0–W3)
and this track can run concurrently by different agents where lanes don't collide; the validators
enforce non-overlap.

## W4 — Complete the loops (Tier-1 survival)
The three things you already sell that don't fully fire, + the free-EAB wedge.
**Exit:** notifications deliver on all channels (FR-P1); the fleet scheduler renews (FR-P2);
PQC has a migrate-wave execute action (FR-P3); ACME EAB ships (FR-P4). **Start here** — nothing
downstream matters if alerts don't send and autopilot doesn't renew.

## W5 — Broaden the addressable surface (+ agentless framework)
**Exit:** install covers nginx/apache/HAProxy/IIS + F5/Citrix + k8s/Istio (FR-P5/6/7); issuance
policy engine (FR-P8); MCP issue/renew/rotate (FR-P9); agent attestation (FR-P23); reports→action
(FR-P1). **Agentless made first-class:** managed-target/fleet model (FR-P24), outbound credential
store (FR-P25), hub-side SSH Executor (FR-P26 — the agentless-install crux; F5/Citrix/k8s adapters
plug into it), DB-persisted + scheduled agentless discovery with cloudinventory wired (FR-P27).
Moves the moat from "nginx-on-Linux-with-an-agent" to a heterogeneous fleet in either mode.

## W6 — Enterprise core + differentiators
**Exit:** HA/clustering (FR-P10); SSO/SCIM + custom RBAC (FR-P11); HSM/KMS complete (FR-P12);
key escrow/recovery (FR-P13); CBOM/CycloneDX export (FR-P14); CT-log monitoring (FR-P15);
cross-signing (FR-P16). Table-stakes enterprise + three differentiators leaders underplay.

## W7 — Frontier / leadership whitespace
**Exit:** SPIFFE workload identity + attestation (FR-P17); AI-agent/NHI identity (FR-P18);
SLO-native PKI ops (FR-P19); AI-assisted ops (FR-P20); CSV/XLSX export (FR-P21); service-mesh
discovery (FR-P22). The category-creation bets — issue identity *for* AI agents, run PKI as an
SRE-instrumented service.

## W8 — UX, onboarding & in-app configuration
The product has strong UI bones (loading/error/skeletons, ⌘K, Approvals inbox, Alerts center) but no
journeys and ~95% env-only config. **Exit:** a wizard/stepper primitive (FR-P28); day-0 onboarding
wizard replacing the empty-dashboard dead end (FR-P29); in-app config store + Integrations UI so
notification/SSO/key-backend/renewal settings are editable without env edits + restart (FR-P30/31);
guided issuance (FR-P32) + renewal-policy (FR-P33) flows; **interactive agent-vs-agentless setup**
(FR-P34 — token-gen+pairing or target+mode+credential); role-aware nav (FR-P35); PQC migration journey
UI (FR-P36); command-palette actions + empty-state CTAs (FR-P37/38); SSE real-time + bulk actions
(FR-P39/40); refreshed IA/design docs for the 29-page product (NFR-P3).

## W9 — Key management (fixes + lifecycle)
The key-management map found **broken paths, not just gaps**. **Exit (bugs first):** PKCS#11 HSM
compiles + is tested (FR-P41); Cloud KMS wired + persisted (FR-P42); PQC/hybrid key export works
(FR-P43); CA re-key lifecycle + the bare-RotateKey guard (FR-P44). **Then leader features:** key-gen
policy (FR-P45), M-of-N ceremony (FR-P46), secure destruction/zeroization (FR-P47), HSM-for-PQC
(FR-P48), per-key ACL + auto-rotate + compromise flow (FR-P49), dual-control (FR-P50), FIPS posture
(FR-P51), and escrow (W9-12, depends the PQC-export fix).

## W10 — Deployment, release & operability
The deployment map found the release/upgrade path is **designed but unproven and partly broken**.
**Exit (bugs first):** a real versioned migration runner (FR-P52 — the 20 migrations are dead code
today, an upgrade-correctness risk); functional `/readyz` (FR-P53); CA-key + DB backup/restore + DR
with an executed drill (FR-P54 — disk loss = permanent CA loss today); fix the deploy pipeline
(FR-P55 — smoke.sh 404s, deploy scripts unwired); reconcile the Helm chart + image path +
external-secrets (FR-P56, default install fails today). **Then:** compose quickstart (FR-P57),
agent/MCP/certmanager images (FR-P58), chart HA/observability (FR-P59), metrics everywhere (FR-P60),
air-gap bundle (FR-P61), IaC (FR-P62), packaging + signing reconcile (FR-P63).

## W11 — Estate management: CA-agnostic inventory + takeover (V5, D-106)
The Venafi mechanic on our platform: manage certificates *other* CAs issued.
**Exit (foundation first):** estate model on inventory — origin + management_state — with the
dashboard/report split (FR-P64); bulk import with dedupe (FR-P65). **Then connectors:**
external-issuer framework the internal engine also satisfies (FR-P66); ACME upstream client with
EAB so renewal executes at the original CA and flows into our last-mile install (FR-P67); ADCS
sync-in + commercial-CA adapter interface, read-only pull first (FR-P68). **Then the payoff:**
one-click approval-gated takeover flow — unmanaged → owned → renewal path chosen (FR-P69).
**In parallel:** SSH CA extending sshkeys inventory to issuance (FR-P70). CT-log (W6-06) feeds
the same unmanaged funnel. Scope recorded: KMIP deferred, PGP out (D-106).
Basis: `docs/sdlc/phase-0-ideation/VISION_V5.md`.

## Spec discipline (NFR-P4, D-078)
Every ticket gets a decision-complete spec in `docs/board/specs/<id>.md` (template + `_TRAPS.md` in
that dir) before it is claimed, so a cheaper model executes it without design decisions.
`validate-plan.mjs` reports spec coverage. Exemplars written: W4-01, W5-09, W5-11, W8-01, W8-02, W8-06.

## Standing / any-wave
Runbooks + executed restore drill (G-8), DATABASE.md regen (G-6), nginx `/readyz` (G-9),
terraform registry publish (G-16, gated on HP-4), pkg/errors→stdlib (G-20).

## Exit-criteria gate (every wave)
1. All wave tickets `done`; validators green.
2. Every FR-R in the wave maps to a named test (TEST_STRATEGY).
3. Ralph coverage loop (cap 3, byte-identical halt) then a fresh-agent CHALLENGER
   (maker≠verifier, independent re-runs) before the STATUS gate entry lands.

## W12 — Wiring wave (landed seams become running defaults)
CT-monitor start, SLO sweep + live expiry histogram, anomaly notifier, mesh-discovery
scheduling, F5/Citrix/K8s pushers into renewal targets, custom-roles admin API,
and the productized day-one estate exercise. Basis: `docs/NEXT_HORIZON.md` §3-D.

## W13 — Drive every CA (estate write-breadth)
WSTEP/CES client against a running Windows ADCS (replace-or-drive story), DigiCert
write adapter, SCEP/EST client modes, live ADCS LDAP sync (go-ldap decision), and
Sectigo/Entrust/AWS-PCA/Google-CAS sync sources. Basis: `docs/NEXT_HORIZON.md` §3-A.

## W14 — See everything (agentless + crypto scanning)
Agentless Linux over the existing SSH executor, agentless Windows via WinRM/PowerShell
remoting (stdlib-SOAP-first, dependency decision pre-flagged), STARTTLS/SSH/RDP
protocol-aware scanning, endpoint crypto-posture probe (incl. ML-KEM-on-the-wire
detection), JKS/PKCS#12 host keystores. Basis: `docs/NEXT_HORIZON.md` §3-B.

## W15 — One key plane
Unified AWS/Azure/GCP key inventory with PQC scoring, key-custody evidence in the
compliance packs, BYOK from escrowed roots; leaf-key escrow filed BLOCKED on the
custody decision (decided together with KMIP). Basis: `docs/NEXT_HORIZON.md` §3-C.

## W16 — Next-wave bets (category creation)
Verifiable audit (Merkle transparency log + external verifier — auditors verify
instead of trust), blast-radius graph with what-breaks-if pre-flight on approvals,
crypto-agility orchestration generalizing PQC waves to any algorithm transition,
cluster-atomic rollout groups with canary, DORA/NIS2 evidence mappings.
