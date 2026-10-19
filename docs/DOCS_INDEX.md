# Documentation Index

Rewritten 2026-09-10 (docs-truth-audit direction decisions D1–D4). Covers
through **W11–W18** (estate-management build) and **W19** (live-UAT plan).
**Rule: when a new planning doc overlaps an existing one, update this index
and mark the older draft historical** — the 2026-07→09 drift (fixed here)
happened because this rule was ignored for two months.

## Start here (current truth, in order)

2. `docs/DECISIONS.md` — the decision ledger (D-001..D-106+, vocabulary canon); new decisions land here only. Last confirmed current: 2026-07-15 (D-106 added 2026-08-18, still current)
3. `docs/sdlc/phase-0-ideation/VISION_V5.md` — the estate-management pivot (D-106): CA-agnostic inventory + takeover, source of the FR-P64..70 requirements. Last confirmed current: 2026-08-18
4. `docs/ROADMAP.md` — the public roadmap: everything deferred from 1.0.0, by theme, with a target (1.1, later, needs partner hardware); `docs/ROADMAP_PROCESS.md` is the rule that keeps it current. Last confirmed current: 2026-10-18
   - `docs/HARDENING_ROADMAP.md` — the hardening-track wave plan (W0–W18), exit criteria per wave (was `docs/ROADMAP.md` until 2026-10-18). Last confirmed current: 2026-07-15 (waves through W18 landed since; see STATUS.md)
5. `docs/NEXT_HORIZON.md` — V6 seed: what comes after the current wave plan, researched against the 2026-08 competitive landscape. Last confirmed current: 2026-08-19
6. `docs/UAT_PLAN.md` — the real-external-system UAT bar (fakes are not evidence); status matrix (4 passed / 8 todo / 3 blocked) and W19-01..12. Last confirmed current: 2026-09-10
8. `docs/PRODUCT_SRS.md` — FR-P/NFR-P requirements, now carrying a Status column traced to the board + STATUS.md. Last confirmed current: 2026-09-10
9. `docs/DOCS_TRUTH_AUDIT_2026-09-10.md` — the audit this index rebuild resolves (D1–D4); kept as the historical record of what was stale and why

## Operate

- `docs/ops/PILOT_RUNBOOK.md` — private design-partner pilot: source tarball/clone + Compose + SQLite, the supported pilot shape
- `docs/ops/PILOT_KNOWN_GAPS.md` — what is verified live vs fakes-only for the pilot. Last confirmed current: 2026-09-10
- `docs/ops/WINRM_ENABLEMENT.md` — enabling WinRM HTTPS on a target Windows host for discovery/install. Last confirmed current: 2026-08-27
- `docs/ops/WINDOWS_ACCESS_MATRIX.md` — required Windows credentials/permissions matrix per operation. Last confirmed current: 2026-08-27
- `docs/ops/DR_RUNBOOK.md` — disaster-recovery procedure; live-proven via `docs/ops/RESTORE_DRILL.md`. Last confirmed current: 2026-07-19
- `docs/ops/RESTORE_DRILL.md` — the executed backup/restore drill record (S-01). Last confirmed current: 2026-07-28
- `docs/ops/KEY_ROTATION.md` — planned/routine CA and key rotation procedure
- `docs/ops/INCIDENT_RESPONSE.md` — CA-compromise response procedure
- `docs/ops/AIRGAP_INSTALL.md` — offline/air-gapped install bundle (FR-P61)
- `docs/ops/OIDC_JWKS_RUNBOOK.md` — OIDC discovery + JWKS rotation, fail-closed behavior
- `docs/deployment.md` — the three deployment targets: Compose, Kubernetes/Helm, bare metal/air-gapped
- `docs/ops/grafana-dashboard.json`, `docs/ops/pki-slo-dashboard.json` — operational dashboards
- `docs/release/ACR_VPAT_v0.21.md` — Accessibility Conformance Report (VPAT 2.5, WCAG 2.2 A/AA) for the v0.21 UI; self-assessment, manual screen-reader fields `PENDING-RUN`. Last confirmed current: 2026-10-17
- `docs/guides/*` — end-user how-tos: `getting-started.md`, `day-one-estate.md`, `replace-adcs.md`, `migrate-from-venafi.md`, `migrate-from-certcentral.md`, `migrate-from-keyfactor.md`, `migrate-from-vault-pki.md`, `intune-byoca.md`, `pqc-certificate.md`, `spiffe.md`, `mcp-server.md`
- Security posture audits: `docs/ops/ws-01-ws-02-security-audit-latest.md`, `docs/ops/ws-05-08-db-adapter-security-audit.md`, `docs/ops/ws-05-08-provider-security-audit.md`, `docs/ops/ws-10-ci-workflow-reaudit-fail-closed.md`, `docs/ops/ws-10-ci-workflow-reaudit-latest.md` (superseded: `docs/ops/ws-10-ci-workflow-baseline-review.md`, `docs/ops/workflow-hardening-report-2026-04-06.md`)

## Build

- `CLAUDE.md` — the mandatory house rules for any session touching this repo
- `CONTRIBUTING.md` — code conventions (feature-sliced layout, no global state, atomic commits)
- `docs/TEST_STRATEGY.md` — test tooling and coverage strategy. Last confirmed current: 2026-09-10
- `docs/sdlc/phase-3-design/ARCHITECTURE.md` — software architecture document (Phase 3). Last confirmed current: 2026-04-05
- `docs/sdlc/phase-3-design/DATABASE.md` — database design (Phase 3, v2.0). Last confirmed current: 2026-07-28
- `docs/sdlc/phase-3-design/API_DESIGN.md` — REST API design (Phase 3). Last confirmed current: 2026-04-05
- `docs/sdlc/phase-3-design/TECH_STACK.md`, `docs/sdlc/phase-3-design/THREAT_MODEL.md` — stack rationale and STRIDE threat model
- `docs/COMPONENT_MAP.md` — current codebase structure / runtime data model review (supplements the Phase 3 docs)
- `docs/openapi.yaml` — the API contract; `ui/` generates its TypeScript types from this (`npm run gen:api-types`), 0 drift enforced as of 2026-09-10
- `docs/design/{DESIGN_PRINCIPLES,STYLE_GUIDE,UX_SPEC,INFORMATION_ARCHITECTURE,TENANCY_POSTURE,FIPS_POSTURE,FINDING_ECONOMICS}.md` — design-system and cross-cutting posture docs
- `docs/sdlc/phase-1-planning/{SCOPE,RISKS,CONSTRAINTS,USER_PERSONAS}.md`, `docs/sdlc/phase-2-requirements/{SRS,USER_STORIES}.md` — foundational requirements, still authoritative for personas/base SRS (superseded/extended by `docs/PRODUCT_SRS.md`'s FR-P series for golden-state + estate scope)
- `docs/research/CLM_LEADERSHIP_2026.md`, `docs/research/RESEARCH_FINDINGS.md` — see Research below
- `CHANGELOG.md` — per-release notes, v1.0 through v2.2

## Research

- `docs/research/CLM_LEADERSHIP_2026.md` — 2026 competitive brief; basis for the FR-P tiering (T1/T2/T3) in `docs/PRODUCT_SRS.md`
- `docs/research/RESEARCH_FINDINGS.md` — supporting research findings feeding the same brief

## Historical (do not use for decisions)

- `docs/archive/GO_FORWARD_PLAN.md` — June 2026 "Three Moats" plan; superseded 2026-09-10 by D-106 + VISION_V5.md (banner added, moved from `docs/GO_FORWARD_PLAN.md`)
- `docs/STRATEGIC_GAP_ANALYSIS.md` — superseded by the (now archived) GO_FORWARD_PLAN; lists shipped features as gaps (banner added)
- `docs/HEALTH_ASSESSMENT.md` — pre-v1.1 snapshot (banner added)
- `docs/{FULL_IMPROVEMENT_PLAN,IMPROVEMENT_PLAN_V2,UX_IMPROVEMENT_PLAN,UX_BACKLOG}.md`, `docs/reviews/*`, `docs/improve/*`, `docs/SPRINT_1_EXECUTION.md`, `docs/SPRINT_1_PLAN.md`, `docs/SPRINT_3_PLAN.md`, `docs/work/SPRINT_2_PLAN.md`, `docs/PHASE_3_ROADMAP.md` — completed/abandoned improvement and sprint arcs
- `docs/ANALYST_REPORT_2026-07-31.md`, `docs/UI_REVIEW_2026-07-31.md` — point-in-time analyst/UI review snapshots
- `docs/reviews/CODE_REVIEW_2026-04-06.md`, `docs/reviews/CODE_REVIEW_2026-04-07.md`, `docs/reviews/CODE_REVIEW_2026-04-09.md`, `docs/reviews/IMPROVEMENT_PLAN_V2_COMPLETE.md` — closed code-review cycles
- `docs/AGENT_REMEDIATION_PLAN.md` — April incident record; note its §9 "Applied fix" is contradicted by §10 (G-26)
- `docs/{FEATURE_CONTEXT,FEATURE_IMPACT_ANALYSIS,FEATURE_IMPLEMENTATION_PLAN,FEATURE_EXECUTION_CHECKLIST,FEATURE_API_REQUIREMENTS,FEATURE_UI_SPEC,DESIGN_CONTEXT,LANDSCAPE}.md` — April working set, reference only
- `docs/API_DESIGN.md`, `docs/DATABASE.md` — earlier top-level WS-02 MVP / Phase-4 migration-plan drafts, superseded by `docs/sdlc/phase-3-design/{API_DESIGN,DATABASE}.md` above
- `docs/v1.2_VISIBILITY_SPRINT.md`, `v1.3_RENEWAL_AUTOPILOT_SCOPE.md`, `v1.3.1_AGENT_PERSISTENCE_SCOPE.md`, `v1.4_AUDIT_READY_SCOPE.md`, `v1.5_PQC_COPILOT_SCOPE.md`, `v2.0_AI_NATIVE_SCOPE.md`, `v2.1_SPIFFE_SCOPE.md`, `v2.2_MULTI_TENANCY_SCOPE.md` — shipped-release scope records, all superseded by the wave-based board
- `docs/git/FEATURE_improve-crypto-inventory-vision.md` — a single completed feature-branch working doc
- `docs/sdlc/SDLC_STATUS.md`, `docs/sdlc/SDLC_TRACKER.md` — frozen-historical (banner added; V1–V4 scheme retired per D-018)
- `docs/sdlc/v2-implementation/`, `docs/sdlc/v3-implementation/`, `docs/sdlc/v4-planning/`, `docs/sdlc/phase-4-implementation/`, `docs/sdlc/phase-4b-implementation/` — superseded phase-snapshot directories from the pre-wave SDLC cadence
- `docs/SRS_REVIEW_ADDENDUM.md` — addendum to the original Phase-2 SRS, now folded into `docs/PRODUCT_SRS.md`'s FR-P series
