# Documentation Index

Rewritten 2026-09-10 (docs-truth-audit direction decisions D1–D4). Covers
through **W11–W18** (estate-management build) and **W19** (live-UAT plan).
**Rule: when a new planning doc overlaps an existing one, update this index
and mark the older draft historical** — the 2026-07→09 drift (fixed here)
happened because this rule was ignored for two months.

## Start here (current truth, in order)

2. `docs/DECISIONS.md` — the decision ledger (D-001..D-106+, vocabulary canon); new decisions land here only. Last confirmed current: 2026-07-15 (D-106 added 2026-08-18, still current)
4. `docs/ROADMAP.md` — the public roadmap: everything deferred from 1.0.0, by theme, with a target (1.1, later, needs partner hardware); `docs/ROADMAP_PROCESS.md` is the rule that keeps it current. Last confirmed current: 2026-10-18

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
- Security posture audits: `docs/ops/ws-01-ws-02-security-audit-latest.md`, `docs/ops/ws-05-08-db-adapter-security-audit.md`, `docs/ops/ws-05-08-provider-security-audit.md`, `docs/ops/ws-10-ci-workflow-reaudit-fail-closed.md`, `docs/ops/ws-10-ci-workflow-reaudit-latest.md` (superseded: `docs/ops/ws-10-ci-workflow-baseline-review.md`, `docs/ops/workflow-hardening-report-2026-04-06.md`)

## Build

- `CONTRIBUTING.md` — code conventions (feature-sliced layout, no global state, atomic commits)
- `docs/TEST_STRATEGY.md` — test tooling and coverage strategy. Last confirmed current: 2026-09-10
- `docs/COMPONENT_MAP.md` — current codebase structure / runtime data model review (supplements the Phase 3 docs)
- `docs/openapi.yaml` — the API contract; `ui/` generates its TypeScript types from this (`npm run gen:api-types`), 0 drift enforced as of 2026-09-10
- `docs/design/{DESIGN_PRINCIPLES,STYLE_GUIDE,UX_SPEC,INFORMATION_ARCHITECTURE,TENANCY_POSTURE,FIPS_POSTURE,FINDING_ECONOMICS}.md` — design-system and cross-cutting posture docs
- `CHANGELOG.md` — per-release notes, v1.0 through v2.2

## Research


## Historical (do not use for decisions)

- `docs/{FEATURE_CONTEXT,FEATURE_IMPACT_ANALYSIS,FEATURE_IMPLEMENTATION_PLAN,FEATURE_EXECUTION_CHECKLIST,FEATURE_API_REQUIREMENTS,FEATURE_UI_SPEC,DESIGN_CONTEXT,LANDSCAPE}.md` — April working set, reference only
- `docs/work/{HANDOFF,GOLDEN_STATE,DECISIONS_PENDING,DELEGATION_LOG,sdlc-state,READINESS_REPORT,PRODUCT_ENHANCEMENTS,IMPROVEMENT_RECOMMENDATIONS,DESIGN_REVIEW,SECURITY_S,SECURITY_W1,SECURITY_W2,SECURITY_W3,SECURITY_W4,SECURITY_W5,SECURITY_W6,SECURITY_W8,SECURITY_W10,MANIFEST_fix-agentstore-share,MANIFEST_fix-lint-path,MANIFEST_S-35}.md` — the 2026-07 design-review/hardening arc's working papers, superseded by the completed wave plan and STATUS.md
- `docs/sdlc/v2-implementation/`, `docs/sdlc/v3-implementation/`, `docs/sdlc/v4-planning/`, `docs/sdlc/phase-4-implementation/`, `docs/sdlc/phase-4b-implementation/` — superseded phase-snapshot directories from the pre-wave SDLC cadence
