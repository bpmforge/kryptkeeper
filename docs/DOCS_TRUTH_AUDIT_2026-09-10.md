# Docs Truth Audit — 2026-09-10

**Summary:** 16 documents audited (README.md, CLAUDE.md, MASTER_PROMPT.md,
PLAYBOOK.md, CONTRIBUTING.md, docs/ROADMAP.md, docs/PRODUCT_SRS.md,
docs/sdlc/phase-0-ideation/VISION_V5.md, docs/DOCS_INDEX.md,
docs/deployment.md, docs/NEXT_HORIZON.md, docs/GO_FORWARD_PLAN.md,
docs/ops/PILOT_RUNBOOK.md, docs/ops/PILOT_KNOWN_GAPS.md,
docs/ops/WINDOWS_ACCESS_MATRIX.md, docs/TEST_STRATEGY.md).
9 mechanical fixes applied across 6 files. 4 direction decisions pending for
the owner. 0 new orphans found — the existing ones are already correctly
banner-marked in docs/DOCS_INDEX.md's "Historical" section.

---

## Section 1 — Mechanical (fixed)

| # | File:line (before) | Before | After | Evidence |
|---|---|---|---|---|
| 1 | CLAUDE.md:46 | `go test ./...` # must pass (28 packages green as of 2026-07-28) | (36 packages ok as of 2026-09-10) | docs/STATUS.md:242,244-248 repeatedly record "go test 36 pkgs" / "go 36 pkgs" through 2026-09-10 |
| 2 | CLAUDE.md:67 (end of lint blockquote) | no mention of current lint/UI test counts | added: "As of 2026-09-10, `make lint` reports 0 issues and `cd ui && npm test -- --run` is 202 tests green." | task's stated ground truth (gate today: make lint 0 issues, ui 202 tests) |
| 3 | README.md:36-59 | Quick Start claimed the bootstrap token is "printed to kryptkeeper container logs on first start" and used `POST /cas` / `POST /certificates` payloads (`validity_str`, `subject`, `sans`) not in the API | rewrote to: token is operator-set and required (Compose refuses to start without it), `POST /cas` needs only `subject_cn`, `POST /certificates` is CSR-in (`ca_id`, `template_id`, `csr_pem`) | docs/ops/PILOT_KNOWN_GAPS.md F5 (verified against `docker-compose.yml`'s `${APP_BOOTSTRAP_TOKEN:?...}` and `internal/bootstrap/auth_config.go:254`); docs/openapi.yaml `POST /cas` and `POST /certificates` schemas |
| 4 | README.md:78-90 | Config table: `APP_JWT_SECRET`, `APP_AUTH_MODE`, `APP_BOOTSTRAP_TOKEN` "(generated if empty)", `KRYPTKEEPER_POSTGRES_DSN`, `APP_KEYSTORE_TYPE` | Corrected to `APP_JWT_HS256_SECRET`, `AUTH_MODE`, `APP_BOOTSTRAP_TOKEN` "**Yes**, not auto-generated", `KRYPTKEEPER_DB_DSN`/`DATABASE_URL`, `KRYPTKEEPER_KEY_BACKEND` | env.example (accurate surface, confirmed by grep); docs/ops/PILOT_KNOWN_GAPS.md F5, which already names these exact real variables |
| 5 | docs/DOCS_INDEX.md:10 | "the decision ledger (D-001..D-021 + vocabulary canon)" | "(D-001..D-106+ as of 2026-09-10 + vocabulary canon)" | docs/DECISIONS.md's newest entry is D-106 (2026-08-18) |
| 6 | docs/DOCS_INDEX.md:22 | "`docs/openapi.yaml` — ⚠️ stale (30 of ~92 routes, G-5) until its ticket lands" | "current: 175 paths, 0 drift against handlers as of 2026-09-10 (G-5 resolved...)" | `docs/openapi.yaml` contains 175 `  /`-prefixed paths (counted directly); docs/STATUS.md 2026-09-10 entries repeatedly record "openapi drift 0 (175 paths)" |
| 7 | docs/ops/PILOT_KNOWN_GAPS.md F1 table | W18-06 "in progress" (live acceptance not yet met); W18-11 "todo" | W18-06 "done (2026-09-10)" with the live-verification detail; W18-11 "done (2026-09-10)" with the preflight endpoint description; added a paragraph noting W18-13's install path is also proven live | docs/STATUS.md:242 (W18-06 done), :243 (W18-11 done), :245 (W18-13 done) |
| 8 | docs/ops/WINDOWS_ACCESS_MATRIX.md WinRM section | "Needs a listener cert + hub trust (W18-06)" / table row "The supported path. Works with today's code. Needs a listener cert + hub trust (W18-06)" | Both updated to state W18-06 is done and live-verified 2026-09-10, with W18-11 preflight and W18-13 install-path proof noted | docs/STATUS.md:242,243,245 |
| 9 | docs/TEST_STRATEGY.md Backend frameworks list | No mention of a gated-live-hardware test pattern | Added a bullet describing the `KK_LIVE_WINRM=1` pattern (`internal/agentdiscovery/live_winrm_test.go`), mirroring `KRYPTKEEPER_TEST_POSTGRES_DSN` | docs/STATUS.md:242 ("Gated live suite internal/agentdiscovery/live_winrm_test.go (KK_LIVE_WINRM=1), 5/5 green"); README.md's existing Postgres pattern as precedent |

## Section 2 — Direction (decisions needed, not rewritten)

| # | File:line | Exact quote | Superseded by | Proposed resolution |
|---|---|---|---|---|
| D1 | README.md:320-334 | Static "Roadmap" table ending at `**v2.2 (current)** \| Multi-tenancy...` with "See docs/GO_FORWARD_PLAN.md for the full strategy" | docs/ROADMAP.md's hardening waves (W0-W18) and docs/NEXT_HORIZON.md's V6 seed — neither v-numbered release nor the estate-management pivot (D-106) appears in this table at all | Retire the static table; point README's Roadmap section at `docs/ROADMAP.md` (living) and `docs/NEXT_HORIZON.md` (forward bets) instead of a frozen v1.0-v2.2 list |
| D2 | docs/GO_FORWARD_PLAN.md (whole doc, dated 2026-06-10) | "supersedes the Sprint 7 list... Input: Full product review 2026-06-10" / "Three Moats" framed entirely around v1.1-v2.0 | docs/ROADMAP.md (2026-07-15+, explicitly the current hardening+product roadmap) and docs/DECISIONS.md D-106 / VISION_V5.md (estate-management pivot, 2026-08-18), none of which this doc mentions | Add a "superseded by docs/ROADMAP.md + docs/NEXT_HORIZON.md" banner at the top (matching the pattern docs/DOCS_INDEX.md already uses for other historical docs), and stop linking to it from README.md as "the full strategy" |
| D3 | docs/DOCS_INDEX.md (whole doc, dated 2026-07-15) | "Rewritten 2026-07-15 (design-review arc, G-4)... Start here (current truth, in order)" | The index predates D-106 (estate pivot, 2026-08-18), docs/NEXT_HORIZON.md (2026-08-19), docs/GO_FORWARD_PLAN.md's supersession, and all of W11-W18 (docs/ops/PILOT_RUNBOOK.md, PILOT_KNOWN_GAPS.md, WINDOWS_ACCESS_MATRIX.md, VISION_V5.md, PRODUCT_SRS.md are not indexed at all) | the owner decide: run a full DOCS_INDEX refresh now (a G-4-style arc), or accept two mechanical corrections above as a stopgap until the next planning arc |
| D4 | docs/PRODUCT_SRS.md (whole doc, dated 2026-07-15) | FR-P64-70 (estate) and the W12-W18 work (agentless WinRM/IIS, SAN persistence, template vocab) have no way to be marked done — the table has no status column | docs/STATUS.md shows FR-P64-70 and much of the W11-W18 surface already shipped and live-verified | the owner decide whether to add a Status column (Done/Partial/Planned, cross-referencing docs/STATUS.md ticket ids) or leave PRODUCT_SRS.md as a pure requirements ledger that is never read for "is this done" |

## Section 3 — Orphans (recommendation)

No new orphans found requiring action. docs/DOCS_INDEX.md's "Historical (do
not use for decisions)" section already correctly lists and banners every
candidate this audit checked: `docs/STRATEGIC_GAP_ANALYSIS.md`,
`docs/HEALTH_ASSESSMENT.md`, `docs/{FULL_IMPROVEMENT_PLAN,IMPROVEMENT_PLAN_V2,
UX_IMPROVEMENT_PLAN,UX_BACKLOG}.md`, `docs/reviews/*`, `docs/improve/*`,
`docs/SPRINT_*`, `docs/work/SPRINT_2_PLAN.md`, `docs/PHASE_3_ROADMAP.md`,
`docs/AGENT_REMEDIATION_PLAN.md`, `docs/IMPLEMENTATION_BOARD.md`, and the
`docs/FEATURE_*`/`docs/DESIGN_CONTEXT.md`/`docs/COMPONENT_MAP.md`/
`docs/LANDSCAPE.md` April working set (verified present on disk, all
correctly marked historical at docs/DOCS_INDEX.md:34-41).

| # | Doc | Currently indexed as | Recommendation |
|---|---|---|---|
| O1 | docs/GO_FORWARD_PLAN.md | Canonical reference ("strategy + roadmap") | Should move to Historical alongside the doc's own supersession claim over STRATEGIC_GAP_ANALYSIS — see D2 above; it is itself now superseded and belongs in the same bucket it once put another doc in |
