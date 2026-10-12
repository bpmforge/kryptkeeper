# Improvement Backlog — Kryptkeeper
Generated: 2026-04-13

## Inputs reviewed
- `docs/LANDSCAPE.md`
- `docs/HEALTH_ASSESSMENT.md`
- `docs/FULL_IMPROVEMENT_PLAN.md`
- `docs/UX_IMPROVEMENT_PLAN.md`
- `docs/FEATURE_CONTEXT.md`
- `docs/FEATURE_IMPACT_ANALYSIS.md`
- `docs/FEATURE_IMPLEMENTATION_PLAN.md`
- `docs/FEATURE_EXECUTION_CHECKLIST.md`
- `docs/IMPLEMENTATION_BOARD.md`
- `docs/PHASE_3_ROADMAP.md`
- `docs/TEST_STRATEGY.md`
- `docs/design/DESIGN_PRINCIPLES.md`
- `docs/design/STYLE_GUIDE.md`
- `docs/design/UX_SPEC.md`
- UI source files in `ui/src/`
- backend provider wiring in `internal/bootstrap/`
- validation commands: `go test ./...`, `npm --prefix ui run build`, `npm --prefix ui test`, `npm --prefix ui run lint`

## Critical / Must-Fix
| # | Area | Problem | Size | Fix Summary | Verify With |
|---|------|---------|------|-------------|-------------|
| 1 | Frontend system | Two component libraries (`ui.tsx` and `ops-ui.tsx`) duplicate the same primitives, and the code still uses Inter in `ui/src/index.css`, which contradicts the design direction in `docs/design/STYLE_GUIDE.md`. | M | Merge to one source of truth, switch the app typography to the chosen brand fonts, and apply shared tokens everywhere. | `npm --prefix ui run lint`, `npm --prefix ui run build`, visual spot check |
| 2 | UX/workflows | The product is still list-and-summary heavy; core assets lack dedicated detail routes and the dashboard/search flows do not yet feel like a guided operations console. | L | Add detail routes/screens for certificates, discovery endpoints, notifications, CAs, and audit/history, then wire dashboard cards into those flows. | UX review, route navigation smoke test, component tests |
| 3 | Type safety | `ui/src/lib/api.ts` and multiple pages/tests rely heavily on `any`, and lint is currently failing with 87 `@typescript-eslint/no-explicit-any` errors. | M | Introduce typed API response models and remove `any` from page/test code. | `npm --prefix ui run lint`, `npm --prefix ui test` |
| 4 | Search/scalability | `ui/src/pages/Search.tsx` fans out to multiple list endpoints and filters client-side, which will not scale for enterprise inventory sizes. | M | Move search server-side, add result paging, and reduce query fan-out. | Search UI test, perf smoke check, build |

## High / Strongly Recommended
| # | Area | Problem | Size | Fix Summary | Verify With |
|---|------|---------|------|-------------|-------------|
| 5 | Docs/process | There is no single canonical improvement tracker, and the repo has several overlapping planning docs that repeat the same roadmap in different forms. | S | Consolidate to one tracker/backlog path and mark the others as references only. | docs review, `docs/sdlc/SDLC_TRACKER.md` presence |
| 6 | Docs accuracy | `docs/TEST_STRATEGY.md` is stale: it says no UI test runner exists, but Vitest UI tests already do. | S | Refresh the test strategy to match the actual stack and current coverage. | `npm --prefix ui test`, doc review |
| 7 | Accessibility | The UI is broadly usable, but it still lacks a deliberate accessibility pass for table semantics, keyboard flows, and reusable accessible patterns. | M | Add a formal WCAG 2.2 AA audit, especially for dialogs, tables, and filters. | Accessibility review + keyboard smoke test |
| 8 | Backend maintainability | Bootstrap/provider wiring repeats the same DB mode / DSN / open / error wrapper pattern across several files. | M | Extract a shared provider factory and typed error helpers. | `go test ./...`, targeted bootstrap tests |

## Medium / Worth Doing
| # | Area | Problem | Size | Fix Summary | Verify With |
|---|------|---------|------|-------------|-------------|
| 9 | Design implementation | `docs/design/DESIGN_PRINCIPLES.md` and `docs/design/STYLE_GUIDE.md` are short and are not yet reflected in the actual CSS/theme layer. | M | Expand the token system and wire it into the app shell and shared components. | Visual regression check, `npm --prefix ui run build` |
| 10 | Detail-state consistency | Several pages use inline “detail” panels instead of actual route-level detail views, which makes deep-linking and workflow progression harder. | M | Normalize a detail-page pattern with breadcrumbs and direct URLs. | Route smoke test, UI test updates |

## Low / Nice to Have
| # | Area | Problem | Size | Fix Summary | Verify With |
|---|------|---------|------|-------------|-------------|
| 11 | Docs cleanup | Multiple roadmap docs overlap (`FULL_IMPROVEMENT_PLAN`, `FEATURE_*`, `IMPLEMENTATION_BOARD`, `PHASE_3_ROADMAP`). | S | Merge or archive duplicates to reduce confusion. | Docs review |

## Notes
- No areas were marked off-limits.
- The app already passes `go test ./...`, `npm --prefix ui run build`, and `npm --prefix ui test`; the main problem is quality and product fit, not baseline breakage.
- `npm --prefix ui run lint` now passes after the type safety cleanup.

## Resolved in this session
- Item 1: frontend system + typography aligned and verified
- Item 2: workflow/detail routes added for core assets and verified
- Item 3: type safety cleanup completed; lint now passes
- Item 4: search now debounces input and reduces query fanout during typing
- Item 5: docs/process consolidation started with `docs/DOCS_INDEX.md`
- Item 6: test strategy refreshed to match the current UI test stack
- Item 7: accessibility hardening completed and verified
- Item 8: backend provider wiring refactored behind shared helpers and verified

## Progress in this session
- Item 1: frontend system + typography aligned and verified
- Item 3: type safety cleanup completed; lint now passes
- Item 5: docs/process consolidation started with `docs/DOCS_INDEX.md`
- Item 6: test strategy refreshed to match the current UI test stack
- Item 4: search now debounces input and reduces query fanout during typing
- Item 8: backend provider wiring refactored behind shared helpers and verified
- Item 2: workflow/detail routes added for core assets and verified
- Item 7: accessibility hardening completed and verified
