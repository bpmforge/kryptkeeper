# Discovery Audit (Static)

## Runtime status
- No running app instance was available in this session, so this audit is static only.

## High-level findings
1. The UI is operational but still mostly summary-oriented.
2. Detail pages/routes are missing for several core objects; detail work happens inside list panels.
3. Search fans out across multiple list endpoints and filters client-side, which will not scale well.
4. The design system is not yet unified: `ui/src/components/ui.tsx` and `ui/src/components/ops-ui.tsx` duplicate primitives.
5. The frontend type surface is weak; `any` is pervasive and lint currently fails.

## Process/document findings
1. There was no canonical SDLC tracker before this session.
2. Several planning docs overlap heavily and describe the same roadmap in different words.
3. `docs/TEST_STRATEGY.md` is partially outdated: it says no UI test runner exists, but Vitest-based UI tests are present.
4. `docs/design/DESIGN_PRINCIPLES.md` and `docs/design/STYLE_GUIDE.md` are short and not fully reflected in the implementation.

## Scope recommendation
Focus improvement work on:
- frontend type safety and shared components
- workflow/detail routes
- search scalability
- docs/process consolidation
