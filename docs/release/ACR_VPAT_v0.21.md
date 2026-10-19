# Accessibility Conformance Report (VPAT 2.5, WCAG 2.2 edition) - Kryptkeeper UI v0.21

| Field | Value |
|---|---|
| Product | Kryptkeeper web UI (`ui/`, React) |
| Version | `v0.21.0-pending` (release tag not cut at the time of writing; rename the version on tagging) |
| Report date | 2026-10-17 |
| Commit documented | `149028ad` (W33 integration; every W33 UI ticket merged) |
| Report type | Self-assessment (not a third-party audit) |
| Contact | Accessibility feedback: open an issue in the repository (`bpmforge/kryptkeeper`). `SECURITY.md` is for vulnerability reports only and is not an accessibility channel. |
| Applicable standard | WCAG 2.2 Level A and Level AA only. Level AAA is out of scope. WCAG 2.1 and 2.0 criteria are a subset of 2.2 A/AA and are covered by the same rows (4.1.1 Parsing is obsolete in 2.2 and is not rated). |
| Evidence status | The spec files named below exist and assert what is stated at this commit. The pass/fail result of the full e2e run against a live stack was not captured for this report: every CI run link is `PENDING-RUN`. No row is rated from an unrun result. |

## Evaluation methods

1. **Static lint (W33-11).** `eslint-plugin-jsx-a11y` recommended config, errors, over all non-test `.ts/.tsx` under `ui/src` (`ui/eslint.config.js`; `label-has-associated-control` at depth 3). Run via `npm --prefix ui run lint`; 0 errors required.
2. **Automated axe-core sweep (W33-12).** `ui/e2e/a11y/axe-sweep.spec.ts`: every authenticated route derived from `ui/src/App.tsx` (53 distinct paths at this commit, kept in step by a count test and a nav.ts coverage test in the same spec; route derivation in `ui/e2e/a11y/routes.ts`) plus `/login`, each in light and dark theme at 375, 768 and 1440 px, tags `wcag2a, wcag2aa, wcag21a, wcag21aa, wcag22aa`. The spec fails on any serious or critical violation. No rule is disabled and no region is excluded; `KNOWN_FALSE_POSITIVES` in `routes.ts` is empty. The zero-CA first-run wizard is swept separately by `ui/e2e/onboarding/onboarding-axe.spec.ts` (same tags, theme and width matrix). Contrast token fixes found by the sweep are in `ui/src/index.css` (`--state-attn`, `--state-auto`, `--state-over`). CI wiring: `.github/workflows/ui-e2e.yml` (`npm --prefix ui run test:a11y`).
3. **Keyboard-only journeys (W33-13).** `ui/e2e/a11y/keyboard-journeys.spec.ts`: login, skip link, onboarding wizard, issue, approve, revoke (with dialog focus trap, Escape and focus return), target setup. Only keyboard input drives them; a guard test (`no pointer calls in journey source`) enforces that. Fixes made on the way: Wizard no longer hijacks Enter on a focused Back/Cancel button (`ui/src/components/Wizard.tsx`); Dialog returns focus to its opener (`ui/src/components/ui.tsx`, unit test `ui/src/test/DialogFocusReturn.test.tsx`).
4. **Target size (W33-13).** `ui/e2e/a11y/target-size.spec.ts`: every nav.ts route at 1440 and 375 px; measured set is `nav a`, `header button`, `main [data-slot="button"]` and plain `main button`.
5. **Reflow / navigation drawer (W33-34).** `ui/e2e/a11y/mobile-nav.spec.ts`: at 375 px on `/certificates`, no horizontal scroll, drawer opens, Escape closes it and returns focus, a link closes it.
6. **Chart text alternatives and non-color cues (W33-14, W33-31).** `ui/src/test/chart-text-alternatives.test.tsx` (vitest): named charts with data tables (horizon, expiry distribution, issuance velocity, crypto posture trend), named trust-breakdown group, risk gauge and compliance ring with a visible status word, `GradeLabel` icon plus text cue for every grade (`ui/src/components/StatusCue.tsx`).
7. **Manual screen-reader pass.** Not yet performed. See "Manual screen-reader findings".

Known limits of the automated evidence: axe decides only the machine-checkable subset of each criterion; "incomplete" (needs-review) axe results are not triaged by the spec; the sweep loads each page in its initial state only (no open dialogs, hover/focus states, error states or post-action states); data is the seeded e2e stack; `:id` detail routes (`/cas/:id`, `/discovery/endpoints/:id`, `/alerts/deliveries/:id`, `/audit/:id`, `/certificates/:fingerprint`, action history) are swept with the first seeded record when the API returns one, and otherwise in the not-found/empty state (the spec falls back to a placeholder id), so detail-page content may not be what was scanned on a given run; the onboarding sweep skips itself when the stack already has a CA.

## Terms

Standard VPAT 2.5 terms:

- **Supports**: the functionality meets the criterion. In this report that is claimed only where a cited automated assertion decides the criterion over the states it samples (stated in Remarks).
- **Partially Supports**: some functionality does not meet the criterion, or verification covers only part of the criterion's scope. The Remarks say which of the two applies. No row relies on this term to hide a known failure: known failures are listed under "Known limitations".
- **Does Not Support**: the majority of functionality does not meet the criterion. (No row at this commit.)
- **Not Applicable**: the criterion does not apply (no such content in the UI).
- **Not Evaluated**: no evidence exists yet. This is the honest default for criteria that need a human or assistive-technology judgement.

The W33-15 board wording "supports/partial/not-supported" maps to the first three terms; Not Applicable and Not Evaluated are added as VPAT 2.5 requires.

Evidence abbreviations (all repo-relative): **AXE** `ui/e2e/a11y/axe-sweep.spec.ts`; **ONB** `ui/e2e/onboarding/onboarding-axe.spec.ts`; **KJ** `ui/e2e/a11y/keyboard-journeys.spec.ts`; **TS** `ui/e2e/a11y/target-size.spec.ts`; **MN** `ui/e2e/a11y/mobile-nav.spec.ts`; **LINT** `ui/eslint.config.js`; **CH** `ui/src/test/chart-text-alternatives.test.tsx`; **DFR** `ui/src/test/DialogFocusReturn.test.tsx`. CI run URL for every automated spec: `PENDING-RUN`.

## Table 1: Success Criteria, Level A

| Criterion | Conformance level | Remarks and explanations | Evidence |
|---|---|---|---|
| 1.1.1 Non-text Content | Partially Supports | Verification is partial. axe image-alt/svg-img-alt/role-img-alt and jsx-a11y alt-text pass; charts have names and table alternatives (W33-14, W33-31). Whether the text alternatives are adequate was not reviewed with a screen reader. | AXE, ONB, LINT, CH |
| 1.2.1 Audio-only and Video-only (Prerecorded) | Not Applicable | No `<audio>` or `<video>` in `ui/src` (grep at the documented commit). | `ui/src` (grep) |
| 1.2.2 Captions (Prerecorded) | Not Applicable | As 1.2.1. | `ui/src` (grep) |
| 1.2.3 Audio Description or Media Alternative (Prerecorded) | Not Applicable | As 1.2.1. | `ui/src` (grep) |
| 1.3.1 Info and Relationships | Not Evaluated | Machine-checkable subset is asserted (axe label, th/td, list, aria-required-children, landmark rules; jsx-a11y label association) but landmark and table-header semantics were not verified with a screen reader. Depends on the manual pass. | AXE, ONB, LINT |
| 1.3.2 Meaningful Sequence | Not Evaluated | DOM reading order versus visual order was not reviewed. The keyboard journeys follow DOM order without surprises but do not assert it. | KJ |
| 1.3.3 Sensory Characteristics | Not Evaluated | Instruction copy was not reviewed for shape/colour/position-only references. | none |
| 1.4.1 Use of Color | Partially Supports | Verification is partial. Status, grade and gauge states carry an icon plus a text cue (`StatusCue`, `GradeLabel`; W33-14, W33-31) asserted for every grade. Other colour-only uses (link-in-text distinction, remaining badges, chart series) were not exhaustively reviewed. | CH |
| 1.4.2 Audio Control | Not Applicable | No audio in the UI (see 1.2.1). | `ui/src` (grep) |
| 2.1.1 Keyboard | Partially Supports | Verification is partial. Seven keyboard-only journeys (login, skip link, onboarding, issue, approve, revoke, target setup) complete without a pointer. Other pages and controls are not covered by a keyboard assertion. | KJ |
| 2.1.2 No Keyboard Trap | Partially Supports | Verification is partial. Dialog focus is trapped by design and Escape releases it (checked in the revoke journey); no trap was found elsewhere in the journeys. Not swept across all pages. | KJ, DFR |
| 2.1.4 Character Key Shortcuts | Not Evaluated | The command palette opens on Ctrl/Cmd+K (a modified key). No single-character shortcut was found by reading `ui/src/components/CommandPalette.tsx`, but no test asserts it. | none |
| 2.2.1 Timing Adjustable | Not Evaluated | Session expiry behaviour was not assessed against this criterion. | none |
| 2.2.2 Pause, Stop, Hide | Not Evaluated | `prefers-reduced-motion` is honoured in `ui/src/index.css` and the axe sweep runs with reduced motion, but auto-updating content (polling dashboards, loading skeletons) was not assessed for a pause control. | none |
| 2.3.1 Three Flashes or Below Threshold | Not Evaluated | No flashing content is known; not tested. | none |
| 2.4.1 Bypass Blocks | Supports | A skip link is the first Tab stop and moves focus past the navigation (asserted); axe `bypass`/`region` rules pass in the sweep. | KJ (`skip link moves focus past the navigation`), AXE |
| 2.4.2 Page Titled | Partially Supports | Verification is partial. axe `document-title` passes on every swept page. Whether titles are distinct and descriptive per route was not reviewed. | AXE |
| 2.4.3 Focus Order | Partially Supports | Verification is partial. Journeys proceed in a sensible order and a Dialog returns focus to its opener (fixed in W33-13). Not asserted on all pages. | KJ, DFR |
| 2.4.4 Link Purpose (In Context) | Partially Supports | Verification is partial. axe `link-name` passes; purpose in context was not reviewed. | AXE, ONB |
| 2.5.1 Pointer Gestures | Not Evaluated | No path-based or multi-point gesture was found, but no test asserts this. | none |
| 2.5.2 Pointer Cancellation | Not Evaluated | Not assessed. | none |
| 2.5.3 Label in Name | Not Evaluated | jsx-a11y and axe check that controls are labelled; visible-label-versus-accessible-name matching was not checked. | LINT |
| 2.5.4 Motion Actuation | Not Applicable | No device-motion or orientation-actuated functionality in `ui/src` (grep). | `ui/src` (grep) |
| 3.1.1 Language of Page | Supports | `<html lang="en">` in `ui/index.html`; axe `html-has-lang` / `html-lang-valid` pass in the sweep. | `ui/index.html`, AXE |
| 3.2.1 On Focus | Not Evaluated | Not assessed beyond the keyboard journeys, which showed no focus-triggered context change. | KJ |
| 3.2.2 On Input | Not Evaluated | Wizard step changes are explicit Next/Back actions (KJ); other forms were not assessed. | KJ |
| 3.2.6 Consistent Help | Not Evaluated | Not assessed. | none |
| 3.3.1 Error Identification | Not Evaluated | Error text exists in forms, but whether errors are announced to assistive technology depends on the manual pass. | none |
| 3.3.2 Labels or Instructions | Partially Supports | Verification is partial. jsx-a11y `label-has-associated-control` is an error and axe `label` passes; adequacy of instructions was not reviewed. | LINT, AXE, ONB |
| 3.3.7 Redundant Entry | Not Evaluated | Wizard and multi-step flows were not reviewed for repeated entry. | none |
| 4.1.2 Name, Role, Value | Partially Supports | Verification is partial. axe aria-* and name rules pass at 0 serious/critical across the sweep and jsx-a11y role rules pass at 0 errors. Custom widget behaviour under a screen reader was not evaluated. | AXE, ONB, LINT |

## Table 2: Success Criteria, Level AA

| Criterion | Conformance level | Remarks and explanations | Evidence |
|---|---|---|---|
| 1.2.4 Captions (Live) | Not Applicable | No media in the UI. | `ui/src` (grep) |
| 1.2.5 Audio Description (Prerecorded) | Not Applicable | No media in the UI. | `ui/src` (grep) |
| 1.3.4 Orientation | Not Evaluated | No orientation lock is known; the sweep uses portrait phone and landscape desktop sizes only. | none |
| 1.3.5 Identify Input Purpose | Partially Supports | Verification is partial. The login form sets `autoComplete` (`email`, `current-password`); other personal-data fields were not reviewed. | `ui/src/pages/Login.tsx` |
| 1.4.3 Contrast (Minimum) | Supports | axe `color-contrast` reports 0 serious/critical across all routes in light and dark at 3 widths, and the wizard. Token fixes landed in `ui/src/index.css`. Limits: initial page state only; text over images/gradients and axe "incomplete" results are not triaged. | AXE, ONB, `ui/src/index.css` |
| 1.4.4 Resize Text | Not Evaluated | `ui/index.html` viewport meta does not disable zoom; 200% text resize was not tested. | `ui/index.html` |
| 1.4.5 Images of Text | Not Evaluated | No images of text are known; not tested. | none |
| 1.4.10 Reflow | Partially Supports | Verification is partial. Below md the sidebar is a drawer (W33-34) and `/certificates` at 375 px has no horizontal scroll (asserted). The axe sweep covers 375 px for its rules but axe does not test reflow; other pages (wide tables) were not asserted. | MN, AXE |
| 1.4.11 Non-text Contrast | Not Evaluated | axe has no general non-text-contrast rule. Focus ring (`:focus-visible`, brand cyan) and control borders were not measured. | none |
| 1.4.12 Text Spacing | Not Evaluated | Not tested. | none |
| 1.4.13 Content on Hover or Focus | Not Evaluated | Not tested. | none |
| 2.4.5 Multiple Ways | Not Evaluated | A sidebar/drawer navigation and a command palette exist; not assessed against the criterion. | `ui/e2e/a11y/mobile-nav.spec.ts` |
| 2.4.6 Headings and Labels | Not Evaluated | Descriptiveness was not reviewed (axe checks only presence/order). | none |
| 2.4.7 Focus Visible | Partially Supports | Verification is partial. A global `:focus-visible` outline is defined in `ui/src/index.css`; the journeys tab through controls but do not assert a visible indicator, and axe cannot. | `ui/src/index.css`, KJ |
| 2.4.11 Focus Not Obscured (Minimum) | Not Evaluated | Sticky sidebar/header exist; focus-obscured behaviour was not tested. | none |
| 2.5.7 Dragging Movements | Not Evaluated | No drag-and-drop library or handler was found in `ui/src` by grep, but no test asserts a single-pointer alternative. | none |
| 2.5.8 Target Size (Minimum) | Partially Supports | Verification is partial. Action buttons and nav items are asserted at 44x44 px at 1440 and 375 px over every nav route (exceeds the 24x24 minimum; see "Target size decision"). Inputs, checkboxes and table links are not in the measured set. | TS |
| 3.1.2 Language of Parts | Not Evaluated | Not assessed. | none |
| 3.2.3 Consistent Navigation | Not Evaluated | All routes share one layout in `ui/src/App.tsx`; not asserted. | none |
| 3.2.4 Consistent Identification | Not Evaluated | Not assessed. | none |
| 3.3.3 Error Suggestion | Not Evaluated | Not assessed. | none |
| 3.3.4 Error Prevention (Legal, Financial, Data) | Not Evaluated | Certificate revoke requires a typed `REVOKE` confirmation (exercised in KJ) and approvals are gated, but review/undo coverage across data-modifying forms was not assessed. | KJ |
| 3.3.8 Accessible Authentication (Minimum) | Partially Supports | Verification is partial. Login uses `autoComplete` on the email and password fields and no paste-blocking handler was found in `ui/src/pages/Login.tsx`; no cognitive-function test is used. SSO and token flows were not assessed. | KJ (`login by keyboard`), `ui/src/pages/Login.tsx` |
| 4.1.3 Status Messages | Not Evaluated | `role="alert"`/`role="status"`/`aria-live` are used in 22 source files, but announcement was not verified with a screen reader. Depends on the manual pass. | none |

## Manual screen-reader findings

No manual assistive-technology pass has been performed for v0.21. Every field below is `PENDING-RUN`. [HUMAN]: an operator must run it.

| Item | VoiceOver (Safari, macOS) | NVDA (Firefox or Chrome, Windows) |
|---|---|---|
| Date | PENDING-RUN | PENDING-RUN |
| OS / browser / AT versions | PENDING-RUN | PENDING-RUN |
| Tester | PENDING-RUN | PENDING-RUN |
| Journeys covered (login, onboarding, issue, approve, revoke, target setup) | PENDING-RUN | PENDING-RUN |
| Landmarks and table headers announced (1.3.1) | PENDING-RUN | PENDING-RUN |
| Form errors announced (3.3.1) | PENDING-RUN | PENDING-RUN |
| Status messages announced (4.1.3) | PENDING-RUN | PENDING-RUN |
| Chart names and data tables read (1.1.1) | PENDING-RUN | PENDING-RUN |
| Findings | PENDING-RUN | PENDING-RUN |

Rows that depend on this pass and are therefore `Not Evaluated` (or capped at `Partially Supports`): 1.1.1, 1.3.1, 3.3.1, 4.1.2, 4.1.3. JAWS has not been tested either. Update the affected rows when the pass is recorded.

## Target size decision

WCAG 2.5.8 (Level AA) requires pointer targets of at least 24x24 CSS px (with spacing and inline exceptions). The project standard is stricter: action buttons and nav items are at least 44x44 CSS px (`docs/design/UX_SPEC.md`, "Accessibility Plan", Target size line; floor enforced in `ui/src/index.css`). `ui/e2e/a11y/target-size.spec.ts` asserts it for every nav route at 1440 and 375 px with a 0.5 px tolerance. 44 exceeds the criterion. The spec applies only the exceptions stated in it: inline controls inside a paragraph, disabled controls, aria-hidden/sr-only content and elements not rendered. Targets outside its selector set (form inputs, checkboxes, in-table links) are not asserted, which is why 2.5.8 is rated `Partially Supports` rather than `Supports`.

## Known limitations

- Partially Supports rows (verification covers only part of the scope; no failing behaviour is known): 1.1.1, 1.3.5, 1.4.1, 1.4.10, 2.1.1, 2.1.2, 2.4.2, 2.4.3, 2.4.4, 2.4.7, 2.5.8, 3.3.2, 3.3.8, 4.1.2.
- Does Not Support rows: none recorded. This is not a claim that none exist: most criteria are `Not Evaluated`.
- Not Evaluated rows: 1.3.1, 1.3.2, 1.3.3, 1.3.4, 1.4.4, 1.4.5, 1.4.11, 1.4.12, 1.4.13, 2.1.4, 2.2.1, 2.2.2, 2.3.1, 2.4.5, 2.4.6, 2.4.11, 2.5.1, 2.5.2, 2.5.3, 2.5.7, 3.1.2, 3.2.1, 3.2.2, 3.2.3, 3.2.4, 3.2.6, 3.3.1, 3.3.3, 3.3.4, 3.3.7, 4.1.3. Most need human or assistive-technology judgement.
- `KNOWN_FALSE_POSITIVES` in `ui/e2e/a11y/routes.ts` is empty: no axe exception exists.
- axe sweep limits: only serious/critical impacts fail the spec (minor/moderate are not gated); initial page state only; seeded data only; `:id` detail routes may be scanned in the not-found state when the API returns no record; onboarding sweep is skipped when a CA exists; no real-user data.
- No automated run result is recorded in this document: CI run URLs are `PENDING-RUN`. If any named spec is red at the release commit, rows citing it must be downgraded before publication.
- This is a self-assessment. It is not an independent audit and not a statement of legal compliance.
