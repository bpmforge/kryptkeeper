# UX Review — Kryptkeeper accessibility audit
**Date:** 2026-04-13
**Reviewer:** ux-engineer
**Scope:** `ui/src/App.tsx`, `ui/src/components/ui.tsx`, `ui/src/pages/Certificates.tsx`, `ui/src/pages/CAs.tsx`, `ui/src/pages/Discovery.tsx`, `ui/src/pages/Alerts.tsx`, `ui/src/pages/Search.tsx`, `ui/src/pages/History.tsx`, `ui/src/pages/Audit.tsx`
**Method:** Static only — live verification not performed
**Viewports tested:** Not tested live
**Design principles reference:** `docs/design/STYLE_GUIDE.md`

## Summary
The app has a solid operational skeleton: landmarks exist, focus rings are present, and the core screens are organized around inventory and triage. The main accessibility gaps are in form labeling, dialog keyboard behavior, and async feedback announcements; these issues affect the exact workflows enterprise users will use most.

## What Works Well
- Main navigation and `main` landmark are present in the app shell.
- Most interactive controls have visible focus styling.
- Table-heavy inventory screens use semantic tables instead of div-based grid imitation.

## Findings

### High-Priority
#### [High-Priority] Filter and search controls rely on placeholder text instead of labels
**Where:** `ui/src/pages/Certificates.tsx:165-195`, `ui/src/pages/CAs.tsx:137-146`, `ui/src/pages/Discovery.tsx:124-140`, `ui/src/pages/Alerts.tsx:102-139`, `ui/src/pages/Search.tsx:83-86`, `ui/src/pages/Audit.tsx:77-89`
**Problem:** The primary filter and search inputs are visually obvious to sighted users but ambiguous to screen reader users and anyone who loses placeholder text after typing. Several filter controls also have no visible label at all.
**Why it matters:** These are the core enterprise workflows. If users cannot confidently understand which filter changes which dataset, they slow down or make mistakes.
**Suggested direction:** Give every filter control a visible label or grouped legend, and keep helper text separate from the control name.

#### [High-Priority] Dialogs do not show keyboard safety behavior
**Where:** `ui/src/components/ui.tsx:32-50`
**Problem:** The dialog pattern exposes `role="dialog"`, but there is no focus trap, no Escape-to-close handling, and no focus restoration to the triggering control.
**Why it matters:** Keyboard and assistive-tech users can lose their place inside confirm flows, especially in destructive actions like revoke, suspend, or ack/retry dialogs.
**Suggested direction:** Trap focus inside the modal, move initial focus to the primary action or close button, support Escape, and restore focus on close.

#### [High-Priority] Async loading and error messages are not announced to assistive tech
**Where:** `ui/src/components/ui.tsx:60-76`
**Problem:** `StateMessage` is used for loading, success, and error states throughout the app, but it has no live-region semantics.
**Why it matters:** Screen reader users may not hear that data is loading, failed, or recovered, which makes the app feel broken even when the UI updates visually.
**Suggested direction:** Add `role="status"` / `aria-live` for non-error updates and `role="alert"` for failures.

### Medium-Priority
#### [Medium-Priority] Keyboard users must tab through the full global nav on every screen
**Where:** `ui/src/App.tsx:33-68`
**Problem:** The shell has no skip link or jump-to-main affordance, so the persistent nav is always first in tab order.
**Why it matters:** In an inventory-heavy app, users will visit many pages repeatedly. Extra tab stops add friction to every task.
**Suggested direction:** Add a visible-on-focus skip link to main content.

### Nits
- Nit: Some tables would benefit from explicit captions, but the surrounding headings already provide most of the context.

## Accessibility Summary
- Keyboard navigation: partial pass — visible focus exists, but modal behavior and skip navigation need work.
- Focus indicators: pass.
- Contrast: not verified live.
- Semantic HTML: pass overall; landmarks and tables are present.
- Forms: fail — several critical filter/search controls are unlabeled.

## Console/Network Observations
- Not verified live.
