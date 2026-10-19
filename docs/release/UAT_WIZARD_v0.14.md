# Issuance wizard UAT record (v0.14.0)

Manual and browser acceptance record for the certificate issuance wizard
(`/certificates/issue`, W26-26). Every cell ships `PENDING-RUN`. No cell may be
filled from a reading of the code or from the jsdom unit tests: they prove
validation and navigation logic, not layout, timing or real-browser a11y.
Run via the `ui-verify` skill (playwright-mcp) against a local hub plus
`npm --prefix ui run build` or the dev server.

The timing criterion needs 3 humans who have never seen the wizard. An agent
run does NOT satisfy it and must be labelled "agent" in the User type column.

## Environment

| Item | Value |
|------|-------|
| Hub commit | PENDING-RUN |
| Browser / version | PENDING-RUN |
| Date (UTC) | PENDING-RUN |
| Tester | PENDING-RUN |

## Walkthrough (PASS / FAIL + note)

| Viewport | CA | Template | Names | Key/CSR | Review | Result |
|----------|----|----|----|----|----|----|
| 375x812 | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 768x1024 | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 1440x900 | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |

## Timing: first-time user issues a certificate (threshold 120 s)

| User | User type (human / agent) | Start-to-result (s) | Within 120 s |
|------|---------------------------|---------------------|--------------|
| 1 | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 2 | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 3 | PENDING-RUN | PENDING-RUN | PENDING-RUN |

## Keyboard-only run

Tab, Shift+Tab, Enter and Space only; no pointer.

| Viewport | Completes to Result | Focus order sensible | Notes |
|----------|---------------------|----------------------|-------|
| 375x812 | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 768x1024 | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 1440x900 | PENDING-RUN | PENDING-RUN | PENDING-RUN |

## Accessibility (axe-core 4.x, tags `wcag2a,wcag2aa,wcag21aa,wcag22aa`)

Run on each step at each viewport with `page.addScriptTag` from a pinned
cdnjs axe-core version. Target: 0 serious and 0 critical.

2026-10-16 (lead, built-in browser, axe-core 4.10.3 from cdnjs, `vite preview` of the
production bundle against a local hub): the CA step was audited at all three viewports in
dark theme and at 1440 in light theme. The first pass found one moderate `heading-order`
(Wizard step heading was h3 under the page h1); fixed in b12d48dc (step heading is h2), then
0/0/0. The same pass cleared /acme, /enrollment and /ssh-certificates. Later steps still need
a filled form (template, names, key) and remain PENDING-RUN.

| Viewport | Step | Critical | Serious | Moderate |
|----------|------|----------|---------|----------|
| 375x812 | CA | 0 | 0 | 0 |
| 375x812 | Template | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 375x812 | Names | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 375x812 | Key/CSR | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 375x812 | Review | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 375x812 | Result | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 768x1024 | CA | 0 | 0 | 0 |
| 768x1024 | Template | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 768x1024 | Names | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 768x1024 | Key/CSR | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 768x1024 | Review | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 768x1024 | Result | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 1440x900 | CA | 0 | 0 | 0 |
| 1440x900 | Template | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 1440x900 | Names | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 1440x900 | Key/CSR | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 1440x900 | Review | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| 1440x900 | Result | PENDING-RUN | PENDING-RUN | PENDING-RUN |

## Findings and fixes

| # | Finding | Severity | Fix / commit |
|---|---------|----------|--------------|
| 1 | PENDING-RUN | PENDING-RUN | PENDING-RUN |
