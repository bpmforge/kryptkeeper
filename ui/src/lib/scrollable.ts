/**
 * Spread onto any element that scrolls (overflow-x-auto tables, code blocks).
 * A scrollable region must be reachable by keyboard (WCAG 2.1.1; axe
 * scrollable-region-focusable). Kept as a spread so the one deliberate
 * tabIndex on a non-interactive element lives here, not at 25 call sites.
 */
export const scrollableProps = { tabIndex: 0 } as const;
