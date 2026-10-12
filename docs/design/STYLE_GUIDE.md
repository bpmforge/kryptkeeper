# Style Guide

## Typography
- **Display font:** IBM Plex Serif
- **Body font:** IBM Plex Sans
- **Monospace:** IBM Plex Mono
- **Pairing rationale:** The serif gives the interface a clear editorial hierarchy for critical states and section headings; the sans keeps dense operational lists readable; the mono handles fingerprints, serials, and IDs.
- **Scale:** 1.2 major third
  - 12, 14, 16, 19, 23, 28, 34, 41

## Color Tokens (CSS variables)
```css
:root {
  --color-bg: #0b0f14;
  --color-surface: #11161d;
  --color-surface-2: #171d26;
  --color-fg: #e7edf5;
  --color-muted: #9aa7b6;
  --color-border: #263244;
  --color-accent: #56b6c2;
  --color-accent-2: #d19a66;
  --color-danger: #ff6b6b;
  --color-success: #4caf7d;
  --color-warning: #f0b35a;
}
```

## Spacing Scale
4 / 8 / 12 / 16 / 24 / 32 / 48 / 64

## Motion Principles
- **Page load:** minimal stagger on key summary blocks only
- **Hover:** border and background shift, not scale-heavy animation
- **Transition timing:** cubic-bezier(0.2, 0, 0, 1)
- **Duration scale:** 120ms fast / 220ms normal / 360ms deliberate

## Component Primitives
- **Button:** primary, secondary, destructive, ghost; compact and high-contrast
- **Input:** strong focus ring, clear invalid state, helper text below field
- **Card:** data-first, not decorative; low radius, strong border, clear title and action area
- **Table:** dense, sortable, filterable, zebra only when needed for scanability
- **Status badge:** text-forward, not color-only, paired with icon or label
- **Command rail:** urgent queue panel with ranked items and actions
