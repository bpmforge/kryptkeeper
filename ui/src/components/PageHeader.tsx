import type { ReactNode } from "react";
import { SectionLabel } from "./ui";

type PageHeaderProps = {
  /**
   * The sidebar section this screen lives in (e.g. "INVENTORY", "TRUST").
   * Every routed screen belongs to exactly one nav section — this names it.
   */
  eyebrow: string;
  title: string;
  description: string;
  /** Right-aligned page-level actions (buttons), if the screen has any. */
  actions?: ReactNode;
};

// S-48. docs/ANALYST_REPORT_2026-07-31.md I-1 counted three header shapes across
// 31 screens (eyebrow+H1, icon+H1, H1-only) that split by which screen's author
// wrote it, not by section or any other rule. This is the one shape: eyebrow +
// H1 + description, with optional actions. Icon+H1 was rejected as the canon
// because every sidebar nav item already renders its own icon next to the
// active route (see lib/nav.ts) — repeating it in the page body is redundant,
// while the eyebrow names the section a screen belongs to, which the icon does
// not.
//
// `eyebrow`, `title` and `description` are required and there is no `icon`,
// `children` or `className` prop — the shape is fixed at the type level, not a
// convention a new page can quietly opt out of.
export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: PageHeaderProps) {
  return (
    <header className="flex items-start justify-between">
      <div>
        <SectionLabel>{eyebrow}</SectionLabel>
        <h1 className="mt-2 text-3xl font-semibold text-foreground">{title}</h1>
        <p className="mt-2 text-sm text-muted-foreground">{description}</p>
      </div>
      {actions ? (
        <div className="flex items-center gap-2">{actions}</div>
      ) : null}
    </header>
  );
}

export default PageHeader;
