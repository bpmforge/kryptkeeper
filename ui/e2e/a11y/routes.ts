// W33-12: route list for the axe sweep. Derived from src/App.tsx and src/lib/nav.ts so
// a new page is covered automatically (the count test in axe-sweep.spec.ts enforces it).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const srcDir = path.resolve(here, "../../src");

export const THEMES = ["light", "dark"] as const;
export const WIDTHS = [
  { w: 375, h: 812 },
  { w: 768, h: 1024 },
  { w: 1440, h: 900 },
] as const;

/**
 * Named, justified axe exceptions. Empty on purpose: the sweep never uses
 * disableRules/exclude to get green. An entry needs rule id, route and a WCAG reason.
 */
export const KNOWN_FALSE_POSITIVES: ReadonlyArray<{ rule: string; route: string; reason: string }> = [];

export function readAppSource(): string {
  return fs.readFileSync(path.join(srcDir, "App.tsx"), "utf8");
}

/** Every authenticated `<Route path>` in App.tsx (login, `/*` wrapper and `*` 404 dropped). */
export function deriveRoutes(src: string = readAppSource()): { authed: string[]; login: string } {
  const seen = new Set<string>();
  for (const m of src.matchAll(/path="([^"]+)"/g)) {
    const p = m[1];
    if (p === "*" || p === "/*" || p === "/login") continue;
    seen.add(p);
  }
  return { authed: [...seen], login: "/login" };
}

/** Independent of the path= regex on purpose: login, the `/*` wrapper and the `*` 404 are not pages. */
export function countRouteElements(src: string = readAppSource()): number {
  return (src.match(/<Route\b/g) ?? []).length - 3;
}

/** Every `to: "/x"` in nav.ts (the sidebar's destinations). */
export function navPaths(): string[] {
  const src = fs.readFileSync(path.join(srcDir, "lib/nav.ts"), "utf8");
  return [...new Set([...src.matchAll(/to: "([^"]+)"/g)].map((m) => m[1]))];
}

export function resolveParams(route: string, ids: Record<string, string>): string {
  return route.replace(/:([A-Za-z]+)/g, (_, name: string) => encodeURIComponent(ids[name] ?? "seed-missing"));
}
