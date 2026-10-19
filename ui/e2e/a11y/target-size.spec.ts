import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Page } from "@playwright/test";
import { expect, loginAs, test } from "../fixtures";

// Project decision (UX_SPEC): action buttons and nav items are at least 44x44 CSS px.
// WCAG 2.5.8 (AA) only asks for 24px; this is stricter on purpose, so do not weaken it.
const MIN = 44;
const TOLERANCE = 0.5;

const navTs = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../src/lib/nav.ts");
const navPaths = [...new Set([...fs.readFileSync(navTs, "utf8").matchAll(/to: "([^"]+)"/g)].map((m) => m[1]))];

// WCAG 2.5.8 exceptions applied explicitly (nothing else is excluded):
//  - Inline: a link inside a sentence/paragraph is not an "action button" and is exempt.
//  - aria-hidden elements and the sr-only table are not exposed controls.
const SELECTOR = [
  "nav a",
  "header button",
  'main [data-slot="button"]',
  'main button:not([data-slot]):not(p button)',
].join(", ");

type Offender = { sel: string; text: string; w: number; h: number };
type Measured = { bad: Offender[]; measured: number };

async function offenders(page: Page): Promise<Measured> {
  return page.locator(SELECTOR).evaluateAll(
    (els, min) => {
      let measured = 0;
      const bad = els.flatMap((el) => {
        const e = el as HTMLElement;
        if (e.closest("[aria-hidden='true'], .sr-only, table.sr-only")) return [];
        if (e.closest("p")) return []; // WCAG 2.5.8 inline exception: set inside a sentence
        if ((e as HTMLButtonElement).disabled || e.getAttribute("aria-disabled") === "true") return [];
        const r = e.getBoundingClientRect();
        if (r.width === 0 && r.height === 0) return []; // not rendered (display:none / collapsed)
        const cs = getComputedStyle(e);
        if (cs.visibility === "hidden" || cs.display === "none") return [];
        measured++;
        if (r.width >= min - 0.5 && r.height >= min - 0.5) return [];
        const tag = e.tagName.toLowerCase();
        const label = (e.getAttribute("aria-label") || e.textContent || "").trim().replace(/\s+/g, " ").slice(0, 40);
        return [{ sel: `${tag}${e.getAttribute("data-slot") ? "[data-slot=button]" : ""}`, text: label, w: Math.round(r.width * 10) / 10, h: Math.round(r.height * 10) / 10 }];
      });
      return { bad, measured };
    },
    MIN,
  );
}

for (const width of [1440, 375]) {
  test.describe(`target size at ${width}px`, () => {
    test.use({ viewport: { width, height: width === 1440 ? 900 : 812 } });

    for (const route of navPaths) {
      test(`${route} has no control under ${MIN}x${MIN}`, async ({ page }) => {
        await loginAs(page, "admin");
        await page.goto(route);
        // The page body is a lazy chunk and data may still be loading: wait for the shell, then settle.
        // On a phone (W33-34) the sidebar is a closed drawer, so the shell signal is its header trigger.
        const shell = width === 1440 ? page.getByRole("navigation").first() : page.getByRole("button", { name: "Open navigation" });
        await expect(shell).toBeAttached({ timeout: 20_000 });
        await expect(page.locator("main")).toBeVisible({ timeout: 20_000 });
        await page.waitForLoadState("networkidle").catch(() => undefined);
        // The drawer trigger is a header control and is measured with the page; open the drawer so its nav items are too.
        const { bad, measured } = await offenders(page);
        if (width !== 1440) {
          await page.getByRole("button", { name: "Open navigation" }).click();
          await expect(page.getByRole("navigation", { name: "Main navigation" })).toBeVisible();
          const drawer = await offenders(page);
          bad.push(...drawer.bad.filter((d) => !bad.some((b) => b.sel === d.sel && b.text === d.text && b.w === d.w && b.h === d.h)));
          expect(drawer.measured, `${route} @${width}: drawer nav items were not measured`).toBeGreaterThan(0); // page content is aria-hidden behind the open drawer, so only drawer controls count
        }
        // Guard against a vacuous pass (blank page, selector drift): every nav route has some control.
        expect(measured, `${route} @${width}: no nav item or action button was measured`).toBeGreaterThan(0);
        expect(
          bad,
          `${route} @${width}: ${bad.length} control(s) under ${MIN}x${MIN} (tolerance ${TOLERANCE}px):\n` +
            bad.map((b) => `  ${b.sel} "${b.text}" ${b.w}x${b.h}`).join("\n"),
        ).toEqual([]);
      });
    }
  });
}
