// W33-12: axe sweep of the first-run wizard (zero CAs) at "/", light/dark x 375/768/1440.
// Needs the first-run stack (see README.md). Sorts before onboarding.spec.ts so it runs
// while the stack is still empty; skips loudly (never passes silently) if a CA exists.
import AxeBuilder from "@axe-core/playwright";
import { apiRequest, expect, loginAs, test } from "../fixtures";
import { THEMES, WIDTHS } from "../a11y/routes";

for (const theme of THEMES) {
  for (const vp of WIDTHS) {
    test(`@a11y axe onboarding wizard ${theme} ${vp.w}`, async ({ page, request }) => {
      const listed = await apiRequest(request, "admin", "GET", "/cas");
      const cas = ((await listed.json()) as { data: unknown[] }).data;
      test.skip(cas.length > 0, "stack not clean: CA already exists (start a fresh first-run stack, see README.md)");

      await loginAs(page, "admin");
      await page.setViewportSize({ width: vp.w, height: vp.h });
      await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
      await page.addInitScript((t: string) => localStorage.setItem("theme", t), theme);
      await page.goto("/");
      await expect(page.getByRole("heading", { name: "Welcome to Kryptkeeper" })).toBeVisible({ timeout: 30_000 });
      expect(await page.evaluate(() => document.documentElement.classList.contains("dark"))).toBe(theme === "dark");

      const r = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
        .analyze();
      const bad = r.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
      expect(
        bad,
        bad.map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`).join("\n"),
      ).toEqual([]);
    });
  }
}
