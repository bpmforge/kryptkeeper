import AxeBuilder from "@axe-core/playwright";
import { expect, loginAs, test } from "../fixtures";

// W33-34: below md the sidebar is a drawer opened from a header button (WCAG 1.4.10 Reflow).
test.describe("navigation drawer at 375px", () => {
  test.use({ viewport: { width: 375, height: 812 } });

  test("no horizontal scroll; drawer opens, Escape closes and returns focus; link closes it", async ({ page }) => {
    await loginAs(page, "admin");
    await page.goto("/certificates");
    await expect(page.locator("main")).toBeVisible({ timeout: 20_000 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await expect(page.getByRole("navigation", { name: "Main navigation" })).toHaveCount(0);

    const open = page.getByRole("button", { name: "Open navigation" });
    await open.click();
    const nav = page.getByRole("navigation", { name: "Main navigation" });
    await expect(nav).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(nav).toHaveCount(0);
    await expect(open).toBeFocused();

    await open.click();
    await nav.locator('a[href="/cas"]').click();
    await expect(page).toHaveURL(/\/cas$/);
    await expect(nav).toHaveCount(0);
  });

  for (const theme of ["light", "dark"] as const) {
    test(`open drawer has no serious/critical axe violations (${theme})`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
      await page.addInitScript((t: string) => localStorage.setItem("theme", t), theme);
      await loginAs(page, "admin");
      await page.goto("/certificates");
      await expect(page.locator("main")).toBeVisible({ timeout: 20_000 });
      await page.getByRole("button", { name: "Open navigation" }).click();
      await expect(page.getByRole("navigation", { name: "Main navigation" })).toBeVisible();
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
});
