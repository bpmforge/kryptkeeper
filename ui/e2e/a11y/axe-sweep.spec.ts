// W33-12: axe-core sweep of every UI route x light/dark x 375/768/1440.
// Fails on any serious or critical violation (WCAG 2.0/2.1/2.2 A and AA tags).
// No rule is disabled and no region excluded; see KNOWN_FALSE_POSITIVES in routes.ts.
// Run: `npm --prefix ui run test:a11y` (same stack and env as the other e2e specs).
import AxeBuilder from "@axe-core/playwright";
import { apiRequest, expect, loginAs, test } from "../fixtures";
import {
  KNOWN_FALSE_POSITIVES,
  THEMES,
  WIDTHS,
  countRouteElements,
  deriveRoutes,
  navPaths,
  readAppSource,
  resolveParams,
} from "./routes";

const { authed, login } = deriveRoutes();

test.describe("@a11y axe sweep: route list", () => {
  test("route list equals App.tsx <Route> count", () => {
    expect(authed.length).toBe(countRouteElements(readAppSource()));
  });

  test("every nav.ts destination is swept", () => {
    expect(navPaths().filter((p) => !authed.includes(p))).toEqual([]);
  });
});

type ListResp = { data?: Array<Record<string, unknown>> } | Array<Record<string, unknown>>;

async function firstId(
  request: import("@playwright/test").APIRequestContext,
  apiPath: string,
  keys: string[],
): Promise<string | undefined> {
  try {
    const res = await apiRequest(request, "admin", "GET", apiPath);
    if (!res.ok()) return undefined;
    const body = (await res.json()) as ListResp;
    const rows = Array.isArray(body) ? body : (body.data ?? []);
    for (const k of keys) {
      const v = rows[0]?.[k];
      if (typeof v === "string" || typeof v === "number") return String(v);
    }
  } catch {
    /* fall through to the not-found state */
  }
  return undefined;
}

async function sweep(page: import("@playwright/test").Page, url: string, route: string, theme: string, vp: { w: number; h: number }) {
  await page.setViewportSize({ width: vp.w, height: vp.h });
  await page.emulateMedia({ colorScheme: theme as "light" | "dark", reducedMotion: "reduce" });
  await page.addInitScript((t: string) => localStorage.setItem("theme", t), theme);
  await page.goto(url);
  await page.locator("main, form").first().waitFor({ timeout: 30_000 });
  // Lazy page chunk + data: wait for the network to settle and for loading skeletons to go.
  await page.waitForLoadState("networkidle", { timeout: 30_000 }).catch(() => undefined);
  await expect(page.locator("main [aria-busy='true'], main .animate-pulse")).toHaveCount(0, { timeout: 15_000 }).catch(() => undefined);
  expect(await page.evaluate(() => document.documentElement.classList.contains("dark")), "theme class applied").toBe(theme === "dark");

  const r = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  const bad = r.violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .filter((v) => !KNOWN_FALSE_POSITIVES.some((k) => k.rule === v.id && k.route === route));
  expect(
    bad,
    bad.map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`).join("\n"),
  ).toEqual([]);
}

test.describe("@a11y axe sweep: authenticated routes", () => {
  const ids: Record<string, string> = {};

  test.beforeAll(async ({ request }) => {
    const found: Record<string, string | undefined> = {
      fingerprint: await firstId(request, "/certificates?limit=1", ["fingerprint", "fingerprint_sha256", "id"]),
      id: undefined,
      actionId: await firstId(request, "/dashboard/actions/history?limit=1", ["action_id", "id"]),
    };
    // `:id` is shared by /cas/:id, /discovery/endpoints/:id, /alerts/deliveries/:id, /audit/:id.
    found.id = await firstId(request, "/cas", ["id"]);
    for (const [k, v] of Object.entries(found)) if (v) ids[k] = v;
  });

  for (const theme of THEMES) {
    for (const vp of WIDTHS) {
      for (const route of authed) {
        test(`axe ${route} ${theme} ${vp.w}`, async ({ page }) => {
          await loginAs(page, "admin");
          await sweep(page, resolveParams(route, ids), route, theme, vp);
        });
      }
    }
  }
});

test.describe("@a11y axe sweep: login", () => {
  test.use({ storageState: { cookies: [], origins: [] } });
  for (const theme of THEMES) {
    for (const vp of WIDTHS) {
      test(`axe ${login} ${theme} ${vp.w}`, async ({ page }) => {
        await sweep(page, login, login, theme, vp);
      });
    }
  }
});
