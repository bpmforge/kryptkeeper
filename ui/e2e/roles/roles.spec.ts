// Run order: onboarding (W33-02) assumes zero CAs and sorts before `roles`; this suite
// leaves a CA in place only via bulk.spec.ts, so never run roles/ first on a clean stack
// that onboarding still needs.
import { apiRequest, expect, loginAs, test, type Role } from "../fixtures";

// Copied literally from src/test/nav.test.ts `expected` (do not import app source).
const ALL_PATHS = [
  "/", "/inbox", "/alerts", "/ct-findings", "/automation", "/targets/setup",
  "/targets/renewal-policy", "/renewal/rollout-groups", "/delivery-plugins", "/agents",
  "/integrations", "/certificates", "/cas", "/ceremonies", "/keys", "/code-signing",
  "/spiffe", "/ssh-certificates", "/templates", "/discovery", "/search",
  "/reports/compliance-evidence", "/audit", "/reports/change-audit", "/history",
  "/crypto-posture", "/reports/pqc-migration", "/reports/algorithm-sunset",
  "/reports/expiry-timeline", "/reports/ca-health", "/reports/issuance-velocity",
  "/reports/revocation-activity", "/inventory/keys", "/inventory-sources", "/acme",
  "/enrollment", "/migration", "/users", "/access-review", "/tenants", "/policies",
  "/roles", "/settings",
  "/blast-radius", "/issuers", "/nhi", "/reports/anomalies", "/reports/slo", "/reports/key-custody", "/targets",
];

// requester has its own two-item nav and is covered by requester.spec.ts.
type MatrixRole = Exclude<Role, "admin" | "requester">;

// Paths each role must NOT see with scopes [] (MULTI_TENANCY unset also hides /tenants for all).
const HIDDEN: Record<MatrixRole, string[]> = {
  viewer: [
    "/ct-findings", "/integrations", "/audit", "/ceremonies", "/renewal/rollout-groups",
    "/acme", "/enrollment", "/users", "/access-review", "/policies", "/roles",
    "/reports/key-custody",
  ],
  "pki-operator": [
    "/ceremonies", "/renewal/rollout-groups", "/acme", "/users", "/access-review",
    "/policies", "/roles", "/reports/key-custody",
  ],
  "pki-admin": [],
};

const ROLES: MatrixRole[] = ["viewer", "pki-operator", "pki-admin"];

test.describe("role matrix", () => {
  for (const role of ROLES) {
    test.describe(role, () => {
      test("precondition: key has the expected role and no scopes", async ({ request }) => {
        const res = await apiRequest(request, role, "GET", "/authz-check");
        expect(res.status()).toBe(200);
        const body = (await res.json()) as {
          role?: string; scopes?: string[]; data?: { role?: string; scopes?: string[] };
        };
        const got = body.role ?? body.data?.role;
        const scopes = body.scopes ?? body.data?.scopes ?? [];
        expect(got).toBe(role);
        expect(
          scopes,
          `key for ${role} carries scopes ${JSON.stringify(scopes)}; the hidden-set assumptions need none (a "*" scope reveals every gated nav item)`,
        ).toEqual([]);
      });

      test("sees exactly the nav items for its role", async ({ page }) => {
        await loginAs(page, role);
        await page.goto("/");
        const nav = page.getByRole("navigation", { name: "Main navigation" });
        await expect(nav).toBeVisible({ timeout: 20_000 });
        // Wait for the role to resolve: the gated items settle only after /authz-check.
        await expect(nav.locator('a[href="/certificates"]')).toBeVisible();
        const expected = ALL_PATHS.filter((p) => !HIDDEN[role].includes(p) && p !== "/tenants").sort();
        await expect
          .poll(async () => {
            const hrefs = await nav.locator("a[href]").evaluateAll((els) =>
              els.map((e) => e.getAttribute("href") ?? ""),
            );
            return [...new Set(hrefs)].sort();
          })
          .toEqual(expected);
        for (const hidden of [...HIDDEN[role], "/tenants"]) {
          await expect(nav.locator(`a[href="${hidden}"]`)).toHaveCount(0);
        }
      });
    });
  }

  test("certificates page actions per role", async ({ browser }) => {
    const expectations: Record<MatrixRole, boolean> = { viewer: false, "pki-operator": true, "pki-admin": true };
    for (const role of ROLES) {
      const fresh = await browser.newContext({ baseURL: test.info().project.use.baseURL });
      const p = await fresh.newPage();
      await loginAs(p, role);
      await p.goto("/certificates");
      await expect(p.getByRole("heading", { name: "Certificates" }).first()).toBeVisible({ timeout: 20_000 });
      await expect(p.getByRole("button", { name: "Select all visible" })).toBeVisible();
      for (const name of ["Bulk import", "Issue certificate", "Bulk revoke", "Bulk renew"]) {
        const btn = p.getByRole("button", { name, exact: true });
        if (expectations[role]) await expect(btn.first(), `${role} ${name}`).toBeVisible();
        else await expect(btn, `${role} ${name}`).toHaveCount(0);
      }
      await fresh.close();
    }
  });

  test("CAs page create buttons per role", async ({ browser }) => {
    const expectations: Record<MatrixRole, boolean> = { viewer: false, "pki-operator": true, "pki-admin": true };
    for (const role of ROLES) {
      const ctx = await browser.newContext({ baseURL: test.info().project.use.baseURL });
      const p = await ctx.newPage();
      await loginAs(p, role);
      await p.goto("/cas");
      await expect(p.getByRole("heading", { name: "Certificate Authorities" }).first()).toBeVisible({ timeout: 20_000 });
      const btn = p.getByRole("button", { name: "New CA", exact: true });
      if (expectations[role]) await expect(btn, role).toBeVisible();
      else await expect(btn, role).toHaveCount(0);
      await ctx.close();
    }
  });

  test("users page invite control: viewer none, admin present", async ({ browser }) => {
    for (const [role, present] of [["viewer", false], ["pki-admin", true]] as const) {
      const ctx = await browser.newContext({ baseURL: test.info().project.use.baseURL });
      const p = await ctx.newPage();
      await loginAs(p, role);
      await p.goto("/users");
      const btn = p.getByRole("button", { name: "Invite user", exact: true });
      if (present) {
        await expect(btn, role).toBeVisible({ timeout: 20_000 });
      } else {
        // Let the page settle (heading or any main content) before asserting absence.
        await expect(p.locator("main")).toBeVisible({ timeout: 20_000 });
        await p.waitForLoadState("networkidle");
        await expect(btn, role).toHaveCount(0);
      }
      await ctx.close();
    }
  });

  test("viewer API 403 names the permission", async ({ request }) => {
    const res = await apiRequest(request, "viewer", "GET", "/audit/export");
    expect(res.status()).toBe(403);
    expect(await res.text()).toMatch(/does not have the audit\.read permission/);
  });
});
