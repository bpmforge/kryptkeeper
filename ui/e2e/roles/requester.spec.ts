import { apiRequest, expect, loginAs, test } from "../fixtures";

test.describe("requester role", () => {
  test("precondition: key has the requester role and no scopes", async ({ request }) => {
    const res = await apiRequest(request, "requester", "GET", "/authz-check");
    expect(res.status()).toBe(200);
    const body = (await res.json()) as { role?: string; scopes?: string[]; data?: { role?: string; scopes?: string[] } };
    expect(body.role ?? body.data?.role).toBe("requester");
    expect(body.scopes ?? body.data?.scopes ?? []).toEqual([]);
  });

  test("sees only Request and My Requests", async ({ page }) => {
    await loginAs(page, "requester");
    await page.goto("/");
    const nav = page.getByRole("navigation", { name: "Main navigation" });
    await expect(nav).toBeVisible({ timeout: 20_000 });
    await expect
      .poll(async () => {
        const hrefs = await nav.locator("a[href]").evaluateAll((els) => els.map((e) => e.getAttribute("href") ?? ""));
        return [...new Set(hrefs)].sort();
      })
      .toEqual(["/certificates/issue", "/my-requests"]);
    await expect(page).toHaveURL(/\/my-requests$/);
    await expect(page.getByRole("heading", { name: "My requests" })).toBeVisible();
  });

  test("API refuses writes outside POST /certificates", async ({ request }) => {
    for (const [method, path] of [
      ["POST", "/users"],
      ["POST", "/cas"],
      ["POST", "/templates"],
      ["POST", "/certificates/import"],
      ["POST", "/certificates/abc/revoke"],
      ["POST", "/approvals/abc/approve"],
      ["POST", "/pending-actions"],
    ] as const) {
      const res = await apiRequest(request, "requester", method, path, {});
      expect(res.status(), `${method} ${path}`).toBe(403);
    }
  });
});
