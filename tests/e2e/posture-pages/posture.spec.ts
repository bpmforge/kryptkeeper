import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

// W28-18. Kept free of project-specific imports so W33-01 can move it under
// ui/e2e/posture/ as a plain file move.
const token = process.env.APP_BOOTSTRAP_TOKEN ?? "";
const base = process.env.KK_E2E_BASE_URL ?? "http://localhost:3000";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any;

async function api(request: APIRequestContext, path: string): Promise<Json> {
  const res = await request.get(`${base}/api/v1${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(res.ok(), `GET ${path} -> ${res.status()}`).toBeTruthy();
  return res.json();
}

// The tile is the label's parent: label and value share one container.
const tile = (page: Page, label: string) =>
  page.getByText(label, { exact: true }).locator("xpath=..");

const card = (page: Page, title: string) =>
  page
    .locator('[data-slot="card"]')
    .filter({ has: page.locator('[data-slot="card-title"]', { hasText: new RegExp(`^${title}$`) }) });

async function expectInventoryCount(page: Page, request: APIRequestContext, query: string) {
  const expected = (await api(request, `/certificates?limit=1&${query}`)).meta.total as number;
  await expect(page.getByText(new RegExp(`Certificate inventory · ${expected} (records|matching)`))).toBeVisible();
  return expected;
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript(
    ([t]) => {
      sessionStorage.setItem("kk_session", "1");
      sessionStorage.setItem("auth_token", t);
    },
    [token],
  );
});

test("posture and operations pages match the API", async ({ page, request }) => {
  expect(token, "APP_BOOTSTRAP_TOKEN must be set").not.toBe("");

  await test.step("precondition: at least 1,000 certificates seeded", async () => {
    const certs = await api(request, "/certificates?limit=1");
    expect(certs.meta.total).toBeGreaterThanOrEqual(1000);
  });

  await test.step("Algorithm Sunset", async () => {
    const { data } = await api(request, "/reports/algorithm-sunset");
    await page.goto("/reports/algorithm-sunset");
    await expect(page.getByRole("heading", { name: "Algorithm Sunset" })).toBeVisible();
    await expect(tile(page, "Banned Now")).toContainText(String(data.summary.banned_now));
    await expect(tile(page, "Sunset 2030")).toContainText(String(data.summary.sunset_2030));
    await expect(tile(page, "Compliant")).toContainText(String(data.summary.compliant));

    // A fingerprint chip opens that certificate.
    const fp = data.groups[0].fingerprints[0] as string;
    await page.getByRole("link", { name: fp, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/certificates/${fp}$`));
    await page.goBack();

    // "+N more" opens the inventory filtered to that group's own certificates:
    // non-empty, and the same count the report gave for the group.
    const group = (data.groups as Array<{ id: string; count: number; fingerprints: string[] }>).find(
      (g) => g.fingerprints.length > 5,
    );
    expect(group, "a sunset group with more than 5 certificates").toBeTruthy();
    const more = page.getByRole("link", { name: /search the inventory/ }).first();
    await expect(more).toBeVisible();
    await more.click();
    await expect(page).toHaveURL(/\/certificates\?sunset_group=/);
    const id = new URL(page.url()).searchParams.get("sunset_group") ?? "";
    expect(id).toBe(data.groups.find((g: { fingerprints: string[] }) => g.fingerprints.length > 5).id);
    const total = await expectInventoryCount(page, request, `sunset_group=${encodeURIComponent(id)}`);
    expect(total).toBeGreaterThan(0);
    expect(total).toBe(group!.count);
    await page.goBack();
  });

  await test.step("Issuance Velocity", async () => {
    const { data } = await api(request, "/reports/issuance-velocity");
    await page.goto("/reports/issuance-velocity");
    await expect(page.getByRole("heading", { name: "Issuance Velocity" })).toBeVisible();
    await expect(tile(page, "Last 7 days")).toContainText(String(data.windows.last_7d));
    await expect(tile(page, "Last 30 days")).toContainText(String(data.windows.last_30d));
    await expect(tile(page, "Last 90 days")).toContainText(String(data.windows.last_90d));

    const caId = Object.keys(data.by_ca as Record<string, number>).find((k) => k !== "unknown");
    expect(caId, "by_ca has a real CA after seeding").toBeTruthy();
    const link = card(page, "By CA").getByRole("link").first();
    await expect(link).toBeVisible();
    const label = (await link.innerText()).trim();
    await link.click();
    await expect(page).toHaveURL(/\/certificates\?ca_id=/);
    const target = new URL(page.url()).searchParams.get("ca_id") ?? "";
    expect(Object.keys(data.by_ca)).toContain(target);
    expect(label).not.toBe("");
    await expectInventoryCount(page, request, `ca_id=${encodeURIComponent(target)}`);
    await page.goBack();
  });

  await test.step("CA Health", async () => {
    const { data } = await api(request, "/reports/ca-health");
    await page.goto("/reports/ca-health");
    await expect(page.getByRole("heading", { name: "CA Health" })).toBeVisible();
    await expect(page.getByText(`${data.total_cas} CAs`, { exact: false })).toBeVisible();
    await expect(page.locator("tbody tr")).toHaveCount(data.total_cas);

    const first = data.items[0];
    const link = page.getByRole("link", { name: first.name, exact: true });
    await link.click();
    await expect(page).toHaveURL(new RegExp(`/certificates\\?ca_id=${encodeURIComponent(first.id)}`));
    await expectInventoryCount(page, request, `ca_id=${encodeURIComponent(first.id)}`);
    await page.goBack();
  });

  await test.step("Revocation Activity", async () => {
    const { data } = await api(request, "/reports/revocation-activity");
    expect(data.total_revoked).toBeGreaterThanOrEqual(3);
    await page.goto("/reports/revocation-activity");
    await expect(page.getByRole("heading", { name: "Revocation Activity" })).toBeVisible();
    await expect(
      page.getByText(/revocations in the last/).locator("xpath=.."),
    ).toContainText(String(data.total_revoked));

    // By CA -> revoked list for that CA.
    const byCa = card(page, "By CA").getByRole("link").first();
    await byCa.click();
    await expect(page).toHaveURL(/\/certificates\?status=revoked&ca_id=/);
    const caId = new URL(page.url()).searchParams.get("ca_id") ?? "";
    expect(Object.keys(data.by_ca)).toContain(caId);
    await expectInventoryCount(page, request, `status=revoked&ca_id=${encodeURIComponent(caId)}`);
    await page.goBack();

    // Recent revocations: the common name opens the certificate detail.
    const recent = data.recent_revocations[0];
    await page.getByRole("link", { name: recent.common_name, exact: true }).first().click();
    await expect(page).toHaveURL(new RegExp(`/certificates/${recent.fingerprint_sha256}$`));
    await page.goBack();
  });

  await test.step("Change Audit", async () => {
    const { data } = await api(request, "/reports/change-audit");
    await page.goto("/reports/change-audit");
    await expect(page.getByRole("heading", { name: "Change Audit" })).toBeVisible();
    await expect(
      page.getByText(`${data.events.length} events shown (max 500)`),
    ).toBeVisible();

    const withResource = data.events.find((e: Json) => e.resource_id);
    expect(withResource, "an event with a resource id after seeding").toBeTruthy();
    await page.getByRole("link", { name: withResource.resource_id, exact: true }).first().click();
    await expect(page).toHaveURL(new RegExp(`/audit\\?resource_id=${encodeURIComponent(withResource.resource_id)}`));
    await expect(page.getByText(`Filtered to resource ${withResource.resource_id}`)).toBeVisible();
    await page.goBack();

    // Events with no resource link to their action instead.
    const noResource = data.events.find((e: Json) => !e.resource_id);
    if (noResource) {
      await page
        .locator("tbody a[href^='/audit?action=']")
        .first()
        .click();
      await expect(page).toHaveURL(/\/audit\?action=/);
      await page.goBack();
    }
  });

  await test.step("Search", async () => {
    const cn = "e2e-777.example.test";
    const { data } = await api(request, `/search?q=${cn}`);
    await page.goto("/search");
    await expect(page.getByRole("heading", { name: "Global Search" })).toBeVisible();
    await page.getByLabel("Search all inventory").fill(cn);
    await expect(page.getByText(`Results · ${data.length}`)).toBeVisible();
    const hit = page.getByRole("button", { name: new RegExp(cn) });
    await expect(hit).toHaveCount(1);
    await hit.click();
    await expect(page).toHaveURL(/\/certificates\/[0-9a-f]{64}/);
  });
});
