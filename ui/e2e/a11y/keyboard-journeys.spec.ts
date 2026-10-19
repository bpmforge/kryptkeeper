import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { APIRequestContext, Locator, Page } from "@playwright/test";
import { apiRequest, expect, loginAs, test } from "../fixtures";
import { ensureCaAndTemplate, issueCerts } from "../roles/seed";

// Keyboard-only journeys (W33-13, UC-L07). Only `keyboard.press/type` and `tabTo` drive the page;
// the guard test below reads this file so that property cannot rot. Seeding goes through the API.
test.use({ trace: "on" });

async function tabTo(page: Page, target: Locator, max = 300): Promise<void> {
  const el = target.first();
  for (let i = 0; i < max; i++) {
    if (
      await el.evaluate((n) => n === document.activeElement).catch(() => false)
    )
      return;
    await page.keyboard.press("Tab");
  }
  throw new Error(`not reachable by Tab within ${max} presses: ${target}`);
}

async function expectTrapped(
  page: Page,
  dialog: Locator,
  presses = 14,
): Promise<void> {
  for (let i = 0; i < presses; i++) {
    await page.keyboard.press("Tab");
    expect(
      await dialog.evaluate((d) => d.contains(document.activeElement)),
    ).toBe(true);
  }
  for (let i = 0; i < presses; i++) {
    await page.keyboard.press("Shift+Tab");
    expect(
      await dialog.evaluate((d) => d.contains(document.activeElement)),
    ).toBe(true);
  }
}

function csrFor(cn: string): string {
  return execFileSync(
    "openssl",
    [
      "req",
      "-new",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-nodes",
      "-keyout",
      "/dev/null",
      "-subj",
      `/CN=${cn}`,
    ],
    { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
  );
}

const uniq = () =>
  `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;

/** A wizard step is current when its stepper item carries aria-current="step". */
async function expectStep(page: Page, title: string | RegExp): Promise<void> {
  await expect(page.locator('[aria-current="step"]')).toContainText(title);
}

/** Focus a <select> by Tab and pick its first real option by typing its label (typeahead). */
async function chooseByTypeahead(page: Page, select: Locator): Promise<void> {
  const label = (await select.locator("option:not([disabled])").first().textContent())?.trim();
  expect(label, "select has a selectable option").toBeTruthy();
  await tabTo(page, select);
  await page.keyboard.type(label!);
}

/** First Tab stop is the skip link: use it, as a keyboard user would, instead of tabbing through 45 nav links. */
async function skipToMain(page: Page): Promise<void> {
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to main content" })).toBeFocused();
  await page.keyboard.press("Enter");
}

/** Sign in as the named (non-bootstrap) administrator over the API; the bootstrap token may not approve actions. */
async function loginAsNamedAdmin(page: Page, request: APIRequestContext): Promise<void> {
  const email = process.env.KK_E2E_LOGIN_EMAIL;
  const password = process.env.KK_E2E_LOGIN_PASSWORD;
  test.skip(!email || !password, "needs a named administrator: set KK_E2E_LOGIN_EMAIL/KK_E2E_LOGIN_PASSWORD (see e2e/a11y/docker-compose.a11y.yml)");
  const base = process.env.KK_E2E_BASE_URL ?? "http://localhost:3000";
  const res = await request.post(`${base}/api/v1/auth/login`, { data: { email, password } });
  expect(res.status(), "named admin login").toBe(200);
  const token = ((await res.json()) as { data: { access_token: string } }).data.access_token;
  await page.addInitScript((t: string) => {
    sessionStorage.setItem("kk_session", "1");
    sessionStorage.setItem("auth_token", t);
  }, token);
}

/** Tab to the wizard's Next button and press Enter on it. */
async function nextByKeyboard(page: Page): Promise<void> {
  await tabTo(page, page.getByRole("button", { name: "Next", exact: true }));
  await page.keyboard.press("Enter");
}

test("login by keyboard", async ({ page }) => {
  const email = process.env.KK_E2E_LOGIN_EMAIL;
  const password = process.env.KK_E2E_LOGIN_PASSWORD;
  test.skip(
    !email || !password,
    "login journey needs a password-login user on the hub: set KK_E2E_LOGIN_EMAIL/KK_E2E_LOGIN_PASSWORD (see e2e/a11y/docker-compose.a11y.yml)",
  );
  await page.goto("/login");
  await tabTo(page, page.getByLabel("Email"));
  await page.keyboard.type(email!);
  await page.keyboard.press("Tab");
  await page.keyboard.type(password!);
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/$/, { timeout: 20_000 });
  await expect(page.locator("main")).toBeVisible({ timeout: 20_000 });
  // Focus must land somewhere reachable, not be dropped on <body> with no way back into the page.
  await page.keyboard.press("Tab");
  expect(await page.evaluate(() => document.activeElement?.tagName)).not.toBe(
    "BODY",
  );
});

test("skip link moves focus past the navigation", async ({ page }) => {
  await loginAs(page, "admin");
  await page.goto("/certificates");
  await expect(page.locator("main")).toBeVisible({ timeout: 20_000 });
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Skip to main content" }),
  ).toBeFocused();
  await page.keyboard.press("Enter");
  await page.keyboard.press("Tab");
  expect(
    await page.evaluate(
      () => !!document.activeElement?.closest("#main-content"),
    ),
  ).toBe(true);
});

test("onboarding wizard by keyboard", async ({ page }) => {
  // The compose stack already has a CA, so the first-run state is simulated at the two reads that
  // decide it (zero CAs, onboarding not dismissed). Every create/issue call below hits the real hub.
  await page.route(/\/api\/v1\/cas\?limit=1$/, (route) =>
    route.request().method() === "GET"
      ? route.fulfill({ json: { data: [] } })
      : route.continue(),
  );
  await page.route(/\/api\/v1\/users\/me\/prefs$/, (route) =>
    route.fulfill({
      json: {
        data: { onboarding_dismissed: route.request().method() === "PUT" },
      },
    }),
  );
  await loginAs(page, "admin");
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Welcome to Kryptkeeper" }),
  ).toBeVisible({ timeout: 20_000 });

  const id = uniq();
  await expectStep(page, "Root CA");
  await tabTo(page, page.getByLabel("Subject common name"));
  await page.keyboard.type(`kb-e2e root ${id}`);
  await page.keyboard.press("Tab");
  await page.keyboard.type("kb-e2e");
  await tabTo(page, page.getByRole("button", { name: "Create root CA" }));
  await page.keyboard.press("Enter");
  await expect(page.getByText(/^Created /)).toBeVisible({ timeout: 30_000 });
  await nextByKeyboard(page);

  await expectStep(page, "Template");
  await tabTo(page, page.getByLabel("Name", { exact: true }));
  await page.keyboard.type(`kb-e2e-${id}`);
  await tabTo(page, page.getByRole("button", { name: "Create template" }));
  await page.keyboard.press("Enter");
  await expect(page.getByText(/^Created /)).toBeVisible({ timeout: 30_000 });
  await nextByKeyboard(page);

  await expectStep(page, "First certificate");
  await tabTo(page, page.getByLabel("CSR PEM"));
  await page.keyboard.type(csrFor(`kb-${id}.example.test`));
  await tabTo(page, page.getByRole("button", { name: "Issue certificate" }));
  await page.keyboard.press("Enter");
  await expect(page.getByText(/^Issued /)).toBeVisible({ timeout: 30_000 });
  await nextByKeyboard(page);

  await expectStep(page, /Connect SSO or notifications/);
  await nextByKeyboard(page);

  await expectStep(page, "Discovery & install");
  await tabTo(
    page,
    page.getByRole("button", { name: "Choose agentless mode" }),
  );
  await page.keyboard.press("Enter");
  await tabTo(page, page.getByRole("button", { name: "Finish" }));
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/targets\/setup$/, { timeout: 20_000 });
});

test("issue by keyboard", async ({ page, request }) => {
  await ensureCaAndTemplate(request);
  await loginAs(page, "admin");
  await page.goto("/certificates/issue");
  await expect(
    page.getByRole("heading", { name: "Certificate Authority", level: 2 }),
  ).toBeVisible({ timeout: 20_000 });
  const cn = `kb-issue-${uniq()}.example.test`;

  await expectStep(page, "Certificate Authority");
  await chooseByTypeahead(page, page.getByLabel("Certificate authority"));
  await nextByKeyboard(page);

  await expectStep(page, "Template");
  await chooseByTypeahead(page, page.getByLabel("Issuance template"));
  await nextByKeyboard(page);

  await expectStep(page, "Subject & SANs");
  await tabTo(page, page.getByLabel("Subject common name"));
  await page.keyboard.type(cn);
  await nextByKeyboard(page);

  await expectStep(page, "Key or CSR");
  await tabTo(page, page.getByRole("button", { name: "I already have a CSR" }));
  await page.keyboard.press("Enter");
  await tabTo(page, page.getByLabel("CSR PEM"));
  await page.keyboard.type(csrFor(cn));
  await nextByKeyboard(page);

  await expectStep(page, "Review");
  await tabTo(page, page.getByRole("button", { name: "Finish" }));
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("heading", {
      name: /Certificate issued|Approval requested/,
    }),
  ).toBeVisible({ timeout: 30_000 });
});

test("approve by keyboard", async ({ page, request }) => {
  // The proposer cannot approve their own request, so a second principal (pki-admin) files it
  // and the bootstrap admin approves it in the inbox.
  const seeded = await ensureCaAndTemplate(request);
  const [fingerprint] = await issueCerts(
    request,
    seeded,
    1,
    `kb-approve-${uniq()}`,
  );
  const proposed = await apiRequest(
    request,
    "pki-admin",
    "POST",
    "/pending-actions",
    {
      action_type: "revoke",
      params: { fingerprint },
      rationale: "keyboard journey seed",
    },
  );
  test.skip(
    proposed.status() !== 201,
    `cannot seed a pending action as pki-admin: HTTP ${proposed.status()} ${await proposed.text()}`,
  );

  await loginAsNamedAdmin(page, request);
  await page.goto("/inbox");
  const approve = page.locator("button:not([disabled])", {
    hasText: "Approve",
  });
  await expect(approve.first()).toBeVisible({ timeout: 20_000 });
  await skipToMain(page);
  await tabTo(page, approve);
  await page.keyboard.press("Enter");
  await expect(page.getByText("Approved", { exact: true }).first()).toBeVisible(
    { timeout: 20_000 },
  );
});

test("revoke by keyboard with dialog", async ({ page, request }) => {
  const seeded = await ensureCaAndTemplate(request);
  const [fingerprint] = await issueCerts(
    request,
    seeded,
    1,
    `kb-revoke-${uniq()}`,
  );
  await loginAs(page, "admin");
  await page.goto(`/certificates/${fingerprint}`);
  const trigger = page.getByRole("button", { name: "Revoke", exact: true });
  await expect(trigger).toBeVisible({ timeout: 20_000 });
  const dialog = page.getByRole("dialog", { name: "Revoke certificate" });

  await skipToMain(page);
  await tabTo(page, trigger);
  await page.keyboard.press("Enter");
  await expect(dialog).toBeVisible();
  await expectTrapped(page, dialog);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused(); // focus returns to the control that opened it

  await page.keyboard.press("Enter");
  await expect(dialog).toBeVisible();
  await tabTo(page, dialog.getByPlaceholder("Optional explanation"));
  await page.keyboard.type("keyboard journey");
  await tabTo(page, dialog.getByPlaceholder("REVOKE"));
  await page.keyboard.type("REVOKE");
  await tabTo(page, dialog.getByRole("button", { name: "Confirm revoke" }));
  await page.keyboard.press("Enter");
  await expect(dialog).toBeHidden({ timeout: 20_000 });
  await expect
    .poll(
      async () => {
        const res = await apiRequest(request, "admin", "GET", `/certificates/${fingerprint}`);
        return ((await res.json()) as { data?: { renewal_status?: string } }).data?.renewal_status;
      },
      { timeout: 20_000 },
    )
    .toBe("revoked");
});

test("target setup by keyboard", async ({ page }) => {
  await loginAs(page, "admin");
  await page.goto("/targets/setup");
  await expect(
    page.getByRole("radiogroup", { name: "Setup mode" }),
  ).toBeVisible({ timeout: 20_000 });
  const id = uniq();

  await tabTo(page, page.getByRole("radio", { name: /Agentless/ }));
  await page.keyboard.press("Enter");
  await expectStep(page, "Host");
  await tabTo(page, page.getByLabel("Target name"));
  await page.keyboard.type(`kb-${id}.internal`);
  await page.keyboard.press("Tab");
  await page.keyboard.type(`kb-${id}.internal.example.test`);
  await page.keyboard.press("Enter"); // Enter in a text field advances the wizard

  await expectStep(page, "Discovery");
  await nextByKeyboard(page);

  await expectStep(page, "Install");
  await tabTo(page, page.getByLabel("Install mode"));
  await page.keyboard.type("ACME"); // typeahead; ACME needs no credential or pinned host key
  await nextByKeyboard(page);

  await expectStep(page, "Credential");
  await nextByKeyboard(page);

  await expectStep(page, "Review");
  await tabTo(page, page.getByRole("button", { name: "Finish" }));
  await page.keyboard.press("Enter");
  await expect(page.getByText(/declared$/)).toBeVisible({ timeout: 30_000 });
});

test("no pointer calls in journey source", () => {
  const src = fs.readFileSync(
    path.join(
      path.dirname(fileURLToPath(import.meta.url)),
      "keyboard-journeys.spec.ts",
    ),
    "utf8",
  );
  // Built from pieces so this file's own text never contains the banned call names.
  const banned = [
    "cl" + "ick(",
    "fi" + "ll(",
    "ch" + "eck(",
    "selectOpt" + "ion(",
    "ho" + "ver(",
    "tap" + "(",
  ];
  const code = src
    .split("\n")
    .filter((l) => !l.trim().startsWith("//"))
    .join("\n");
  for (const b of banned)
    expect(code.includes(`.${b}`), `journey source calls .${b}`).toBe(false);
});
