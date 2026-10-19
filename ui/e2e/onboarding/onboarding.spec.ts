// W33-02: first-run wizard -> first certificate -> /targets/setup, on a stack with ZERO CAs.
// Prerequisite and run command: see README.md in this folder.
//
// Known limitation (UC-L01 edge, deliberately not asserted): refreshing the page
// mid-wizard loses the wizard's in-memory state; created CA/template stay on the
// server but the form restarts.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { apiRequest, expect, loginAs, test } from "../fixtures";

const HEADING = "Welcome to Kryptkeeper";

test.describe.serial("first-run onboarding", () => {
  test.beforeAll(() => {
    // Fail loudly (not skip) when the verification tool is missing.
    execFileSync("openssl", ["version"]);
  });

  // Runs BEFORE the CA exists: with zero CAs this is the exact case where a failed
  // first-run probe could trap the admin in the wizard.
  test("CA list 500 does not trap the shell", async ({ page }) => {
    await loginAs(page, "admin");
    await page.route("**/api/v1/cas*", (r) =>
      r.fulfill({ status: 500, contentType: "application/json", body: "{}" }),
    );
    await page.goto("/");
    const t = Date.now();
    await expect(page.getByRole("navigation").first()).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("heading", { name: HEADING })).toHaveCount(0);
    expect(Date.now() - t).toBeLessThan(5000);
  });

  test("admin completes wizard, cert verifies, lands on target setup", async ({ page, request }, testInfo) => {
    const listed = await apiRequest(request, "admin", "GET", "/cas");
    expect(listed.status()).toBe(200);
    const existing = ((await listed.json()) as { data: unknown[] }).data;
    test.skip(existing.length > 0, "stack not clean: CA already exists (start a fresh first-run stack, see README.md)");

    // The wizard takes a CSR the operator already holds; generate a throwaway one.
    const keyPath = testInfo.outputPath("leaf.key");
    const csrPath = testInfo.outputPath("leaf.csr");
    execFileSync("openssl", [
      "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
      "-keyout", keyPath, "-out", csrPath,
      "-subj", "/CN=e2e.example.test", "-addext", "subjectAltName=DNS:e2e.example.test",
    ], { stdio: "pipe" });
    const csrPem = fs.readFileSync(csrPath, "utf8");

    await loginAs(page, "admin");
    await page.goto("/");
    await expect(page.getByRole("heading", { name: HEADING })).toBeVisible({ timeout: 20_000 });
    const start = Date.now();

    // Step 1: Root CA
    await page.getByLabel("Subject common name").fill("e2e-root");
    await page.getByLabel("Organization").fill("E2E");
    await page.getByLabel("Algorithm").selectOption({ label: "ECDSA P-256" });
    await page.getByLabel("Validity", { exact: true }).fill("10y");
    await page.getByRole("button", { name: "Create root CA" }).click();
    await expect(page.getByRole("button", { name: "Root CA created" })).toBeVisible();
    await page.getByRole("button", { name: "Next" }).click();

    // Step 2: Template
    await expect(page.getByRole("heading", { name: "Template" })).toBeVisible();
    await page.getByLabel("Name", { exact: true }).fill("e2e-template");
    await page.getByLabel("Validity period").fill("90d");
    await page.getByRole("button", { name: "Create template" }).click();
    await expect(page.getByRole("button", { name: "Template created" })).toBeVisible();
    await page.getByRole("button", { name: "Next" }).click();

    // Step 3: First certificate
    await expect(page.getByRole("heading", { name: "First certificate" })).toBeVisible();
    await page.getByLabel("CSR PEM").fill(csrPem);
    await page.getByRole("button", { name: "Issue certificate" }).click();
    const issued = page.getByRole("button", { name: "Certificate issued" });
    const failure = page.locator("p.text-state-over, [role=alert]");
    await expect(issued.or(failure.first())).toBeVisible();
    // A pending-approval (HTTP 202) or any other failure surfaces as text: fail with it, no workaround.
    expect(await failure.allTextContents(), "issuance must succeed without an approval step").toEqual([]);
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download certificate" }).click();
    const download = await downloadPromise;
    const leafPath = testInfo.outputPath("leaf.pem");
    await download.saveAs(leafPath);
    await expect(page.getByText(/download failed/i)).toHaveCount(0);
    await page.getByRole("button", { name: "Next" }).click();

    // Step 4: optional integrations (W33-03 added it), then Step 5: Discovery & install
    await page.getByRole("button", { name: "Next" }).click();
    await expect(page.getByRole("heading", { name: "Discovery & install" })).toBeVisible();
    await page.getByRole("button", { name: "Choose agentless mode" }).click();
    await page.getByRole("button", { name: "Finish" }).click();
    await expect(page).toHaveURL(/\/targets\/setup$/);

    // Chain proof: the downloaded leaf verifies against the new root fetched from the API.
    const cas = await apiRequest(request, "admin", "GET", "/cas");
    const caList = ((await cas.json()) as { data: { id: string }[] }).data;
    expect(caList).toHaveLength(1);
    const chain = await apiRequest(request, "admin", "GET", `/cas/${caList[0].id}/chain?format=pem`);
    expect(chain.status()).toBe(200);
    const rootPath = testInfo.outputPath("root.pem");
    fs.writeFileSync(rootPath, await chain.text());

    const leaf = fs.readFileSync(leafPath, "utf8");
    expect(leaf.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
    const out = execFileSync("openssl", ["verify", "-CAfile", rootPath, leafPath], { encoding: "utf8" });
    expect(out).toContain(": OK");

    expect(Date.now() - start).toBeLessThan(600_000);
  });

  test("non-admin first login sees no CA-creation controls", async ({ page }) => {
    await loginAs(page, "viewer");
    await page.goto("/cas");
    await expect(page.getByRole("heading", { name: "Certificate Authorities" }).first()).toBeVisible({ timeout: 20_000 });
    await expect(page.getByRole("button", { name: "New CA" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Import external root" })).toHaveCount(0);

    await page.goto("/");
    await expect(page.getByRole("navigation").first()).toBeVisible();
    await expect(page.getByText("Root CA")).toHaveCount(0);
  });
});
