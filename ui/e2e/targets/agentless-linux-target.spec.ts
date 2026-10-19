// W33-26: add an agentless Linux target (SSH push) through /targets/setup with a
// throwaway sshd container. Skipped unless E2E_TARGETS=1.
import { apiRequest, expect, loginAs, test } from "../fixtures";
import { elapsedMs, randomId, startSshd, type SshdFixture } from "./helpers";

test.skip(!process.env.E2E_TARGETS, "needs sshd + agent sidecars (set E2E_TARGETS=1)");

test.describe.configure({ mode: "serial" });

test.describe("agentless Linux target", () => {
  let sshd: SshdFixture;
  const createdTargets: string[] = [];
  const createdCredentials: string[] = [];

  test.beforeAll(async () => {
    test.setTimeout(600_000);
    sshd = await startSshd();
  });

  test.afterAll(async ({ request }) => {
    for (const id of createdTargets) await apiRequest(request, "admin", "DELETE", `/targets/${id}`);
    for (const id of createdCredentials) await apiRequest(request, "admin", "DELETE", `/credentials/${id}`);
    await sshd?.dispose();
  });

  test("adds an SSH push target with a pinned host key", async ({ page, request }) => {
    const targetName = `e2e-ssh-${randomId()}`;
    const credName = `e2e-ssh-cred-${randomId()}`;
    await loginAs(page, "admin");
    await page.goto("/targets/setup");

    await page.getByRole("radio", { name: /^Agentless/ }).click();

    // Host step: name, host, OS Linux (the default).
    await page.getByLabel("Target name").fill(targetName);
    await page.getByLabel("Host", { exact: true }).fill(sshd.host);
    await expect(page.getByRole("radio", { name: /Linux/ })).toBeChecked();
    await page.getByRole("button", { name: "Next" }).click();

    // Discovery step: the Linux options are Network scan / Cloud / None; keep the default.
    await expect(page.getByLabel("Discovery mode")).toBeVisible();
    await page.getByRole("button", { name: "Next" }).click();

    // Install step: SSH push.
    await page.getByLabel("Install mode").selectOption("ssh");
    await page.getByRole("button", { name: "Next" }).click();

    // Credential step: create an ssh_key credential from the per-run key.
    await page.getByRole("combobox", { name: /^Credential/ }).selectOption("__new__");
    await page.getByLabel("Name", { exact: true }).fill(credName);
    await page.getByLabel("SSH user").fill(sshd.user);
    await page.getByLabel("Private key (PEM)").fill(sshd.privateKey);
    await page.getByLabel("Host public key (pinned)").fill(sshd.hostPublicKey);
    const created = page.waitForResponse(
      (r) => r.url().endsWith("/api/v1/credentials") && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Create & use" }).click();
    const credRes = await created;
    expect(credRes.status()).toBe(201);
    createdCredentials.push(((await credRes.json()) as { data: { id: string } }).data.id);
    await expect(page.getByRole("combobox", { name: /^Credential/ })).toHaveValue(createdCredentials[0]);
    await page.getByRole("button", { name: "Next" }).click();

    // Host key step: probe, compare against what the container really holds, confirm.
    await page.getByRole("button", { name: "Fetch host key" }).click();
    const fingerprint = page.getByLabel("Host key fingerprint");
    await expect(fingerprint).toBeVisible({ timeout: 15_000 });
    const shown = ((await fingerprint.textContent()) ?? "").trim();
    expect(sshd.hostFingerprints, `UI fingerprint ${shown} is one of the sshd host keys`).toContain(shown);
    await page.getByRole("checkbox", { name: /verified this fingerprint/i }).check();

    await page.getByRole("button", { name: "Next" }).click();

    // Review step, then Finish creates the target.
    const target = page.waitForResponse(
      (r) => r.url().endsWith("/api/v1/targets") && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Finish" }).click();
    const targetRes = await target;
    expect(targetRes.status()).toBe(201);
    createdTargets.push(((await targetRes.json()) as { data: { id: string } }).data.id);
    await expect(page.getByText(`${targetName} declared`)).toBeVisible();
    await expect(page.getByText(shown)).toBeVisible();

    const list = await apiRequest(request, "admin", "GET", "/targets");
    expect(list.ok()).toBe(true);
    const found = ((await list.json()) as {
      data: { id: string; name: string; install_mode: string; credential_ref?: string }[];
    }).data.find((t) => t.name === targetName);
    expect(found?.install_mode).toBe("ssh");
    expect(found?.credential_ref).toBe(createdCredentials[0]);

    // The new SSH target is offered as a managed target to scan from Discovery.
    await page.goto("/discovery");
    await expect(page.getByRole("heading").first()).toBeVisible({ timeout: 20_000 });
    await page.getByRole("button", { name: /scan/i }).first().click();
    await page.getByRole("combobox", { name: /^Scan type/ }).selectOption({ label: "SSH — Linux/Unix cert files and host keys (managed target)" });
    await expect(page.getByLabel("Managed target").locator("option", { hasText: targetName })).toHaveCount(1);
  });

  // [W33-30] The hub has no SSH credential preflight yet (POST /credentials/{id}/preflight is
  // windows_password only). These two are written against the planned contract: a "Test
  // credential" button for ssh_key credentials and a data-testid="credential-preflight" verdict.
  test.fixme("SSH preflight with the authorized key reports success (blocked by W33-30)", async ({ page }) => {
    await loginAs(page, "admin");
    await page.goto("/targets/setup");
    await page.getByRole("button", { name: "Test credential" }).click();
    await expect(page.getByTestId("credential-preflight")).toContainText(/can discover and install/i);
  });

  test.fixme("SSH preflight with an unauthorized key fails fast with a specific message (blocked by W33-30)", async ({ page }) => {
    await loginAs(page, "admin");
    await page.goto("/targets/setup");
    const t0 = Date.now();
    await page.getByRole("button", { name: "Test credential" }).click();
    const verdict = page.getByTestId("credential-preflight");
    await expect(verdict).toBeVisible({ timeout: 10_000 });
    expect(elapsedMs(t0)).toBeLessThan(10_000);
    await expect(verdict).toContainText(/authentication failed|unauthenticated|permission denied/i);
    await expect(verdict).toContainText(sshd.user);
    await expect(verdict).toContainText(sshd.host);
    // Never echoes key material.
    expect(await verdict.textContent()).not.toContain(sshd.wrongPrivateKey.split("\n")[1]);
  });

  // [W34-10] Needs the non-root `kkscan` fixture from tests/live/agentless-sudo (a
  // root-owned 0600 JKS behind a non-root Tomcat). startSshd() logs in as root, which
  // can read everything, so the Blocked state cannot appear against it. The flow is
  // written against the shipped contract: GET /targets carries `blocked` and the
  // Targets page renders it with the recipe; switching the credential to helper mode
  // clears it on the next scheduler tick.
  test.fixme("a root-owned install path blocks the target until the credential is switched to helper mode", async ({ page, request }) => {
    await loginAs(page, "admin");
    await page.goto("/targets");
    const row = page.getByTestId(`target-${createdTargets[0]}`);
    await expect(row).toContainText("Blocked");
    await expect(row).toContainText("renewal needs root on this host");
    await expect(row).toContainText(/Scan ran unprivileged; \d+ paths? unreadable/);
    // Switch the target to a helper-mode credential, then wait for the scheduler tick.
    const res = await apiRequest(request, "admin", "PATCH", `/targets/${createdTargets[0]}`, { credential_ref: createdCredentials[1] });
    expect(res.ok()).toBe(true);
    await page.reload();
    await expect(row).not.toContainText("Blocked", { timeout: 120_000 });
  });
});
