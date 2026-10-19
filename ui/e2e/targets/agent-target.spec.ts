// W33-26: add an agent target through /targets/setup (token mint, live pairing).
// Needs the compose hub plus a podman machine; skipped unless E2E_TARGETS=1.
import { apiRequest, expect, loginAs, test } from "../fixtures";
import {
  buildAgentFixture,
  elapsedMs,
  randomId,
  waitForAgentLog,
  type AgentFixture,
  type AgentHandle,
} from "./helpers";

test.skip(!process.env.E2E_TARGETS, "needs sshd + agent sidecars (set E2E_TARGETS=1)");

test.describe.configure({ mode: "serial" });

test.describe("agent target", () => {
  let fixture: AgentFixture;
  let agent: AgentHandle | undefined;
  let agentName = "";

  test.beforeAll(async () => {
    test.setTimeout(600_000);
    fixture = await buildAgentFixture();
  });

  test.afterAll(async () => {
    await fixture?.dispose();
  });

  test.afterEach(async ({ request }) => {
    await agent?.stop();
    agent = undefined;
    if (!agentName) return;
    const list = await apiRequest(request, "admin", "GET", "/agents");
    if (list.ok()) {
      const { agents } = (await list.json()) as { agents: { id: string; name: string }[] };
      for (const a of agents.filter((x) => x.name === agentName)) {
        await apiRequest(request, "admin", "DELETE", `/agents/${a.id}`);
      }
    }
    agentName = "";
  });

  test("mints a token, pairs a real agent within one poll, and burns the token", async ({ page, request }) => {
    agentName = `e2e-agent-${randomId()}`;
    await loginAs(page, "admin");
    await page.goto("/targets/setup");

    await page.getByRole("radio", { name: /^Agent(?!less)/ }).click();
    await page.getByLabel("Agent name").fill(agentName);
    await page.getByLabel("Host type").selectOption("linux");
    await page.getByRole("button", { name: /generate|mint/i }).click();

    const command = page.locator("pre").filter({ hasText: "KRYPTKEEPER_ENROLL_TOKEN=" });
    await expect(command).toBeVisible();
    const text = (await command.textContent()) ?? "";
    const token = /KRYPTKEEPER_ENROLL_TOKEN=(\S+)/.exec(text)?.[1];
    const hubUrl = /KRYPTKEEPER_HUB_URL=(\S+)/.exec(text)?.[1];
    expect(token, "command carries an enrollment token").toMatch(/^kke_/);
    expect(hubUrl, "command carries the hub URL").toBeTruthy();
    expect(text).not.toContain("KRYPTKEEPER_AGENT_TOKEN");

    await expect(page.getByText("Waiting for agent...")).toBeVisible();

    // The browser sees the hub through the dashboard on a host port; the agent
    // container reaches it on the compose network (helpers.HUB_URL_IN_NETWORK).
    agent = await fixture.start({ token: token as string, name: agentName, type: "linux" });
    const t0 = await waitForAgentLog(agent, /registered:/);

    await expect(page.getByText(/Paired ✓/)).toBeVisible({ timeout: 6_500 });
    const pairedAfter = elapsedMs(t0);
    expect(pairedAfter, "paired within one 5 s poll of registering").toBeLessThanOrEqual(5_000);

    // The used token is no longer shown.
    await expect(page.getByText("The token has been used and is no longer shown.")).toBeVisible();

    // Single use: replaying the token is refused with a generic 403.
    const replay = await request.post(
      `${process.env.KK_E2E_BASE_URL ?? "http://localhost:3000"}/api/v1/agent/register`,
      { data: { name: "e2e-replay", enrollment_token: token } },
    );
    expect(replay.status()).toBe(403);
  });
});
