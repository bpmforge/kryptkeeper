import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  fetchJSON: vi.fn(),
  api: {
    authzCheck: vi.fn(),
    runtimeConfig: vi.fn(),
    setRuntimeConfig: vi.fn(),
    resetRuntimeConfig: vi.fn(),
    dcvValidations: vi.fn(),
    protectedConfig: vi.fn(),
    testNotificationDelivery: vi.fn(),
    createCredential: vi.fn(),
  },
}));

import Integrations from "./Integrations";
import { api, fetchJSON } from "../lib/api";

const STORED = "stored-secret-value-123";

function setting(key: string, over: Record<string, unknown> = {}) {
  return {
    key,
    category: "notifications",
    env_var: "KK_" + key.replace(/\./g, "_").toUpperCase(),
    secret: true,
    source: "database",
    effective_source: "override",
    configured: true,
    updated_at: "2026-10-16T00:00:00Z",
    ...over,
  };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Integrations />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue({ principal: "a", role: "pki-admin", scopes: [] } as unknown as never);
  vi.mocked(api.runtimeConfig).mockResolvedValue({
    data: [
      setting("notifications.webhook_url"),
      setting("notifications.webhook_secret"),
    ],
  } as unknown as never);
  vi.mocked(api.dcvValidations).mockResolvedValue({ data: [], schedule: [], current_reuse_days: 0 } as unknown as never);
  vi.mocked(api.protectedConfig).mockResolvedValue({ auth_mode: "x", config: { oidc_enabled: false } } as unknown as never);
  vi.mocked(fetchJSON).mockResolvedValue({ data: { items: [] } } as unknown as never);
});

describe("Integrations webhook config", () => {
  it("shows webhook URL and signing secret fields, secrets masked", async () => {
    renderPage();
    const url = await screen.findByLabelText("Webhook URL");
    const secret = screen.getByLabelText("Webhook signing secret");
    expect(url).toHaveAttribute("type", "password");
    expect(secret).toHaveAttribute("type", "password");
    expect(url).toHaveValue("");
    expect(secret).toHaveValue("");
    expect(document.body.textContent).not.toContain(STORED);
  });

  it("shows friendly labels, not raw keys, for chatops settings", async () => {
    vi.mocked(api.runtimeConfig).mockResolvedValueOnce({
      data: [
        setting("notifications.slack_bot_token", { source: "unset", configured: false }),
        setting("notifications.teams_app_id", { source: "unset", configured: false }),
      ],
    } as unknown as never);
    renderPage();
    expect(await screen.findByLabelText("Slack bot token")).toBeInTheDocument();
    expect(screen.getByLabelText("Teams app ID")).toBeInTheDocument();
    expect(screen.queryByText("notifications.slack_bot_token")).toBeNull();
  });

  it("saves webhook URL", async () => {
    const user = userEvent.setup();
    vi.mocked(api.setRuntimeConfig).mockResolvedValue(undefined as never);
    vi.mocked(api.runtimeConfig).mockResolvedValueOnce({
      data: [setting("notifications.webhook_url", { source: "unset", configured: false })],
    } as unknown as never);
    renderPage();
    const input = await screen.findByLabelText("Webhook URL");
    expect(screen.getByText("Not configured.")).toBeInTheDocument();
    await user.type(input, "http://lan.example/hook");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(api.setRuntimeConfig).toHaveBeenCalledWith("notifications.webhook_url", "http://lan.example/hook"),
    );
    expect((await screen.findAllByText(/Configured \(override\)/)).length).toBeGreaterThan(0);
  });

  it("stale test-only copy is gone", async () => {
    renderPage();
    await screen.findByLabelText("Webhook URL");
    expect(screen.queryByText(/never persisted/i)).toBeNull();
    expect(screen.queryByText(/no saved config at all/i)).toBeNull();
    expect(screen.getByText(/saved in the Notifications panel above/i)).toBeInTheDocument();
  });
});
