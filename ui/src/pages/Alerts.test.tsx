import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      authzCheck: vi.fn(),
      notificationRules: vi.fn(),
      createNotificationRule: vi.fn(),
      updateNotificationRule: vi.fn(),
      deleteNotificationRule: vi.fn(),
      notificationTeamRoutes: vi.fn(),
      createNotificationTeamRoute: vi.fn(),
      deleteNotificationTeamRoute: vi.fn(),
      ownerlessCertificates: vi.fn(),
      notificationsSummary: vi.fn(),
      notificationDeliveries: vi.fn(),
      testNotificationDelivery: vi.fn(),
      retryNotificationDelivery: vi.fn(),
      acknowledgeNotificationDelivery: vi.fn(),
      runtimeConfig: vi.fn(),
      protectedConfig: vi.fn(),
    },
  };
});

vi.mock("../lib/rolesApi", () => ({
  rolesApi: { preview: vi.fn() },
}));

import Alerts from "./Alerts";
import Integrations from "./Integrations";
import { api } from "../lib/api";

const adminAuthz = {
  service: "kryptkeeper",
  authenticated: true,
  principal: "admin-1",
  role: "pki-admin",
  scopes: ["*"],
};
const viewerAuthz = {
  service: "kryptkeeper",
  authenticated: true,
  principal: "viewer-1",
  role: "pki-viewer",
  scopes: [],
};

function renderPage(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const DELIVERIES = [
  {
    id: "del-failed",
    channel: "slack",
    target: "#ops",
    status: "failed",
    queued_at: "2026-10-01T00:00:00Z",
  },
  {
    id: "dash-1",
    channel: "dashboard",
    target: "unrouted",
    status: "queued",
    queued_at: "2026-10-01T01:00:00Z",
  },
];

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue(adminAuthz as unknown as never);
  vi.mocked(api.notificationsSummary).mockResolvedValue({
    data: {},
  } as unknown as never);
  vi.mocked(api.notificationDeliveries).mockResolvedValue({
    data: { deliveries: DELIVERIES },
  } as unknown as never);
  vi.mocked(api.notificationRules).mockResolvedValue({
    data: {
      items: [
        {
          id: "r1",
          name: "pct rule",
          threshold_pct: 25,
          channel: "email",
          target: "@owner_team",
          enabled: true,
        },
        {
          id: "r2",
          name: "days rule",
          threshold_days: 30,
          channel: "slack",
          target: "#pki",
          enabled: true,
        },
        {
          id: "r3",
          name: "expired rule",
          threshold_pct: 0,
          channel: "email",
          target: "a@example.com",
          enabled: false,
        },
      ],
    },
  } as unknown as never);
  vi.mocked(api.createNotificationRule).mockResolvedValue({
    data: {},
  } as unknown as never);
  vi.mocked(api.notificationTeamRoutes).mockResolvedValue({
    data: { items: [] },
  } as unknown as never);
  vi.mocked(api.ownerlessCertificates).mockResolvedValue({
    data: { items: [] },
  } as unknown as never);
});

async function openNewRule(user: ReturnType<typeof userEvent.setup>) {
  renderPage(<Alerts />);
  await user.click(await screen.findByRole("button", { name: "Alert rules" }));
  await user.click(await screen.findByRole("button", { name: "New rule" }));
  await user.type(
    await screen.findByPlaceholderText("30-day expiry alert"),
    "r",
  );
}

describe("Alerts rule form (W30-18)", () => {
  it("creates a rule with threshold_pct when unit is percent", async () => {
    const user = userEvent.setup();
    await openNewRule(user);
    const threshold = screen.getByLabelText("Threshold");
    await user.clear(threshold);
    await user.type(threshold, "10");
    await user.click(screen.getByLabelText("Route to owner team"));
    await user.click(screen.getByRole("button", { name: "Create rule" }));
    await waitFor(() =>
      expect(api.createNotificationRule).toHaveBeenCalledTimes(1),
    );
    const body = vi.mocked(api.createNotificationRule).mock.calls[0][0];
    expect(body.threshold_pct).toBe(10);
    expect(body).not.toHaveProperty("threshold_days");
    expect(body.target).toBe("@owner_team");
  });

  it("sends a percent of 0 (at expiry) rather than dropping it", async () => {
    const user = userEvent.setup();
    await openNewRule(user);
    const threshold = screen.getByLabelText("Threshold");
    await user.clear(threshold);
    await user.type(threshold, "0");
    await user.type(
      screen.getByPlaceholderText("pki-team@example.com"),
      "ops@example.com",
    );
    await user.click(screen.getByRole("button", { name: "Create rule" }));
    await waitFor(() =>
      expect(api.createNotificationRule).toHaveBeenCalledTimes(1),
    );
    expect(
      vi.mocked(api.createNotificationRule).mock.calls[0][0],
    ).toMatchObject({ threshold_pct: 0, target: "ops@example.com" });
  });

  it("creates a rule with threshold_days when unit is days", async () => {
    const user = userEvent.setup();
    await openNewRule(user);
    await user.selectOptions(screen.getByLabelText("Threshold unit"), "days");
    const threshold = screen.getByLabelText("Threshold");
    await user.clear(threshold);
    await user.type(threshold, "14");
    await user.type(
      screen.getByPlaceholderText("pki-team@example.com"),
      "ops@example.com",
    );
    await user.click(screen.getByRole("button", { name: "Create rule" }));
    await waitFor(() =>
      expect(api.createNotificationRule).toHaveBeenCalledTimes(1),
    );
    const body = vi.mocked(api.createNotificationRule).mock.calls[0][0];
    expect(body.threshold_days).toBe(14);
    expect(body).not.toHaveProperty("threshold_pct");
  });

  it("rejects percent > 100 and days < 1 without calling the API", async () => {
    const user = userEvent.setup();
    await openNewRule(user);
    await user.type(
      screen.getByPlaceholderText("pki-team@example.com"),
      "ops@example.com",
    );
    const threshold = screen.getByLabelText("Threshold");
    await user.clear(threshold);
    await user.type(threshold, "101");
    await user.click(screen.getByRole("button", { name: "Create rule" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /between 0 and 100/,
    );

    await user.selectOptions(screen.getByLabelText("Threshold unit"), "days");
    await user.clear(screen.getByLabelText("Threshold"));
    await user.type(screen.getByLabelText("Threshold"), "0");
    await user.click(screen.getByRole("button", { name: "Create rule" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /between 1 and 3650/,
    );
    expect(api.createNotificationRule).not.toHaveBeenCalled();
  });

  it("rules table shows 25% / 30d / At expiry and owner team routing", async () => {
    const user = userEvent.setup();
    renderPage(<Alerts />);
    await user.click(
      await screen.findByRole("button", { name: "Alert rules" }),
    );
    expect(await screen.findByText("25%")).toBeInTheDocument();
    expect(screen.getByText("30d")).toBeInTheDocument();
    expect(screen.getByText("At expiry")).toBeInTheDocument();
    expect(screen.getByText("Owner team routing")).toBeInTheDocument();
  });
});

describe("Alerts delivery queue (W30-18)", () => {
  it("failed delivery shows Retry and Acknowledge; a dashboard-queued row shows the badge and no external-send claim", async () => {
    renderPage(<Alerts />);
    expect(await screen.findByText("Queued in dashboard")).toBeInTheDocument();
    expect(
      screen.getByText(/nothing was sent externally/i),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Retry" })).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: "Acknowledge" })).toHaveLength(
      1,
    );
  });

  it("read-only role sees no retry/ack controls", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue(
      viewerAuthz as unknown as never,
    );
    renderPage(<Alerts />);
    await screen.findByText("Queued in dashboard");
    await waitFor(() => expect(api.authzCheck).toHaveBeenCalled());
    await waitFor(() =>
      expect(screen.getAllByText("Read only").length).toBeGreaterThan(0),
    );
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Acknowledge" })).toBeNull();
  });
});

describe("Integrations copy (W30-18)", () => {
  it("no longer says restart or startup for notification channels", async () => {
    vi.mocked(api.runtimeConfig).mockResolvedValue({
      data: [],
    } as unknown as never);
    vi.mocked(api.protectedConfig).mockResolvedValue({
      service: "kryptkeeper",
      resource: "protected-config",
      auth_mode: "bootstrap",
      config: {
        oidc_enabled: false,
        discovery_enabled: false,
        jwt_mode_enabled: false,
      },
    } as unknown as never);
    renderPage(<Integrations />);
    expect(
      await screen.findByText(/apply on the next send; no restart is needed/i),
    ).toBeInTheDocument();
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(
      /startup environment variables|rewired to read the config store|never persisted/i,
    );
    expect(
      await screen.findByText(/server restarts with SSO consumers rewired/i),
    ).toBeInTheDocument();
  });
});

describe("Alerts delivery failure reason (CB-14)", () => {
  it("shows why an egress-refused delivery failed and what to change", async () => {
    vi.mocked(api.notificationDeliveries).mockResolvedValue({
      data: {
        deliveries: [
          {
            ...DELIVERIES[0],
            failure_reason: "Blocked by the hub's outbound egress guard: loopback is never allowed. Use a LAN address.",
          },
        ],
      },
    } as unknown as never);
    renderPage(<Alerts />);
    expect(await screen.findByText(/Blocked by the hub's outbound egress guard/)).toBeInTheDocument();
  });
});
