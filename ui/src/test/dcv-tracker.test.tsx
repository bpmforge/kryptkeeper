import { render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    runtimeConfig: vi.fn(),
    setRuntimeConfig: vi.fn(),
    resetRuntimeConfig: vi.fn(),
    testNotificationDelivery: vi.fn(),
    protectedConfig: vi.fn(),
    dcvValidations: vi.fn(),
  },
}));
vi.mock("../lib/rolesApi", () => ({ rolesApi: { preview: vi.fn() } }));

import Integrations from "../pages/Integrations";
import { api } from "../lib/api";
import { formatDateTime } from "../components/ui";

// Shapes follow docs/openapi.yaml listDcvValidations.
const FIXTURE = {
  data: [
    {
      domain: "b.example.com",
      connector_id: "c1",
      validated_at: "2026-09-01T00:00:00Z",
      expires_at: "2026-12-10T00:00:00Z",
      reuse_days: 100,
      days_remaining: 55,
      warn: false,
    },
    {
      domain: "a.example.com",
      connector_id: "c1",
      validated_at: "2026-07-01T00:00:00Z",
      expires_at: "2026-10-20T00:00:00Z",
      reuse_days: 100,
      days_remaining: 4,
      warn: true,
    },
    {
      domain: "c.example.com",
      connector_id: "c2",
      validated_at: "2026-10-01T00:00:00Z",
      expires_at: "2027-01-09T00:00:00Z",
      reuse_days: 100,
      days_remaining: 85,
      warn: false,
    },
  ],
  schedule: [
    { effective: "2026-03-15", days: 200 },
    { effective: "2027-03-15", days: 100 },
  ],
  current_reuse_days: 200,
};

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
  vi.mocked(api.authzCheck).mockResolvedValue({
    service: "kryptkeeper",
    authenticated: true,
    principal: "admin-1",
    role: "pki-admin",
    scopes: ["*"],
  } as never);
  vi.mocked(api.runtimeConfig).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.protectedConfig).mockResolvedValue({
    service: "kryptkeeper",
    resource: "protected-config",
    auth_mode: "bootstrap",
    config: { oidc_enabled: false, discovery_enabled: false, jwt_mode_enabled: false },
  } as never);
  vi.mocked(api.dcvValidations).mockResolvedValue(FIXTURE as never);
});

async function domainTable() {
  return screen.findByRole("table", { name: "Domain validations" });
}

describe("DCV tracker panel", () => {
  it("renders each domain with expiry and days remaining", async () => {
    renderPage();
    const table = await domainTable();
    const body = within(table).getAllByRole("row").slice(1);
    expect(body).toHaveLength(3);
    // Sorted ascending by days remaining.
    expect(within(body[0]).getByText("a.example.com")).toBeInTheDocument();
    expect(within(body[0]).getByText("4")).toBeInTheDocument();
    expect(within(body[0]).getByText(formatDateTime("2026-10-20T00:00:00Z"))).toBeInTheDocument();
    expect(within(body[1]).getByText("55")).toBeInTheDocument();
    expect(within(body[2]).getByText("85")).toBeInTheDocument();
  });

  it("flags rows under 20 percent", async () => {
    renderPage();
    const rows = (await domainTable()).querySelectorAll("tbody tr");
    expect(rows[0].getAttribute("data-warn")).toBe("true");
    expect(within(rows[0] as HTMLElement).getByText("Under 20% left")).toBeInTheDocument();
    expect(rows[1].getAttribute("data-warn")).toBeNull();
    expect(within(rows[1] as HTMLElement).getByText("OK")).toBeInTheDocument();
    expect(within(rows[2] as HTMLElement).getByText("OK")).toBeInTheDocument();
  });

  it("shows the schedule and marks the current period", async () => {
    renderPage();
    await domainTable();
    const sched = screen.getByRole("table", { name: "Reuse period schedule" });
    const rows = within(sched).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByText("Current")).toBeInTheDocument();
    expect(within(rows[1]).queryByText("Current")).not.toBeInTheDocument();
  });

  it("shows empty and error states", async () => {
    vi.mocked(api.dcvValidations).mockResolvedValueOnce({
      data: [],
      schedule: [],
      current_reuse_days: 0,
    } as never);
    const first = renderPage();
    expect(await screen.findByText("No validations yet")).toBeInTheDocument();
    first.unmount();

    vi.mocked(api.dcvValidations).mockRejectedValueOnce(new Error("boom"));
    renderPage();
    expect(await screen.findByText("Domain validations could not be loaded.")).toBeInTheDocument();
  });

  it("has no serious or critical axe violations", async () => {
    const { container } = renderPage();
    await domainTable();
    const { default: axe } = await import("axe-core");
    // color-contrast is disabled because jsdom cannot compute rendered colours.
    const r = await axe.run(container, {
      runOnly: ["wcag2a", "wcag2aa"],
      rules: { "color-contrast": { enabled: false } },
    });
    expect(r.violations.filter((v) => v.impact === "serious" || v.impact === "critical")).toEqual([]);
  });
});
