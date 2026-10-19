import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    dashboardSummary: vi.fn(),
    cas: vi.fn(),
    auditList: vi.fn(),
    cryptoPosture: vi.fn(),
    certificates: vi.fn(),
    authzCheck: vi.fn(),
    executiveSummaryPdfUrl: () => "/api/v1/reports/executive-summary?format=pdf",
  },
}));
vi.mock("../lib/ownershipApi", () => ({
  listOrphans: vi.fn(),
  reassignOrphans: vi.fn(),
}));

import Dashboard from "../pages/Dashboard";
import Certificates from "../pages/Certificates";
import { api } from "../lib/api";
import { listOrphans, reassignOrphans } from "../lib/ownershipApi";

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="location">{loc.pathname + loc.search}</div>;
}

function wrap(ui: React.ReactNode, entry = "/") {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[entry]}>
        {ui}
        <LocationProbe />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const adminAuthz = { principal: "admin@example.com", role: "pki-admin", scopes: ["*"] };
const viewerAuthz = { principal: "v@example.com", role: "pki-auditor", scopes: [] };

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.cas).mockResolvedValue({ data: [{ id: "ca-1", name: "Root CA", type: "root" }] } as never);
  vi.mocked(api.auditList).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.cryptoPosture).mockResolvedValue({ data: null } as never);
  vi.mocked(api.certificates).mockResolvedValue({ data: [], meta: { total: 7 } } as never);
  vi.mocked(api.authzCheck).mockResolvedValue(adminAuthz as never);
  vi.mocked(listOrphans).mockResolvedValue({
    data: [{ user_id: "u1", owner_email: "gone@example.com", cert_count: 3 }],
  });
});

describe("unowned certificates", () => {
  it("dashboard unowned card shows count and links to the filter", async () => {
    vi.mocked(api.dashboardSummary).mockResolvedValue({
      data: { certificates: { total: 12, unowned: 7 } },
    } as never);
    wrap(<Dashboard />);
    const card = await screen.findByTestId("unowned-card");
    expect(card).toHaveTextContent("7 unowned");
    expect(card.className).toContain("text-state-attn");
    await userEvent.click(card);
    expect(screen.getByTestId("location")).toHaveTextContent("/certificates?owner=unassigned");
  });

  it("dashboard card is muted at zero", async () => {
    vi.mocked(api.dashboardSummary).mockResolvedValue({
      data: { certificates: { total: 12 } },
    } as never);
    wrap(<Dashboard />);
    const card = await screen.findByTestId("unowned-card");
    expect(card).toHaveTextContent("0 unowned");
    expect(card.className).toContain("text-muted-foreground");
    expect(card.className).not.toContain("text-state-attn");
  });

  it("certificates page sends owner=unassigned from the URL", async () => {
    wrap(
      <Routes>
        <Route path="/certificates" element={<Certificates />} />
      </Routes>,
      "/certificates?owner=unassigned",
    );
    await waitFor(() =>
      expect(api.certificates).toHaveBeenCalledWith(
        expect.objectContaining({ owner: "unassigned" }),
      ),
    );
    expect(screen.getByRole("button", { name: "Unowned only" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  it("orphan banner lists departed owners and bulk reassigns", async () => {
    vi.mocked(reassignOrphans).mockResolvedValue({ data: { reassigned: 3 } });
    wrap(
      <Routes>
        <Route path="/certificates" element={<Certificates />} />
      </Routes>,
      "/certificates",
    );
    await screen.findByText(/gone@example.com left — 3 certificates/);
    await userEvent.click(
      screen.getByRole("button", { name: /reassign certificates of gone@example.com/i }),
    );
    await userEvent.type(await screen.findByLabelText("New owner team"), "platform");
    await userEvent.type(screen.getByLabelText("New owner email"), "lead@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Reassign" }));
    await waitFor(() =>
      expect(reassignOrphans).toHaveBeenCalledWith({
        from_email: "gone@example.com",
        to_team: "platform",
        to_email: "lead@example.com",
      }),
    );
    await screen.findByText("Reassigned 3 certificates.");
  });

  it("orphan banner is hidden for viewers", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue(viewerAuthz as never);
    wrap(
      <Routes>
        <Route path="/certificates" element={<Certificates />} />
      </Routes>,
      "/certificates",
    );
    await waitFor(() => expect(api.certificates).toHaveBeenCalled());
    await waitFor(() => expect(api.authzCheck).toHaveBeenCalled());
    expect(screen.queryByTestId("orphan-banner")).not.toBeInTheDocument();
    expect(listOrphans).not.toHaveBeenCalled();
  });

  it("renders no banner or error when the orphan list is refused (403)", async () => {
    vi.mocked(listOrphans).mockRejectedValue(Object.assign(new Error("forbidden"), { status: 403 }));
    wrap(
      <Routes>
        <Route path="/certificates" element={<Certificates />} />
      </Routes>,
      "/certificates",
    );
    await waitFor(() => expect(listOrphans).toHaveBeenCalled());
    expect(screen.queryByTestId("orphan-banner")).not.toBeInTheDocument();
  });
});
