import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    dashboardSummary: vi.fn(),
    cas: vi.fn(),
    auditList: vi.fn(),
    cryptoPosture: vi.fn(),
    executiveSummaryPdfUrl: () =>
      "/api/v1/reports/executive-summary?format=pdf",
  },
}));

import Dashboard from "../pages/Dashboard";
import { api } from "../lib/api";

const summary = {
  data: {
    certificates: { total: 12, expiring_30_days: 4, expired: 2, managed: 7, external: 2, unmanaged: 3 },
    discovery: { discovered_endpoints: 20, risky_endpoints: 5 },
    notifications: { pending_notifications: 3 },
  },
};

const emptyCas = { data: [] };
// W8-02: Dashboard now renders the onboarding wizard in place of its normal
// content when the hub has zero CAs (useFirstRun's own signal, reusing this
// same mocked api.cas call). These dashboard-content tests are about
// dashboard content given specific summary/audit data, not about the
// zero-CA state -- so the default fixture here is a non-empty CA list,
// leaving `emptyCas` for the dedicated first-run test below.
const oneCa = { data: [{ id: "ca-1", name: "Root CA", type: "root" }] };
const emptyAudit = { data: [] };
const emptyPosture = { data: null };

function renderDashboard() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.mocked(api.dashboardSummary).mockReset();
  vi.mocked(api.cas).mockResolvedValue(oneCa as never);
  vi.mocked(api.auditList).mockResolvedValue(emptyAudit as never);
  vi.mocked(api.cryptoPosture).mockResolvedValue(emptyPosture as never);
});

describe("Dashboard", () => {
  it("renders a skeleton loading state while fetching", () => {
    vi.mocked(api.dashboardSummary).mockImplementation(
      () => new Promise(() => {}) as never,
    );
    renderDashboard();

    // DashboardSkeleton renders animate-pulse divs, not text
    expect(
      document.querySelector('[class*="animate-pulse"]'),
    ).toBeInTheDocument();
  });

  it("KPI tiles have a structured accessible name, not run-together text", async () => {
    vi.mocked(api.dashboardSummary).mockResolvedValue(summary as never);
    renderDashboard();
    expect(
      await screen.findByRole("button", { name: /^Expiring 30d: 4, needs renewal$/ }),
    ).toBeInTheDocument();
  });

  it("shows the estate split with drill-down counts (W11-08)", async () => {
    vi.mocked(api.dashboardSummary).mockResolvedValue(summary as never);
    renderDashboard();
    const strip = await screen.findByTestId("estate-strip");
    expect(strip).toHaveTextContent("7 managed");
    expect(strip).toHaveTextContent("2 externally managed");
    expect(strip).toHaveTextContent("3 unmanaged");
  });

  it("renders key metric tiles when data loads", async () => {
    vi.mocked(api.dashboardSummary).mockResolvedValue(summary as never);
    renderDashboard();

    // Stat tile labels from the new dashboard design
    expect(await screen.findByText(/active certs/i)).toBeInTheDocument();
    expect(screen.getByText(/expiring 30d/i)).toBeInTheDocument();
    // "Expired" appears on the stat tile label
    expect(screen.getAllByText(/expired/i).length).toBeGreaterThan(0);
  });

  it("offers the executive one-pager PDF download", async () => {
    vi.mocked(api.dashboardSummary).mockResolvedValue(summary as never);
    renderDashboard();

    const button = await screen.findByRole("button", {
      name: /download executive one-pager pdf/i,
    });
    expect(button).toBeInTheDocument();
  });

  it("shows the attention banner when certs are expiring or expired", async () => {
    vi.mocked(api.dashboardSummary).mockResolvedValue(summary as never);
    renderDashboard();

    // The attention strip appears because expired=2 and expiring30=4
    expect(await screen.findByText(/attention required/i)).toBeInTheDocument();
    expect(screen.getByText(/4 expiring in 30d/i)).toBeInTheDocument();
    expect(screen.getByText(/2 expired/i)).toBeInTheDocument();
  });

  // W8-02
  it("renders the onboarding wizard instead of dashboard content when there are zero CAs", async () => {
    vi.mocked(api.cas).mockResolvedValue(emptyCas as never);
    vi.mocked(api.dashboardSummary).mockResolvedValue(summary as never);
    renderDashboard();

    expect(
      await screen.findByText(/welcome to kryptkeeper/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/total certs/i)).not.toBeInTheDocument();
  });
});

describe("Dashboard PQC readiness card", () => {
  it("shows the parts that make up the readiness percentage", async () => {
    vi.mocked(api.dashboardSummary).mockResolvedValue(summary as never);
    vi.mocked(api.cryptoPosture).mockResolvedValue({
      data: {
        total_certs: 7,
        pqc_readiness: {
          quantum_safe: 0,
          quantum_safe_leaf_only: 0,
          migration_ready: 1,
          vulnerable: 0,
          not_applicable: 6,
          pqc_score_percent: 14,
          quantum_safe_percent: 0,
        },
      },
    } as never);
    renderDashboard();
    // 14% beside "0 quantum-safe / 0 vulnerable" was unexplained: the
    // migration-ready certificate that makes up the 14% is now listed.
    expect(await screen.findByText("14%")).toBeInTheDocument();
    expect(screen.getByText("migration-ready")).toBeInTheDocument();
    expect(screen.getByText("leaf-only PQC")).toBeInTheDocument();
    expect(
      screen.getByText(/1 of 7 certificates are quantum-safe, leaf-only PQC or migration-ready/),
    ).toBeInTheDocument();
  });
});
