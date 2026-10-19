import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", async (orig) => ({
  ...(await orig<typeof import("../lib/api")>()),
  api: {
    cryptoPosture: vi.fn(),
    cryptoPostureTrend: vi.fn(),
    tenantContext: vi.fn(),
    authzCheck: vi.fn(),
  },
  downloadAuthedFile: vi.fn(),
}));

import CryptoPosture from "./CryptoPosture";
import { api } from "../lib/api";

const DAY = 86_400_000;

function report(over: Record<string, unknown> = {}) {
  return {
    generated_at: "2026-10-16T00:00:00Z",
    total_certs: 10,
    algorithm_breakdown: { RSA: 10 },
    pqc_readiness: {
      quantum_safe: 0,
      quantum_safe_leaf_only: 0,
      migration_ready: 0,
      vulnerable: 10,
      not_applicable: 0,
      pqc_score_percent: 0,
      quantum_safe_percent: 0,
    },
    risk_breakdown: { critical: 1, high: 2, medium: 3, low: 4 },
    expiry_buckets: {
      expired: 0,
      expiring_47d: 0,
      expiring_90d: 0,
      expiring_200d: 0,
      expiring_1yr: 0,
    },
    automation_coverage: { automated: 0, automation_percent: 0 },
    grade_distribution: { A: 5, B: 5 },
    ...over,
  };
}

function snap(id: string, date: string, total: number, rep = {}) {
  return {
    id,
    captured_at: `${date}T00:00:00Z`,
    total_certs: total,
    pqc_score_percent: 10,
    automation_percent: 20,
    risk_critical: 1,
    risk_high: 2,
    risk_medium: 3,
    risk_low: 4,
    expired: 0,
    expiring_47d: 0,
    report: report(rep),
  };
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <CryptoPosture />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function trend(...snapshots: unknown[]) {
  vi.mocked(api.cryptoPostureTrend).mockResolvedValue({
    data: { snapshots },
  } as never);
}

function rowCells(label: string) {
  const row = screen.getByRole("rowheader", { name: label }).closest("tr")!;
  return within(row)
    .getAllByRole("cell")
    .map((c) => c.textContent);
}

beforeEach(() => {
  vi.mocked(api.cryptoPosture).mockReset();
  vi.mocked(api.cryptoPostureTrend).mockReset();
  vi.mocked(api.tenantContext).mockReset();
  vi.mocked(api.authzCheck).mockReset();
  vi.mocked(api.cryptoPosture).mockResolvedValue({ data: report() } as never);
  vi.mocked(api.tenantContext).mockResolvedValue({
    data: {
      enabled: true,
      super_admin: true,
      tenant: "",
      scoped: false,
      tenants: [],
    },
  } as never);
  vi.mocked(api.authzCheck).mockResolvedValue({
    role: "viewer",
    scopes: [],
  } as never);
  trend();
});

describe("CryptoPosture trend", () => {
  it("requests since/limit for the selected range", async () => {
    const user = userEvent.setup();
    renderPage();
    const picker = await screen.findByRole("combobox", { name: "Trend range" });
    const lastCall = () =>
      vi.mocked(api.cryptoPostureTrend).mock.calls.at(-1)![0]!;
    const expectRange = (days: number) => {
      const p = lastCall();
      expect(p.limit).toBe(days);
      expect(
        Math.abs(Date.parse(p.since!) - (Date.now() - days * DAY)),
      ).toBeLessThan(5000);
    };
    await waitFor(() => expect(api.cryptoPostureTrend).toHaveBeenCalled());
    expectRange(90);
    await user.selectOptions(picker, "Last 30 days");
    await waitFor(() => expect(lastCall().limit).toBe(30));
    expectRange(30);
    await user.selectOptions(picker, "Last 365 days");
    await waitFor(() => expect(lastCall().limit).toBe(365));
    expectRange(365);
  });

  it("score link points at the published formula", async () => {
    renderPage();
    const link = await screen.findByRole("link", {
      name: /how risk scores are computed/i,
    });
    expect(link.getAttribute("href")).toContain("docs/guides/RISK_SCORING.md");
  });

  it("compare view shows two dates side by side", async () => {
    const user = userEvent.setup();
    trend(
      snap("s1", "2026-09-01", 11),
      snap("s2", "2026-09-15", 22),
      snap("s3", "2026-10-01", 33),
    );
    renderPage();
    await screen.findByRole("combobox", { name: "Compare from" });
    expect(rowCells("Total certificates")).toEqual(["11", "33"]);
    await user.selectOptions(
      screen.getByRole("combobox", { name: "Compare from" }),
      "2026-09-15",
    );
    expect(rowCells("Total certificates")).toEqual(["22", "33"]);
  });

  it("compare keeps raw and effective separate", async () => {
    trend(
      snap("s1", "2026-09-01", 11, {
        findings: { raw: 12, effective: 5 },
      }),
      snap("s2", "2026-10-01", 33),
    );
    renderPage();
    await screen.findByRole("combobox", { name: "Compare from" });
    expect(rowCells("Findings (raw)")).toEqual(["12", "—"]);
    expect(rowCells("Findings (effective)")).toEqual(["5", "—"]);
  });

  it("hides trend for tenant-scoped principals", async () => {
    vi.mocked(api.tenantContext).mockResolvedValue({
      data: {
        enabled: true,
        super_admin: false,
        tenant: "t1",
        scoped: true,
        tenants: [],
      },
    } as never);
    renderPage();
    expect(
      await screen.findByText(/available to super-admins only/i),
    ).toBeInTheDocument();
    expect(api.cryptoPostureTrend).not.toHaveBeenCalled();
  });
});
