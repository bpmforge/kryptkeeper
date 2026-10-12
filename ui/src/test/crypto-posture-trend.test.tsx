import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    cryptoPosture: vi.fn(),
    cryptoPostureTrend: vi.fn(),
    cryptoPostureCsvUrl: () => "/api/v1/reports/crypto-posture?format=csv",
  },
}));

import CryptoPosture from "../pages/CryptoPosture";
import { api } from "../lib/api";

const report = {
  generated_at: "2026-06-15T00:00:00Z",
  total_certs: 10,
  algorithm_breakdown: { RSA: 6, ECDSA: 4 },
  pqc_readiness: {
    quantum_safe: 2,
    migration_ready: 1,
    vulnerable: 5,
    not_applicable: 2,
    pqc_score_percent: 30,
  },
  expiry_buckets: {
    expired: 1,
    expiring_47d: 2,
    expiring_90d: 1,
    expiring_200d: 1,
    expiring_1yr: 1,
  },
  grade_distribution: { A: 4, B: 3, F: 3 },
  automation_coverage: { automated: 5, manual: 5, automation_percent: 50 },
  risk_breakdown: { critical: 1, high: 2, medium: 3, low: 4 },
};

function snapshot(captured_at: string, pqc: number, automation: number) {
  return {
    id: `psn-${captured_at}`,
    captured_at,
    total_certs: 10,
    pqc_score_percent: pqc,
    automation_percent: automation,
    risk_critical: 1,
    risk_high: 2,
    risk_medium: 3,
    risk_low: 4,
    expired: 1,
    expiring_47d: 2,
    report,
  };
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <CryptoPosture />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.cryptoPosture).mockResolvedValue({
    data: report,
  } as unknown as never);
});

describe("CryptoPosture trend chart", () => {
  it("renders the trend chart when at least two snapshots exist", async () => {
    vi.mocked(api.cryptoPostureTrend).mockResolvedValue({
      data: {
        snapshots: [
          snapshot("2026-06-01T00:00:00Z", 20, 40),
          snapshot("2026-06-02T00:00:00Z", 30, 50),
        ],
      },
    } as unknown as never);

    renderPage();

    await screen.findByText(/posture trend/i);
    expect(screen.getByText(/2 captured/i)).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: /posture trend over time/i }),
    ).toBeInTheDocument();
  });

  it("shows an accumulating message with fewer than two snapshots", async () => {
    vi.mocked(api.cryptoPostureTrend).mockResolvedValue({
      data: { snapshots: [snapshot("2026-06-01T00:00:00Z", 20, 40)] },
    } as unknown as never);

    renderPage();

    await screen.findByText(/trend data is accumulating/i);
  });
});
