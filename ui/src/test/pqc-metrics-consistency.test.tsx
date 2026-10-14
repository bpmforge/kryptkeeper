import { render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    cryptoPosture: vi.fn(),
    cryptoPostureTrend: vi.fn(),
    cryptoPostureCsvUrl: () => "/api/v1/reports/crypto-posture?format=csv",
    pqcMigration: vi.fn(),
    pqcWaves: vi.fn(),
    pqcCountdown: vi.fn(),
    pqcCountdownPdfUrl: () => "/api/v1/reports/pqc-countdown?format=pdf",
    templates: vi.fn(),
  },
}));

import CryptoPosture from "../pages/CryptoPosture";
import PQCMigration from "../pages/PQCMigration";
import { api } from "../lib/api";

// Mirrors the Go fixture in internal/bootstrap/pqc_metrics_consistency_test.go:
// 40 certs = 5 quantum-safe (full chain), 5 leaf-only ML-DSA under a classical
// CA, 20 migration-ready (16 short-lived + 4 hybrid), 8 vulnerable, 2 n/a.
const counts = {
  quantum_safe: 5,
  quantum_safe_leaf_only: 5,
  migration_ready: 20,
  vulnerable: 8,
  not_applicable: 2,
  pqc_score_percent: 75,
  quantum_safe_percent: 12,
};

const posture = {
  generated_at: "2026-10-14T00:00:00Z",
  total_certs: 40,
  algorithm_breakdown: { ECDSA: 35, "ML-DSA": 5 },
  pqc_readiness: counts,
  expiry_buckets: {
    expired: 0,
    expiring_47d: 0,
    expiring_90d: 0,
    expiring_200d: 0,
    expiring_1yr: 0,
  },
  grade_distribution: { A: 40 },
  automation_coverage: { automated: 40, manual: 0, automation_percent: 100 },
  risk_breakdown: { critical: 0, high: 0, medium: 0, low: 40 },
};

function client() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.cryptoPosture).mockResolvedValue({
    data: posture,
  } as unknown as never);
  vi.mocked(api.cryptoPostureTrend).mockResolvedValue({
    data: { snapshots: [] },
  } as unknown as never);
  vi.mocked(api.pqcWaves).mockResolvedValue({ data: [] } as unknown as never);
  vi.mocked(api.templates).mockResolvedValue({ data: [] } as unknown as never);
  vi.mocked(api.pqcMigration).mockResolvedValue({
    data: {
      generated_at: "2026-10-14T00:00:00Z",
      total_certs: 40,
      ...counts,
      items: [],
    },
  } as unknown as never);
  vi.mocked(api.pqcCountdown).mockResolvedValue({
    data: {
      generated_at: "2026-10-14T00:00:00Z",
      org: "Kryptkeeper",
      total_certs: 40,
      ...counts,
      status: "at_risk",
      deadlines: [],
      trend: [],
      waves: [],
    },
  } as unknown as never);
});

describe("PQC metrics consistency", () => {
  it("Crypto Posture: tile and panel agree; leaf-only is not quantum-safe", async () => {
    render(
      <QueryClientProvider client={client()}>
        <MemoryRouter>
          <CryptoPosture />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await screen.findByText("Quantum-safe today");
    // Tile: full-chain only (5/40), readiness in the hint.
    expect(screen.getByText("12%")).toBeInTheDocument();
    expect(screen.getByText(/75% PQC readiness/)).toBeInTheDocument();

    // Panel: same readiness number, separate leaf-only row, no 63%-style drift.
    const panel = screen.getByText("PQC Readiness").closest("[data-slot=card]") as HTMLElement;
    expect(within(panel).getByText("75%")).toBeInTheDocument();
    const row = (label: string) =>
      within(panel).getByText(label).closest("li")!;
    expect(row("Quantum-safe")).toHaveTextContent("5");
    expect(row("Leaf-only PQC")).toHaveTextContent("5");
    expect(row("Migration-ready")).toHaveTextContent("20");
    expect(row("Vulnerable")).toHaveTextContent("8");
    // Percent shares add to 100 because leaf-only is in the denominator.
    expect(row("Quantum-safe")).toHaveTextContent("(13%)");
    expect(row("Leaf-only PQC")).toHaveTextContent("(13%)");
  });

  it("PQC Migration: tile row and countdown card show the same readiness", async () => {
    render(
      <QueryClientProvider client={client()}>
        <MemoryRouter>
          <PQCMigration />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await waitFor(() => expect(screen.getAllByText("75%")).toHaveLength(2));
    expect(screen.queryByText("63%")).not.toBeInTheDocument();
    expect(screen.getAllByText("Leaf-only PQC")).toHaveLength(2);
  });
});
