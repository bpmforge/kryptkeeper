import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";

vi.mock("../lib/api", () => ({
  api: {
    cryptoPosture: vi.fn(),
    cryptoPostureTrend: vi.fn(),
    cryptoPostureCsvUrl: () => "/api/v1/reports/crypto-posture?format=csv",
    expiryTimeline: vi.fn(),
  },
}));

import CryptoPosture from "../pages/CryptoPosture";
import ExpiryTimeline from "../pages/ExpiryTimeline";
import { api } from "../lib/api";

function renderWithProviders(ui: ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const baseCryptoReport = {
  generated_at: "2026-06-15T16:31:49Z",
  total_certs: 0,
  algorithm_breakdown: {},
  pqc_readiness: {
    quantum_safe: 0,
    migration_ready: 0,
    vulnerable: 0,
    not_applicable: 0,
    pqc_score_percent: 0,
  },
  expiry_buckets: {
    expired: 0,
    expiring_47d: 0,
    expiring_90d: 0,
    expiring_200d: 0,
    expiring_1yr: 0,
  },
  grade_distribution: {},
  automation_coverage: { automated: 0, manual: 0, automation_percent: 0 },
  risk_breakdown: { critical: 0, high: 0, medium: 0, low: 0 },
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.cryptoPostureTrend).mockResolvedValue({
    data: { snapshots: [] },
  } as unknown as never);
});

describe("CryptoPosture report timestamp and empty panels (S-49)", () => {
  it("formats the generated-at header without raw toLocaleString seconds (I-5)", async () => {
    vi.mocked(api.cryptoPosture).mockResolvedValue({
      data: {
        ...baseCryptoReport,
        total_certs: 4,
        algorithm_breakdown: { RSA: 4 },
        grade_distribution: { A: 4 },
      },
    } as unknown as never);

    renderWithProviders(<CryptoPosture />);

    const generated = await screen.findByText(/^Generated/i);
    expect(generated.textContent).not.toMatch(/\d{1,2}:\d{2}:\d{2}/);
  });

  it("names the next action instead of a blank panel when no certificates exist to break down (I-3)", async () => {
    vi.mocked(api.cryptoPosture).mockResolvedValue({
      data: baseCryptoReport,
    } as unknown as never);

    renderWithProviders(<CryptoPosture />);

    expect(
      await screen.findByText(
        /issue a certificate to populate the algorithm breakdown/i,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/grades appear once certificates are issued/i),
    ).toBeInTheDocument();
  });
});

describe("ExpiryTimeline report timestamp and empty panels (S-49)", () => {
  it("formats the generated-at subtitle without raw toLocaleString seconds (I-5) and names the next action at zero certs", async () => {
    vi.mocked(api.expiryTimeline).mockResolvedValue({
      data: {
        generated_at: "2026-06-15T16:33:47Z",
        total_certs: 0,
        buckets: [],
        by_ca: {},
        by_owner_team: {},
      },
    } as unknown as never);

    renderWithProviders(<ExpiryTimeline />);

    const subtitle = await screen.findByText(/certificates ·/i);
    expect(subtitle.textContent).not.toMatch(/\d{1,2}:\d{2}:\d{2}/);

    // Zero certificates in inventory is not the same condition as "certs
    // exist but none have a parseable expiry" (handlers_reports.go:
    // TotalCerts counts every cert; ByCA/ByOwnerTeam only count certs with a
    // parseable ValidUntil) — the copy must not claim expiry data is
    // malformed when there is simply no data yet.
    expect(
      await screen.findByText(
        /no certificates in inventory yet\. issue a certificate to populate the ca breakdown/i,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        /no certificates in inventory yet\. issue a certificate to populate the owner-team breakdown/i,
      ),
    ).toBeInTheDocument();
  });

  it("names why the CA and owner-team breakdowns are empty instead of a blank panel", async () => {
    vi.mocked(api.expiryTimeline).mockResolvedValue({
      data: {
        generated_at: "2026-06-15T16:33:47Z",
        total_certs: 2,
        buckets: [],
        by_ca: {},
        by_owner_team: {},
      },
    } as unknown as never);

    renderWithProviders(<ExpiryTimeline />);

    expect(
      await screen.findByText(
        /no certificates have a usable expiry date to group by ca\. set a valid expiry/i,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        /no certificates have a usable expiry date to group by owner team\. set a valid expiry/i,
      ),
    ).toBeInTheDocument();
  });
});
