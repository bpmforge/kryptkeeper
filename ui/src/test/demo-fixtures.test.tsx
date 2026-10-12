import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";

// Demo mode serves the MSW fixtures; these render each affected page from
// the very fixtures the mocks serve, so a fixture that drifts from the page's
// contract fails here instead of crashing the demo.

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    expiryTimeline: vi.fn(),
    cas: vi.fn(),
    approvals: vi.fn(),
    approveRequest: vi.fn(),
    rejectRequest: vi.fn(),
    pqcMigration: vi.fn(),
    pqcWaves: vi.fn(),
    autoDerivePqcWaves: vi.fn(),
    deletePqcWave: vi.fn(),
    pqcCountdown: vi.fn(),
    pqcCountdownPdfUrl: () => "/api/v1/reports/pqc-countdown?format=pdf",
    createPqcWave: vi.fn(),
    addPqcWaveMember: vi.fn(),
    proposePqcWaveExecute: vi.fn(),
    approvePqcWaveExecute: vi.fn(),
    acceptPqcWave: vi.fn(),
    templates: vi.fn(),
  },
}));

import ExpiryTimeline from "../pages/ExpiryTimeline";
import Approvals from "../pages/Approvals";
import PQCMigration from "../pages/PQCMigration";
import { api } from "../lib/api";
import * as fx from "../mocks/fixtures";

function renderPage(ui: ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue(fx.authzCheck as never);
  vi.mocked(api.expiryTimeline).mockResolvedValue(fx.expiryTimeline as never);
  vi.mocked(api.cas).mockResolvedValue(fx.cas as never);
  vi.mocked(api.approvals).mockResolvedValue(fx.approvals as never);
  vi.mocked(api.pqcMigration).mockResolvedValue(fx.pqcMigration as never);
  vi.mocked(api.pqcCountdown).mockResolvedValue(fx.pqcCountdown as never);
  vi.mocked(api.pqcWaves).mockResolvedValue(fx.pqcWaves as never);
  vi.mocked(api.templates).mockResolvedValue(fx.templates as never);
});

describe("demo-mode fixtures", () => {
  it("Expiry Timeline renders the CA and team breakdowns", async () => {
    renderPage(<ExpiryTimeline />);
    expect(
      await screen.findByText("By Certificate Authority"),
    ).toBeInTheDocument();
    expect(
      await screen.findByText("Kryptkeeper Intermediate CA"),
    ).toBeInTheDocument();
    expect(screen.getByText("platform")).toBeInTheDocument();
  });

  it("Approvals shows the pending queue", async () => {
    renderPage(<Approvals />);
    expect(await screen.findByText(/dev-release-bot/)).toBeInTheDocument();
    expect(
      screen.getAllByRole("button", { name: /approve/i }).length,
    ).toBeGreaterThan(0);
  });

  it("PQC Migration shows the roadmap, countdown and waves", async () => {
    renderPage(<PQCMigration />);
    expect(await screen.findByText("legacy.example.com")).toBeInTheDocument();
    expect(await screen.findByText("At risk")).toBeInTheDocument();
    expect(await screen.findByText("Wave 1 — public edge")).toBeInTheDocument();
  });
});
