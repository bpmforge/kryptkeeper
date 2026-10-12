import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
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

const emptyCountdown = {
  data: {
    generated_at: "2026-06-18T00:00:00Z",
    org: "Kryptkeeper",
    total_certs: 0,
    vulnerable: 0,
    migration_ready: 0,
    quantum_safe: 0,
    pqc_score_percent: 0,
    status: "behind",
    deadlines: [],
    trend: [],
    waves: [],
  },
};

import PQCMigration from "../pages/PQCMigration";
import { api } from "../lib/api";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <PQCMigration />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.pqcWaves).mockResolvedValue({ data: [] } as unknown as never);
  vi.mocked(api.pqcCountdown).mockResolvedValue(
    emptyCountdown as unknown as never,
  );
});

describe("PQC Migration page", () => {
  it("shows the roadmap with prioritized items and readiness", async () => {
    vi.mocked(api.pqcMigration).mockResolvedValue({
      data: {
        generated_at: "2026-06-17T00:00:00Z",
        total_certs: 4,
        vulnerable: 2,
        migration_ready: 1,
        quantum_safe: 1,
        items: [
          {
            fingerprint: "ca",
            common_name: "Root CA",
            priority: "critical",
            reason: "CA certificate — compromises entire chain",
            action: "Plan CA key ceremony with ML-DSA",
            deadline: "2030-01-01T00:00:00Z",
          },
          {
            fingerprint: "tls",
            common_name: "long.example.com",
            priority: "high",
            reason: "Long-lived certificate",
            action: "Migrate to ML-DSA at next renewal",
            deadline: "2030-01-01T00:00:00Z",
          },
        ],
      },
    } as unknown as never);

    renderPage();

    await screen.findByText("Root CA");
    // PQC readiness = (1 migration_ready + 1 quantum_safe) / 4 = 50%
    expect(screen.getByText("50%")).toBeInTheDocument();
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.getByText("long.example.com")).toBeInTheDocument();
  });

  it("shows an all-clear state when nothing needs migration", async () => {
    vi.mocked(api.pqcMigration).mockResolvedValue({
      data: {
        generated_at: "2026-06-17T00:00:00Z",
        total_certs: 3,
        vulnerable: 0,
        migration_ready: 1,
        quantum_safe: 2,
        items: [],
      },
    } as unknown as never);

    renderPage();

    await screen.findByText(
      /every certificate is migration-ready or quantum-safe/i,
    );
  });

  it("shows migration waves with progress", async () => {
    vi.mocked(api.pqcMigration).mockResolvedValue({
      data: {
        generated_at: "2026-06-17T00:00:00Z",
        total_certs: 2,
        vulnerable: 2,
        migration_ready: 0,
        quantum_safe: 0,
        items: [],
      },
    } as unknown as never);
    vi.mocked(api.pqcWaves).mockResolvedValue({
      data: [
        {
          id: "wave-1",
          name: "Customer-Facing",
          owner: "payments",
          created_at: "2026-06-17T00:00:00Z",
          members: [{ fingerprint: "c1", common_name: "shop" }],
          total: 2,
          migrated: 1,
          progress_percent: 50,
        },
      ],
    } as unknown as never);

    renderPage();

    await screen.findByText("Customer-Facing");
    expect(screen.getByText(/owner: payments/i)).toBeInTheDocument();
    expect(screen.getByText(/1\/2 migrated \(50%\)/i)).toBeInTheDocument();
  });

  it("shows the CNSA/NIST countdown with deadlines and a PDF download", async () => {
    vi.mocked(api.pqcMigration).mockResolvedValue({
      data: {
        generated_at: "2026-06-18T00:00:00Z",
        total_certs: 5,
        vulnerable: 2,
        migration_ready: 1,
        quantum_safe: 2,
        items: [],
      },
    } as unknown as never);
    vi.mocked(api.pqcCountdown).mockResolvedValue({
      data: {
        generated_at: "2026-06-18T00:00:00Z",
        org: "Acme",
        total_certs: 5,
        vulnerable: 2,
        migration_ready: 1,
        quantum_safe: 2,
        pqc_score_percent: 60,
        status: "at_risk",
        deadlines: [
          {
            name: "CNSA 2.0 — software/firmware signing",
            date: "2030-01-01",
            days_remaining: 1200,
            passed: false,
          },
        ],
        trend: [],
        waves: [],
      },
    } as unknown as never);

    renderPage();

    // Status badge renders after the countdown query resolves (the panel title
    // shows during loading, so await the badge specifically).
    expect(await screen.findByText("At risk")).toBeInTheDocument();
    expect(
      screen.getByText(/cnsa 2.0 — software\/firmware signing/i),
    ).toBeInTheDocument();
    const pdf = screen.getByRole("button", { name: /countdown pdf/i });
    expect(pdf).toBeInTheDocument();
  });
});

// W8-09: the driven journey — plan → select → schedule → execute (propose).
const journeyRoadmap = {
  data: {
    generated_at: "2026-08-19T00:00:00Z",
    total_certs: 2,
    vulnerable: 2,
    migration_ready: 0,
    quantum_safe: 0,
    items: [
      {
        fingerprint: "aaaa1111",
        common_name: "internal.example.com",
        priority: "high",
        reason: "RSA-2048",
        action: "re-issue with ML-DSA",
      },
      {
        fingerprint: "bbbb2222",
        common_name: "edge.example.com",
        priority: "critical",
        reason: "expiring + RSA",
        action: "re-issue with ML-DSA",
      },
    ],
  },
};

describe("PQC migration journey (W8-09)", () => {
  beforeEach(() => {
    vi.mocked(api.pqcMigration).mockResolvedValue(
      journeyRoadmap as unknown as never,
    );
  });

  it("walks plan → select → schedule and proposes the W4-03 execute", async () => {
    vi.mocked(api.createPqcWave).mockResolvedValue({
      data: { id: "wave-9" },
    } as unknown as never);
    vi.mocked(api.addPqcWaveMember).mockResolvedValue({
      data: { status: "added" },
    } as unknown as never);
    vi.mocked(api.proposePqcWaveExecute).mockResolvedValue({
      data: { id: "act-42", status: "pending" },
    } as unknown as never);
    vi.mocked(api.templates).mockResolvedValue({
      data: {
        items: [
          {
            id: "tpl-mldsa",
            name: "mldsa-tls",
            display_name: "ML-DSA TLS",
            active: true,
            allowed_algorithms: ["ML-DSA-65"],
          },
        ],
      },
    } as unknown as never);

    renderPage();
    fireEvent.click(await screen.findByText("Start migration wave"));

    // Plan: name is required before Next.
    fireEvent.click(screen.getByText("Next"));
    expect(await screen.findByText("Give the wave a name.")).toBeTruthy();
    fireEvent.change(screen.getByPlaceholderText("e.g. internal-services-wave-1"), {
      target: { value: "wave-one" },
    });
    fireEvent.click(screen.getByText("Next"));

    // Select: at least one certificate.
    fireEvent.click(screen.getByText("Next"));
    expect(
      await screen.findByText("Select at least one certificate."),
    ).toBeTruthy();
    fireEvent.click(screen.getByText("Select all"));
    fireEvent.click(screen.getByText("Next"));

    // Schedule: pick the PQC template the execute proposal requires.
    fireEvent.change(
      await screen.findByLabelText(/issuance template/i),
      { target: { value: "tpl-mldsa" } },
    );
    fireEvent.click(screen.getByText("Next"));
    expect(await screen.findByText(/2 certificate\(s\) will be added/)).toBeTruthy();
    fireEvent.click(screen.getByText("Finish"));

    await waitFor(() =>
      expect(vi.mocked(api.proposePqcWaveExecute)).toHaveBeenCalledWith("wave-9", "tpl-mldsa"),
    );
    expect(vi.mocked(api.createPqcWave)).toHaveBeenCalledWith(
      expect.objectContaining({ name: "wave-one" }),
    );
    expect(vi.mocked(api.addPqcWaveMember)).toHaveBeenCalledTimes(2);
    expect(vi.mocked(api.addPqcWaveMember)).toHaveBeenCalledWith(
      "wave-9",
      "aaaa1111",
    );

    // Honest ending: proposed, needs a DIFFERENT approver.
    const result = await screen.findByTestId("journey-result");
    expect(result.textContent).toContain("act-42");
    expect(result.textContent).toContain("different");
  });

  it("surfaces member-add failures instead of swallowing them", async () => {
    vi.mocked(api.createPqcWave).mockResolvedValue({
      data: { id: "wave-9" },
    } as unknown as never);
    vi.mocked(api.addPqcWaveMember)
      .mockResolvedValueOnce({ data: { status: "added" } } as unknown as never)
      .mockRejectedValueOnce(new Error("boom"));
    vi.mocked(api.proposePqcWaveExecute).mockResolvedValue({
      data: { id: "act-43", status: "pending" },
    } as unknown as never);

    renderPage();
    fireEvent.click(await screen.findByText("Start migration wave"));
    fireEvent.change(screen.getByPlaceholderText("e.g. internal-services-wave-1"), {
      target: { value: "wave-two" },
    });
    fireEvent.click(screen.getByText("Next"));
    fireEvent.click(screen.getByText("Select all"));
    fireEvent.click(screen.getByText("Next"));
    fireEvent.click(screen.getByText("Next"));
    fireEvent.click(screen.getByText("Finish"));

    const result = await screen.findByTestId("journey-result");
    expect(result.textContent).toContain("could not be added");
  });
});
