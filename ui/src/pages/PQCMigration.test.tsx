import { render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    pqcMigration: vi.fn(),
    pqcCountdown: vi.fn(),
    cryptoPosture: vi.fn(),
    pqcWaves: vi.fn(),
    templates: vi.fn(),
  },
  downloadAuthedFile: vi.fn(),
}));

import PQCMigration from "./PQCMigration";
import { api } from "../lib/api";

const QUARTERS = [
  { quarter: "2027-Q3", due: 11, migrated: 1 },
  { quarter: "2027-Q4", due: 12, migrated: 2 },
  { quarter: "2028-Q1", due: 13, migrated: 3 },
  { quarter: "2030-Q1", due: 14, migrated: 4 },
];

function roadmap(withTimeline: boolean) {
  return {
    generated_at: "2026-10-16T00:00:00Z",
    total_certs: 17,
    quantum_safe: 2,
    quantum_safe_leaf_only: 7,
    migration_ready: 3,
    vulnerable: 4,
    not_applicable: 1,
    pqc_score_percent: 60,
    quantum_safe_percent: 11,
    items: [],
    ...(withTimeline
      ? {
          timeline: {
            quarters: QUARTERS,
            expire_before_2030: 31,
            expire_after_2030: 9,
          },
        }
      : {}),
  };
}

function mockApi(withTimeline: boolean) {
  vi.mocked(api.pqcMigration).mockResolvedValue({
    data: roadmap(withTimeline),
  } as unknown as never);
  vi.mocked(api.pqcCountdown).mockResolvedValue({
    data: undefined,
  } as unknown as never);
  vi.mocked(api.cryptoPosture).mockResolvedValue({
    data: { algorithm_breakdown: { "RSA-2048": 5, "ECDSA-P256": 3 } },
  } as unknown as never);
  vi.mocked(api.pqcWaves).mockResolvedValue({ data: [] } as unknown as never);
  vi.mocked(api.templates).mockResolvedValue({
    data: [],
  } as unknown as never);
}

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
});

describe("PQCMigration", () => {
  it("leaf-only is labelled with its explanation and not as quantum safe", async () => {
    mockApi(true);
    renderPage();
    const dl = await screen.findByTestId("pqc-label-explanations");
    expect(within(dl).getByText(/NOT quantum safe/)).toBeInTheDocument();

    const quantumCard = screen
      .getByText("Quantum-safe")
      .closest("div")!.parentElement!;
    expect(within(quantumCard).getByText("2")).toBeInTheDocument();
    expect(within(quantumCard).queryByText("9")).not.toBeInTheDocument();

    const leafCard = screen
      .getAllByText("Leaf-only PQC")[0]
      .closest("div")!.parentElement!;
    expect(within(leafCard).getByText("7")).toBeInTheDocument();
  });

  it("renders per-quarter timeline from payload", async () => {
    mockApi(true);
    renderPage();
    const rows = await screen.findAllByTestId("pqc-quarter");
    expect(rows).toHaveLength(QUARTERS.length);
    QUARTERS.forEach((q, i) => {
      expect(within(rows[i]).getByText(q.quarter)).toBeInTheDocument();
      expect(within(rows[i]).getByText(String(q.due))).toBeInTheDocument();
      expect(within(rows[i]).getByText(String(q.migrated))).toBeInTheDocument();
    });
  });

  it("renders before and after 2030 split and readiness percent", async () => {
    mockApi(true);
    renderPage();
    expect(await screen.findByText("31")).toBeInTheDocument();
    expect(screen.getByText("9")).toBeInTheDocument();
    expect(screen.getAllByText("60%").length).toBeGreaterThan(0);
  });

  it("renders by-algorithm breakdown from crypto-posture", async () => {
    mockApi(true);
    renderPage();
    const rows = await screen.findAllByTestId("pqc-algorithm-row");
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByText("RSA-2048")).toBeInTheDocument();
    expect(within(rows[0]).getByText("5")).toBeInTheDocument();
    expect(within(rows[1]).getByText("ECDSA-P256")).toBeInTheDocument();
  });

  it("timeline absent shows explicit empty state, no zeros", async () => {
    mockApi(false);
    renderPage();
    expect(
      await screen.findByText("Timeline not reported by this hub version."),
    ).toBeInTheDocument();
    expect(screen.queryAllByTestId("pqc-quarter")).toHaveLength(0);
    expect(screen.queryByText("Expire before 2030")).not.toBeInTheDocument();
  });
});
