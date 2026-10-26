import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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
    createPqcWave: vi.fn(),
    addPqcWaveMember: vi.fn(),
    proposePqcWaveExecute: vi.fn(),
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

  describe("target algorithm on wave execution", () => {
    async function runJourney(pick?: { template: string; algorithm?: string }) {
      mockApi(true);
      vi.mocked(api.pqcMigration).mockResolvedValue({
        data: {
          ...roadmap(true),
          items: [
            {
              fingerprint: "fp-aaaaaaaaaaaaaaaaaa",
              common_name: "svc.example",
              priority: "high",
              reason: "RSA",
            },
          ],
        },
      } as unknown as never);
      vi.mocked(api.templates).mockResolvedValue({
        data: [
          {
            id: "t1",
            name: "pqc",
            active: true,
            allowed_algorithms: ["ML-DSA-65", "ECDSA-P384"],
          },
        ],
      } as unknown as never);
      vi.mocked(api.createPqcWave).mockResolvedValue({
        data: { id: "w1" },
      } as unknown as never);
      vi.mocked(api.addPqcWaveMember).mockResolvedValue({
        data: { status: "ok" },
      } as unknown as never);
      const user = userEvent.setup();
      renderPage();
      await user.click(
        await screen.findByRole("button", { name: /start migration wave/i }),
      );
      await user.type(screen.getByLabelText(/wave name/i), "w");
      await user.click(screen.getByRole("button", { name: "Next" }));
      await user.click(await screen.findByRole("checkbox"));
      await user.click(screen.getByRole("button", { name: "Next" }));
      const tmpl = await screen.findByLabelText(/issuance template/i);
      await screen.findByRole("option", { name: "pqc" });
      if (pick) await user.selectOptions(tmpl, pick.template);
      const target = screen.getByLabelText(/target algorithm/i);
      if (pick?.algorithm) await user.selectOptions(target, pick.algorithm);
      await user.click(screen.getByRole("button", { name: "Next" }));
      await user.click(screen.getByRole("button", { name: "Finish" }));
      return target;
    }

    it("offers only the default until a template is chosen, then its algorithms", async () => {
      mockApi(true);
      vi.mocked(api.pqcMigration).mockResolvedValue({
        data: {
          ...roadmap(true),
          items: [
            {
              fingerprint: "fp-aaaaaaaaaaaaaaaaaa",
              common_name: "svc.example",
              priority: "high",
              reason: "RSA",
            },
          ],
        },
      } as unknown as never);
      vi.mocked(api.templates).mockResolvedValue({
        data: [
          {
            id: "t1",
            name: "pqc",
            active: true,
            allowed_algorithms: ["ML-DSA-65", "ECDSA-P384"],
          },
        ],
      } as unknown as never);
      const user = userEvent.setup();
      renderPage();
      await user.click(
        await screen.findByRole("button", { name: /start migration wave/i }),
      );
      await user.type(screen.getByLabelText(/wave name/i), "w");
      await user.click(screen.getByRole("button", { name: "Next" }));
      await user.click(await screen.findByRole("checkbox"));
      await user.click(screen.getByRole("button", { name: "Next" }));
      const target = await screen.findByLabelText(/target algorithm/i);
      expect(within(target).getAllByRole("option")).toHaveLength(1);
      await screen.findByRole("option", { name: "pqc" });
      await user.selectOptions(
        screen.getByLabelText(/issuance template/i),
        "t1",
      );
      const names = within(target)
        .getAllByRole("option")
        .map((o) => o.textContent);
      expect(names).toEqual([
        "Template default (PQC)",
        "ML-DSA-65",
        "ECDSA-P384",
      ]);
    });

    it("default sends no target_algorithm", async () => {
      vi.mocked(api.proposePqcWaveExecute).mockResolvedValue({
        data: { id: "a1", status: "PROPOSED" },
      } as unknown as never);
      await runJourney({ template: "t1" });
      await waitFor(() =>
        expect(api.proposePqcWaveExecute).toHaveBeenCalledWith(
          "w1", "t1",
        ),
      );
    });

    it("selecting ECDSA-P384 sends it", async () => {
      vi.mocked(api.proposePqcWaveExecute).mockResolvedValue({
        data: { id: "a1", status: "PROPOSED" },
      } as unknown as never);
      await runJourney({ template: "t1", algorithm: "ECDSA-P384" });
      await waitFor(() =>
        expect(api.proposePqcWaveExecute).toHaveBeenCalledWith(
          "w1",
          "t1",
          "ECDSA-P384",
        ),
      );
    });

    it("shows the server message on a 400 rejection", async () => {
      vi.mocked(api.proposePqcWaveExecute).mockRejectedValue(
        new Error("target_algorithm is not a supported transition target"),
      );
      await runJourney({ template: "t1", algorithm: "ECDSA-P384" });
      expect(
        await screen.findByText(/not a supported transition target/),
      ).toBeInTheDocument();
    });
  });
});
