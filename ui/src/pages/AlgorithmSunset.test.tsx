import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

const navigate = vi.fn();
vi.mock("react-router-dom", async (orig) => ({
  ...(await orig<typeof import("react-router-dom")>()),
  useNavigate: () => navigate,
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("../lib/api", () => ({
  api: {
    algorithmSunset: vi.fn(),
    cryptoAgilityRoadmap: vi.fn(),
    createPqcWave: vi.fn(),
    addPqcWaveMember: vi.fn(),
  },
}));

import AlgorithmSunset from "./AlgorithmSunset";
import { api } from "../lib/api";
import type { AgilityRoadmapResult } from "../lib/api";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AlgorithmSunset />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function result(over: Partial<AgilityRoadmapResult> = {}): AgilityRoadmapResult {
  return {
    roadmap: {
      policy: "Algorithm transition",
      total_matched: 5,
      deadline: "2030-01-01T00:00:00Z",
      by_wave: {
        "Customer-Facing": [
          { fingerprint: "fp-c1", common_name: "shop.example", reason: "RSA-2048", wave_tier: "Customer-Facing" },
        ],
        Internal: [
          { fingerprint: "fp-i1", common_name: "intranet.example", reason: "RSA-2048", wave_tier: "Internal" },
          { fingerprint: "fp-i2", common_name: "wiki.example", reason: "ECDSA", wave_tier: "Internal" },
        ],
        Test: [
          { fingerprint: "fp-t1", common_name: "test.example", reason: "RSA-1024", wave_tier: "Test" },
          { fingerprint: "fp-t2", common_name: "dev.example", reason: "RSA-1024", wave_tier: "Test" },
        ],
      },
    },
    progress: {
      total_inventory: 10,
      matched_remaining: 6,
      percent_migrated: 40,
      overdue: false,
    },
    ...over,
  };
}

async function derive(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: "Derive roadmap" }));
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.algorithmSunset).mockRejectedValue(new Error("sunset down"));
});

describe("Crypto-agility roadmap panel", () => {
  it("shows ordered tiers and percent migrated", async () => {
    const user = userEvent.setup();
    vi.mocked(api.cryptoAgilityRoadmap).mockResolvedValue({ data: result() });
    renderPage();
    await user.type(screen.getByLabelText("Algorithms"), "RSA, ECDSA");
    await user.type(screen.getByLabelText("Max key bits"), "2048");
    await user.type(screen.getByLabelText("Deadline"), "2030-01-01");
    await derive(user);

    await screen.findByText("Test (2)");
    const headings = screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent);
    expect(headings).toEqual(["Test (2)", "Internal (2)", "Customer-Facing (1)"]);
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "40");
    expect(screen.getByText("40% migrated (6 of 10 remaining)")).toBeInTheDocument();
    expect(api.cryptoAgilityRoadmap).toHaveBeenCalledWith({
      name: "Algorithm transition",
      algorithms: ["RSA", "ECDSA"],
      max_key_bits: 2048,
      deadline: "2030-01-01T00:00:00Z",
    });
  });

  it("empty policy shows the server 400 message", async () => {
    const user = userEvent.setup();
    const msg = "a policy must constrain algorithms, max_key_bits, or both";
    vi.mocked(api.cryptoAgilityRoadmap).mockRejectedValue(
      Object.assign(new Error(msg), { status: 400 }),
    );
    renderPage();
    await derive(user);
    expect(await screen.findByText(msg)).toBeInTheDocument();
    expect(api.cryptoAgilityRoadmap).toHaveBeenCalledTimes(1);
  });

  it("zero matches with inventory shows success; empty inventory shows info not success", async () => {
    const user = userEvent.setup();
    vi.mocked(api.cryptoAgilityRoadmap).mockResolvedValue({
      data: result({
        roadmap: { total_matched: 0, by_wave: {} },
        progress: { total_inventory: 4, matched_remaining: 0, percent_migrated: 100 },
      }),
    });
    renderPage();
    await derive(user);
    expect(await screen.findByText("No active certificates match this policy")).toBeInTheDocument();

    vi.mocked(api.cryptoAgilityRoadmap).mockResolvedValue({
      data: result({
        roadmap: { total_matched: 0, by_wave: {} },
        progress: { total_inventory: 0, matched_remaining: 0, percent_migrated: 0 },
      }),
    });
    await derive(user);
    expect(await screen.findByText("Inventory is empty; nothing has been checked")).toBeInTheDocument();
    expect(screen.queryByText("No active certificates match this policy")).not.toBeInTheDocument();
  });

  it("create wave hands tier members to the PQC wave flow", async () => {
    const user = userEvent.setup();
    vi.mocked(api.cryptoAgilityRoadmap).mockResolvedValue({ data: result() });
    vi.mocked(api.createPqcWave).mockResolvedValue({
      data: { id: "w1", name: "x", created_at: "", members: [], total: 0 },
    } as never);
    vi.mocked(api.addPqcWaveMember).mockResolvedValue({ data: { status: "ok" } });
    renderPage();
    await derive(user);
    await user.click(await screen.findByRole("button", { name: "Create wave from Internal" }));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/reports/pqc-migration"));
    expect(api.createPqcWave).toHaveBeenCalledTimes(1);
    expect(vi.mocked(api.createPqcWave).mock.calls[0][0].name).toBe("Algorithm transition - Internal");
    expect(vi.mocked(api.addPqcWaveMember).mock.calls).toEqual([
      ["w1", "fp-i1"],
      ["w1", "fp-i2"],
    ]);
  });

  it("create wave stops on member failure", async () => {
    const user = userEvent.setup();
    vi.mocked(api.cryptoAgilityRoadmap).mockResolvedValue({ data: result() });
    vi.mocked(api.createPqcWave).mockResolvedValue({
      data: { id: "w9", name: "x", created_at: "", members: [], total: 0 },
    } as never);
    vi.mocked(api.addPqcWaveMember)
      .mockResolvedValueOnce({ data: { status: "ok" } })
      .mockRejectedValueOnce(new Error("member refused"));
    renderPage();
    await derive(user);
    await user.click(await screen.findByRole("button", { name: "Create wave from Internal" }));
    const alert = await screen.findByText(/Wave w9 was created.*member refused/);
    expect(alert).toBeInTheDocument();
    expect(navigate).not.toHaveBeenCalled();
  });

  it("overdue badge when progress.overdue", async () => {
    const user = userEvent.setup();
    vi.mocked(api.cryptoAgilityRoadmap).mockResolvedValue({
      data: result({
        progress: { total_inventory: 10, matched_remaining: 6, percent_migrated: 40, overdue: true },
      }),
    });
    renderPage();
    await derive(user);
    const bar = await screen.findByRole("progressbar");
    expect(bar).toBeInTheDocument();
    expect(screen.getByText("Overdue")).toBeInTheDocument();
    expect(within(document.body).getByText("Crypto-agility roadmap")).toBeInTheDocument();
  });
});
