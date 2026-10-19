import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    algorithmSunset: vi.fn(),
  },
}));

import AlgorithmSunset from "../pages/AlgorithmSunset";
import { api } from "../lib/api";

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

beforeEach(() => {
  vi.clearAllMocks();
});

// S-39. Until this file existed, nothing in src/ or test/ rendered this page —
// which is how it shipped throwing on every render, blanking the entire app.
//
// These payloads are deliberately NOT cast with `as unknown as never`. They are
// checked against components["schemas"]["AlgorithmSunsetReport"] through the
// mocked api signature, so if the server renames a field and the spec is
// regenerated, this file stops compiling instead of the page going black.
describe("AlgorithmSunset report page", () => {
  it("renders the summary from `summary`, the field the server actually sends", async () => {
    vi.mocked(api.algorithmSunset).mockResolvedValue({
      data: {
        generated_at: "2026-07-31T21:34:25Z",
        total_certs: 4,
        groups: [
          {
            algorithm: "Classical algorithms (PQC-vulnerable)",
            deadline: "2030-01-01T00:00:00Z",
            standard: "CNSA 2.0 / NIST IR 8413",
            status: "sunset_2030",
            urgency: "medium",
            count: 4,
            recommended_replacement:
              "ML-DSA-65, ML-DSA-87, or Hybrid ECDSA+ML-DSA",
            fingerprints: [
              "cd57cafe8bca3b632ee294b9d49054177b4d1ac4ca43fbd0336b95e",
            ],
          },
        ],
        summary: { banned_now: 0, sunset_2030: 4, compliant: 0 },
      },
    });

    renderPage();

    await screen.findByText("Classical algorithms (PQC-vulnerable)");
    // The three summary tiles. banned_now 0 / sunset_2030 4 / compliant 0.
    expect(screen.getByText("Banned Now")).toBeInTheDocument();
    expect(screen.getByText("Sunset 2030")).toBeInTheDocument();
    expect(screen.getByText("Compliant")).toBeInTheDocument();
    // recommended_replacement, not `recommended` — the second drift in the
    // same type, which a summary-only fix would have left rendering undefined.
    expect(
      screen.getByText("ML-DSA-65, ML-DSA-87, or Hybrid ECDSA+ML-DSA"),
    ).toBeInTheDocument();
  });

  it("links '+N more' to the group's own certificates, not a label search", async () => {
    const fps = Array.from({ length: 7 }, (_, i) => `fp${i}`);
    vi.mocked(api.algorithmSunset).mockResolvedValue({
      data: {
        generated_at: "2026-07-31T21:34:25Z",
        total_certs: 7,
        groups: [
          {
            id: "pqc_vulnerable",
            algorithm: "Classical algorithms (PQC-vulnerable)",
            status: "sunset_2030",
            urgency: "medium",
            count: 7,
            fingerprints: fps,
          },
        ],
        summary: { banned_now: 0, sunset_2030: 7, compliant: 0 },
      },
    });

    renderPage();

    const more = await screen.findByRole("link", {
      name: /search the inventory/,
    });
    expect(more).toHaveAttribute(
      "href",
      "/certificates?sunset_group=pqc_vulnerable",
    );
  });

  it("survives a response with no summary and no groups", async () => {
    // The generated type marks every field optional, so this is reachable.
    // Previously any such response threw and took the app shell down with it.
    vi.mocked(api.algorithmSunset).mockResolvedValue({
      data: { generated_at: "2026-07-31T21:34:25Z", total_certs: 0 },
    });

    renderPage();

    // Zero inventory must NOT read as a green all-clear — nothing was checked.
    await screen.findByText("Nothing inventoried yet");
    expect(screen.getByText("Algorithm Sunset")).toBeInTheDocument();
  });

  it("renders an error state rather than a blank page when the fetch fails", async () => {
    vi.mocked(api.algorithmSunset).mockRejectedValue(new Error("boom"));

    renderPage();

    await screen.findByText("Report unavailable");
  });
});
