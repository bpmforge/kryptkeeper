import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("../lib/api", async (importOriginal) => {
  const mod = (await importOriginal()) as Record<string, unknown>;
  return {
    ...mod,
    api: {
      ...(mod.api as Record<string, unknown>),
      renewalSLO: vi.fn(),
      expiryTimeline: vi.fn(),
      runtimeConfig: vi.fn(),
      setRuntimeConfig: vi.fn(),
    },
  };
});

import SLO from "./SLO";
import { api } from "../lib/api";
import { toast } from "sonner";

// Shapes follow docs/openapi.yaml RenewalSloBudget / RenewalSloReport.
const budget = (over: Record<string, unknown>) => ({
  name: "renewal-success-rate",
  objective: 0.99,
  window_days: 30,
  has_data: true,
  budget_remaining_pct: 87.5,
  burn_rate_1h: 1.2,
  burn_rate_6h: 0.4,
  breached: false,
  ...over,
});
const report = (slos: unknown[]) => ({
  data: { generated_at: "2026-10-16T00:00:00Z", slos },
});
const timeline = {
  data: {
    generated_at: "2026-10-16T00:00:00Z",
    total_certs: 30,
    buckets: [
      { label: "0–7 days", days_from: 0, days_to: 7, count: 4 },
      { label: "7–30 days", days_from: 7, days_to: 30, count: 26 },
    ],
    by_ca: {},
    by_owner_team: {},
  },
};
const config = (renewal?: string) => ({
  data: renewal
    ? [
        {
          key: "slo.renewal_success_objective",
          value: renewal,
          configured: true,
        },
      ]
    : [],
});

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <SLO />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.expiryTimeline).mockResolvedValue(timeline as never);
  vi.mocked(api.runtimeConfig).mockResolvedValue(config() as never);
});

describe("SLO page", () => {
  it("renders budget remaining and 1h/6h burn for each SLO", async () => {
    vi.mocked(api.renewalSLO).mockResolvedValue(
      report([
        budget({}),
        budget({
          name: "issuance-success-rate",
          objective: 0.995,
          budget_remaining_pct: 10,
          burn_rate_1h: 2,
          burn_rate_6h: 1,
        }),
      ]) as never,
    );
    renderPage();
    expect(await screen.findByText("87.5%")).toBeInTheDocument();
    expect(screen.getByText(/burn 1h 1\.20× · 6h 0\.40×/)).toBeInTheDocument();
    expect(screen.getByText("10.0%")).toBeInTheDocument();
    expect(screen.getByText(/burn 1h 2\.00× · 6h 1\.00×/)).toBeInTheDocument();
  });

  it("renders no-data SLOs as em dash without throwing", async () => {
    vi.mocked(api.renewalSLO).mockResolvedValue(
      report([
        budget({
          has_data: false,
          budget_remaining_pct: 100,
          burn_rate_1h: 0,
          burn_rate_6h: 0,
        }),
      ]) as never,
    );
    renderPage();
    expect(await screen.findByText(/burn 1h — · 6h —/)).toBeInTheDocument();
    expect(screen.queryByText(/NaN/)).not.toBeInTheDocument();
  });

  it("renders the time-to-expiry distribution buckets with counts", async () => {
    vi.mocked(api.renewalSLO).mockResolvedValue(report([budget({})]) as never);
    renderPage();
    expect(await screen.findByText("0–7 days")).toBeInTheDocument();
    expect(screen.getByText("7–30 days")).toBeInTheDocument();
    expect(screen.getByText("26")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
  });

  it("shows an honest state for tenant-scoped users (403)", async () => {
    vi.mocked(api.renewalSLO).mockRejectedValue(
      Object.assign(new Error("forbidden"), { status: 403 }),
    );
    renderPage();
    expect(
      await screen.findByText("Not available for tenant-scoped users"),
    ).toBeInTheDocument();
    expect(screen.queryByText("SLOs unavailable")).not.toBeInTheDocument();
  });

  it("editing an objective calls PUT /config/slo.renewal_success_objective with the typed value and refetches", async () => {
    vi.mocked(api.renewalSLO)
      .mockResolvedValueOnce(report([budget({ objective: 0.99 })]) as never)
      .mockResolvedValue(report([budget({ objective: 0.97 })]) as never);
    vi.mocked(api.setRuntimeConfig).mockResolvedValue(undefined as never);
    vi.mocked(api.runtimeConfig)
      .mockResolvedValueOnce(config() as never)
      .mockResolvedValue(config("0.97") as never);
    renderPage();
    expect(await screen.findByText(/Objective 0\.99 /)).toBeInTheDocument();

    const input = screen.getByLabelText("Renewal success rate");
    await userEvent.clear(input);
    await userEvent.type(input, "0.97");
    await userEvent.click(
      screen.getByRole("button", { name: "Save objectives" }),
    );

    await waitFor(() =>
      expect(api.setRuntimeConfig).toHaveBeenCalledWith(
        "slo.renewal_success_objective",
        "0.97",
      ),
    );
    expect(await screen.findByText(/Objective 0\.97 /)).toBeInTheDocument();
    expect(toast.success).toHaveBeenCalled();
    expect(screen.getByLabelText("Renewal success rate")).toHaveValue(0.97);
  });

  it("rejects renewal rate > 1 client-side", async () => {
    vi.mocked(api.renewalSLO).mockResolvedValue(report([budget({})]) as never);
    renderPage();
    const input = await screen.findByLabelText("Renewal success rate");
    await userEvent.clear(input);
    await userEvent.type(input, "1.5");
    expect(
      screen.getByRole("button", { name: "Save objectives" }),
    ).toBeDisabled();
    expect(api.setRuntimeConfig).not.toHaveBeenCalled();
  });
});
