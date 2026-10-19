import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    issuanceVelocity: vi.fn(),
    cas: vi.fn(),
    templates: vi.fn(),
  },
}));

import IssuanceVelocity from "../pages/IssuanceVelocity";
import { api } from "../lib/api";

function bucketsOf(
  days: number,
  nonZero?: { offsetFromEnd: number; count: number },
) {
  return Array.from({ length: days }, (_, i) => ({
    date: `2026-05-${String((i % 28) + 1).padStart(2, "0")}`,
    count:
      nonZero && i === days - 1 - nonZero.offsetFromEnd ? nonZero.count : 0,
  }));
}

function report(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    generated_at: "2026-07-31T00:00:00Z",
    total_issued: 4,
    windows: { last_7d: 4, last_30d: 4, last_90d: 4 },
    daily_buckets: bucketsOf(90, { offsetFromEnd: 0, count: 4 }),
    by_ca: {},
    by_team: {},
    by_template: {},
    anomaly_days: [],
    ...overrides,
  };
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <IssuanceVelocity />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("IssuanceVelocity daily chart", () => {
  it("renders a bar for the day holding the payload's only non-zero count", async () => {
    vi.mocked(api.issuanceVelocity).mockResolvedValue({
      data: report(),
    } as unknown as never);

    renderPage();

    await screen.findByText("Daily Issuance — Last 90 Days");
    const bars = screen.getAllByTestId("issuance-bar");
    // Guards bucket count and the inline height style attribute only.
    // jsdom performs no layout, so this cannot see whether the bar is
    // actually visible on screen — that's browser-verified (docs/STATUS.md).
    expect(bars).toHaveLength(90);
    expect(bars.some((bar) => bar.style.height === "100%")).toBe(true);
  });

  it("labels the panel with the window the payload actually covers, not a hardcoded 30", async () => {
    vi.mocked(api.issuanceVelocity).mockResolvedValue({
      data: report({
        daily_buckets: bucketsOf(90, { offsetFromEnd: 0, count: 4 }),
      }),
    } as unknown as never);

    renderPage();

    await screen.findByText(/Daily Issuance/);
    expect(
      screen.getByText("Daily Issuance — Last 90 Days"),
    ).toBeInTheDocument();
  });

  it("relabels when the payload covers a different window than 90 days", async () => {
    vi.mocked(api.issuanceVelocity).mockResolvedValue({
      data: report({
        daily_buckets: bucketsOf(5, { offsetFromEnd: 2, count: 2 }),
      }),
    } as unknown as never);

    renderPage();

    await screen.findByText(/Daily Issuance/);
    expect(
      screen.getByText("Daily Issuance — Last 5 Days"),
    ).toBeInTheDocument();
  });
});


// S-64: the threshold is shown where the warning renders, from the payload.
describe("anomaly threshold visibility (S-64)", () => {
  it("states the detector's minimum sample beside the anomaly warning, read from the payload", async () => {
    vi.mocked(api.issuanceVelocity).mockResolvedValue({
      data: report({
        total_issued: 40,
        windows: { last_7d: 10, last_30d: 40, last_90d: 40 },
        anomaly_days: ["2026-05-28"],
        anomaly_minimum_sample: 5,
      }),
    } as never);
    renderPage();

    expect(await screen.findByText(/Anomaly detected/)).toBeInTheDocument();
    // The value comes from the payload (5 here), never a component constant.
    expect(
      screen.getByText(/at least 5 certificates were issued/i),
    ).toBeInTheDocument();
  });

  it("renders the payload's below-threshold note instead of an anomaly panel", async () => {
    vi.mocked(api.issuanceVelocity).mockResolvedValue({
      data: report({
        total_issued: 3,
        windows: { last_7d: 3, last_30d: 3, last_90d: 3 },
        anomaly_days: [],
        anomaly_minimum_sample: 5,
        anomaly_threshold_note:
          "Anomaly detection requires a minimum sample of 5 certificates in the last 30 days (currently 3). No anomalies reported below this threshold.",
      }),
    } as never);
    renderPage();

    expect(
      await screen.findByText(/requires a minimum sample of 5/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Anomaly detected/)).not.toBeInTheDocument();
  });
});

describe("IssuanceVelocity drill-through (W28-21)", () => {
  it("links each By CA row to the certificate list filtered by that CA id", async () => {
    vi.mocked(api.cas).mockResolvedValue({
      data: { items: [{ id: "ca-1", name: "Root One" }] },
    } as unknown as never);
    vi.mocked(api.templates).mockResolvedValue({
      data: { items: [] },
    } as unknown as never);
    vi.mocked(api.issuanceVelocity).mockResolvedValue({
      data: report({ by_ca: { "ca-1": 3, unknown: 1 } }),
    } as unknown as never);

    renderPage();

    const link = await screen.findByRole("link", { name: "Root One" });
    expect(link).toHaveAttribute("href", "/certificates?ca_id=ca-1");
    expect(screen.queryByRole("link", { name: "unknown" })).toBeNull();
  });
});
