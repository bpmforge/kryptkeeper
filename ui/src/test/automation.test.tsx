import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    renewalSchedulerStatus: vi.fn(),
    renewalSLO: vi.fn(),
  },
}));

import Automation from "../pages/Automation";
import { api } from "../lib/api";

const runningScheduler = {
  data: {
    has_run: true,
    status: {
      running: true,
      threshold_days: 30,
      poll_interval_hours: 24,
      last_run_at: "2026-06-16T00:00:00Z",
      next_run_at: "2026-06-17T00:00:00Z",
      last_candidates: 0,
      last_expired_skipped: 0,
      last_auto_renew_triggers: 0,
      last_notifications: 0,
    },
  },
};

function renderAutomation() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Automation />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.renewalSchedulerStatus).mockResolvedValue(
    runningScheduler as unknown as never,
  );
});

describe("Automation page — autopilot SLO", () => {
  it("shows SLO metrics and the failed-renewal queue", async () => {
    vi.mocked(api.renewalSLO).mockResolvedValue({
      data: {
        generated_at: "2026-06-17T00:00:00Z",
        agents_total: 3,
        agents_active: 2,
        endpoints_managed: 12,
        outcomes: { installed_verified: 9, verify_failed: 1 },
        total_renewals: 10,
        success_rate_percent: 90,
        mean_time_to_renew_secs: 300,
        mttr_samples: 9,
        failed_renewals: [
          {
            agent_id: "agent-abc123",
            task_id: "t1",
            fingerprint: "deadbeefdeadbeef",
            outcome: "verify_failed",
            rolled_back: true,
            detail: "served fingerprint does not match",
            reported_at: "2026-06-16T12:00:00Z",
          },
        ],
      },
    } as unknown as never);

    renderAutomation();

    await screen.findByText("90%");
    expect(screen.getByText("5m")).toBeInTheDocument(); // 300s MTTR
    expect(
      screen.getByText(/served fingerprint does not match/i),
    ).toBeInTheDocument();
    // status badge for the failed outcome
    expect(screen.getByText("verify_failed")).toBeInTheDocument();
  });

  it("shows a clean failed-renewal queue when all verified", async () => {
    vi.mocked(api.renewalSLO).mockResolvedValue({
      data: {
        generated_at: "2026-06-17T00:00:00Z",
        agents_total: 1,
        agents_active: 1,
        endpoints_managed: 4,
        outcomes: { installed_verified: 4 },
        total_renewals: 4,
        success_rate_percent: 100,
        mean_time_to_renew_secs: 120,
        mttr_samples: 4,
        failed_renewals: [],
      },
    } as unknown as never);

    renderAutomation();

    await screen.findByText(/every install verified/i);
  });

  it("renders the scheduler panel alongside autopilot", async () => {
    vi.mocked(api.renewalSLO).mockResolvedValue({
      data: {
        generated_at: "2026-06-17T00:00:00Z",
        agents_total: 0,
        agents_active: 0,
        endpoints_managed: 0,
        outcomes: {},
        total_renewals: 0,
        success_rate_percent: 0,
        mean_time_to_renew_secs: 0,
        mttr_samples: 0,
        failed_renewals: [],
      },
    } as unknown as never);

    renderAutomation();

    await screen.findByText("Renewal Scheduler");
    expect(await screen.findByText("Running")).toBeInTheDocument();
    expect(
      await screen.findByText(/no autopilot renewals reported yet/i),
    ).toBeInTheDocument();
  });
});
