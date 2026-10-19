import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    renewalSchedulerStatus: vi.fn(),
    renewalSLO: vi.fn(),
    renewalRetry: vi.fn(),
    authzCheck: vi.fn(),
  },
}));

import Automation from "../pages/Automation";
import { api } from "../lib/api";

const FP = "deadbeefdeadbeefdeadbeefdeadbeef";

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

const failure = (over: Record<string, unknown> = {}) => ({
  agent_id: "agent-abc123",
  task_id: "",
  fingerprint: FP,
  outcome: "install_failed",
  rolled_back: false,
  reported_at: "2026-06-16T12:00:00Z",
  type: "execute_failure",
  ...over,
});

function slo(failed: unknown[], queue?: unknown) {
  return {
    data: {
      generated_at: "2026-06-17T00:00:00Z",
      agents_total: 3,
      agents_active: 2,
      endpoints_managed: 7,
      outcomes: {},
      total_renewals: 10,
      success_rate_percent: 90,
      mean_time_to_renew_secs: 300,
      mttr_samples: 9,
      failed_renewals: failed,
      ...(queue ? { queue } : {}),
    },
  } as unknown as never;
}

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
  vi.mocked(api.authzCheck).mockResolvedValue({
    role: "pki-admin",
    scopes: [],
  } as unknown as never);
});

describe("Automation page — failed-renewal queue", () => {
  it("shows attempt and reason and Retry updates the row", async () => {
    vi.mocked(api.renewalSLO).mockResolvedValue(
      slo([failure({ attempt: 2, max_attempts: 5, detail: "nginx -t failed" })]),
    );
    vi.mocked(api.renewalRetry).mockResolvedValue({
      data: { fingerprint: FP, status: "queued" },
    } as unknown as never);
    renderAutomation();

    await screen.findByText("2/5");
    expect(screen.getByText("nginx -t failed")).toBeInTheDocument();
    await userEvent.click(
      screen.getByRole("button", { name: "Retry renewal deadbeefdead" }),
    );
    expect(api.renewalRetry).toHaveBeenCalledWith(FP);
    expect(await screen.findByText("Retry queued")).toBeInTheDocument();
    await waitFor(() => expect(api.renewalSLO).toHaveBeenCalledTimes(2));
  });

  it("notification dead letters share the list with a type badge", async () => {
    vi.mocked(api.renewalSLO).mockResolvedValue(
      slo([
        failure(),
        failure({ type: "notification_dead_letter", fingerprint: "aa".repeat(16) }),
        failure({ type: "agent_result", fingerprint: "bb".repeat(16), task_id: "t1" }),
      ]),
    );
    renderAutomation();

    const table = await screen.findByRole("table", { name: "Failed renewals" });
    expect(within(table).getByText("Execute failure")).toBeInTheDocument();
    expect(within(table).getByText("Notification dead letter")).toBeInTheDocument();
    expect(within(table).getByText("Agent result")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /^Retry renewal/ })).toHaveLength(1);
  });

  it("viewer sees no Retry button", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({
      role: "pki-viewer",
      scopes: [],
    } as unknown as never);
    vi.mocked(api.renewalSLO).mockResolvedValue(slo([failure()]));
    renderAutomation();

    await screen.findByRole("table", { name: "Failed renewals" });
    await waitFor(() => expect(api.authzCheck).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: /^Retry renewal/ })).toBeNull();
  });

  it("renders queue depth, ETA and connector budgets from the endpoint", async () => {
    vi.mocked(api.renewalSLO).mockResolvedValue(
      slo([], {
        depth: 12,
        eta_seconds: 3600,
        eta_known: true,
        connector_budgets: [
          { connector_id: "c1", in_flight: 3, cap: 10, daily_used: 40, daily_limit: 300 },
        ],
      }),
    );
    renderAutomation();

    await screen.findByText("Queue depth");
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("1.0h")).toBeInTheDocument();
    expect(screen.getByText("c1")).toBeInTheDocument();
    expect(screen.getByText("3/10")).toBeInTheDocument();
    expect(screen.getByText("40/300")).toBeInTheDocument();
  });

  it("retry error is shown in the row", async () => {
    vi.mocked(api.renewalSLO).mockResolvedValue(slo([failure()]));
    vi.mocked(api.renewalRetry).mockRejectedValue(
      new Error("no failed renewal is queued"),
    );
    renderAutomation();

    await userEvent.click(
      await screen.findByRole("button", { name: "Retry renewal deadbeefdead" }),
    );
    expect(await screen.findByText("no failed renewal is queued")).toBeInTheDocument();
  });

  it("passes axe with 0 serious or critical violations", async () => {
    vi.mocked(api.renewalSLO).mockResolvedValue(
      slo([failure({ attempt: 1, max_attempts: 5 })], {
        depth: 3,
        eta_seconds: 300,
        eta_known: true,
        connector_budgets: [{ connector_id: "c1", in_flight: 1, cap: 10 }],
      }),
    );
    const { container } = renderAutomation();
    await screen.findByRole("table", { name: "Failed renewals" });
    await screen.findByRole("button", { name: /^Retry renewal/ });

    const axe = (await import("axe-core")).default;
    // color-contrast is disabled because jsdom cannot compute rendered colours.
    const r = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(r.violations.filter((v) => v.impact === "serious" || v.impact === "critical")).toEqual([]);
  });
});
