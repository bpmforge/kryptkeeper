import { MemoryRouter } from "react-router-dom";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    targets: vi.fn(),
    updateTarget: vi.fn(),
    renewalSchedulerStatus: vi.fn(),
    createDiscoveryScan: vi.fn(),
  },
}));

import RenewalPolicy from "../pages/RenewalPolicy";
import { api } from "../lib/api";

const TARGET_NO_OVERRIDE = {
  id: "target-1",
  name: "db-01",
  host: "db-01.internal.example.com",
  discovery_mode: "network",
  install_mode: "ssh",
  renewal_method: "acme",
  tenant: "default",
  created_at: "2026-07-28T00:00:00Z",
  updated_at: "2026-07-28T00:00:00Z",
};

const TARGET_WITH_OVERRIDE = {
  id: "target-2",
  name: "web-02",
  host: "web-02.example.com",
  discovery_mode: "network",
  install_mode: "acme",
  renewal_method: "manual",
  renewal_threshold_days: 10,
  tenant: "default",
  created_at: "2026-07-28T00:00:00Z",
  updated_at: "2026-07-28T00:00:00Z",
};

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <RenewalPolicy />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

function rowFor(targetName: string) {
  const heading = screen.getByText(targetName);
  return within(heading.closest("div.space-y-2") as HTMLElement);
}

beforeEach(() => {
  vi.mocked(api.targets).mockReset();
  vi.mocked(api.updateTarget).mockReset();
  vi.mocked(api.renewalSchedulerStatus).mockReset();
  vi.mocked(api.renewalSchedulerStatus).mockResolvedValue({
    data: {
      has_run: true,
      status: {
        running: true,
        threshold_days: 30,
        poll_interval_hours: 24,
        last_candidates: 0,
        last_expired_skipped: 0,
        last_auto_renew_triggers: 0,
        last_notifications: 0,
      },
    },
  } as unknown as never);
});

describe("RenewalPolicy page (acceptance #1 — set threshold + method per target)", () => {
  it("saves a per-target renewal method and threshold override", async () => {
    const user = userEvent.setup();
    vi.mocked(api.targets).mockResolvedValue({
      data: [TARGET_NO_OVERRIDE],
    } as unknown as never);
    vi.mocked(api.updateTarget).mockResolvedValue({
      data: {
        ...TARGET_NO_OVERRIDE,
        renewal_method: "scep",
        renewal_threshold_days: 14,
      },
    } as unknown as never);

    renderPage();
    await screen.findByText("db-01");
    const row = rowFor("db-01");

    await user.selectOptions(
      row.getByLabelText(/db-01 renewal method/i),
      "scep",
    );
    await user.type(
      row.getByLabelText(/db-01 auto-renew threshold days/i),
      "14",
    );
    await user.click(row.getByRole("button", { name: /^save$/i }));

    await waitFor(() =>
      expect(api.updateTarget).toHaveBeenCalledWith("target-1", {
        renewal_method: "scep",
        renewal_threshold_days: 14,
      }),
    );
  });

  it("shows the env default badge when a target carries no override, and an override badge when it does", async () => {
    vi.mocked(api.targets).mockResolvedValue({
      data: [TARGET_NO_OVERRIDE, TARGET_WITH_OVERRIDE],
    } as unknown as never);

    renderPage();
    await screen.findByText("db-01");

    expect(rowFor("db-01").getByText("env default (30d)")).toBeInTheDocument();
    expect(rowFor("web-02").getByText("10d override")).toBeInTheDocument();
  });

  it("disables Save until a field actually changes", async () => {
    vi.mocked(api.targets).mockResolvedValue({
      data: [TARGET_NO_OVERRIDE],
    } as unknown as never);

    renderPage();
    await screen.findByText("db-01");
    const row = rowFor("db-01");

    expect(row.getByRole("button", { name: /^save$/i })).toBeDisabled();
    await userEvent.type(
      row.getByLabelText(/db-01 auto-renew threshold days/i),
      "7",
    );
    expect(row.getByRole("button", { name: /^save$/i })).toBeEnabled();
    expect(api.updateTarget).not.toHaveBeenCalled();
  });

  it("rejects a negative threshold locally without calling the API", async () => {
    vi.mocked(api.targets).mockResolvedValue({
      data: [TARGET_NO_OVERRIDE],
    } as unknown as never);

    renderPage();
    await screen.findByText("db-01");
    const row = rowFor("db-01");

    // A number input's own keyboard filtering rejects letters outright, so
    // the reachable "typed something, still invalid" case is a negative
    // number (min=0 doesn't block typing "-", only submission/spinners).
    await userEvent.type(
      row.getByLabelText(/db-01 auto-renew threshold days/i),
      "-1",
    );

    await screen.findByText(/enter a whole number of days/i);
    expect(row.getByRole("button", { name: /^save$/i })).toBeDisabled();
    expect(api.updateTarget).not.toHaveBeenCalled();
  });
});

describe("RenewalPolicy page — clearing an override", () => {
  it("sends 0 to clear a per-target threshold override, reverting to the env default (acceptance #2 — drives the W4-02 scheduler per target)", async () => {
    const user = userEvent.setup();
    vi.mocked(api.targets).mockResolvedValue({
      data: [TARGET_WITH_OVERRIDE],
    } as unknown as never);
    vi.mocked(api.updateTarget).mockResolvedValue({
      data: { ...TARGET_WITH_OVERRIDE, renewal_threshold_days: undefined },
    } as unknown as never);

    renderPage();
    await screen.findByText("web-02");
    const row = rowFor("web-02");

    await user.click(row.getByRole("button", { name: /clear override/i }));

    await waitFor(() =>
      expect(api.updateTarget).toHaveBeenCalledWith("target-2", {
        renewal_threshold_days: 0,
      }),
    );
  });

  it("disables Clear override for a target with no override set", async () => {
    vi.mocked(api.targets).mockResolvedValue({
      data: [TARGET_NO_OVERRIDE],
    } as unknown as never);

    renderPage();
    await screen.findByText("db-01");
    const row = rowFor("db-01");

    expect(row.getByRole("button", { name: /clear override/i })).toBeDisabled();
  });
});

describe("RenewalPolicy page — loading and empty states", () => {
  it("shows an empty state pointing at Target Setup when no targets exist", async () => {
    vi.mocked(api.targets).mockResolvedValue({
      data: [],
    } as unknown as never);

    renderPage();
    await screen.findByText(/no managed targets yet/i);
  });

  it("shows an error state when targets fail to load", async () => {
    vi.mocked(api.targets).mockRejectedValue(new Error("boom"));

    renderPage();
    await screen.findByText(/managed targets could not be loaded/i);
  });
});

// W18-12: a winrm target can be discovered on demand from its row; other
// discovery modes get no such button because the hub has no runner for them.
describe("RenewalPolicy page — WinRM discover now (W18-12)", () => {
  it("files a winrm scan for the target and hides the action elsewhere", async () => {
    const user = userEvent.setup();
    vi.mocked(api.targets).mockResolvedValue({
      data: [
        TARGET_NO_OVERRIDE,
        { ...TARGET_WITH_OVERRIDE, id: "target-win", name: "iis-01", discovery_mode: "winrm", install_mode: "iis" },
      ],
    } as unknown as never);
    vi.mocked(api.createDiscoveryScan).mockResolvedValue({
      data: { scan_job: { id: "scan-1", status: "running" } },
    } as unknown as never);

    renderPage();
    await screen.findByText("iis-01");
    expect(screen.queryByRole("button", { name: /db-01 discover now/i })).toBeNull();
    await user.click(screen.getByRole("button", { name: /iis-01 discover now/i }));

    await waitFor(() =>
      expect(api.createDiscoveryScan).toHaveBeenCalledWith({
        scan_type: "winrm",
        target: "target-win",
      }),
    );
    expect(await screen.findByText(/scan queued/i)).toBeInTheDocument();
  });
});
