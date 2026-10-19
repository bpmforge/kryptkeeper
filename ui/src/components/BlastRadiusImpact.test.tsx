import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    blastRadius: vi.fn(),
    pendingActions: vi.fn(),
    approvePendingAction: vi.fn(),
    rejectPendingAction: vi.fn(),
    approvals: vi.fn(),
    cas: vi.fn(),
    templates: vi.fn(),
    approveRequest: vi.fn(),
    rejectRequest: vi.fn(),
  },
}));

import {
  BlastRadiusImpact,
  approveEnabled,
  impactForPendingAction,
} from "./BlastRadiusImpact";
import PendingActions from "../pages/PendingActions";
import Approvals from "../pages/Approvals";
import { api } from "../lib/api";
import type { BlastRadiusResult } from "../lib/models";

function wrap(ui: React.ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function result(over: Partial<BlastRadiusResult> = {}) {
  return {
    data: {
      action: "revoke",
      target: "fp-1",
      total_affected: 5,
      severity: "high",
      affected_by_kind: {
        cert: ["c1", "c2"],
        service: ["svc-a", "svc-b", "svc-c"],
      },
      graph_size: "9 nodes",
      ...over,
    },
  } as unknown as never;
}

function httpError(status: number, message = "boom") {
  return Object.assign(new Error(message), { status });
}

function expectNoAllClear() {
  expect(screen.queryByText(/safe/i, { selector: "*" })).toBeNull();
  expect(screen.queryByRole("img")).toBeNull();
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("BlastRadiusImpact (W31-16)", () => {
  it("shows cert and service counts and severity", async () => {
    vi.mocked(api.blastRadius).mockResolvedValue(result());
    wrap(<BlastRadiusImpact action="revoke" target="fp-1" />);
    expect(
      await screen.findByText("2 certificates, 3 services affected"),
    ).toBeInTheDocument();
    expect(screen.getByText("high")).toBeInTheDocument();
    expect(screen.getByText("Affected services")).toBeInTheDocument();
  });

  it("zero affected says nothing depends (explicit, no success tick)", async () => {
    vi.mocked(api.blastRadius).mockResolvedValue(
      result({ total_affected: 0, severity: "none", affected_by_kind: {} }),
    );
    wrap(<BlastRadiusImpact action="revoke" target="fp-1" />);
    expect(
      await screen.findByText(
        "Nothing depends on this target in the inventory graph.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("0 certificates, 0 services affected"),
    ).toBeInTheDocument();
    expect(screen.queryByRole("img")).toBeNull();
  });

  it("403 renders the permission message and reports error state", async () => {
    vi.mocked(api.blastRadius).mockRejectedValue(httpError(403));
    const onState = vi.fn();
    wrap(
      <BlastRadiusImpact
        action="revoke"
        target="fp-1"
        onStateChange={onState}
      />,
    );
    expect(
      await screen.findByText("Blast radius not permitted"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/\(403\)\. It cannot be treated as safe\./),
    ).toBeInTheDocument();
    await waitFor(() => expect(onState).toHaveBeenLastCalledWith("error"));
    expect(screen.queryByRole("img")).toBeNull();
  });

  it("404 renders the not-found message and reports error state", async () => {
    vi.mocked(api.blastRadius).mockRejectedValue(httpError(404));
    const onState = vi.fn();
    wrap(
      <BlastRadiusImpact
        action="revoke"
        target="fp-1"
        onStateChange={onState}
      />,
    );
    expect(
      await screen.findByText("Blast radius target not found"),
    ).toBeInTheDocument();
    expect(screen.getByText(/Impact is unknown/)).toBeInTheDocument();
    await waitFor(() => expect(onState).toHaveBeenLastCalledWith("error"));
    expect(screen.queryByRole("img")).toBeNull();
  });

  it("500 renders retry and reports error", async () => {
    vi.mocked(api.blastRadius).mockRejectedValue(httpError(500, "server down"));
    const onState = vi.fn();
    wrap(
      <BlastRadiusImpact
        action="revoke"
        target="fp-1"
        onStateChange={onState}
      />,
    );
    expect(
      await screen.findByText("Blast radius unavailable"),
    ).toBeInTheDocument();
    expect(screen.getByText("server down")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    await waitFor(() => expect(onState).toHaveBeenLastCalledWith("error"));
    expectNoAllClear();
  });

  it("reports loading then ready", async () => {
    vi.mocked(api.blastRadius).mockResolvedValue(result());
    const onState = vi.fn();
    wrap(
      <BlastRadiusImpact
        action="revoke"
        target="fp-1"
        onStateChange={onState}
      />,
    );
    expect(screen.getByRole("status")).toHaveTextContent(
      "Calculating blast radius...",
    );
    expect(onState).toHaveBeenNthCalledWith(1, "loading");
    await screen.findByText(/services affected/);
    await waitFor(() => expect(onState).toHaveBeenLastCalledWith("ready"));
  });

  it("impactForPendingAction maps revoke, bulk_revoke, ca_revoke and returns null for pqc_migrate_wave and empty targets", () => {
    expect(
      impactForPendingAction({
        action_type: "revoke",
        params: { fingerprint: "fp" },
      }),
    ).toEqual({ action: "revoke", target: "fp" });
    expect(
      impactForPendingAction({
        action_type: "bulk_revoke",
        params: { ca_id: "ca" },
      }),
    ).toEqual({ action: "retire_ca", target: "ca" });
    expect(
      impactForPendingAction({
        action_type: "ca_revoke",
        params: { ca_id: "ca" },
      }),
    ).toEqual({ action: "retire_ca", target: "ca" });
    expect(
      impactForPendingAction({
        action_type: "pqc_migrate_wave",
        params: { wave_id: "w" },
      }),
    ).toBeNull();
    expect(
      impactForPendingAction({
        action_type: "revoke",
        params: { fingerprint: "" },
      }),
    ).toBeNull();
    expect(
      impactForPendingAction({ action_type: "revoke", params: null }),
    ).toBeNull();
  });

  it("approveEnabled truth table", () => {
    expect(approveEnabled(false, undefined)).toBe(true);
    expect(approveEnabled(false, "error")).toBe(true);
    expect(approveEnabled(true, undefined)).toBe(false);
    expect(approveEnabled(true, "loading")).toBe(false);
    expect(approveEnabled(true, "error")).toBe(false);
    expect(approveEnabled(true, "ready")).toBe(true);
  });
});

describe("PendingActions gating (W31-16)", () => {
  const proposed = {
    id: "act-1",
    action_type: "bulk_revoke",
    params: { ca_id: "ca-7", reason_code: 4 },
    proposed_by: "mcp:agent",
    rationale: "r",
    status: "pending",
    created_at: "2026-06-18T00:00:00Z",
  };

  it("PendingActions: Approve stays disabled until blast radius resolves, enables on success, stays disabled on 404", async () => {
    vi.mocked(api.pendingActions).mockResolvedValue({
      data: [proposed],
    } as unknown as never);
    let release!: (v: never) => void;
    vi.mocked(api.blastRadius).mockReturnValueOnce(
      new Promise((res) => {
        release = res as (v: never) => void;
      }),
    );
    const first = wrap(<PendingActions />);
    const btn = await screen.findByRole("button", { name: /^approve$/i });
    expect(btn).toBeDisabled();
    release(result({ action: "retire_ca" }));
    await screen.findByText("2 certificates, 3 services affected");
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /^approve$/i })).toBeEnabled(),
    );
    first.unmount();

    vi.mocked(api.blastRadius).mockRejectedValue(httpError(404));
    wrap(<PendingActions />);
    await screen.findByText("Blast radius target not found");
    expect(screen.getByRole("button", { name: /^approve$/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /^reject$/i })).toBeEnabled();
  });
});

describe("Approvals notice (W31-16)", () => {
  it("Approvals: pending request shows the not-applicable notice and Approve is enabled", async () => {
    vi.mocked(api.cas).mockResolvedValue({
      data: { items: [] },
    } as unknown as never);
    vi.mocked(api.templates).mockResolvedValue({
      data: { items: [] },
    } as unknown as never);
    vi.mocked(api.approvals).mockResolvedValue({
      data: [
        {
          id: "apr-1",
          template_id: "tpl-1",
          ca_id: "ca-1",
          requester: "user-7",
          status: "pending",
          csr_pem: "x",
          requested_at: "2026-06-01T12:00:00Z",
        },
      ],
      meta: { total: 1, limit: 50, offset: 0 },
    } as unknown as never);
    wrap(<Approvals />);
    expect(
      await screen.findByText(
        "Issuance adds a certificate and removes nothing, so no blast radius applies.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^approve$/i })).toBeEnabled();
    expect(api.blastRadius).not.toHaveBeenCalled();
  });
});
