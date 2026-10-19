import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: { blastRadius: vi.fn() },
}));

import { BlastRadiusPanel } from "./BlastRadiusPanel";
import { api } from "../lib/api";
import type { BlastRadiusResult } from "../lib/models";

function renderPanel(onConfirm = vi.fn()) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <BlastRadiusPanel
        action="retire_ca"
        target="ca-1"
        confirmLabel="Rotate key"
        onConfirm={onConfirm}
      />
    </QueryClientProvider>,
  );
  return onConfirm;
}

function result(over: Partial<BlastRadiusResult> = {}): {
  data: BlastRadiusResult;
} {
  return {
    data: {
      action: "retire_ca",
      target: "ca-1",
      total_affected: 4,
      severity: "high",
      affected_by_kind: {
        key: ["key-9"],
        endpoint: ["api.example.com:443", "db.example.com:5432"],
        service: ["billing"],
      },
      graph_size: "12 nodes",
      ...over,
    },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("BlastRadiusPanel (W23-17)", () => {
  it("renders loading state and keeps confirm disabled", () => {
    vi.mocked(api.blastRadius).mockReturnValue(new Promise(() => {}));
    renderPanel();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Calculating blast radius...",
    );
    expect(screen.getByRole("button", { name: "Rotate key" })).toBeDisabled();
  });

  it("renders affected endpoints, services and keys", async () => {
    vi.mocked(api.blastRadius).mockResolvedValue(result());
    renderPanel();
    expect(await screen.findByText("4 affected")).toBeInTheDocument();
    expect(screen.getByText("high")).toBeInTheDocument();
    expect(screen.getByText("Endpoints")).toBeInTheDocument();
    expect(screen.getByText("api.example.com:443")).toBeInTheDocument();
    expect(screen.getByText("db.example.com:5432")).toBeInTheDocument();
    expect(screen.getByText("Services")).toBeInTheDocument();
    expect(screen.getByText("billing")).toBeInTheDocument();
    expect(screen.getByText("Keys")).toBeInTheDocument();
    expect(screen.getByText("key-9")).toBeInTheDocument();
    const headings = screen
      .getAllByRole("heading", { level: 4 })
      .map((h) => h.textContent);
    expect(headings).toEqual(["Endpoints", "Services", "Keys"]);
    expect(screen.getByRole("button", { name: "Rotate key" })).toBeEnabled();
  });

  it("renders the empty state when total_affected is 0 and enables confirm", async () => {
    vi.mocked(api.blastRadius).mockResolvedValue(
      result({ total_affected: 0, severity: "none", affected_by_kind: {} }),
    );
    renderPanel();
    expect(
      await screen.findByText("Nothing depends on this target."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rotate key" })).toBeEnabled();
  });

  it("renders the error state, disabled confirm, and retry refetches", async () => {
    vi.mocked(api.blastRadius)
      .mockRejectedValueOnce(new Error("boom"))
      .mockResolvedValueOnce(result());
    renderPanel();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Blast radius unavailable",
    );
    expect(screen.getByText("boom")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rotate key" })).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("4 affected")).toBeInTheDocument();
    expect(api.blastRadius).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("button", { name: "Rotate key" })).toBeEnabled();
  });

  it("calls api.blastRadius with action and target", async () => {
    vi.mocked(api.blastRadius).mockResolvedValue(result());
    renderPanel();
    await waitFor(() =>
      expect(api.blastRadius).toHaveBeenCalledWith("retire_ca", "ca-1"),
    );
  });

  it("confirm click calls onConfirm exactly once after load", async () => {
    vi.mocked(api.blastRadius).mockResolvedValue(result());
    const onConfirm = renderPanel();
    const btn = screen.getByRole("button", { name: "Rotate key" });
    expect(btn).toBeDisabled();
    await screen.findByText("4 affected");
    await userEvent.click(btn);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});
