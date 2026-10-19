import { fireEvent, render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: { keyCustody: vi.fn() },
}));

import KeyCustody from "../pages/KeyCustody";
import { api } from "../lib/api";
import { navSections } from "../lib/nav";

const ev = (over: Record<string, unknown> = {}) => ({
  action: "key.export",
  occurred_at: "2026-06-02T00:00:00Z",
  requester: "alice",
  approver: "bob",
  redeemer: "alice",
  dual_control: true,
  ...over,
});

function report(over: Record<string, unknown> = {}) {
  return {
    data: {
      generated_at: "2026-07-31T00:00:00Z",
      backend: "software",
      dual_control_escrow: true,
      event_counts: {
        "key.export": 1,
        "key.escrow": 0,
        "key.escrow_recover": 0,
        "key.rotate": 1,
        "key.delete": 0,
      },
      targets: [],
      keys: [
        {
          key_id: "ca-root-key",
          algorithm: "ECDSA-P256",
          backend: "software",
          rotation_count: 2,
          last_rotated_at: "2026-06-01T00:00:00Z",
          access_count: 3,
          events: [ev(), ev({ action: "key.rotate" })],
        },
        {
          key_id: "web-key",
          algorithm: "RSA-2048",
          backend: "software",
          rotation_count: 0,
          access_count: 0,
          events: [],
        },
      ],
      ...over,
    },
  };
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <KeyCustody />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("KeyCustody", () => {
  it("renders backend, rotation history and SoD actors per key", async () => {
    vi.mocked(api.keyCustody).mockResolvedValue(report() as never);
    renderPage();
    expect(await screen.findByText("ca-root-key")).toBeInTheDocument();
    expect(screen.getByText("web-key")).toBeInTheDocument();
    const rotations = within(screen.getAllByTestId("field-Rotations")[0]);
    expect(rotations.getByText(/^2 \(last/)).toBeInTheDocument();
    expect(screen.getAllByTestId("field-Backend")[0]).toHaveTextContent(
      "software",
    );
    const row = screen.getByText("key.export").closest("li") as HTMLElement;
    expect(
      within(within(row).getByTestId("field-Requester")).getByText("alice"),
    ).toBeInTheDocument();
    expect(
      within(within(row).getByTestId("field-Approver")).getByText("bob"),
    ).toBeInTheDocument();
    expect(
      within(within(row).getByTestId("field-Redeemer")).getByText("alice"),
    ).toBeInTheDocument();
    expect(screen.getByText("No custody events recorded")).toBeInTheDocument();
  });

  it("filters by key id", async () => {
    vi.mocked(api.keyCustody).mockResolvedValue(report() as never);
    renderPage();
    await screen.findByText("ca-root-key");
    const box = screen.getByLabelText("Filter by key");
    fireEvent.change(box, { target: { value: "ca-root" } });
    expect(screen.getByText("ca-root-key")).toBeInTheDocument();
    expect(screen.queryByText("web-key")).not.toBeInTheDocument();
    fireEvent.change(box, { target: { value: "CA-ROOT" } });
    expect(screen.getByText("ca-root-key")).toBeInTheDocument();
    expect(screen.queryByText("web-key")).not.toBeInTheDocument();
  });

  it("shows the no-match empty state and clears it", async () => {
    vi.mocked(api.keyCustody).mockResolvedValue(report() as never);
    renderPage();
    await screen.findByText("ca-root-key");
    fireEvent.change(screen.getByLabelText("Filter by key"), {
      target: { value: "zzz" },
    });
    expect(screen.getByText('No keys match "zzz"')).toBeInTheDocument();
    fireEvent.click(screen.getByText("Clear filter"));
    expect(screen.getByText("ca-root-key")).toBeInTheDocument();
    expect(screen.getByText("web-key")).toBeInTheDocument();
  });

  it("shows the empty keystore state", async () => {
    vi.mocked(api.keyCustody).mockResolvedValue(report({ keys: [] }) as never);
    renderPage();
    expect(
      await screen.findByText("No keys in the keystore"),
    ).toBeInTheDocument();
  });

  it("shows None (dual control off) for a single-actor event", async () => {
    vi.mocked(api.keyCustody).mockResolvedValue(
      report({
        keys: [
          {
            key_id: "solo-key",
            algorithm: "ECDSA-P256",
            backend: "software",
            rotation_count: 0,
            access_count: 0,
            events: [ev({ approver: "", dual_control: false })],
          },
        ],
      }) as never,
    );
    renderPage();
    expect(
      await screen.findByText("None (dual control off)"),
    ).toBeInTheDocument();
  });

  it("shows an error state", async () => {
    vi.mocked(api.keyCustody).mockRejectedValue(
      new Error("Admin role required"),
    );
    renderPage();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Admin role required",
    );
  });

  it("is reachable from the reports navigation", () => {
    const tos = navSections.flatMap((s) => s.items.map((i) => i.to));
    expect(tos).toContain("/reports/key-custody");
  });
});
