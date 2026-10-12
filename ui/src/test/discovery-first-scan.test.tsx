import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("../lib/api", async (importOriginal) => {
  const mod = (await importOriginal()) as Record<string, unknown>;
  return {
    ...mod,
    api: {
      ...(mod.api as Record<string, unknown>),
      authzCheck: vi.fn(),
      discoverySummary: vi.fn(),
      discoveryEndpoints: vi.fn(),
      discoveryScanJobs: vi.fn(),
      createDiscoveryScan: vi.fn(),
      targets: vi.fn(),
    },
  };
});

import Discovery from "../pages/Discovery";
import { api } from "../lib/api";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Discovery />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.mocked(api.authzCheck).mockResolvedValue({
    role: "pki-admin",
    scopes: [],
  } as never);
  vi.mocked(api.discoverySummary).mockResolvedValue({ data: {} } as never);
  vi.mocked(api.discoveryEndpoints).mockResolvedValue({
    data: { items: [] },
    meta: { total: 0 },
  } as never);
  vi.mocked(api.discoveryScanJobs).mockResolvedValue({
    data: { items: [] },
    meta: { total: 0 },
  } as never);
  vi.mocked(api.createDiscoveryScan).mockResolvedValue({
    data: { id: "scan-1" },
  } as never);
  vi.mocked(api.targets).mockResolvedValue({
    data: [
      {
        id: "t-win-1",
        name: "win-box",
        host: "10.0.0.5",
        discovery_mode: "winrm",
        install_mode: "iis",
        renewal_method: "manual",
        tenant: "default",
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      },
      {
        id: "t-net-1",
        name: "net-box",
        host: "10.0.0.6",
        discovery_mode: "network",
        install_mode: "acme",
        renewal_method: "manual",
        tenant: "default",
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      },
    ],
  } as never);
});

// The bootstrap dead-end this guards: the only Queue-scan button lived in
// the endpoint DETAIL panel, which needs an existing endpoint — so a fresh
// install (zero endpoints) could never start its FIRST scan.
describe("discovery — first scan", () => {
  it("offers New scan at page level even with zero endpoints", async () => {
    renderPage();
    expect(
      await screen.findByRole("button", { name: /new scan/i }),
    ).toBeInTheDocument();
  });

  it("queues a scan from the page-level entry", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: /new scan/i }));
    const target = await screen.findByLabelText(/target/i);
    await user.type(target, "127.0.0.1");
    await user.click(screen.getByRole("button", { name: /^queue scan$/i }));
    await waitFor(() =>
      expect(api.createDiscoveryScan).toHaveBeenCalledWith(
        expect.objectContaining({ target: "127.0.0.1" }),
      ),
    );
  });

  // W18-17: winrm's target is a managed target id, not a host/CIDR — the
  // dialog must offer a target picker instead of the free-text field, and
  // must never send a "ports" key (the backend rejects one on this type).
  it("files a winrm scan against a selected managed target", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: /new scan/i }));
    await user.selectOptions(
      await screen.findByLabelText(/^scan type$/i),
      "winrm",
    );

    const targetPicker = await screen.findByLabelText(/managed target/i);
    // Only the winrm-mode target is offered, not the network one.
    expect(
      screen.queryByRole("option", { name: /net-box/i }),
    ).not.toBeInTheDocument();
    await user.selectOptions(targetPicker, "t-win-1");

    await user.click(screen.getByRole("button", { name: /^queue scan$/i }));
    await waitFor(() =>
      expect(api.createDiscoveryScan).toHaveBeenCalledWith({
        scan_type: "winrm",
        target: "t-win-1",
      }),
    );
    const call = vi.mocked(api.createDiscoveryScan).mock.calls.at(-1)?.[0];
    expect(call).not.toHaveProperty("ports");
  });
});
