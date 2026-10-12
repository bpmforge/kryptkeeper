import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// W19-22: a mesh/K8s-secret discovery source (Istio/Linkerd) has no
// listening socket, so its endpoint row carries port=0 (not a network
// address) once persistence stops rejecting it outright. The endpoint
// list must render that as "secret", not a literal ":0" that reads like a
// scan bug.
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
    data: {
      items: [
        {
          id: "ep-istio-ca",
          hostname: "istio-system/istio-ca-secret",
          ip_address: "istio-system/istio-ca-secret",
          port: 0,
          protocol: "istio-mesh",
          risk_score: 0,
        },
      ],
    },
    meta: { total: 1 },
  } as never);
  vi.mocked(api.discoveryScanJobs).mockResolvedValue({
    data: { items: [] },
    meta: { total: 0 },
  } as never);
  vi.mocked(api.targets).mockResolvedValue({ data: [] } as never);
});

describe("discovery — port-less mesh endpoint", () => {
  it("renders 'secret' instead of a literal 0 for a port-less source", async () => {
    renderPage();
    const hostnameButton = await screen.findByRole("button", {
      name: "istio-system/istio-ca-secret",
    });
    const row = hostnameButton.closest("tr");
    if (!row)
      throw new Error("expected the hostname button inside a table row");
    // "secret" (not a literal port "0", which would read as a scan bug).
    expect(within(row).getByText("secret")).toBeInTheDocument();
  });
});
