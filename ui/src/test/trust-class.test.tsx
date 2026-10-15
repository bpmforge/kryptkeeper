import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";

vi.mock("../lib/api", () => ({
  api: {
    dashboardSummary: vi.fn(),
    cas: vi.fn(),
    auditList: vi.fn(),
    cryptoPosture: vi.fn(),
    certificates: vi.fn(),
    authzCheck: vi.fn(),
    discoverySummary: vi.fn(),
    discoveryEndpoints: vi.fn(),
    discoveryScanJobs: vi.fn(),
    targets: vi.fn(),
    search: vi.fn(),
    notificationRules: vi.fn(),
  },
  downloadAuthedFile: vi.fn(),
}));

import Dashboard from "../pages/Dashboard";
import Certificates from "../pages/Certificates";
import Discovery from "../pages/Discovery";
import { TrustBreakdown } from "../components/TrustBreakdown";
import { api } from "../lib/api";

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="location">{loc.pathname + loc.search}</div>;
}

function renderPage(ui: ReactElement, initialEntries?: string[]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={initialEntries}>
        {ui}
        <LocationProbe />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const counts = {
  managed: 4,
  public: 9,
  private_other: 2,
  self_signed: 3,
  unknown: 0,
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue({
    role: "pki-admin",
    scopes: ["*"],
  } as never);
  vi.mocked(api.cas).mockResolvedValue({
    data: [{ id: "ca-1", name: "Root", type: "root" }],
  } as never);
  vi.mocked(api.auditList).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.cryptoPosture).mockResolvedValue({ data: null } as never);
  vi.mocked(api.certificates).mockResolvedValue({
    data: { items: [] },
    meta: { total: 0, limit: 50 },
  } as never);
  vi.mocked(api.discoverySummary).mockResolvedValue({ data: {} } as never);
  vi.mocked(api.discoveryScanJobs).mockResolvedValue({
    data: { items: [] },
    meta: { total: 0 },
  } as never);
  vi.mocked(api.discoveryEndpoints).mockResolvedValue({
    data: { endpoints: [] },
    meta: { total: 0 },
  } as never);
  vi.mocked(api.targets).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.notificationRules).mockResolvedValue({
    data: { items: [] },
    meta: { total: 0 },
  } as never);
});

describe("TrustBreakdown", () => {
  it("shows every class with its count and drills into the filtered inventory", async () => {
    const user = userEvent.setup();
    renderPage(<TrustBreakdown counts={counts} />);
    const strip = screen.getByTestId("trust-strip");
    expect(strip).toHaveTextContent("4 managed");
    expect(strip).toHaveTextContent("9 public");
    expect(strip).toHaveTextContent("2 other private CA");
    expect(strip).toHaveTextContent("3 self-signed");
    expect(strip).toHaveTextContent("0 unknown");

    await user.click(screen.getByTestId("trust-private_other"));
    expect(screen.getByTestId("location")).toHaveTextContent(
      "/discovery?trust_class=private_other",
    );
  });

  it("does not colour a zero count as a finding", () => {
    renderPage(<TrustBreakdown counts={counts} />);
    expect(screen.getByTestId("trust-unknown").className).toContain(
      "text-muted-foreground",
    );
    expect(screen.getByTestId("trust-self_signed").className).toContain(
      "text-state-attn",
    );
  });
});

describe("Dashboard trust breakdown", () => {
  it("renders next to the estate strip when the hub reports trust classes", async () => {
    vi.mocked(api.dashboardSummary).mockResolvedValue({
      data: {
        certificates: { total: 5, managed: 1, external: 0, unmanaged: 4 },
        discovery: {
          discovered_endpoints: 7,
          risky_endpoints: 1,
          trust_classes: counts,
        },
        notifications: {},
      },
    } as never);
    renderPage(<Dashboard />);
    expect(await screen.findByTestId("estate-strip")).toBeInTheDocument();
    expect(await screen.findByTestId("trust-strip")).toHaveTextContent(
      "9 public",
    );
  });

  it("is absent on a summary without trust classes (file-backed hubs)", async () => {
    vi.mocked(api.dashboardSummary).mockResolvedValue({
      data: { certificates: { total: 1 }, discovery: {}, notifications: {} },
    } as never);
    renderPage(<Dashboard />);
    await screen.findByTestId("estate-strip");
    expect(screen.queryByTestId("trust-strip")).not.toBeInTheDocument();
  });
});

describe("trust class filters", () => {
  it("Certificates seeds the filter from the URL and sends it to the API", async () => {
    renderPage(<Certificates />, [
      "/certificates?origin=discovered&trust_class=self_signed",
    ]);
    await waitFor(() =>
      expect(api.certificates).toHaveBeenCalledWith(
        expect.objectContaining({
          origin: "discovered",
          trust_class: "self_signed",
        }),
      ),
    );
    const select = screen.getByRole("combobox", {
      name: /filter by trust class/i,
    }) as HTMLSelectElement;
    expect(select.value).toBe("self_signed");
  });

  it("Certificates changes the trust class filter", async () => {
    const user = userEvent.setup();
    renderPage(<Certificates />);
    await user.selectOptions(
      screen.getByRole("combobox", { name: /filter by trust class/i }),
      "public",
    );
    await waitFor(() =>
      expect(api.certificates).toHaveBeenCalledWith(
        expect.objectContaining({ trust_class: "public" }),
      ),
    );
  });

  it("Discovery filters endpoints by trust class and labels mapped certs", async () => {
    const user = userEvent.setup();
    vi.mocked(api.discoveryEndpoints).mockResolvedValue({
      data: {
        endpoints: [
          {
            id: "ep-1",
            hostname: "svc.other.test",
            port: 443,
            protocol: "tls",
            risk_score: 0,
            mapped_certs: [
              {
                fingerprint: "fp-leaf",
                common_name: "svc.other.test",
                risk_score: 0,
                trust_class: "private_other",
              },
              {
                fingerprint: "fp-root",
                common_name: "Other Root",
                risk_score: 0,
                chain_ca: true,
              },
            ],
          },
        ],
      },
      meta: { total: 1 },
    } as never);
    renderPage(<Discovery />);
    await user.selectOptions(
      await screen.findByRole("combobox", { name: /filter by trust class/i }),
      "private_other",
    );
    await waitFor(() =>
      expect(api.discoveryEndpoints).toHaveBeenCalledWith(
        expect.objectContaining({ trust_class: "private_other" }),
      ),
    );
    await user.click(
      await screen.findByRole("button", { name: "svc.other.test" }),
    );
    expect(await screen.findByText(/·\s*other private CA/)).toBeInTheDocument();
    expect(screen.getByText(/CA in served chain/)).toBeInTheDocument();
  });
});
