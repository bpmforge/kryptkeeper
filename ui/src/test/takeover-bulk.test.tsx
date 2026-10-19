import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
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
      certificates: vi.fn(),
      connectors: vi.fn(),
      estateBulkTakeover: vi.fn(),
      estateTakeover: vi.fn(),
      estateTakeoverSuggestions: vi.fn(),
    },
  };
});

import Discovery from "../pages/Discovery";
import Certificates from "../pages/Certificates";
import { api } from "../lib/api";

function renderAt(ui: React.ReactElement, path = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/targets/setup" element={<Probe />} />
          <Route path="*" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function Probe() {
  const loc = useLocation();
  return <div data-testid="probe">{loc.search}</div>;
}

function makeCerts(n: number) {
  return Array.from({ length: n }, (_, i) => ({
    fingerprint_sha256: `fp-${i}`,
    common_name: `host${i}.example.com`,
    issuer_cn: "Some CA",
    valid_until: "2027-01-01T00:00:00Z",
    origin: "discovered",
    management_state: "unmanaged",
  }));
}

function asAdmin(role = "pki-admin") {
  vi.mocked(api.authzCheck).mockResolvedValue({
    role,
    scopes: role === "pki-admin" ? ["*"] : [],
  } as never);
}

beforeEach(() => {
  vi.clearAllMocks();
  asAdmin();
  vi.mocked(api.discoverySummary).mockResolvedValue({ data: {} } as never);
  vi.mocked(api.discoveryEndpoints).mockResolvedValue({
    data: { items: [] },
    meta: { total: 0 },
  } as never);
  vi.mocked(api.discoveryScanJobs).mockResolvedValue({
    data: { items: [] },
    meta: { total: 0 },
  } as never);
  vi.mocked(api.connectors).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.estateTakeoverSuggestions).mockResolvedValue([]);
});

describe("Discovery bulk takeover", () => {
  it("bulk takeover of 20 discovered certs issues ONE call and renders per-cert outcomes", async () => {
    const certs = makeCerts(20);
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: certs },
      meta: { total: 20 },
    } as never);
    vi.mocked(api.estateBulkTakeover).mockResolvedValue({
      data: {
        total: 20,
        succeeded: 19,
        failed: 1,
        skipped: 0,
        results: certs.map((c, i) =>
          i === 7
            ? { fingerprint: c.fingerprint_sha256, status: "error", error: "already managed" }
            : { fingerprint: c.fingerprint_sha256, status: "ok" },
        ),
      },
    } as never);
    const user = userEvent.setup();
    renderAt(<Discovery />);

    await screen.findByRole("checkbox", { name: "Select host0.example.com" });
    // The scan-jobs panel also has a "Select all visible"; ours comes first.
    await user.click(screen.getAllByRole("button", { name: "Select all visible" })[0]);
    expect(screen.getByText("20 selected")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Take over selected" }));
    const dialog = await screen.findByRole("dialog", {
      name: /take selected certificates under management/i,
    });
    await user.type(
      within(dialog).getByLabelText("Takeover owner email"),
      "owner@example.com",
    );
    await user.click(within(dialog).getByRole("button", { name: "Take over 20" }));

    await waitFor(() => expect(api.estateBulkTakeover).toHaveBeenCalledTimes(1));
    const body = vi.mocked(api.estateBulkTakeover).mock.calls[0][0];
    expect(body.items).toHaveLength(20);
    expect(body.items.every((i) => i.renewal_path.mode === "internal")).toBe(true);
    expect(await within(dialog).findByText("19 succeeded, 1 failed")).toBeInTheDocument();
    expect(within(dialog).getByText("already managed")).toBeInTheDocument();
  });

  it("prefills the owner when every suggestion agrees", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: makeCerts(2) },
      meta: { total: 2 },
    } as never);
    const s = (fp: string) => ({
      fingerprint: fp,
      owner_email: "ops@example.com",
      owner_team: "ops",
      service_name: "",
      source: "sibling_certificate",
      confidence: "medium",
    });
    vi.mocked(api.estateTakeoverSuggestions).mockResolvedValue([s("fp-0"), s("fp-1")] as never);
    const user = userEvent.setup();
    renderAt(<Discovery />);
    await screen.findByRole("checkbox", { name: "Select host0.example.com" });
    await user.click(screen.getAllByRole("button", { name: "Select all visible" })[0]);
    await user.click(screen.getByRole("button", { name: "Take over selected" }));
    const dialog = await screen.findByRole("dialog");
    await waitFor(() =>
      expect(within(dialog).getByLabelText("Takeover owner email")).toHaveValue("ops@example.com"),
    );
  });

  it("Take over selected is disabled with nothing selected", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: makeCerts(3) },
      meta: { total: 3 },
    } as never);
    renderAt(<Discovery />);
    expect(await screen.findByRole("button", { name: "Take over selected" })).toBeDisabled();
  });

  it("hides the panel from a viewer", async () => {
    asAdmin("pki-viewer");
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: makeCerts(3) },
      meta: { total: 3 },
    } as never);
    renderAt(<Discovery />);
    await screen.findByText("Scan jobs");
    await waitFor(() => expect(api.authzCheck).toHaveBeenCalled());
    expect(screen.queryByText("Discovered certificates")).not.toBeInTheDocument();
    expect(api.certificates).not.toHaveBeenCalled();
  });
});

describe("single takeover hand-off", () => {
  it("offers Set up target and navigates with host and cert", async () => {
    const cert = {
      fingerprint_sha256: "fp-1",
      common_name: "app.example.com",
      subject_alt_names: ["app.example.com"],
      origin: "imported",
      management_state: "unmanaged",
      issuer_cn: "Root CA",
      team_id: "team-1",
    };
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: [cert] },
      meta: { total: 1, limit: 50 },
    } as never);
    vi.mocked(api.estateTakeover).mockResolvedValue({
      data: { ...cert, management_state: "managed" },
    } as never);
    const user = userEvent.setup();
    renderAt(<Certificates />, "/certificates");

    await user.click(await screen.findByRole("button", { name: /^take over$/i }));
    const dialog = screen.getByRole("dialog", { name: /take certificate under management/i });
    await user.click(within(dialog).getByRole("button", { name: /^take over$/i }));
    await user.click(await within(dialog).findByRole("button", { name: "Set up target" }));

    const probe = await screen.findByTestId("probe");
    expect(probe.textContent).toContain("host=app.example.com");
    expect(probe.textContent).toContain("certificate=fp-1");
  });
});
