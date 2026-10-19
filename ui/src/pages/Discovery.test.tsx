import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { formatDateTime } from "../components/ui";
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
      discoverySchedules: vi.fn(),
      updateDiscoverySchedule: vi.fn(),
      createAuthorizedIssuer: vi.fn(),
    },
  };
});

import Discovery from "./Discovery";
import { api } from "../lib/api";

const A = {
  key: "env:10.0.0.0/24",
  scan_type: "targeted",
  target: "10.0.0.0/24",
  name: "lan-sweep",
  source: "env",
  interval_seconds: null,
  effective_interval_seconds: 43200,
  last_run: "2026-10-15T08:00:00Z",
  next_run: "2026-10-15T20:00:00Z",
  running: false,
};
const B = {
  key: "managed:t-win-1",
  scan_type: "winrm",
  target: "t-win-1",
  name: "win-box",
  source: "managed",
  interval_seconds: 3600,
  effective_interval_seconds: 3600,
  last_run: "2026-10-15T08:30:00Z",
  next_run: "2026-10-15T09:00:00Z",
  running: true,
  running_job_id: "scan-9",
};

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
  vi.mocked(api.targets).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.discoverySchedules).mockResolvedValue({
    data: [A, B],
  } as never);
  vi.mocked(api.updateDiscoverySchedule).mockResolvedValue({
    data: A,
  } as never);
});

describe("discovery — scan schedules", () => {
  it("shows last run and next run per target", async () => {
    renderPage();
    expect(await screen.findByText(/lan-sweep/)).toBeInTheDocument();
    expect(screen.getByText(/win-box/)).toBeInTheDocument();
    for (const iso of [
      A.last_run,
      A.next_run,
      B.last_run,
      B.next_run,
    ]) {
      expect(
        screen.getAllByText(formatDateTime(iso)).length,
      ).toBeGreaterThan(0);
    }
  });

  it("sets a per-target interval", async () => {
    const user = userEvent.setup();
    renderPage();
    const input = await screen.findByLabelText(`Interval (minutes) for ${A.key}`);
    await user.type(input, "30");
    const before = vi.mocked(api.discoverySchedules).mock.calls.length;
    await user.click(
      screen.getByRole("button", { name: `Save interval for ${A.key}` }),
    );
    await waitFor(() =>
      expect(api.updateDiscoverySchedule).toHaveBeenCalledWith({
        key: A.key,
        interval_seconds: 1800,
      }),
    );
    await waitFor(() =>
      expect(vi.mocked(api.discoverySchedules).mock.calls.length).toBeGreaterThan(before),
    );
  });

  it("clears a per-target interval", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole("button", {
        name: `Clear interval for ${B.key}`,
      }),
    );
    await waitFor(() =>
      expect(api.updateDiscoverySchedule).toHaveBeenCalledWith({
        key: B.key,
        interval_seconds: null,
      }),
    );
  });

  it("running target shows running state and keeps its next run", async () => {
    renderPage();
    const row = (await screen.findByText(/win-box/)).closest("tr")!;
    expect(within(row).getByText("running")).toBeInTheDocument();
    expect(
      within(row).getByText(formatDateTime(B.next_run)),
    ).toBeInTheDocument();
  });

  it("read-only role cannot edit", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({
      role: "viewer",
      scopes: [],
    } as never);
    renderPage();
    await screen.findByText(/lan-sweep/);
    expect(
      screen.queryByRole("button", { name: /Save interval for/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Clear interval for/ }),
    ).not.toBeInTheDocument();
  });
});

describe("discovery — ssh scan type (W24-10)", () => {
  const base = {
    renewal_method: "manual",
    tenant: "default",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  };
  beforeEach(() => {
    vi.mocked(api.targets).mockResolvedValue({
      data: [
        { ...base, id: "t-ssh-1", name: "ssh-box", host: "10.0.0.7", discovery_mode: "network", install_mode: "ssh" },
        { ...base, id: "t-win-1", name: "win-box", host: "10.0.0.5", discovery_mode: "winrm", install_mode: "iis" },
        { ...base, id: "t-agent-1", name: "agent-box", host: "10.0.0.8", discovery_mode: "none", install_mode: "agent" },
      ],
    } as never);
  });

  async function openSshDialog(user: ReturnType<typeof userEvent.setup>) {
    renderPage();
    await user.click(await screen.findByRole("button", { name: /new scan/i }));
    const dialog = await screen.findByRole("dialog", { name: /scan/i });
    await user.selectOptions(within(dialog).getByLabelText(/^scan type/i), "ssh");
  }

  it("offers the ssh scan type with ssh-mode targets only", async () => {
    const user = userEvent.setup();
    await openSshDialog(user);
    const select = await screen.findByLabelText("Managed target");
    await waitFor(() =>
      expect(within(select).getByText(/ssh-box/)).toBeInTheDocument(),
    );
    expect(within(select).queryByText(/win-box/)).not.toBeInTheDocument();
    expect(within(select).queryByText(/agent-box/)).not.toBeInTheDocument();
  });

  it("posts scan_type ssh with the managed target id", async () => {
    const user = userEvent.setup();
    await openSshDialog(user);
    const select = await screen.findByLabelText("Managed target");
    await waitFor(() =>
      expect(within(select).getByText(/ssh-box/)).toBeInTheDocument(),
    );
    await user.selectOptions(select, "t-ssh-1");
    await user.click(screen.getByRole("button", { name: /queue scan/i }));
    await waitFor(() =>
      expect(api.createDiscoveryScan).toHaveBeenCalledWith({
        scan_type: "ssh",
        target: "t-ssh-1",
      }),
    );
  });

  it("sends a one-off sudo password only when one is typed (W34-17)", async () => {
    const user = userEvent.setup();
    await openSshDialog(user);
    const select = await screen.findByLabelText("Managed target");
    await waitFor(() => expect(within(select).getByText(/ssh-box/)).toBeInTheDocument());
    await user.selectOptions(select, "t-ssh-1");
    await user.type(screen.getByLabelText(/run with sudo password/i), "pw-once");
    await user.click(screen.getByRole("button", { name: /queue scan/i }));
    await waitFor(() =>
      expect(api.createDiscoveryScan).toHaveBeenCalledWith({
        scan_type: "ssh",
        target: "t-ssh-1",
        jit_sudo_password: "pw-once",
      }),
    );
  });
});

describe("discovery — inventory class and authorized issuers (W34-06)", () => {
  const unknownEp = {
    id: "ep-1",
    hostname: "legacy.corp.test",
    port: 443,
    protocol: "tls",
    risk_score: 10,
    inventory_class: "unknown_issuer",
    mapped_certs: [
      {
        fingerprint: "ffeeddccbbaa99887766",
        common_name: "legacy.corp.test",
        risk_score: 10,
        trust_class: "private_other",
        issuer_class: "private_unknown",
        inventory_class: "unknown_issuer",
        issuer_dn: "CN=Corp Legacy CA,O=Corp",
      },
    ],
  };

  beforeEach(() => {
    vi.mocked(api.discoverySummary).mockResolvedValue({
      data: {
        discovered_endpoints: 1,
        inventory_classes: {
          managed: 0,
          ours_unmanaged: 0,
          authorized_external: 0,
          unknown_issuer: 1,
          self_signed: 0,
        },
      },
    } as never);
    vi.mocked(api.discoveryEndpoints).mockResolvedValue({
      data: { endpoints: [unknownEp] },
      meta: { total: 1 },
    } as never);
    vi.mocked(api.createAuthorizedIssuer).mockResolvedValue({
      data: { id: "ai-1" },
    } as never);
  });

  it("shows the class, its summary count and filters by it", async () => {
    const user = userEvent.setup();
    renderPage();
    expect((await screen.findAllByText("Unknown issuer")).length).toBeGreaterThan(0);
    const counts = await screen.findByRole("list", { name: "Certificates by issuer class" });
    expect(within(counts).getByText("Unknown issuer").parentElement).toHaveTextContent("1");
    await user.selectOptions(
      screen.getByLabelText("Filter by inventory class"),
      "authorized_external",
    );
    await waitFor(() =>
      expect(api.discoveryEndpoints).toHaveBeenLastCalledWith(
        expect.objectContaining({ inventory_class: "authorized_external" }),
      ),
    );
  });

  it("authorizes the observed issuer and re-classifies the page at once", async () => {
    const user = userEvent.setup();
    // Like the hub: once the rule exists, the refetch returns the new class.
    let authorized = false;
    vi.mocked(api.createAuthorizedIssuer).mockImplementation(async () => {
      authorized = true;
      return { data: { id: "ai-1" } } as never;
    });
    vi.mocked(api.discoveryEndpoints).mockImplementation(async () => {
      const mc = authorized
        ? { ...unknownEp.mapped_certs[0], issuer_class: "authorized", inventory_class: "authorized_external" }
        : unknownEp.mapped_certs[0];
      return {
        data: { endpoints: [{ ...unknownEp, inventory_class: mc.inventory_class, mapped_certs: [mc] }] },
        meta: { total: 1 },
      } as never;
    });
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: /Authorize this issuer for legacy.corp.test/ }),
    );
    await waitFor(() =>
      expect(api.createAuthorizedIssuer).toHaveBeenCalledWith({
        name: "Corp Legacy CA",
        kind: "issuer_dn",
        value: "CN=Corp Legacy CA,O=Corp",
      }),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: /Authorize this issuer/ }),
      ).not.toBeInTheDocument(),
    );
    expect((await screen.findAllByText(/Authorized external CA/)).length).toBeGreaterThan(0);
  });

  it("offers no authorize action to a read-only role", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({ role: "viewer", scopes: [] } as never);
    renderPage();
    await screen.findAllByText("Unknown issuer");
    expect(
      screen.queryByRole("button", { name: /Authorize this issuer/ }),
    ).not.toBeInTheDocument();
  });
});
