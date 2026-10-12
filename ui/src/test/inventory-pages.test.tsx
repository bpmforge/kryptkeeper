import {
  render,
  screen,
  waitFor,
  within,
  fireEvent,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";

vi.mock("../lib/api", () => ({
  api: {
    certificates: vi.fn(),
    authzCheck: vi.fn(),
    discoverySummary: vi.fn(),
    discoveryEndpoints: vi.fn(),
    discoveryScanJobs: vi.fn(),
    createDiscoveryScan: vi.fn(),
    cancelDiscoveryScanJob: vi.fn(),
    requeueDiscoveryScanJob: vi.fn(),
    notificationsSummary: vi.fn(),
    notificationDeliveries: vi.fn(),
    notificationRules: vi.fn(),
    testNotificationDelivery: vi.fn(),
    retryNotificationDelivery: vi.fn(),
    acknowledgeNotificationDelivery: vi.fn(),
    cas: vi.fn(),
    activateCa: vi.fn(),
    suspendCa: vi.fn(),
    updateCa: vi.fn(),
    createCa: vi.fn(),
    renewCertificate: vi.fn(),
    revokeCertificate: vi.fn(),
    importCertificate: vi.fn(),
    issueCertificate: vi.fn(),
    downloadCertificatePem: vi.fn(),
    bulkImportCertificates: vi.fn(),
    connectors: vi.fn(),
    estateTakeover: vi.fn(),
    templates: vi.fn(),
    createTemplate: vi.fn(),
    updateTemplate: vi.fn(),
    search: vi.fn(),
  },
}));

import Certificates from "../pages/Certificates";
import Discovery from "../pages/Discovery";
import Alerts from "../pages/Alerts";
import CAs from "../pages/CAs";
import Templates from "../pages/Templates";
import { api } from "../lib/api";
import { formatValidityPeriod } from "../lib/utils";

function renderWithQuery(ui: ReactElement, initialEntries?: string[]) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={initialEntries}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue({
    service: "kryptkeeper",
    authenticated: true,
    principal: "pki-admin",
    role: "pki-admin",
    scopes: ["*"],
  } as unknown as never);
  // Prevent React Query v5 "data cannot be undefined" errors for unconfigured calls.
  vi.mocked(api.cas).mockResolvedValue({
    data: { items: [] },
    meta: { total: 0 },
  } as unknown as never);
  vi.mocked(api.notificationRules).mockResolvedValue({
    data: { items: [] },
    meta: { total: 0 },
  } as unknown as never);
});

const certMock = {
  fingerprint_sha256: "fp-1",
  origin: "imported",
  management_state: "unmanaged",
  common_name: "api.example.com",
  issuer_cn: "Root CA",
  valid_until: "2026-05-01T00:00:00Z",
  grade: "A",
  renewal_status: "expiring soon",
  team_id: "team-1",
  ca_id: "ca-root",
  status: "active",
};

describe("Certificates page", () => {
  it("renders the estate badge and passes the management_state filter to the API (W11-08)", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: [certMock] },
      meta: { total: 1, limit: 50 },
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<Certificates />);

    // The row carries the estate badge for its management_state.
    await screen.findByRole("button", { name: "api.example.com" });
    expect(screen.getAllByText("unmanaged").length).toBeGreaterThan(0);

    await user.selectOptions(
      screen.getByRole("combobox", { name: /filter by management state/i }),
      "managed",
    );
    await user.click(screen.getByRole("button", { name: /apply filters/i }));
    await waitFor(() =>
      expect(api.certificates).toHaveBeenCalledWith(
        expect.objectContaining({ management_state: "managed" }),
      ),
    );
  });

  it("takes over an unmanaged cert with a connector renewal path (W11-06)", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: [certMock] },
      meta: { total: 1, limit: 50 },
    } as unknown as never);
    vi.mocked(api.connectors).mockResolvedValue({
      data: [
        {
          id: "conn-up",
          name: "Upstream LE",
          type: "acme",
          health: { status: "healthy" },
        },
      ],
    } as unknown as never);
    vi.mocked(api.estateTakeover).mockResolvedValue({
      data: { ...certMock, management_state: "managed" },
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<Certificates />);

    // The unmanaged cert's detail pane offers the takeover.
    await user.click(await screen.findByRole("button", { name: /take over/i }));
    const dialog = screen.getByRole("dialog", {
      name: /take certificate under management/i,
    });
    await user.type(
      within(dialog).getByLabelText(/takeover owner email/i),
      "owner@example.com",
    );
    await user.click(
      within(dialog).getByRole("radio", {
        name: /original ca via a connector/i,
      }),
    );
    await user.selectOptions(
      within(dialog).getByRole("combobox", { name: /takeover connector/i }),
      "conn-up",
    );
    await user.click(
      within(dialog).getByRole("button", { name: /^take over$/i }),
    );

    await waitFor(() =>
      expect(api.estateTakeover).toHaveBeenCalledWith(
        expect.objectContaining({
          fingerprint: "fp-1",
          renewal_path: { mode: "connector", connector_id: "conn-up" },
        }),
      ),
    );
    expect(await within(dialog).findByText(/now managed/i)).toBeInTheDocument();
  });

  it("deep-link ?takeover=1 auto-opens the takeover dialog (W11-06)", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: [certMock] },
      meta: { total: 1, limit: 50 },
    } as unknown as never);
    vi.mocked(api.connectors).mockResolvedValue({
      data: [],
    } as unknown as never);

    renderWithQuery(<Certificates />, ["/certificates?takeover=1"]);
    expect(
      await screen.findByRole("dialog", {
        name: /take certificate under management/i,
      }),
    ).toBeInTheDocument();
  });

  it("bulk-imports a pasted bundle and reports the counts (W11-08)", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: [certMock] },
      meta: { total: 1, limit: 50 },
    } as unknown as never);
    vi.mocked(api.bulkImportCertificates).mockResolvedValue({
      data: {
        imported: 2,
        skipped_duplicates: 1,
        failed: [{ index: 3, reason: "not a certificate" }],
        fingerprints: ["fp-a", "fp-b"],
      },
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<Certificates />);

    await user.click(
      await screen.findByRole("button", { name: /bulk import/i }),
    );
    await user.type(
      screen.getByLabelText(/bulk import bundle/i),
      "-----BEGIN CERTIFICATE-----",
    );
    const dialog = screen.getByRole("dialog", {
      name: /bulk import certificates/i,
    });
    await user.click(within(dialog).getByRole("button", { name: /^import$/i }));

    await waitFor(() =>
      expect(api.bulkImportCertificates).toHaveBeenCalledWith(
        expect.objectContaining({ format: "pem" }),
      ),
    );
    expect(
      await screen.findByText(/imported 2 · skipped 1 duplicates · 1 failed/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/#3: not a certificate/i)).toBeInTheDocument();
  });

  it("downloads the selected certificate's PEM from the download endpoint (S-69)", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: [certMock] },
      meta: { total: 1, limit: 50 },
    } as unknown as never);
    const pem =
      "-----BEGIN CERTIFICATE-----\nserver-provided-bytes\n-----END CERTIFICATE-----\n";
    vi.mocked(api.downloadCertificatePem).mockResolvedValue(
      pem as unknown as never,
    );

    const savedBlobs: Blob[] = [];
    const createObjectURL = vi
      .spyOn(URL, "createObjectURL")
      .mockImplementation((blob) => {
        savedBlobs.push(blob as Blob);
        return "blob:pem";
      });
    const revokeObjectURL = vi
      .spyOn(URL, "revokeObjectURL")
      .mockImplementation(() => undefined);

    const user = userEvent.setup();
    renderWithQuery(<Certificates />);

    await user.click(
      await screen.findByRole("button", { name: "api.example.com" }),
    );
    await user.click(
      await screen.findByRole("button", { name: "Download PEM" }),
    );

    await waitFor(() =>
      expect(api.downloadCertificatePem).toHaveBeenCalledWith("fp-1"),
    );
    await waitFor(() => expect(savedBlobs).toHaveLength(1));
    // Assert the saved bytes, not merely that a mock was called (S-59
    // lesson): this fails if the download is wired to an absent field.
    expect(await savedBlobs[0].text()).toBe(pem);

    createObjectURL.mockRestore();
    revokeObjectURL.mockRestore();
  });

  it("renders inventory rows, detail panel, and selection/export", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: [certMock] },
      meta: { total: 1, limit: 50 },
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<Certificates />);

    const createObjectURL = vi
      .spyOn(URL, "createObjectURL")
      .mockReturnValue("blob:certs");
    const revokeObjectURL = vi
      .spyOn(URL, "revokeObjectURL")
      .mockImplementation(() => undefined);

    expect(
      await screen.findByRole("button", { name: /api\.example\.com/i }),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/fp-1/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/certificate detail/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /^renew$/i }),
    ).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: /select all visible/i }),
    );
    expect(screen.getByText(/1 selected/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /export csv/i }));
    expect(createObjectURL).toHaveBeenCalled();
    expect(revokeObjectURL).toHaveBeenCalled();

    createObjectURL.mockRestore();
    revokeObjectURL.mockRestore();
  });

  it("renew dialog opens and submits to API", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: [certMock] },
      meta: { total: 1, limit: 50 },
    } as unknown as never);
    vi.mocked(api.renewCertificate).mockResolvedValue({
      data: { fingerprint_sha256: "fp-2" },
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<Certificates />);

    await screen.findByRole("button", { name: /api\.example\.com/i });
    await user.click(screen.getByRole("button", { name: /^renew$/i }));
    const renewDialog = screen.getByRole("dialog", {
      name: /renew certificate/i,
    });
    expect(renewDialog).toBeInTheDocument();
    await user.type(
      within(renewDialog).getByPlaceholderText(/certificate request/i),
      "MY-CSR",
    );
    fireEvent.submit(renewDialog.querySelector("form")!);
    await waitFor(() =>
      expect(api.renewCertificate).toHaveBeenCalledWith(
        "fp-1",
        expect.objectContaining({ csr_pem: "MY-CSR" }),
      ),
    );
  });

  // W8-05: the flat issue dialog (G-56/S-12) is gone -- "Issue certificate"
  // now navigates to the guided /certificates/issue wizard (IssueWizard.tsx)
  // instead of opening an in-page dialog. The wizard's own test file
  // (IssueWizard.test.tsx) carries the required-fields + csr_pem-not-subject
  // coverage this test used to own.
  it("Issue certificate navigates to the guided issuance wizard, not a dialog (W8-05)", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: [certMock] },
      meta: { total: 1, limit: 50 },
    } as unknown as never);

    const user = userEvent.setup();
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/certificates"]}>
          <Routes>
            <Route path="/certificates" element={<Certificates />} />
            <Route
              path="/certificates/issue"
              element={<div>issue-wizard-route</div>}
            />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await screen.findByRole("button", { name: /api\.example\.com/i });
    expect(screen.queryByText("issue-wizard-route")).not.toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: /^issue certificate$/i }),
    );

    expect(await screen.findByText("issue-wizard-route")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(api.issueCertificate).not.toHaveBeenCalled();
  });

  it("revoke dialog opens and submits to API", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: [certMock] },
      meta: { total: 1, limit: 50 },
    } as unknown as never);
    vi.mocked(api.revokeCertificate).mockResolvedValue({
      data: { fingerprint_sha256: "fp-1" },
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<Certificates />);

    await screen.findByRole("button", { name: /api\.example\.com/i });
    await user.click(screen.getByRole("button", { name: /^revoke$/i }));
    const revokeDialog = screen.getByRole("dialog", {
      name: /revoke certificate/i,
    });
    expect(revokeDialog).toBeInTheDocument();
    await user.selectOptions(within(revokeDialog).getByRole("combobox"), "1");
    await user.type(
      within(revokeDialog).getByPlaceholderText(/optional explanation/i),
      "compromised",
    );
    fireEvent.submit(revokeDialog.querySelector("form")!);
    await waitFor(() =>
      expect(api.revokeCertificate).toHaveBeenCalledWith(
        "fp-1",
        expect.objectContaining({ reason_code: 1, reason_text: "compromised" }),
      ),
    );
  });

  it("renders DNS SANs from the wire field subject_alt_names (W2-05/G-10 regression)", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: {
        items: [
          {
            ...certMock,
            subject_alt_names: [
              "api-alt-1.example.com",
              "api-alt-2.example.com",
            ],
          },
        ],
      },
      meta: { total: 1, limit: 50 },
    } as unknown as never);

    renderWithQuery(<Certificates />);

    await screen.findByRole("button", { name: /api\.example\.com/i });
    expect(screen.getByText(/^sans$/i)).toBeInTheDocument();
    expect(screen.getByText("api-alt-1.example.com")).toBeInTheDocument();
    expect(screen.getByText("api-alt-2.example.com")).toBeInTheDocument();
  });

  it("keeps filter controls visible for inventory narrowing", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: [] },
      meta: { total: 0, limit: 50 },
    } as unknown as never);
    renderWithQuery(<Certificates />);

    expect((await screen.findAllByText(/filters/i)).length).toBeGreaterThan(0);
    expect(
      screen.getByPlaceholderText(/cn, issuer, fingerprint/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /apply filters/i }),
    ).toBeInTheDocument();
  });
});

describe("Discovery page", () => {
  it("renders summary cards, endpoint table, and scan jobs", async () => {
    vi.mocked(api.discoverySummary).mockResolvedValue({
      data: {
        discovered_endpoints: 12,
        mapped_certificates: 8,
        risky_endpoints: 3,
        active_scan_jobs: 1,
      },
    } as unknown as never);
    vi.mocked(api.discoveryEndpoints).mockResolvedValue({
      data: {
        endpoints: [
          {
            id: "ep-1",
            hostname: "host1.example.com",
            ip_address: "10.0.0.1",
            port: 443,
            protocol: "tls",
            risk_score: 85,
            last_seen_at: "2026-04-11T00:00:00Z",
          },
        ],
      },
    } as unknown as never);
    vi.mocked(api.discoveryScanJobs).mockResolvedValue({
      data: {
        scan_jobs: [
          {
            id: "job-1",
            type: "network",
            connector: "scanner",
            status: "queued",
            scope: { cidr: "10.0.0.0/24" },
          },
        ],
      },
    } as unknown as never);
    vi.mocked(api.createDiscoveryScan).mockResolvedValue({
      data: { scan_job: { id: "job-2" } },
    } as unknown as never);
    vi.mocked(api.cancelDiscoveryScanJob).mockResolvedValue({
      data: { scan_job_id: "job-1" },
    } as unknown as never);
    vi.mocked(api.requeueDiscoveryScanJob).mockResolvedValue({
      data: { scan_job_id: "job-2" },
    } as unknown as never);
    vi.mocked(api.search).mockResolvedValue({
      data: [],
    } as unknown as never);

    const user = userEvent.setup();

    renderWithQuery(<Discovery />);

    expect(await screen.findByText(/discovered/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /host1\.example\.com/i }),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/scan jobs/i).length).toBeGreaterThan(0);
    expect(api.discoveryScanJobs).toHaveBeenCalled();

    // Click the "Queue scan" button in the detail panel (first occurrence).
    await user.click(screen.getAllByRole("button", { name: /queue scan/i })[0]);
    expect(
      screen.getByRole("dialog", { name: /queue discovery scan/i }),
    ).toBeInTheDocument();
    await user.clear(screen.getByPlaceholderText(/10\.0\.0\.0\/24 or host/i));
    await user.type(
      screen.getByPlaceholderText(/10\.0\.0\.0\/24 or host/i),
      "10.0.0.0/24",
    );
    // Click the submit button inside the dialog.
    const dialog = screen.getByRole("dialog", {
      name: /queue discovery scan/i,
    });
    await user.click(
      within(dialog).getByRole("button", { name: /queue scan/i }),
    );
    await waitFor(() =>
      expect(api.createDiscoveryScan).toHaveBeenCalledWith(
        expect.objectContaining({ scan_type: "full", target: "10.0.0.0/24" }),
      ),
    );

    await user.click(screen.getByRole("button", { name: /^requeue$/i }));
    expect(
      screen.getByRole("dialog", { name: /requeue scan job/i }),
    ).toBeInTheDocument();
    await user.type(
      screen.getByPlaceholderText(/optional context/i),
      "retry after fix",
    );
    await user.click(screen.getByRole("button", { name: /confirm/i }));
    await waitFor(() =>
      expect(api.requeueDiscoveryScanJob).toHaveBeenCalledWith(
        expect.objectContaining({
          scan_job_id: "job-1",
          reason: "retry after fix",
        }),
      ),
    );

    await user.click(screen.getByRole("button", { name: /^cancel$/i }));
    expect(
      screen.getByRole("dialog", { name: /cancel scan job/i }),
    ).toBeInTheDocument();
    await user.type(screen.getByPlaceholderText(/optional context/i), "stale");
    await user.click(screen.getByRole("button", { name: /confirm/i }));
    await waitFor(() =>
      expect(api.cancelDiscoveryScanJob).toHaveBeenCalledWith(
        expect.objectContaining({ scan_job_id: "job-1", reason: "stale" }),
      ),
    );
  });

  it("supports selecting multiple scan jobs and firing a bulk action, including a partial-failure case (W8-11)", async () => {
    vi.mocked(api.discoverySummary).mockResolvedValue({
      data: {
        discovered_endpoints: 0,
        mapped_certificates: 0,
        risky_endpoints: 0,
        active_scan_jobs: 2,
      },
    } as unknown as never);
    vi.mocked(api.discoveryEndpoints).mockResolvedValue({
      data: { endpoints: [] },
    } as unknown as never);
    vi.mocked(api.discoveryScanJobs).mockResolvedValue({
      data: {
        scan_jobs: [
          {
            id: "job-1",
            scan_type: "full",
            target: "10.0.0.1",
            status: "queued",
          },
          {
            id: "job-2",
            scan_type: "full",
            target: "10.0.0.2",
            status: "queued",
          },
        ],
      },
    } as unknown as never);
    vi.mocked(api.cancelDiscoveryScanJob)
      .mockResolvedValueOnce({
        data: { scan_job_id: "job-1" },
      } as unknown as never)
      .mockRejectedValueOnce(new Error("cannot cancel"));

    const user = userEvent.setup();
    renderWithQuery(<Discovery />);

    const checkboxes = await screen.findAllByRole("checkbox", {
      name: /select scan job/i,
    });
    expect(checkboxes).toHaveLength(2);
    await user.click(checkboxes[0]);
    await user.click(checkboxes[1]);
    expect(screen.getByText(/2 selected/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /bulk cancel/i }));
    const dialog = screen.getByRole("dialog", {
      name: /bulk cancel 2 scan jobs/i,
    });
    await user.click(
      within(dialog).getByRole("button", { name: /^cancel 2$/i }),
    );

    await waitFor(() =>
      expect(api.cancelDiscoveryScanJob).toHaveBeenCalledTimes(2),
    );
    expect(api.cancelDiscoveryScanJob).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ scan_job_id: "job-1" }),
    );
    expect(api.cancelDiscoveryScanJob).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ scan_job_id: "job-2" }),
    );

    await waitFor(() =>
      expect(screen.getByText(/1 cancellations failed/i)).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/1 of 2 cancelled successfully/i),
    ).toBeInTheDocument();
  });
});

describe("Alerts page", () => {
  it("renders summary, delivery queue, and action controls", async () => {
    vi.mocked(api.notificationsSummary).mockResolvedValue({
      data: {
        pending_notifications: 5,
        ownership_escalations: 2,
        delivery_failures_24h: 1,
      },
    } as unknown as never);
    vi.mocked(api.notificationDeliveries).mockResolvedValue({
      data: {
        deliveries: [
          {
            id: "del-1",
            channel: "email",
            target: "ops@example.com",
            status: "queued",
            queued_at: "2026-04-11T00:00:00Z",
          },
          {
            id: "del-2",
            channel: "slack",
            target: "#ops",
            status: "failed",
            queued_at: "2026-04-11T01:00:00Z",
          },
        ],
      },
    } as unknown as never);
    vi.mocked(api.testNotificationDelivery).mockResolvedValue({
      data: { delivery: { id: "test-1" } },
    } as unknown as never);
    vi.mocked(api.retryNotificationDelivery).mockResolvedValue({
      data: { retry_job_id: "retry-1" },
    } as unknown as never);
    vi.mocked(api.acknowledgeNotificationDelivery).mockResolvedValue({
      data: { delivery_id: "del-1" },
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<Alerts />);

    expect(
      await screen.findByText(/alerts & notifications/i),
    ).toBeInTheDocument();
    await waitFor(() => expect(api.notificationDeliveries).toHaveBeenCalled());
    expect(
      screen.getByRole("button", { name: /send test delivery/i }),
    ).toBeInTheDocument();

    await user.type(
      screen.getByPlaceholderText(/user@example\.com/i),
      "ops@example.com",
    );
    await user.click(
      screen.getByRole("button", { name: /send test delivery/i }),
    );
    await waitFor(() =>
      expect(api.testNotificationDelivery).toHaveBeenCalledWith(
        expect.objectContaining({
          channel: "email",
          target: "ops@example.com",
        }),
      ),
    );

    await user.click(screen.getAllByRole("button", { name: /retry/i })[0]);
    expect(
      screen.getByRole("dialog", { name: /retry delivery/i }),
    ).toBeInTheDocument();
    await user.type(
      screen.getByPlaceholderText(/optional context/i),
      "retry later",
    );
    await user.click(screen.getByRole("button", { name: /confirm/i }));
    await waitFor(() =>
      expect(api.retryNotificationDelivery).toHaveBeenCalledWith(
        expect.objectContaining({
          delivery_id: "del-1",
          reason: "retry later",
        }),
      ),
    );

    await user.click(screen.getAllByRole("button", { name: /ack/i })[0]);
    expect(
      screen.getByRole("dialog", { name: /acknowledge delivery/i }),
    ).toBeInTheDocument();
    await user.type(screen.getByPlaceholderText(/optional context/i), "seen");
    await user.click(screen.getByRole("button", { name: /confirm/i }));
    await waitFor(() =>
      expect(api.acknowledgeNotificationDelivery).toHaveBeenCalledWith(
        expect.objectContaining({ delivery_id: "del-1", note: "seen" }),
      ),
    );
  });
});

describe("CAs page", () => {
  it("renders CA inventory and selected detail state", async () => {
    vi.mocked(api.cas).mockResolvedValue({
      data: {
        items: [
          {
            id: "ca-root",
            display_name: "Root CA",
            type: "root",
            key_storage_type: "pkcs11",
            status: "suspended",
            active_issued_certificates: 8,
          },
        ],
      },
    } as unknown as never);
    vi.mocked(api.activateCa).mockResolvedValue({
      data: {
        id: "ca-root",
        status: "active",
        updated_at: "2026-04-11T00:00:00Z",
      },
    } as unknown as never);
    vi.mocked(api.updateCa).mockResolvedValue({
      data: { id: "ca-root", display_name: "Root CA 2" },
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<CAs />);

    expect(
      await screen.findByRole("button", { name: /root ca/i }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /root ca/i }));
    expect(screen.getByText(/issued/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^activate$/i })).toBeEnabled();

    await user.click(screen.getByRole("button", { name: /^activate$/i }));
    expect(
      screen.getByRole("dialog", { name: /activate ca/i }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /confirm activate/i }));
    await waitFor(() => expect(api.activateCa).toHaveBeenCalledWith("ca-root"));

    await user.click(screen.getByRole("button", { name: /^update$/i }));
    expect(
      screen.getByRole("dialog", { name: /update ca metadata/i }),
    ).toBeInTheDocument();
    await user.clear(screen.getByLabelText(/display name/i));
    await user.type(screen.getByLabelText(/display name/i), "Root CA 2");
    await user.click(screen.getByRole("button", { name: /save changes/i }));
    await waitFor(() =>
      expect(api.updateCa).toHaveBeenCalledWith(
        "ca-root",
        expect.objectContaining({ display_name: "Root CA 2" }),
      ),
    );
  });
});

describe("W8-10 empty-state CTAs", () => {
  it("CAs list empty state offers 'Create your first CA' and opens the create dialog", async () => {
    vi.mocked(api.cas).mockResolvedValue({
      data: { items: [] },
      meta: { total: 0 },
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<CAs />);

    const cta = await screen.findByRole("button", {
      name: /create your first ca/i,
    });
    await user.click(cta);
    expect(
      screen.getByRole("dialog", { name: /new certificate authority/i }),
    ).toBeInTheDocument();
  });

  it("CAs list empty state offers 'Reset filters' instead of create when filters narrow to zero results", async () => {
    vi.mocked(api.cas).mockResolvedValue({
      data: { items: [] },
      meta: { total: 0 },
    } as unknown as never);

    renderWithQuery(<CAs />, ["/cas?status=suspended"]);

    expect(
      await screen.findByRole("button", { name: /reset filters/i }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /create your first ca/i }),
    ).not.toBeInTheDocument();
  });

  // Originally asserted this CTA opened an issue dialog. W8-05 replaced that
  // dialog with the guided wizard at /certificates/issue, so the CTA navigates
  // now — same destination as the header button above. The two tickets were
  // developed in parallel and only collided once both merged.
  it("Certificates empty state offers 'Issue your first certificate' and navigates to the wizard", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: [] },
      meta: { total: 0, limit: 50 },
    } as unknown as never);

    const user = userEvent.setup();
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/certificates"]}>
          <Routes>
            <Route path="/certificates" element={<Certificates />} />
            <Route
              path="/certificates/issue"
              element={<div>issue-wizard-route</div>}
            />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    const cta = await screen.findByRole("button", {
      name: /issue your first certificate/i,
    });
    expect(screen.queryByText("issue-wizard-route")).not.toBeInTheDocument();
    await user.click(cta);

    expect(await screen.findByText("issue-wizard-route")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("Certificates empty state offers 'Reset filters' instead of issue when a filter is active", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: { items: [] },
      meta: { total: 0, limit: 50 },
    } as unknown as never);

    renderWithQuery(<Certificates />, ["/certificates?q=nomatch"]);

    expect(
      await screen.findByRole("button", { name: /reset filters/i }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /issue your first certificate/i }),
    ).not.toBeInTheDocument();
  });

  it("Templates renders ISO-8601 and shorthand validity periods in one format (S-71)", async () => {
    vi.mocked(api.templates).mockResolvedValue({
      data: {
        items: [
          {
            id: "tpl-iso",
            name: "drill-template",
            validity_period: "P90D",
            extended_key_usage: ["serverAuth"],
            active: true,
          },
          {
            id: "tpl-short",
            name: "proof",
            validity_period: "90d",
            extended_key_usage: ["serverAuth"],
            active: true,
          },
        ],
      },
      meta: { total: 2 },
    } as unknown as never);

    renderWithQuery(<Templates />);

    await screen.findByText("drill-template");
    // Both rows render "90d"; the raw ISO form never reaches the user.
    expect(screen.getAllByText("90d")).toHaveLength(2);
    expect(screen.queryByText("P90D")).not.toBeInTheDocument();
  });

  it("formatValidityPeriod normalizes ISO durations and passes through everything else (S-71)", () => {
    expect(formatValidityPeriod("P90D")).toBe("90d");
    expect(formatValidityPeriod("p90d")).toBe("90d");
    expect(formatValidityPeriod("P1Y")).toBe("1y");
    expect(formatValidityPeriod("P1Y6M")).toBe("1y 6mo");
    expect(formatValidityPeriod("P2W")).toBe("2w");
    expect(formatValidityPeriod("90d")).toBe("90d");
    expect(formatValidityPeriod("1y")).toBe("1y");
    expect(formatValidityPeriod("P")).toBe("P");
    expect(formatValidityPeriod("")).toBe("—");
    expect(formatValidityPeriod(undefined)).toBe("—");
  });

  it("editing a template keeps its OID and saves who it is issued to (W20-17)", async () => {
    vi.mocked(api.templates).mockResolvedValue({
      data: {
        items: [
          {
            id: "tpl-win",
            name: "KKWin",
            display_name: "KK Windows",
            oid: "1.3.6.1.4.1.311.21.8.1.2",
            min_key_size: 3072,
            validity_period: "8760h",
            key_usage: ["digitalSignature"],
            extended_key_usage: ["clientAuth"],
            allowed_algorithms: ["RSA"],
            auto_enroll: true,
            enrollee_type: "machine",
            active: true,
          },
        ],
      },
      meta: { total: 1 },
    } as unknown as never);
    vi.mocked(api.updateTemplate).mockResolvedValue({
      data: {},
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<Templates />);
    await user.click(await screen.findByText("KK Windows"));
    expect(await screen.findByText("Machines")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^edit$/i }));
    const dialog = screen.getByRole("dialog");
    await user.selectOptions(
      within(dialog).getByRole("combobox", { name: /issued to/i }),
      "user",
    );
    await user.click(
      within(dialog).getByRole("button", { name: /save changes/i }),
    );

    expect(api.updateTemplate).toHaveBeenCalledWith(
      "tpl-win",
      expect.objectContaining({
        oid: "1.3.6.1.4.1.311.21.8.1.2",
        min_key_size: 3072,
        enrollee_type: "user",
      }),
    );
  });

  it("template editor saves an SSH policy and loads an existing one (A01S-4)", async () => {
    vi.mocked(api.templates).mockResolvedValue({
      data: {
        items: [
          {
            id: "tpl-ssh",
            name: "ssh-ops",
            display_name: "SSH Ops",
            validity_period: "P1D",
            key_usage: ["digitalSignature"],
            extended_key_usage: ["clientAuth"],
            allowed_algorithms: ["ECDSA"],
            auto_enroll: false,
            active: true,
            ssh_policy: {
              cert_types: ["user"],
              allowed_principals: ["deploy"],
              max_ttl_hours: 4,
            },
          },
          {
            id: "tpl-plain",
            name: "plain",
            display_name: "Plain",
            validity_period: "P90D",
            key_usage: ["digitalSignature"],
            extended_key_usage: ["serverAuth"],
            allowed_algorithms: ["ECDSA"],
            auto_enroll: false,
            active: true,
          },
        ],
      },
      meta: { total: 2 },
    } as unknown as never);
    vi.mocked(api.updateTemplate).mockResolvedValue({
      data: {},
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<Templates />);

    // Existing policy is summarised, loaded into the editor, and re-sent on save.
    await user.click(await screen.findByText("SSH Ops"));
    expect(await screen.findByText("user, max 4h")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^edit$/i }));
    let dialog = screen.getByRole("dialog");
    const principals = within(dialog).getByPlaceholderText("deploy,ops");
    expect(principals).toHaveValue("deploy");
    await user.clear(principals);
    await user.type(principals, "deploy, ops");
    await user.click(
      within(dialog).getByRole("button", { name: /save changes/i }),
    );
    expect(api.updateTemplate).toHaveBeenCalledWith(
      "tpl-ssh",
      expect.objectContaining({
        ssh_policy: {
          cert_types: ["user"],
          allowed_principals: ["deploy", "ops"],
          max_ttl_hours: 4,
        },
      }),
    );

    // A template without one sends none until the section is switched on.
    await user.click(await screen.findByText("Plain"));
    expect(await screen.findByText("Not enabled")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^edit$/i }));
    dialog = screen.getByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", { name: /save changes/i }),
    );
    expect(vi.mocked(api.updateTemplate).mock.calls.at(-1)?.[1]).toEqual(
      expect.objectContaining({ ssh_policy: undefined }),
    );
  });

  it("new templates can enable SSH host certificates with host patterns (A01S-4)", async () => {
    vi.mocked(api.templates).mockResolvedValue({
      data: { items: [] },
      meta: { total: 0 },
    } as unknown as never);
    vi.mocked(api.createTemplate).mockResolvedValue({
      data: {},
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<Templates />);
    await user.click(
      await screen.findByRole("button", {
        name: /create your first template/i,
      }),
    );
    const dialog = screen.getByRole("dialog", { name: /new template/i });
    await user.type(
      within(dialog).getByPlaceholderText("tpl-tls"),
      "ssh-hosts",
    );
    await user.click(
      within(dialog).getByRole("checkbox", { name: /allow ssh certificates/i }),
    );
    await user.click(
      within(dialog).getByRole("checkbox", { name: /user certificates/i }),
    );
    await user.click(
      within(dialog).getByRole("checkbox", { name: /host certificates/i }),
    );
    await user.type(
      within(dialog).getByPlaceholderText(/\*\.corp\.example/),
      "*.corp.example",
    );
    await user.click(within(dialog).getByRole("button", { name: /^create$/i }));

    expect(api.createTemplate).toHaveBeenCalledWith(
      expect.objectContaining({
        ssh_policy: {
          cert_types: ["host"],
          host_patterns: ["*.corp.example"],
          max_ttl_hours: 8,
        },
      }),
    );
  });

  it("new templates can restrict issued names with a name policy (SUP-A04-3)", async () => {
    vi.mocked(api.templates).mockResolvedValue({
      data: { items: [] },
      meta: { total: 0 },
    } as unknown as never);
    vi.mocked(api.createTemplate).mockResolvedValue({
      data: {},
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<Templates />);
    await user.click(
      await screen.findByRole("button", {
        name: /create your first template/i,
      }),
    );
    const dialog = screen.getByRole("dialog", { name: /new template/i });
    await user.type(within(dialog).getByPlaceholderText("tpl-tls"), "internal");
    await user.click(
      within(dialog).getByRole("checkbox", { name: /restrict the names/i }),
    );
    await user.type(
      within(dialog).getByPlaceholderText(".corp.example,example.com"),
      ".corp.example",
    );
    await user.click(
      within(dialog).getByRole("checkbox", { name: /cn must be a san/i }),
    );
    await user.click(within(dialog).getByRole("button", { name: /^create$/i }));

    expect(api.createTemplate).toHaveBeenCalledWith(
      expect.objectContaining({
        name_policy: {
          allowed_dns_suffixes: [".corp.example"],
          allowed_dns_names: [],
          allow_ip_sans: false,
          allow_uri_sans: false,
          cn_must_be_san: true,
        },
      }),
    );
  });

  it("Templates empty state offers 'Create your first template' and opens the create dialog", async () => {
    vi.mocked(api.templates).mockResolvedValue({
      data: { items: [] },
      meta: { total: 0 },
    } as unknown as never);

    const user = userEvent.setup();
    renderWithQuery(<Templates />);

    const cta = await screen.findByRole("button", {
      name: /create your first template/i,
    });
    await user.click(cta);
    expect(
      screen.getByRole("dialog", { name: /new template/i }),
    ).toBeInTheDocument();
  });
});

describe("S-49 CA row accessible names and empty-state copy", () => {
  it("CA list row exposes a readable accessible name instead of run-together text (I-4)", async () => {
    vi.mocked(api.cas).mockResolvedValue({
      data: {
        items: [
          {
            id: "ca-1",
            display_name: "acme-root",
            type: "root",
            key_storage_type: "software",
            status: "active",
          },
        ],
      },
      meta: { total: 1 },
    } as unknown as never);

    renderWithQuery(<CAs />);

    expect(
      await screen.findByRole("button", {
        name: "acme-root, root CA, software storage, active",
      }),
    ).toBeInTheDocument();
    // The pre-fix accessible name concatenated with no separators.
    expect(
      screen.queryByRole("button", { name: /rootroot/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /softwareactive/i }),
    ).not.toBeInTheDocument();
  });

  it("does not tell a read-only viewer to create a CA they cannot create", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({
      service: "kryptkeeper",
      authenticated: true,
      principal: "auditor",
      role: "pki-auditor",
      scopes: [],
    } as unknown as never);
    vi.mocked(api.cas).mockResolvedValue({
      data: { items: [] },
      meta: { total: 0 },
    } as unknown as never);

    renderWithQuery(<CAs />);

    expect(
      await screen.findByText(/ask an administrator to create a root ca/i),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/create a root ca to establish/i),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /create your first ca/i }),
    ).not.toBeInTheDocument();
  });
});
