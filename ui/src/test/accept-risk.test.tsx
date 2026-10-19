import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, within, waitFor, fireEvent } from "@testing-library/react";
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
      targets: vi.fn(),
      cryptoPosture: vi.fn(),
      cryptoPostureTrend: vi.fn(),
    },
  };
});
// exceptionsApi imports the mocked fetchJSON, so it is mocked alongside api.
vi.mock("../lib/exceptionsApi", async (importOriginal) => {
  const mod = (await importOriginal()) as Record<string, unknown>;
  return { ...mod, proposeException: vi.fn(), listExceptions: vi.fn() };
});

import Discovery from "../pages/Discovery";
import CryptoPosture from "../pages/CryptoPosture";
import { api } from "../lib/api";
import { proposeException, listExceptions } from "../lib/exceptionsApi";

function renderPage(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const FP = "ab".repeat(32);

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue({ role: "pki-admin", scopes: [] } as never);
  vi.mocked(listExceptions).mockResolvedValue({ data: [] });
  vi.mocked(api.discoverySummary).mockResolvedValue({
    data: { discovered_endpoints: 1, risky_endpoints: 1, findings: { raw: 7, deduped: 5, in_scope: 5, effective: 5, suppressed: 0 } },
  } as never);
  vi.mocked(api.discoveryEndpoints).mockResolvedValue({
    data: {
      endpoints: [
        {
          id: "ep-1",
          hostname: "weak.lab",
          port: 443,
          protocol: "https",
          risk_score: 60,
          risky: true,
          issues: ["TLS10_ONLY: server offers TLS 1.0"],
          mapped_certs: [{ fingerprint: FP, risk_score: 60, risk_flags: ["EXPIRED"] }],
        },
      ],
    },
    meta: { total: 1 },
  } as never);
  vi.mocked(api.discoveryScanJobs).mockResolvedValue({ data: { scan_jobs: [] }, meta: { total: 0 } } as never);
  vi.mocked(api.targets).mockResolvedValue({ data: [] } as never);
});

async function openDialogFromIssue() {
  renderPage(<Discovery />);
  await userEvent.click(await screen.findByRole("button", { name: "weak.lab" }));
  const list = await screen.findByTestId("endpoint-findings");
  await userEvent.click(within(list).getByRole("button", { name: "Accept risk" }));
  return screen.findByRole("dialog");
}

describe("accept-risk dialog", () => {
  it("opens dialog from a discovery issue row with the five justifications", async () => {
    const dialog = await openDialogFromIssue();
    const opts = within(within(dialog).getByLabelText("Justification")).getAllByRole("option");
    expect(opts.map((o) => o.textContent)).toEqual([
      "Risk accepted",
      "Compensating control",
      "False positive",
      "Planned remediation",
      "Not applicable",
    ]);
    expect(within(dialog).getByLabelText("Expiry days")).toHaveValue(90);
    expect(within(dialog).getByLabelText("Target")).toHaveValue(FP);
  });

  it("rejects expiry over 365 days", async () => {
    const dialog = await openDialogFromIssue();
    const days = within(dialog).getByLabelText("Expiry days");
    const submit = within(dialog).getByRole("button", { name: "Propose exception" });
    fireEvent.change(days, { target: { value: "366" } });
    expect(within(dialog).getByText(/between 1 and 365/)).toBeInTheDocument();
    expect(submit).toBeDisabled();
    fireEvent.change(days, { target: { value: "365" } });
    expect(submit).toBeEnabled();
    fireEvent.change(days, { target: { value: "0" } });
    expect(submit).toBeDisabled();
  });

  it("submit calls proposeException and shows pending state", async () => {
    vi.mocked(proposeException).mockResolvedValue({ data: { status: "pending", pending_action_id: "pa-1" } });
    const dialog = await openDialogFromIssue();
    await userEvent.selectOptions(within(dialog).getByLabelText("Justification"), "compensating_control");
    await userEvent.click(within(dialog).getByRole("button", { name: "Propose exception" }));
    await waitFor(() => expect(proposeException).toHaveBeenCalledTimes(1));
    const body = vi.mocked(proposeException).mock.calls[0][0];
    expect(body.target_type).toBe("certificate");
    expect(body.target_id).toBe(FP);
    expect(body.justification_code).toBe("compensating_control");
    expect(new Date(body.expires_at).getTime()).toBeGreaterThan(Date.now());
    expect(await screen.findByText(/Pending approval — a second approver must approve this in/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Approvals" })).toHaveAttribute("href", "/inbox");
    // 202 is pending: the funnel must not have changed without a refetch result.
    expect(screen.getByTestId("funnel-suppressed")).toHaveTextContent("0");
  });

  it("shows a server rejection verbatim", async () => {
    vi.mocked(proposeException).mockRejectedValue(new Error("exception already exists"));
    const dialog = await openDialogFromIssue();
    await userEvent.click(within(dialog).getByRole("button", { name: "Propose exception" }));
    expect(await within(dialog).findByText("exception already exists")).toBeInTheDocument();
  });
});

describe("finding funnel", () => {
  it("renders five stages and updates", async () => {
    renderPage(<Discovery />);
    expect(await screen.findByText("Total findings")).toBeInTheDocument();
    const cells = () =>
      ["raw", "deduped", "in_scope", "effective", "suppressed"].map((s) => screen.getByTestId(`funnel-${s}`).textContent);
    await waitFor(() => expect(cells()[0]).toContain("7"));
    expect(cells().map((c) => c?.match(/\d+|—/)?.[0])).toEqual(["7", "5", "5", "5", "0"]);
  });

  it("updates after a refetch and lists pending vs active exceptions with expiry", async () => {
    vi.mocked(api.discoverySummary).mockResolvedValue({
      data: { findings: { raw: 7, deduped: 5, in_scope: 5, effective: 4, suppressed: 1 } },
    } as never);
    vi.mocked(listExceptions).mockResolvedValue({
      data: [
        { id: "e1", target_id: FP, finding_code: "EXPIRED", status: "active", expires_at: "2027-01-01T00:00:00Z" },
        { id: "e2", target_id: FP, finding_code: "WEAK_KEY", status: "pending", expires_at: "2027-02-01T00:00:00Z" },
      ],
    });
    renderPage(<Discovery />);
    await waitFor(() => expect(screen.getByTestId("funnel-suppressed")).toHaveTextContent("1"));
    expect(screen.getByTestId("funnel-effective")).toHaveTextContent("4");
    const list = await screen.findByTestId("exceptions-list");
    expect(within(list).getByText("Active")).toBeInTheDocument();
    expect(within(list).getByText("Pending approval")).toBeInTheDocument();
    expect(within(list).getAllByText(/expires/)).toHaveLength(2);
  });

  it("shows an em dash, never 0, for old payloads without deduped/in_scope", async () => {
    vi.mocked(api.discoverySummary).mockResolvedValue({
      data: { findings: { raw: 7, effective: 7, suppressed: 0 } },
    } as never);
    renderPage(<Discovery />);
    await waitFor(() => expect(screen.getByTestId("funnel-raw")).toHaveTextContent("7"));
    expect(screen.getByTestId("funnel-deduped")).toHaveTextContent("—");
    expect(screen.getByTestId("funnel-in_scope")).toHaveTextContent("—");
  });

  it("crypto posture renders the same funnel and offers Accept risk", async () => {
    vi.mocked(api.cryptoPostureTrend).mockResolvedValue({ data: { snapshots: [] } } as never);
    vi.mocked(api.cryptoPosture).mockResolvedValue({
      data: {
        generated_at: "2026-06-15T00:00:00Z",
        total_certs: 10,
        algorithm_breakdown: { RSA: 6, ECDSA: 4 },
        pqc_readiness: {
          quantum_safe: 2, quantum_safe_leaf_only: 0, quantum_safe_percent: 20,
          migration_ready: 1, vulnerable: 5, not_applicable: 2, pqc_score_percent: 30,
        },
        expiry_buckets: { expired: 1, expiring_47d: 2, expiring_90d: 1, expiring_200d: 1, expiring_1yr: 1 },
        grade_distribution: { A: 4, B: 3, F: 3 },
        automation_coverage: { automated: 5, manual: 5, automation_percent: 50 },
        risk_breakdown: { critical: 1, high: 2, medium: 3, low: 4 },
        findings: { raw: 7, deduped: 0, in_scope: 0, effective: 7, suppressed: 0 },
      },
    } as never);
    renderPage(<CryptoPosture />);
    await waitFor(() => expect(screen.getByTestId("funnel-raw")).toHaveTextContent("7"));
    expect(screen.getByTestId("funnel-deduped")).toHaveTextContent("—");
    expect(screen.getByTestId("funnel-effective")).toHaveTextContent("7");
    await userEvent.click(await screen.findByRole("button", { name: "Accept risk…" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(within(dialog).getByLabelText("Finding code")).getAllByRole("option")).toHaveLength(8);
  });
});

describe("install posture accept-risk (target_file)", () => {
  const FILE = "file-123";
  beforeEach(() => {
    vi.mocked(api.discoveryEndpoints).mockResolvedValue({
      data: {
        endpoints: [
          {
            id: "ep-2",
            hostname: "tomcat.lab",
            port: 8443,
            protocol: "https",
            risk_score: 20,
            install_posture: {
              file_id: FILE,
              posture: "root_service",
              path: "/opt/tomcat/conf/keystore.jks",
              host: "10.0.0.7",
              owner: "root",
              mode: "600",
              findings: ["SERVICE_RUNS_AS_ROOT: java runs as uid 0", "KEY_WORLD_READABLE: mode 644"],
              accepted_findings: ["KEY_WORLD_READABLE"],
            },
          },
        ],
      },
      meta: { total: 1 },
    } as never);
  });

  it("proposes a target_file exception per finding and marks accepted ones", async () => {
    vi.mocked(proposeException).mockResolvedValue({ data: { status: "pending", pending_action_id: "pa-9" } });
    renderPage(<Discovery />);
    await userEvent.click(await screen.findByRole("button", { name: "tomcat.lab" }));
    const panel = await screen.findByTestId("install-posture");
    expect(within(panel).getByText("Risk accepted")).toBeInTheDocument();
    // Only the open finding offers the action.
    const buttons = within(panel).getAllByRole("button", { name: "Accept risk" });
    expect(buttons).toHaveLength(1);
    await userEvent.click(buttons[0]);
    const dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Propose exception" }));
    await waitFor(() => expect(proposeException).toHaveBeenCalledTimes(1));
    const body = vi.mocked(proposeException).mock.calls[0][0];
    expect(body.target_type).toBe("target_file");
    expect(body.target_id).toBe(FILE);
    expect(body.finding_code).toBe("SERVICE_RUNS_AS_ROOT");
  });

  it("names a file exception by host:path in the exceptions list", async () => {
    vi.mocked(listExceptions).mockResolvedValue({
      data: [
        { id: "e9", target_type: "target_file", target_id: FILE, target_label: "10.0.0.7:/opt/tomcat/conf/keystore.jks", finding_code: "SERVICE_RUNS_AS_ROOT", status: "active", expires_at: "2027-01-01T00:00:00Z" },
      ],
    });
    renderPage(<Discovery />);
    const list = await screen.findByTestId("exceptions-list");
    expect(within(list).getByText("10.0.0.7:/opt/tomcat/conf/keystore.jks")).toBeInTheDocument();
  });
});
