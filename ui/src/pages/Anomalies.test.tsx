import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("../lib/api", async (importOriginal) => {
  const mod = (await importOriginal()) as Record<string, unknown>;
  return {
    ...mod,
    fetchJSON: vi.fn(),
    api: { ...(mod.api as Record<string, unknown>), authzCheck: vi.fn(), cas: vi.fn() },
  };
});
vi.mock("../lib/approvalInboxApi", async (orig) => {
  const actual = await orig<typeof import("../lib/approvalInboxApi")>();
  return {
    ...actual,
    approvalInboxApi: { list: vi.fn(), approve: vi.fn(), reject: vi.fn() },
  };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import Anomalies from "./Anomalies";
import ApprovalInbox from "./ApprovalInbox";
import { api, fetchJSON } from "../lib/api";
import { approvalInboxApi } from "../lib/approvalInboxApi";

function wrap(ui: React.ReactNode, entry = "/reports/anomalies") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[entry]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const finding = {
  kind: "volume_spike",
  severity: "high",
  detail: "ca-1 issued 40 certs in 24h",
  evidence: ["ca-1", "<img src=x onerror=alert(1)>"],
  at: "2026-10-16T01:00:00Z",
};
const proposal = {
  id: "act-9",
  action_type: "anomaly.suspend_ca",
  status: "pending",
  proposed_by: "mcp:agent",
  created_at: "2026-10-16T01:05:00Z",
  params: { finding_kind: "volume_spike", blast_radius: { cas: 1, templates: 0, certificates: 40 } },
};

function mockFetch(report: unknown, remediations: unknown) {
  vi.mocked(fetchJSON).mockImplementation((async (path: string) =>
    path === "/reports/anomalies" ? report : remediations) as never);
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.cas).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.authzCheck).mockResolvedValue({
    principal: "admin@example.com",
    role: "pki-admin",
    scopes: ["*"],
  } as never);
});

describe("Anomalies page", () => {
  it("renders kind, severity and evidence for each finding", async () => {
    mockFetch(
      { data: { findings: [finding], scanned_at: "2026-10-16T02:00:00Z" } },
      { data: [] },
    );
    wrap(<Anomalies />);
    const card = await screen.findByTestId("anomaly-finding");
    expect(within(card).getByText("Volume spike")).toBeInTheDocument();
    expect(within(card).getByText("high")).toBeInTheDocument();
    expect(within(card).getByText("ca-1 issued 40 certs in 24h")).toBeInTheDocument();
    // evidence is attacker-influenced: shown as literal text, never parsed
    expect(within(card).getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(card.querySelector("img")).toBeNull();
    expect(within(card).getByText("No remediation proposed")).toBeInTheDocument();
  });

  it("shows CA names instead of ids and drops empty evidence bullets (CB-09)", async () => {
    vi.mocked(api.cas).mockResolvedValue({
      data: [{ id: "6f1c0000-aaaa", name: "Issuing CA One", type: "intermediate", status: "active" }],
    } as never);
    mockFetch(
      {
        data: {
          findings: [
            {
              ...finding,
              detail: "CA 6f1c0000-aaaa issued 40 certificates in 24h",
              evidence: ["6f1c0000-aaaa", ""],
            },
          ],
        },
      },
      { data: [] },
    );
    wrap(<Anomalies />);
    const card = await screen.findByTestId("anomaly-finding");
    await within(card).findByText("CA Issuing CA One issued 40 certificates in 24h");
    expect(within(card).getAllByRole("listitem")).toHaveLength(1);
    expect(card.textContent).not.toContain("6f1c0000-aaaa");
  });

  it("says no scan yet, not a clean scan, when none has completed", async () => {
    mockFetch({ data: { findings: [] } }, { data: [] });
    wrap(<Anomalies />);
    // No scan yet: must not claim "the latest scan found nothing".
    expect(await screen.findByText("No scan yet")).toBeInTheDocument();
    expect(screen.queryByText("No anomalies")).toBeNull();
    expect(screen.getByText("No scan has completed yet")).toBeInTheDocument();
  });

  it("links a pending remediation to /inbox?focus=pending_action:<id> without implying it ran", async () => {
    mockFetch({ data: { findings: [finding] } }, { data: [proposal] });
    wrap(<Anomalies />);
    const card = await screen.findByTestId("anomaly-finding");
    await within(card).findByText("Proposed - awaiting approval");
    const link = within(card).getByRole("link", { name: "Review in Approvals" });
    expect(link).toHaveAttribute("href", "/inbox?focus=pending_action:act-9");
    expect(within(card).getByText(/1 CA\(s\), 0 template\(s\), 40 certificate\(s\)/)).toBeInTheDocument();
    expect(screen.queryByText(/executed/)).toBeNull();
  });

  it("shows executed only for approved, and no link once decided", async () => {
    mockFetch(
      { data: { findings: [finding] } },
      { data: [{ ...proposal, status: "approved" }, { ...proposal, id: "act-8", status: "rejected" }] },
    );
    wrap(<Anomalies />);
    const card = await screen.findByTestId("anomaly-finding");
    await within(card).findByText("Approved and executed");
    expect(within(card).getByText("Rejected - nothing changed")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Review in Approvals" })).toBeNull();
  });

  it("approval hand-off: focused inbox row is highlighted and approve/reject act on it", async () => {
    vi.mocked(approvalInboxApi.list).mockResolvedValue({
      data: [
        {
          type: "pending_action", id: "act-9", summary: "suspend ca-1", requester: "mcp:agent",
          tenant: "", created_at: "2026-10-16T01:05:00Z", age_seconds: 60,
        },
        {
          type: "pending_action", id: "act-2", summary: "other", requester: "mcp:agent",
          tenant: "", created_at: "2026-10-16T01:05:00Z", age_seconds: 60,
        },
      ],
    } as never);
    vi.mocked(approvalInboxApi.approve).mockResolvedValue({} as never);
    vi.mocked(approvalInboxApi.reject).mockResolvedValue({} as never);
    wrap(<ApprovalInbox />, "/inbox?focus=pending_action:act-9");
    const row = (await screen.findByText("suspend ca-1")).closest("[data-focused]") as HTMLElement;
    expect(row).toHaveAttribute("data-focused", "true");
    expect(screen.getByText("other").closest("div[class*='rounded-2xl']")).not.toHaveAttribute("data-focused");
    const approve = within(row).getByRole("button", { name: /Approve/ });
    expect(approve).toBeEnabled();
    await userEvent.click(approve);
    await waitFor(() => expect(approvalInboxApi.approve).toHaveBeenCalledWith("pending_action", "act-9"));

    await userEvent.click(within(row).getByRole("button", { name: /Reject/ }));
    await userEvent.type(within(row).getByPlaceholderText(/Rejection reason/), "not needed");
    await userEvent.click(within(row).getByRole("button", { name: "Confirm rejection" }));
    await waitFor(() =>
      expect(approvalInboxApi.reject).toHaveBeenCalledWith("pending_action", "act-9", "not needed"),
    );
  });
});
