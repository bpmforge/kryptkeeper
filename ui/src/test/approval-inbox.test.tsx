import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import appSource from "../App.tsx?raw";

vi.mock("../lib/approvalInboxApi", async (orig) => {
  const actual = await orig<typeof import("../lib/approvalInboxApi")>();
  return {
    ...actual,
    approvalInboxApi: { list: vi.fn(), approve: vi.fn(), reject: vi.fn() },
  };
});
vi.mock("../lib/api", () => ({
  api: { authzCheck: vi.fn() },
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import ApprovalInbox from "../pages/ApprovalInbox";
import { approvalInboxApi } from "../lib/approvalInboxApi";
import { api } from "../lib/api";
import { toast } from "sonner";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ApprovalInbox />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const cert = {
  type: "certificate_approval",
  id: "apr-1",
  summary: "Issue server-tls for api.example.com",
  requester: "dev@example.com",
  tenant: "acme",
  created_at: "2026-10-01T00:00:00Z",
  age_seconds: 7500,
};
const action = {
  type: "pending_action",
  id: "act-1",
  summary: "bulk_revoke on ca-7",
  requester: "mcp:agent",
  tenant: "globex",
  created_at: "2026-10-01T00:00:00Z",
  age_seconds: 90000,
  action_type: "bulk_revoke",
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue({
    principal: "admin@example.com",
    role: "pki-admin",
    scopes: ["*"],
  } as never);
  vi.mocked(approvalInboxApi.list).mockResolvedValue({
    data: [cert, action],
  } as never);
});

describe("Approvals inbox", () => {
  it("renders both item types in one list with their badges", async () => {
    renderPage();
    await screen.findByText(cert.summary);
    expect(screen.getByText("Bulk revoke on ca-7")).toBeInTheDocument();
    expect(screen.getByText("Certificate approval")).toBeInTheDocument();
    expect(screen.getByText("Pending action")).toBeInTheDocument();
    expect(screen.getByText("2 h ago")).toBeInTheDocument();
  });

  it("filters by type, age and tenant", async () => {
    renderPage();
    await screen.findByText(cert.summary);
    await userEvent.selectOptions(screen.getByLabelText("Type"), "pending_action");
    await waitFor(() =>
      expect(approvalInboxApi.list).toHaveBeenLastCalledWith({ type: "pending_action" }),
    );
    await userEvent.selectOptions(screen.getByLabelText("Age"), "24h");
    await waitFor(() =>
      expect(approvalInboxApi.list).toHaveBeenLastCalledWith({
        type: "pending_action",
        min_age: "24h",
      }),
    );
    await userEvent.type(screen.getByLabelText("Tenant"), "acme");
    await waitFor(() =>
      expect(approvalInboxApi.list).toHaveBeenLastCalledWith({
        type: "pending_action",
        min_age: "24h",
        tenant: "acme",
      }),
    );
  });

  it("hides the tenant filter when only one tenant is visible", async () => {
    vi.mocked(approvalInboxApi.list).mockResolvedValue({ data: [cert] } as never);
    renderPage();
    await screen.findByText(cert.summary);
    expect(screen.queryByLabelText("Tenant")).not.toBeInTheDocument();
  });

  it("approves a pending action by type and id", async () => {
    vi.mocked(approvalInboxApi.approve).mockResolvedValue({ data: { status: "approved" } });
    renderPage();
    await screen.findByText("Bulk revoke on ca-7");
    await userEvent.click(screen.getAllByRole("button", { name: /^approve$/i })[1]);
    await waitFor(() =>
      expect(approvalInboxApi.approve).toHaveBeenCalledWith("pending_action", "act-1"),
    );
  });

  it("approver role: pending-action Approve/Reject are disabled with the reason (CB-04)", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({
      principal: "dana@example.com",
      role: "approver",
      scopes: [],
    } as never);
    renderPage();
    await screen.findByText("Bulk revoke on ca-7");
    const approves = screen.getAllByRole("button", { name: /^approve$/i });
    const rejects = screen.getAllByRole("button", { name: /^reject$/i });
    // the hub lists only certificate requests the role can decide; the certificate row is actionable
    expect(approves[0]).toBeEnabled();
    expect(approves[1]).toBeDisabled();
    expect(rejects[1]).toBeDisabled();
    expect(approves[1].closest("span")).toHaveAttribute("title", expect.stringContaining("pki-admin or pki-operator"));
    expect(screen.getByRole("note")).toHaveTextContent(/Signed in as approver/);
    expect(screen.getByRole("note")).toHaveTextContent(/templates that name your role/);
  });

  it("approver role: a certificate-only inbox shows enabled Approve, and own requests stay disabled", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({
      principal: "dana@example.com",
      role: "approver",
      scopes: [],
    } as never);
    vi.mocked(approvalInboxApi.list).mockResolvedValue({
      data: [cert, { ...cert, id: "apr-2", summary: "Issue own-cert", requester: "dana@example.com" }],
    } as never);
    renderPage();
    await screen.findByText(cert.summary);
    expect(screen.queryByText("Pending action")).not.toBeInTheDocument();
    const approves = screen.getAllByRole("button", { name: /^approve$/i });
    expect(approves[0]).toBeEnabled();
    expect(approves[1]).toBeDisabled();
    expect(approves[1].closest("span")).toHaveAttribute("title", expect.stringContaining("your own"));
  });

  it("shows n-of-m progress on a 202 quorum response", async () => {
    vi.mocked(approvalInboxApi.approve).mockResolvedValue({
      data: { status: "pending", approvals: 1, required: 2 },
    });
    renderPage();
    await screen.findByText("Bulk revoke on ca-7");
    await userEvent.click(screen.getAllByRole("button", { name: /^approve$/i })[1]);
    await screen.findByText("1 of 2 approvals");
  });

  it("rejects with a reason", async () => {
    vi.mocked(approvalInboxApi.reject).mockResolvedValue({});
    renderPage();
    await screen.findByText(cert.summary);
    await userEvent.click(screen.getAllByRole("button", { name: /^reject$/i })[0]);
    await userEvent.type(screen.getByPlaceholderText(/rejection reason/i), "not authorized");
    await userEvent.click(screen.getByRole("button", { name: /confirm rejection/i }));
    await waitFor(() =>
      expect(approvalInboxApi.reject).toHaveBeenCalledWith(
        "certificate_approval",
        "apr-1",
        "not authorized",
      ),
    );
  });

  it("surfaces the server message when approval is refused", async () => {
    vi.mocked(approvalInboxApi.approve).mockRejectedValue(new Error("tenant mismatch"));
    renderPage();
    await screen.findByText(cert.summary);
    await userEvent.click(screen.getAllByRole("button", { name: /^approve$/i })[0]);
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith("tenant mismatch"));
  });

  it("disables Approve on the caller's own request", async () => {
    vi.mocked(approvalInboxApi.list).mockResolvedValue({
      data: [{ ...cert, requester: "admin@example.com" }],
    } as never);
    renderPage();
    await screen.findByText(cert.summary);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /^approve$/i })).toBeDisabled(),
    );
  });

  it("shows an empty state", async () => {
    vi.mocked(approvalInboxApi.list).mockResolvedValue({ data: [] });
    renderPage();
    await screen.findByText("Inbox empty");
  });

  it("redirects the old routes to the inbox", () => {
    expect(appSource).toMatch(/path="\/approvals"\s+element=\{<Navigate to="\/inbox" replace \/>\}/);
    expect(appSource).toMatch(/path="\/pending-actions"\s+element=\{<Navigate to="\/inbox" replace \/>\}/);
  });
});
