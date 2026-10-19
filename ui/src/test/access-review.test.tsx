import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/accessReviewApi", () => ({
  accessReviewApi: {
    report: vi.fn(),
    campaigns: vi.fn(),
    campaign: vi.fn(),
    open: vi.fn(),
    decide: vi.fn(),
    close: vi.fn(),
  },
}));
vi.mock("../lib/api", () => ({ api: { authzCheck: vi.fn() }, downloadAuthedFile: vi.fn() }));

import AccessReview from "../pages/AccessReview";
import { accessReviewApi } from "../lib/accessReviewApi";
import { api } from "../lib/api";

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AccessReview />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const principal = {
  tenant: "default",
  status: "active" as const,
  dormant: false,
  approver_capable: false,
  executed: false,
  decision_status: "undecided" as const,
};
const entries = [
  { ...principal, entry_id: "user:u1", kind: "user" as const, id: "u1", name: "alice@example.com", role: "pki-admin", source: "local" as const },
  { ...principal, entry_id: "api_key:k1", kind: "api_key" as const, id: "k1", name: "ci-key", role: "pki-viewer", source: "local" as const },
  { ...principal, entry_id: "user:u2", kind: "user" as const, id: "u2", name: "bob@example.com", role: "pki-admin", source: "local" as const },
];
const campaign = {
  id: "c1",
  name: "Q4 review",
  status: "open" as const,
  tenant: "default",
  period_start: "2026-07-01T00:00:00Z",
  period_end: "2026-10-01T00:00:00Z",
  opened_by: "admin",
  opened_at: "2026-10-01T00:00:00Z",
  entries,
};

const emptyReport = {
  generated_at: "2026-10-15T00:00:00Z",
  period_start: "2026-07-17T00:00:00Z",
  period_end: "2026-10-15T00:00:00Z",
  dormant_days: 90,
  principals: [],
  role_changes: [],
  totals: { users: 0, api_keys: 0, dormant: 0, role_changes: 0 },
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue({ principal: "admin", role: "pki-admin", scopes: ["*"] } as never);
  vi.mocked(accessReviewApi.report).mockResolvedValue({ data: emptyReport });
  vi.mocked(accessReviewApi.campaigns).mockResolvedValue({ data: { items: [] } });
});

describe("AccessReview page", () => {
  it("renders role-change and dormant sections from the report API", async () => {
    vi.mocked(accessReviewApi.report).mockResolvedValue({
      data: {
        ...emptyReport,
        principals: [{ ...principal, kind: "user", id: "u9", name: "stale@example.com", role: "pki-viewer", source: "local", dormant: true, last_activity_at: "2026-01-01T00:00:00Z" }],
        role_changes: [
          { timestamp: "2026-10-01T10:00:00Z", action: "users.update", actor: "carol@example.com", resource_type: "user", resource_id: "u1", outcome: "success" },
          { timestamp: "2026-10-02T10:00:00Z", action: "role.update", actor: "dave@example.com", resource_type: "role", resource_id: "r1", outcome: "success" },
        ],
      },
    });
    renderPage();
    await screen.findByText("carol@example.com");
    expect(screen.getByText("dave@example.com")).toBeInTheDocument();
    expect(screen.getByText("stale@example.com")).toBeInTheDocument();
    expect(screen.queryByText("No role changes in this period.")).not.toBeInTheDocument();
    expect(screen.queryByText("No dormant accounts.")).not.toBeInTheDocument();
  });

  it("shows explicit empty states", async () => {
    renderPage();
    await screen.findByText("No role changes in this period.");
    expect(screen.getByText("No dormant accounts.")).toBeInTheDocument();
  });

  it("reviewer opens a campaign, decides every entry and closes it", async () => {
    vi.mocked(accessReviewApi.open).mockResolvedValue({ data: campaign });
    vi.mocked(accessReviewApi.campaign).mockResolvedValue({ data: campaign });
    vi.mocked(accessReviewApi.decide).mockImplementation(async (_id, body) => ({
      data: { ...entries.find((e) => e.entry_id === body.entry_id)!, decision: body.decision, decision_status: "decided" as const },
    }));
    vi.mocked(accessReviewApi.close).mockResolvedValue({ data: { ...campaign, status: "closed", report_sha256: "abc" } });

    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /open campaign/i }));
    await userEvent.type(screen.getByLabelText(/campaign name/i), "Q4 review");
    await userEvent.click(screen.getByRole("button", { name: /start review/i }));
    await screen.findByText("alice@example.com");
    expect(accessReviewApi.open).toHaveBeenCalledWith("Q4 review");

    const close = screen.getByRole("button", { name: /close campaign/i });
    expect(close).toBeDisabled();
    expect(screen.getByText("3 undecided")).toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText("Decision for alice@example.com"), "keep");
    await userEvent.click(screen.getByRole("button", { name: "Save decision for alice@example.com" }));
    await userEvent.selectOptions(screen.getByLabelText("Decision for ci-key"), "revoke");
    await userEvent.click(screen.getByRole("button", { name: "Save decision for ci-key" }));
    await userEvent.selectOptions(screen.getByLabelText("Decision for bob@example.com"), "modify");
    expect(screen.getByRole("button", { name: "Save decision for bob@example.com" })).toBeDisabled();
    await userEvent.type(screen.getByLabelText("New role for bob@example.com"), "pki-viewer");
    await userEvent.click(screen.getByRole("button", { name: "Save decision for bob@example.com" }));

    await waitFor(() => expect(accessReviewApi.decide).toHaveBeenCalledTimes(3));
    expect(accessReviewApi.decide).toHaveBeenCalledWith("c1", { entry_id: "user:u1", decision: "keep" });
    expect(accessReviewApi.decide).toHaveBeenCalledWith("c1", { entry_id: "api_key:k1", decision: "revoke" });
    expect(accessReviewApi.decide).toHaveBeenCalledWith("c1", { entry_id: "user:u2", decision: "modify", new_role: "pki-viewer" });

    await waitFor(() => expect(screen.getByRole("button", { name: /close campaign/i })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: /close campaign/i }));
    await waitFor(() => expect(accessReviewApi.close).toHaveBeenCalledWith("c1", false));
    expect(await screen.findByText(/Export SHA-256: abc/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /export csv/i })).toBeInTheDocument();
  });

  it("scim entries cannot be revoked or modified", async () => {
    const scim = { ...campaign, entries: [{ ...entries[0], source: "scim" as const }] };
    vi.mocked(accessReviewApi.campaigns).mockResolvedValue({ data: { items: [scim] } });
    vi.mocked(accessReviewApi.campaign).mockResolvedValue({ data: scim });
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /Q4 review/ }));
    const select = await screen.findByLabelText("Decision for alice@example.com");
    expect(within(select).getByRole("option", { name: "revoke" })).toBeDisabled();
    expect(within(select).getByRole("option", { name: "modify" })).toBeDisabled();
    expect(within(select).getByRole("option", { name: "keep" })).toBeEnabled();
    expect(screen.getByText(/Managed by SCIM/)).toBeInTheDocument();
  });

  it("shows the server message and a waiting state for held revokes", async () => {
    vi.mocked(accessReviewApi.campaigns).mockResolvedValue({ data: { items: [campaign] } });
    vi.mocked(accessReviewApi.campaign).mockResolvedValue({ data: campaign });
    vi.mocked(accessReviewApi.decide)
      .mockResolvedValueOnce({ data: { ...entries[0], decision: "revoke", decision_status: "pending_second" } })
      .mockRejectedValueOnce(new Error("campaign is closed"));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /Q4 review/ }));
    await userEvent.selectOptions(await screen.findByLabelText("Decision for alice@example.com"), "revoke");
    await userEvent.click(screen.getByRole("button", { name: "Save decision for alice@example.com" }));
    await screen.findByText("Waiting for a second reviewer");
    await userEvent.selectOptions(screen.getByLabelText("Decision for ci-key"), "keep");
    await userEvent.click(screen.getByRole("button", { name: "Save decision for ci-key" }));
    await screen.findByText("campaign is closed");
  });

  it("non-admin sees the limited message", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({ principal: "v", role: "viewer", scopes: [] } as never);
    renderPage();
    await screen.findByText("Access review is limited to administrators.");
    expect(accessReviewApi.campaigns).not.toHaveBeenCalled();
  });
});
