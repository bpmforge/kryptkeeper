import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    approvals: vi.fn(),
    approveRequest: vi.fn(),
    rejectRequest: vi.fn(),
  },
}));

import Approvals from "../pages/Approvals";
import { api } from "../lib/api";

const pendingRequest = {
  id: "apr-1",
  template_id: "tpl-wildcard",
  ca_id: "ca-1",
  requester: "user-7",
  status: "pending",
  csr_pem: "-----BEGIN CERTIFICATE REQUEST-----",
  requested_at: "2026-06-01T12:00:00Z",
};

function renderApprovals() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Approvals />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Approvals page", () => {
  it("lists pending requests with approve and reject actions", async () => {
    vi.mocked(api.approvals).mockResolvedValue({
      data: [pendingRequest],
      meta: { total: 1, limit: 50, offset: 0 },
    } as unknown as never);

    renderApprovals();

    await screen.findByText(/template tpl-wildcard/i);
    expect(screen.getByText(/requested by user-7/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /^approve$/i }),
    ).toBeInTheDocument();
    expect(api.approvals).toHaveBeenCalledWith({ status: "pending" });
  });

  it("approves a request and reports success", async () => {
    vi.mocked(api.approvals).mockResolvedValue({
      data: [pendingRequest],
      meta: { total: 1, limit: 50, offset: 0 },
    } as unknown as never);
    vi.mocked(api.approveRequest).mockResolvedValue({
      data: { fingerprint_sha256: "fp-new" },
    } as unknown as never);

    renderApprovals();

    const approveBtn = await screen.findByRole("button", {
      name: /^approve$/i,
    });
    await userEvent.click(approveBtn);

    await waitFor(() =>
      expect(api.approveRequest).toHaveBeenCalledWith("apr-1"),
    );
  });

  it("requires a reason before confirming rejection", async () => {
    vi.mocked(api.approvals).mockResolvedValue({
      data: [pendingRequest],
      meta: { total: 1, limit: 50, offset: 0 },
    } as unknown as never);
    vi.mocked(api.rejectRequest).mockResolvedValue({
      status: "rejected",
    } as unknown as never);

    renderApprovals();

    const rejectBtn = await screen.findByRole("button", { name: /^reject$/i });
    await userEvent.click(rejectBtn);

    const confirm = screen.getByRole("button", {
      name: /confirm rejection/i,
    });
    expect(confirm).toBeDisabled();

    await userEvent.type(
      screen.getByPlaceholderText(/rejection reason/i),
      "wildcard not justified",
    );
    expect(confirm).toBeEnabled();
    await userEvent.click(confirm);

    await waitFor(() =>
      expect(api.rejectRequest).toHaveBeenCalledWith(
        "apr-1",
        "wildcard not justified",
      ),
    );
  });

  it("shows an empty state when the queue is clear", async () => {
    vi.mocked(api.approvals).mockResolvedValue({
      data: [],
      meta: { total: 0, limit: 50, offset: 0 },
    } as unknown as never);

    renderApprovals();

    await screen.findByText(/nothing waiting for approval/i);
  });
});
