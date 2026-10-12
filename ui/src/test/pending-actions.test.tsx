import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    pendingActions: vi.fn(),
    approvePendingAction: vi.fn(),
    rejectPendingAction: vi.fn(),
  },
}));

import PendingActions from "../pages/PendingActions";
import { api } from "../lib/api";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <PendingActions />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const proposed = {
  id: "act-1",
  action_type: "bulk_revoke",
  params: { ca_id: "ca-7", reason_code: 4 },
  proposed_by: "mcp:agent",
  rationale: "CA-7 compromised — revoke everything it signed.",
  status: "pending",
  created_at: "2026-06-18T00:00:00Z",
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Pending Actions page", () => {
  it("lists AI-proposed actions with approve/reject", async () => {
    vi.mocked(api.pendingActions).mockResolvedValue({
      data: [proposed],
    } as unknown as never);

    renderPage();

    await screen.findByText("bulk_revoke");
    expect(screen.getByText(/ca-7 compromised/i)).toBeInTheDocument();
    expect(screen.getByText(/by mcp:agent/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /^approve$/i }),
    ).toBeInTheDocument();
  });

  it("approves an action", async () => {
    vi.mocked(api.pendingActions).mockResolvedValue({
      data: [proposed],
    } as unknown as never);
    vi.mocked(api.approvePendingAction).mockResolvedValue({
      data: { status: "approved", result: { revoked: 12 } },
    } as unknown as never);

    renderPage();

    await userEvent.click(
      await screen.findByRole("button", { name: /^approve$/i }),
    );
    await waitFor(() =>
      expect(api.approvePendingAction).toHaveBeenCalledWith("act-1"),
    );
  });

  it("requires a reason flow to reject", async () => {
    vi.mocked(api.pendingActions).mockResolvedValue({
      data: [proposed],
    } as unknown as never);
    vi.mocked(api.rejectPendingAction).mockResolvedValue({
      data: { status: "rejected" },
    } as unknown as never);

    renderPage();

    await userEvent.click(
      await screen.findByRole("button", { name: /^reject$/i }),
    );
    await userEvent.type(
      screen.getByPlaceholderText(/reason for rejection/i),
      "not authorized",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /confirm reject/i }),
    );
    await waitFor(() =>
      expect(api.rejectPendingAction).toHaveBeenCalledWith(
        "act-1",
        "not authorized",
      ),
    );
  });

  it("shows an empty state when nothing is proposed", async () => {
    vi.mocked(api.pendingActions).mockResolvedValue({
      data: [],
    } as unknown as never);

    renderPage();

    await screen.findByText(/nothing proposed/i);
  });
});
