import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    dashboardActionsHistory: vi.fn(),
  },
}));

import History from "../pages/History";
import { api } from "../lib/api";

function renderHistory() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <History />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.mocked(api.dashboardActionsHistory).mockReset();
});

describe("History page", () => {
  it("renders action history rows and filters", async () => {
    vi.mocked(api.dashboardActionsHistory).mockResolvedValue({
      data: {
        history: [
          { action_id: "certificate.revoke", category: "certificate", status: "success", updated_by: "bootstrap", updated_at: "2026-04-11T00:00:00Z", note: "revoked" },
        ],
      },
    } as unknown as never);

    renderHistory();

    expect(await screen.findByRole("heading", { level: 1, name: /action history/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /refresh/i })).toBeInTheDocument();
    await waitFor(() => expect(api.dashboardActionsHistory).toHaveBeenCalled());
    await waitFor(() => expect(screen.getByRole("button", { name: /certificate revoke/i })).toBeInTheDocument());
  });
});
