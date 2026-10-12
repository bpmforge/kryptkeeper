import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    certificates: vi.fn(),
    cas: vi.fn(),
    discoveryEndpoints: vi.fn(),
    notificationDeliveries: vi.fn(),
    dashboardActionsHistory: vi.fn(),
  },
}));

import Search from "../pages/Search";
import { api } from "../lib/api";

function renderSearch() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Search />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Search page", () => {
  it("shows unified results across inventory surfaces", async () => {
    vi.mocked(api.certificates).mockResolvedValue({
      data: {
        items: [
          {
            fingerprint_sha256: "fp-1",
            common_name: "api.example.com",
            renewal_status: "expiring soon",
          },
        ],
      },
    } as unknown as never);
    vi.mocked(api.cas).mockResolvedValue({
      data: {
        items: [
          {
            id: "ca-1",
            display_name: "Root CA",
            type: "root",
            status: "active",
          },
        ],
      },
    } as unknown as never);
    vi.mocked(api.discoveryEndpoints).mockResolvedValue({
      data: {
        endpoints: [
          {
            id: "ep-1",
            hostname: "api.example.com",
            protocol: "tls",
            risk_score: 80,
          },
        ],
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
          },
        ],
      },
    } as unknown as never);
    vi.mocked(api.dashboardActionsHistory).mockResolvedValue({
      data: {
        history: [
          {
            action_id: "certificate.revoke",
            category: "certificate",
            status: "success",
            updated_by: "bootstrap",
            updated_at: "2026-04-11T00:00:00Z",
            note: "revoked",
          },
        ],
      },
    } as unknown as never);

    renderSearch();

    await screen.findByText(/start typing/i);
    await waitFor(() => expect(api.certificates).not.toHaveBeenCalled());
    const input = screen.getByPlaceholderText(
      /search by name, fingerprint, host/i,
    );
    input.focus();
  });
});
