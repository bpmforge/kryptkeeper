import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    revocationActivity: vi.fn(),
    cas: vi.fn(),
  },
}));

import RevocationActivity from "../pages/RevocationActivity";
import { api } from "../lib/api";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <RevocationActivity />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const report = {
  generated_at: "2026-10-01T00:00:00Z",
  window_days: 30,
  total_revoked: 3,
  by_reason_code: { superseded: 3 },
  by_ca: {
    "9e21e0d2-0000-0000-0000-000000000001": 2,
    "unknown-ca": 1,
  },
  recent_revocations: [],
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.revocationActivity).mockResolvedValue({
    data: report,
  } as unknown as never);
});

describe("RevocationActivity By CA", () => {
  it("shows CA names and falls back to the ID for unknown CAs", async () => {
    vi.mocked(api.cas).mockResolvedValue({
      data: {
        items: [
          {
            id: "9e21e0d2-0000-0000-0000-000000000001",
            display_name: "Payments Issuing CA",
          },
        ],
      },
    } as unknown as never);

    renderPage();

    await screen.findByText("Payments Issuing CA");
    expect(screen.getByText("unknown-ca")).toBeInTheDocument();
    expect(screen.queryByText(/9e21e0d2/)).toBeNull();
  });
});
