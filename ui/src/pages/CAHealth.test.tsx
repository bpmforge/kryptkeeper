import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({ api: { caHealth: vi.fn() } }));

import CAHealth from "../pages/CAHealth";
import { api } from "../lib/api";

describe("CAHealth drill-through (W28-21)", () => {
  it("links the CA name to the certificate list filtered by ca_id", async () => {
    vi.mocked(api.caHealth).mockResolvedValue({
      data: {
        generated_at: "2026-07-31T00:00:00Z",
        total_cas: 1,
        items: [
          {
            id: "ca-9",
            name: "Issuing CA",
            status: "active",
            algorithm: "ECDSA-P256",
            expires_at: "2030-01-01T00:00:00Z",
            days_until_expiry: 900,
            algorithm_strength: "strong",
          },
        ],
        summary: {
          active: 1,
          expiring_90d: 0,
          expiring_1yr: 0,
          weak_algorithm: 0,
          sunset_algorithm: 0,
        },
      },
    } as unknown as never);

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <CAHealth />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    const link = await screen.findByRole("link", { name: "Issuing CA" });
    expect(link).toHaveAttribute("href", "/certificates?ca_id=ca-9");
  });
});
