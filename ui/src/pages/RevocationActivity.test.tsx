import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: { revocationActivity: vi.fn(), cas: vi.fn() },
}));

import RevocationActivity from "../pages/RevocationActivity";
import { api } from "../lib/api";

describe("RevocationActivity drill-through (W28-21)", () => {
  it("links By CA rows and recent revocations to filtered lists", async () => {
    vi.mocked(api.cas).mockResolvedValue({
      data: { items: [{ id: "ca-2", name: "Edge CA" }] },
    } as unknown as never);
    vi.mocked(api.revocationActivity).mockResolvedValue({
      data: {
        generated_at: "2026-07-31T00:00:00Z",
        window_days: 30,
        total_revoked: 1,
        by_reason_code: { superseded: 1 },
        by_ca: { "ca-2": 1 },
        recent_revocations: [
          {
            fingerprint_sha256: "abc123",
            common_name: "svc.example.com",
            ca_id: "ca-2",
            revoked_at: "2026-07-30T00:00:00Z",
            reason_code: 4,
            reason_label: "superseded",
          },
        ],
      },
    } as unknown as never);

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <RevocationActivity />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    const caLinks = await screen.findAllByRole("link", { name: "Edge CA" });
    expect(caLinks.length).toBe(2);
    for (const l of caLinks) {
      expect(l).toHaveAttribute(
        "href",
        "/certificates?status=revoked&ca_id=ca-2",
      );
    }
    expect(
      screen.getByRole("link", { name: "svc.example.com" }),
    ).toHaveAttribute("href", "/certificates/abc123");
  });
});
