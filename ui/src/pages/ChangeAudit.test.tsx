import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({ api: { changeAudit: vi.fn() } }));

import ChangeAudit from "../pages/ChangeAudit";
import { api } from "../lib/api";

describe("ChangeAudit drill-through (W28-21)", () => {
  it("links the resource to the audit log filtered by resource_id, else by action", async () => {
    vi.mocked(api.changeAudit).mockResolvedValue({
      data: {
        generated_at: "2026-07-31T00:00:00Z",
        window_days: 30,
        total_events: 2,
        by_action: { "certificate.revoke": 1, "ca.create": 1 },
        by_actor: {},
        by_outcome: { success: 2 },
        events: [
          {
            timestamp: "2026-07-30T00:00:00Z",
            action: "certificate.revoke",
            actor_id: "admin",
            actor_type: "user",
            resource_id: "fp-77",
            outcome: "success",
          },
          {
            timestamp: "2026-07-29T00:00:00Z",
            action: "ca.create",
            actor_id: "admin",
            actor_type: "user",
            resource_id: "",
            outcome: "success",
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
          <ChangeAudit />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(await screen.findByRole("link", { name: "fp-77" })).toHaveAttribute(
      "href",
      "/audit?resource_id=fp-77",
    );
    expect(screen.getByRole("link", { name: "CA Create" })).toHaveAttribute(
      "href",
      "/audit?action=ca.create",
    );
  });
});
