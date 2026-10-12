import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    auditList: vi.fn(),
  },
}));

import Audit from "../pages/Audit";
import { api } from "../lib/api";

function renderAudit() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Audit />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue({ service: "kryptkeeper", authenticated: true, principal: "auditor-1", role: "pki-auditor", scopes: ["ops:read"] } as unknown as never);
});

describe("Audit page", () => {
  it("renders audit evidence and exports CSV", async () => {
    vi.mocked(api.auditList).mockResolvedValue({
      data: [
        { id: 1, timestamp: "2026-04-11T00:00:00Z", action: "certificate.issue", actor_type: "user", actor_id: "admin", resource_type: "certificate", resource_id: "fp-1", trace_id: "trace-1", outcome: "success" },
      ],
      meta: { total: 1, limit: 50 },
      principal: "auditor-1",
    } as unknown as never);

    renderAudit();

    expect(await screen.findByRole("heading", { level: 1, name: /audit evidence/i })).toBeInTheDocument();
    await waitFor(() => expect(api.auditList).toHaveBeenCalled());
    await waitFor(() => expect(screen.getByRole("button", { name: /certificate\.issue/i })).toBeInTheDocument());
  });
});
