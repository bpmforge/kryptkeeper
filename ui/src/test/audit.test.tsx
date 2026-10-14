import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

  it("hides read-only events on request but keeps exports and writes", async () => {
    const mk = (id: number, action: string, outcome = "success") => ({
      id,
      timestamp: "2026-04-11T00:00:00Z",
      action,
      actor_type: "user",
      actor_id: "admin",
      resource_type: "key",
      resource_id: `r-${id}`,
      trace_id: "",
      outcome,
    });
    vi.mocked(api.auditList).mockResolvedValue({
      data: [
        mk(1, "certificate.list"),
        mk(2, "key.get"),
        mk(3, "key.export"),
        mk(4, "certificate.issue"),
        mk(5, "authz.check", "denied"),
      ],
      meta: { total: 5, limit: 50 },
    } as unknown as never);

    renderAudit();

    expect(
      await screen.findByRole("button", { name: "certificate.list" }),
    ).toBeInTheDocument();

    await userEvent.click(
      screen.getByRole("checkbox", { name: /hide read-only events/i }),
    );

    expect(screen.queryByRole("button", { name: "certificate.list" })).toBeNull();
    expect(screen.queryByRole("button", { name: "key.get" })).toBeNull();
    expect(screen.getByRole("button", { name: "key.export" })).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "certificate.issue" }),
    ).toBeInTheDocument();
    // A denied read is security-relevant and is never hidden.
    expect(screen.getByRole("button", { name: "authz.check" })).toBeInTheDocument();
  });

  it("shows all events by default", async () => {
    vi.mocked(api.auditList).mockResolvedValue({
      data: [
        {
          id: 1,
          timestamp: "t",
          action: "certificate.list",
          actor_type: "user",
          actor_id: "a",
          resource_type: "certificate",
          resource_id: "x",
          outcome: "success",
        },
      ],
      meta: { total: 1, limit: 50 },
    } as unknown as never);
    renderAudit();
    expect(
      await screen.findByRole("button", { name: "certificate.list" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", { name: /hide read-only events/i }),
    ).not.toBeChecked();
  });
});
