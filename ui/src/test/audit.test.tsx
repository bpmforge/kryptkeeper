import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    auditList: vi.fn(),
    auditExport: vi.fn(),
  },
}));

import Audit from "../pages/Audit";
import { api } from "../lib/api";

function renderAudit(initialEntry = "/") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]}>
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
  it("unknown /audit/:id shows a not-found state instead of the list", async () => {
    vi.mocked(api.auditList).mockResolvedValue({ data: [], meta: { total: 0, limit: 100 } } as unknown as never);
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/audit/99999"]}>
          <Routes>
            <Route path="/audit/:id" element={<Audit />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByText("Audit record not found")).toBeInTheDocument();
  });

  it("empty table says no entries yet unfiltered and 'match these filters' when filtered (CB-05)", async () => {
    vi.mocked(api.auditList).mockResolvedValue({ data: [], meta: { total: 0, limit: 50 } } as unknown as never);
    renderAudit();
    expect(await screen.findByText(/No audit entries yet/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Filter audit action"), "certificate");
    await userEvent.click(screen.getByRole("button", { name: /apply filters/i }));
    expect(await screen.findByText(/No entries match these filters/)).toBeInTheDocument();
    expect(screen.queryByText(/No audit entries yet/)).not.toBeInTheDocument();
  });

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

  it("export button calls the streaming endpoint, not auditList paging", async () => {
    vi.mocked(api.auditList).mockResolvedValue({
      data: [
        { id: 1, timestamp: "2026-04-11T00:00:00Z", action: "certificate.issue", actor_type: "user", actor_id: "admin", resource_type: "certificate", resource_id: "fp-1", trace_id: "trace-1", outcome: "success" },
      ],
      meta: { total: 1, limit: 50 },
      principal: "auditor-1",
    } as unknown as never);
    vi.mocked(api.auditExport).mockResolvedValue(undefined as unknown as never);

    renderAudit();
    await waitFor(() => expect(screen.getByRole("button", { name: /certificate\.issue/i })).toBeInTheDocument());
    const listCalls = vi.mocked(api.auditList).mock.calls.length;
    await userEvent.click(screen.getByRole("button", { name: /export csv/i }));

    await waitFor(() => expect(api.auditExport).toHaveBeenCalledTimes(1));
    expect(vi.mocked(api.auditExport).mock.calls[0][0]).toMatchObject({ format: "csv" });
    expect(vi.mocked(api.auditList).mock.calls.length).toBe(listCalls);
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

    // Hidden by default: the first screen is not the viewer's own reads.
    expect(
      await screen.findByRole("button", { name: "key.export" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "certificate.list" })).toBeNull();

    await userEvent.click(
      screen.getByRole("checkbox", { name: /hide read-only events/i }),
    );
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

  it("hides successful read-only events by default", async () => {
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
    const box = await screen.findByRole("checkbox", { name: /hide read-only events/i });
    expect(box).toBeChecked();
    await waitFor(() => expect(api.auditList).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: "certificate.list" })).toBeNull();
  });

  it("seeds filters from the URL query on load (W28-21)", async () => {
    vi.mocked(api.auditList).mockResolvedValue({
      data: [],
      meta: { total: 0, limit: 50 },
      principal: "auditor-1",
    } as unknown as never);

    renderAudit(
      "/audit?resource_type=certificate&action=certificate.revoke&resource_id=fp-9",
    );

    await waitFor(() => expect(api.auditList).toHaveBeenCalled());
    expect(vi.mocked(api.auditList).mock.calls[0][0]).toMatchObject({
      resource_type: "certificate",
      action: "certificate.revoke",
      resource_id: "fp-9",
    });
    expect(screen.getByText(/Filtered to resource fp-9/)).toBeInTheDocument();
    await userEvent.click(
      screen.getByRole("button", { name: /clear resource filter/i }),
    );
    await waitFor(() =>
      expect(
        vi.mocked(api.auditList).mock.calls.at(-1)?.[0]?.resource_id,
      ).toBe(""),
    );
  });
});
