import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: { authzCheck: vi.fn(), auditList: vi.fn(), auditExport: vi.fn() },
}));

import Audit from "../pages/Audit";
import { shortResourceId } from "../lib/auditResource";
import { api } from "../lib/api";

const FP = "0123456789abcdef".repeat(4);

function renderAudit() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Audit />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const base = {
  timestamp: "2026-04-11T00:00:00Z",
  actor_type: "user",
  actor_id: "admin",
  trace_id: "",
  outcome: "success",
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue({
    service: "kryptkeeper",
    authenticated: true,
    principal: "auditor-1",
    role: "pki-auditor",
    scopes: ["ops:read"],
  } as unknown as never);
  vi.mocked(api.auditList).mockResolvedValue({
    data: [
      {
        ...base,
        id: 1,
        action: "certificate.revoke",
        resource_type: "certificate",
        resource_id: FP,
        resource_name: "api.example.com",
      },
      {
        ...base,
        id: 2,
        action: "certificate.issue",
        resource_type: "certificate",
        resource_id: "certificates",
        outcome: "failure",
      },
    ],
    meta: { total: 2, limit: 50 },
  } as unknown as never);
});

describe("Audit resource column", () => {
  it("shortens IDs only past 16 chars", () => {
    expect(shortResourceId(FP)).toBe(`${FP.slice(0, 12)}…`);
    expect(shortResourceId("certificates")).toBe("certificates");
  });

  it("shows the name as primary text with type and short ID beneath, full ID in the tooltip", async () => {
    renderAudit();
    const row = (
      await screen.findByRole("button", { name: "certificate.revoke" })
    ).closest("tr")!;
    expect(within(row).getByText("api.example.com")).toBeInTheDocument();
    expect(
      within(row).getByText(`certificate · ${FP.slice(0, 12)}…`),
    ).toBeInTheDocument();
    expect(within(row).queryByText(FP)).not.toBeInTheDocument();
    expect(row.querySelector(`[title="certificate:${FP}"]`)).not.toBeNull();
  });

  it("falls back to the ID when no name was resolved", async () => {
    renderAudit();
    const row = (
      await screen.findByRole("button", { name: "certificate.issue" })
    ).closest("tr")!;
    expect(within(row).getByText("certificates")).toBeInTheDocument();
  });

  it("keeps the full ID in the detail pane", async () => {
    renderAudit();
    await screen.findByRole("button", { name: "certificate.revoke" });
    // The first row is selected by default.
    await waitFor(() =>
      expect(screen.getByText(`certificate:${FP}`)).toBeInTheDocument(),
    );
  });

  // W22-05: the CSV is built server-side now (no resource_name column: the
  // server file carries the stored fields plus tenant), so the page only has
  // to hand the applied filters to the streaming endpoint.
  it("exports through the server endpoint instead of building a client CSV", async () => {
    vi.mocked(api.auditExport).mockResolvedValue(undefined as unknown as never);
    renderAudit();
    await screen.findByRole("button", { name: "certificate.revoke" });
    await userEvent.click(screen.getByRole("button", { name: /export csv/i }));
    await waitFor(() => expect(api.auditExport).toHaveBeenCalledTimes(1));
    expect(vi.mocked(api.auditExport).mock.calls[0][0]).toMatchObject({ format: "csv" });
  });
});
