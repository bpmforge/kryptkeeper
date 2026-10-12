import { render, screen, within } from "@testing-library/react";
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
import { AUDIT_OUTCOMES, auditOutcomeTone } from "../lib/auditOutcome";

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
    data: [],
    meta: { total: 0, limit: 50 },
    principal: "auditor-1",
  } as unknown as never);
});

describe("audit outcome vocabulary", () => {
  it("covers every backend outcome and classes adverse ones", () => {
    expect(AUDIT_OUTCOMES.map((o) => o.value).sort()).toEqual([
      "denied",
      "executed",
      "failure",
      "issuance_failed",
      "partial",
      "pending_approval",
      "proposed",
      "skipped",
      "success",
    ]);
    for (const o of ["failure", "denied", "issuance_failed", "partial"]) {
      expect(["danger", "warning"]).toContain(auditOutcomeTone(o));
    }
    for (const o of ["success", "executed"])
      expect(auditOutcomeTone(o)).toBe("success");
    for (const o of [
      "skipped",
      "pending_approval",
      "proposed",
      "something-new",
    ])
      expect(auditOutcomeTone(o)).toBe("neutral");
  });

  it("offers every outcome in the Audit filter", async () => {
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <MemoryRouter>
          <Audit />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const select = await screen.findByLabelText("Filter audit outcome");
    const labels = within(select)
      .getAllByRole("option")
      .map((o) => o.textContent);
    expect(labels).toEqual([
      "All outcomes",
      "Success",
      "Executed",
      "Failure",
      "Issuance failed",
      "Denied",
      "Partial",
      "Skipped",
      "Pending approval",
      "Proposed",
    ]);
  });
});
