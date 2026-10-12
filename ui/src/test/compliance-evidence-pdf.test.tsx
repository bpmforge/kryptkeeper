import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    complianceEvidence: vi.fn(),
    complianceEvidencePdfUrl: (fw: string) =>
      `/api/v1/reports/compliance-evidence?framework=${fw}&format=pdf`,
  },
}));

import ComplianceEvidence from "../pages/ComplianceEvidence";
import { api } from "../lib/api";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ComplianceEvidence />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.complianceEvidence).mockResolvedValue({
    data: {
      generated_at: "2026-06-17T00:00:00Z",
      framework: "all",
      controls: [
        {
          id: "4.2.1.1",
          framework: "pci",
          title: "Inventory",
          status: "pass",
          evidence: "ok",
        },
      ],
      summary: { pass: 1, warn: 0, fail: 0 },
    },
  } as unknown as never);
});

describe("ComplianceEvidence — PDF download", () => {
  it("offers an evidence-pack PDF download for the selected framework", async () => {
    renderPage();

    // The export is now an authenticated fetch (Bearer clients got a 401
    // body named .pdf from the old bare anchor), so assert the control, not
    // an href.
    const button = await screen.findByRole("button", {
      name: /evidence pack \(pdf\)/i,
    });
    expect(button).toBeInTheDocument();
  });
});
