import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    trustBundles: vi.fn(),
    trustBundle: vi.fn(),
    proposeTrustBundle: vi.fn(),
  },
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { TrustStoresPanel } from "./TrustStores";
import { api } from "../lib/api";
import type { AgentInfo } from "../lib/models";

const agents = [
  { id: "ag-1", name: "web-1", type: "linux" },
  { id: "ag-2", name: "win-1", type: "windows" },
] as unknown as AgentInfo[];

const bundle = {
  id: "tb-1",
  name: "Corp Root 2027",
  action: "add" as const,
  certs: [
    {
      sha256: "ab",
      subject: "CN=Root",
      issuer: "CN=Root",
      not_after: "",
      root: true,
    },
  ],
  agent_ids: ["ag-1", "ag-2"],
  created_by: "alice",
  approved_by: "bob",
  created_at: "",
  targets: 2,
  applied: 1,
  refused_not_opted_in: 1,
  failed: 0,
  pending: 0,
};

function renderPanel() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <TrustStoresPanel agents={agents} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("TrustStoresPanel (W40-03)", () => {
  beforeEach(() => {
    vi.mocked(api.trustBundles).mockResolvedValue({ data: [bundle] });
    vi.mocked(api.trustBundle).mockResolvedValue({
      data: {
        bundle,
        hosts: [
          {
            agent_id: "ag-1",
            agent_name: "web-1",
            outcome: "applied",
            detail: "added 1 certificate(s)",
          },
          {
            agent_id: "ag-2",
            agent_name: "win-1",
            outcome: "refused_not_opted_in",
            detail: "not opted in",
          },
        ],
      },
    });
    vi.mocked(api.proposeTrustBundle).mockReset();
  });

  it("shows per-host results for a bundle", async () => {
    renderPanel();
    await userEvent.click(
      await screen.findByRole("button", { name: /Corp Root 2027/ }),
    );
    const table = await screen.findByTestId("trust-hosts");
    expect(table).toHaveTextContent("web-1");
    expect(table).toHaveTextContent("applied");
    expect(table).toHaveTextContent("win-1");
    expect(table).toHaveTextContent("refused: not opted in");
  });

  it("will not submit without a certificate and a target", async () => {
    renderPanel();
    const submit = await screen.findByRole("button", {
      name: "Propose for approval",
    });
    expect(submit).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/^Name/), "rollover");
    await userEvent.type(
      screen.getByLabelText(/CA certificates/),
      "-----BEGIN CERTIFICATE-----",
    );
    expect(submit).toBeDisabled();
    await userEvent.click(screen.getByLabelText("Every Linux agent"));
    expect(submit).toBeEnabled();
  });

  it("proposes and surfaces the removal warning for the approver", async () => {
    vi.mocked(api.proposeTrustBundle).mockResolvedValue({
      data: {
        action_id: "act-1",
        status: "pending",
        targets: 1,
        warnings: [
          "removing the root of hub CA X distrusts 3 live managed certificate(s)",
        ],
      },
    });
    renderPanel();
    await userEvent.type(await screen.findByLabelText(/^Name/), "retire");
    await userEvent.click(screen.getByLabelText(/Remove/));
    await userEvent.type(screen.getByLabelText(/CA certificates/), "pem");
    await userEvent.click(screen.getByLabelText("web-1", { exact: false }));
    await userEvent.click(
      screen.getByRole("button", { name: "Propose for approval" }),
    );
    await waitFor(() => expect(api.proposeTrustBundle).toHaveBeenCalled());
    expect(vi.mocked(api.proposeTrustBundle).mock.calls[0][0]).toMatchObject({
      name: "retire",
      action: "remove",
      selector: { all: false, agent_types: [], agent_ids: ["ag-1"] },
    });
    expect(await screen.findByTestId("trust-warnings")).toHaveTextContent(
      "distrusts 3 live managed certificate(s)",
    );
  });
});
