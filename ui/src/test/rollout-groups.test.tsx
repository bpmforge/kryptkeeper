import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: { authzCheck: vi.fn(), targets: vi.fn() },
  fetchJSON: vi.fn(),
}));

import RolloutGroups from "../pages/RolloutGroups";
import { api, fetchJSON } from "../lib/api";
import { navSections } from "../lib/nav";

const KEY = "kk.rollout-groups.v1";

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <RolloutGroups />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const target = (id: string, install_mode: string) => ({
  id,
  name: `node-${id}`,
  host: `${id}.example.com`,
  discovery_mode: "manual",
  install_mode,
  renewal_method: "acme",
  tenant: "default",
  created_at: "2026-10-01T00:00:00Z",
  updated_at: "2026-10-01T00:00:00Z",
});

const savedGroup = {
  name: "edge",
  nodes: [
    { target_id: "t1", is_canary: true },
    { target_id: "t2", is_canary: false },
    { target_id: "t3", is_canary: false },
  ],
  window: { start_hour: 22, end_hour: 4 },
};

const result = (over: Record<string, unknown> = {}) => ({
  data: {
    group: "edge",
    deferred: false,
    halted: false,
    mode: "staged",
    new_fingerprint: "abcdef0123456789abcdef",
    node_results: [
      { node_id: "t1", is_canary: true, outcome: "installed" },
      { node_id: "t2", is_canary: false, outcome: "skipped" },
    ],
    ...over,
  },
});

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  vi.mocked(api.authzCheck).mockResolvedValue({ principal: "admin", role: "pki-admin", scopes: ["*"] } as never);
  vi.mocked(api.targets).mockResolvedValue({
    data: [target("t1", "ssh"), target("t2", "ssh"), target("t3", "ssh"), target("t4", "local")],
  } as never);
});

async function runSaved() {
  window.localStorage.setItem(KEY, JSON.stringify([savedGroup]));
  renderPage();
  await userEvent.click(await screen.findByRole("button", { name: /^edge/ }));
  await userEvent.type(screen.getByLabelText("Certificate fingerprint"), "fp");
  await userEvent.click(screen.getByRole("button", { name: "Run rollout" }));
  await userEvent.click(await screen.findByRole("button", { name: "Confirm rollout" }));
}

describe("RolloutGroups page", () => {
  it("lists saved groups and runs a rollout with canary and UTC window", async () => {
    vi.mocked(fetchJSON).mockResolvedValue(
      result({
        halted: true,
        halt_reason: "canary verify failed",
        node_results: [
          { node_id: "t1", is_canary: true, outcome: "rolled_back" },
          { node_id: "t2", is_canary: false, outcome: "rolled_back" },
          { node_id: "t3", is_canary: false, outcome: "failed", detail: "reload refused" },
        ],
      }),
    );
    await runSaved();

    await waitFor(() => expect(fetchJSON).toHaveBeenCalledTimes(1));
    const [path, init] = vi.mocked(fetchJSON).mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/renewal/rollout");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      fingerprint: "fp",
      group: "edge",
      nodes: [
        { target_id: "t1", is_canary: true },
        { target_id: "t2", is_canary: false },
        { target_id: "t3", is_canary: false },
      ],
      window: { start_hour: 22, end_hour: 4 },
    });

    const table = await screen.findByRole("table");
    expect(within(table).getAllByRole("row")).toHaveLength(4); // header + 3
    expect(within(table).getAllByText("rolled_back")).toHaveLength(2);
    expect(within(table).getByText("failed")).toBeInTheDocument();
    expect(within(table).getByText("reload refused")).toBeInTheDocument();
    expect(screen.getByText("canary verify failed")).toBeInTheDocument();
  });

  it("creates a group from targets and persists it", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /new group/i }));
    await screen.findByLabelText("node-t1 (ssh)", { exact: false });

    // No canary / nodes yet.
    await userEvent.type(screen.getByLabelText("Group name"), "pair");
    await userEvent.click(screen.getByRole("button", { name: "Save group" }));
    expect(await screen.findByText("Pick at least one node.")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("checkbox", { name: /node-t1/ }));
    await userEvent.click(screen.getByRole("checkbox", { name: /node-t2/ }));
    // Canary defaults to the first picked node; switch to t2.
    await userEvent.click(screen.getByRole("radio", { name: "node-t2" }));

    const end = screen.getByLabelText("Window end (UTC)");
    await userEvent.clear(end);
    await userEvent.type(end, "24");
    await userEvent.click(screen.getByRole("button", { name: "Save group" }));
    expect(await screen.findByText(/whole numbers from 0 to 23/)).toBeInTheDocument();

    await userEvent.clear(end);
    await userEvent.type(end, "4");
    await userEvent.clear(screen.getByLabelText("Window start (UTC)"));
    await userEvent.type(screen.getByLabelText("Window start (UTC)"), "22");
    await userEvent.click(screen.getByRole("button", { name: "Save group" }));

    expect(await screen.findByText(/2 nodes · canary node-t2 · 22:00-04:00 UTC/)).toBeInTheDocument();
    expect(JSON.parse(window.localStorage.getItem(KEY) ?? "[]")).toEqual([
      {
        name: "pair",
        nodes: [
          { target_id: "t1", is_canary: false },
          { target_id: "t2", is_canary: true },
        ],
        window: { start_hour: 22, end_hour: 4 },
      },
    ]);
  });

  it("rejects a group when the canary is missing", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /new group/i }));
    await userEvent.type(screen.getByLabelText("Group name"), "solo");
    // Picking then unpicking leaves no nodes and therefore no canary.
    await userEvent.click(screen.getByRole("checkbox", { name: /node-t1/ }));
    await userEvent.click(screen.getByRole("checkbox", { name: /node-t1/ }));
    await userEvent.click(screen.getByRole("button", { name: "Save group" }));
    expect(await screen.findByText("Pick at least one node.")).toBeInTheDocument();
    expect(window.localStorage.getItem(KEY)).toBeNull();
  });

  it("deferred result is explained", async () => {
    vi.mocked(fetchJSON).mockResolvedValue(result({ deferred: true, new_fingerprint: "", node_results: [] }));
    await runSaved();
    expect(await screen.findByText(/Deferred: outside the maintenance window/)).toBeInTheDocument();
  });

  it("shows an HTTP error and does not treat it as success", async () => {
    vi.mocked(fetchJSON).mockRejectedValue(new Error("403 a node is not visible"));
    await runSaved();
    expect(await screen.findByText("403 a node is not visible")).toBeInTheDocument();
  });

  it("non-admin sees Not permitted and no fetch of targets happens", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({ principal: "op", role: "pki-operator", scopes: [] } as never);
    renderPage();
    expect(await screen.findByText("Not permitted")).toBeInTheDocument();
    expect(api.targets).not.toHaveBeenCalled();
  });

  it("is reachable from the nav for pki-admin only", () => {
    const item = navSections.flatMap((s) => s.items).find((i) => i.to === "/renewal/rollout-groups");
    expect(item?.permission?.("pki-admin")).toBe(true);
    expect(item?.permission?.("pki-operator")).toBe(false);
  });

  it("passes axe with 0 serious or critical violations", async () => {
    vi.mocked(fetchJSON).mockResolvedValue(result());
    window.localStorage.setItem(KEY, JSON.stringify([savedGroup]));
    const { container } = renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /^edge/ }));
    await userEvent.type(screen.getByLabelText("Certificate fingerprint"), "fp");
    await userEvent.click(screen.getByRole("button", { name: "Run rollout" }));
    await userEvent.click(await screen.findByRole("button", { name: "Confirm rollout" }));
    await screen.findByRole("table");

    const axe = (await import("axe-core")).default;
    // color-contrast is disabled because jsdom cannot compute rendered colours.
    const r = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(r.violations.filter((v) => v.impact === "serious" || v.impact === "critical")).toEqual([]);
  });
});
