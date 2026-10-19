import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));
vi.mock("../lib/api", () => ({
  api: {
    inventorySources: vi.fn(),
    createInventorySource: vi.fn(),
    syncInventorySource: vi.fn(),
    deleteInventorySource: vi.fn(),
    credentials: vi.fn(),
  },
}));

import InventorySources from "./InventorySources";
import { api } from "../lib/api";
import { toast } from "sonner";

function src(over: Record<string, unknown> = {}) {
  return {
    id: "s1",
    name: "Prod DigiCert",
    type: "digicert",
    config_json: '{"secret_url":"https://internal.example"}',
    credential_ref: "c1",
    schedule_minutes: 60,
    tenant: "default",
    last_sync_at: "2026-10-01T12:00:00Z",
    last_sync_result: '{"synced":5,"skipped":2,"revoked_marked":0,"failed":[]}',
    created_at: "2026-09-01T00:00:00Z",
    updated_at: "2026-10-01T12:00:00Z",
    ...over,
  };
}

function list(...s: unknown[]) {
  return { data: s } as never;
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <InventorySources />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.credentials).mockResolvedValue({
    data: { items: [{ id: "c1", name: "digicert-key", credential_type: "api_token" }] },
  } as never);
  vi.mocked(api.inventorySources).mockResolvedValue(list());
});

describe("InventorySources", () => {
  it("lists sources with type, schedule, last sync and result", async () => {
    vi.mocked(api.inventorySources).mockResolvedValue(
      list(
        src(),
        src({
          id: "s2",
          name: "Broken Sectigo",
          type: "sectigo",
          schedule_minutes: 0,
          last_sync_at: undefined,
          last_sync_result: '{"error":"digicert returned 401"}',
        }),
      ),
    );
    renderPage();
    expect(await screen.findByText("Prod DigiCert")).toBeInTheDocument();
    expect(screen.getByText("every 60 min")).toBeInTheDocument();
    expect(screen.getByText(/5 new, 2 existing/)).toBeInTheDocument();
    expect(screen.getByText("Manual")).toBeInTheDocument();
    expect(screen.getByText("Never")).toBeInTheDocument();
    expect(screen.getByText("digicert returned 401")).toBeInTheDocument();
    expect(screen.getByText("Failed")).toBeInTheDocument();
    // config_json is never displayed in the table
    expect(screen.queryByText(/internal\.example/)).not.toBeInTheDocument();
  });

  it("creates a source with a credential picker", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createInventorySource).mockResolvedValue({ data: src() } as never);
    renderPage();
    await screen.findByText("No inventory sources");
    await user.type(screen.getByLabelText("Source name"), "My DC");
    await user.selectOptions(screen.getByLabelText("Source type"), "digicert");
    await screen.findByRole("option", { name: "digicert-key" });
    await user.selectOptions(screen.getByLabelText("Credential"), "c1");
    await user.clear(screen.getByLabelText("Schedule minutes"));
    await user.type(screen.getByLabelText("Schedule minutes"), "30");
    await user.click(screen.getByRole("button", { name: "Add source" }));
    await waitFor(() =>
      expect(api.createInventorySource).toHaveBeenCalledWith({
        name: "My DC",
        type: "digicert",
        config_json: '{"base_url":"https://www.digicert.com"}',
        credential_ref: "c1",
        schedule_minutes: 30,
      }),
    );
  });

  it("blocks create when credential missing for a vendor type", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("No inventory sources");
    await user.type(screen.getByLabelText("Source name"), "My DC");
    expect(screen.getByRole("button", { name: "Add source" })).toBeDisabled();
    // adcs_export needs no credential
    await user.selectOptions(screen.getByLabelText("Source type"), "adcs_export");
    expect(screen.getByRole("button", { name: "Add source" })).toBeEnabled();
  });

  it("invalid JSON config disables submit", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("No inventory sources");
    await user.type(screen.getByLabelText("Source name"), "x");
    await user.selectOptions(screen.getByLabelText("Source type"), "adcs_export");
    const cfg = screen.getByLabelText("Configuration JSON");
    await user.clear(cfg);
    await user.type(cfg, "not json");
    expect(screen.getByRole("button", { name: "Add source" })).toBeDisabled();
    expect(screen.getByText(/not valid JSON/)).toBeInTheDocument();
  });

  it("sync now calls the API, toasts and refetches", async () => {
    const user = userEvent.setup();
    vi.mocked(api.inventorySources).mockResolvedValue(list(src()));
    vi.mocked(api.syncInventorySource).mockResolvedValue({
      data: { synced: 3, skipped: 4, revoked_marked: 0, failed: [] },
    } as never);
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Sync Prod DigiCert now" }),
    );
    await waitFor(() => expect(api.syncInventorySource).toHaveBeenCalledWith("s1"));
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith("Synced: 3 new, 4 existing"),
    );
    await waitFor(() =>
      expect(vi.mocked(api.inventorySources).mock.calls.length).toBeGreaterThan(1),
    );
  });

  it("sync failure toasts the server message", async () => {
    const user = userEvent.setup();
    vi.mocked(api.inventorySources).mockResolvedValue(list(src()));
    vi.mocked(api.syncInventorySource).mockRejectedValue(new Error("vendor 401"));
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Sync Prod DigiCert now" }),
    );
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith("vendor 401"));
  });

  it("delete asks for confirmation mentioning synced certificates stay, then deletes", async () => {
    const user = userEvent.setup();
    vi.mocked(api.inventorySources).mockResolvedValue(list(src()));
    vi.mocked(api.deleteInventorySource).mockResolvedValue(undefined as never);
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Delete Prod DigiCert" }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText(/Already-synced certificates stay in inventory/),
    ).toBeInTheDocument();
    expect(api.deleteInventorySource).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: "Delete source" }));
    await waitFor(() => expect(api.deleteInventorySource).toHaveBeenCalledWith("s1"));
  });

  it("unparseable last_sync_result does not crash", async () => {
    vi.mocked(api.inventorySources).mockResolvedValue(
      list(src({ last_sync_result: "{not json" })),
    );
    renderPage();
    expect(await screen.findByText("Unreadable result")).toBeInTheDocument();
  });
});
