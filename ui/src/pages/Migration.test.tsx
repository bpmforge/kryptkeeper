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
    migrationSources: vi.fn(),
    migrationDryRun: vi.fn(),
    migrationApply: vi.fn(),
    migrationBatches: vi.fn(),
    migrationReport: vi.fn(),
    migrationRollback: vi.fn(),
  },
}));

import Migration from "./Migration";
import { api } from "../lib/api";
import { toast } from "sonner";

const diff = {
  source: "vault",
  entries: [
    {
      source_key: "k1",
      name: "web-role",
      action: "create",
      fields: [
        { field: "ttl", status: "mapped", target: "validity_days" },
        { field: "key_usage", status: "partial", note: "approximated" },
        { field: "ext_custom", status: "unmapped" },
      ],
    },
    {
      source_key: "k2",
      name: "db-role",
      action: "create",
      fields: [{ field: "ttl", status: "mapped" }],
    },
    {
      source_key: "k3",
      name: "old-role",
      action: "conflict",
      reason: "template exists with different settings",
      fields: [],
    },
  ],
  counts: { create: 2, skip: 0, conflict: 1 },
  unmapped: 1,
  unsupported: 0,
};

const batches = [
  { id: "b-applied", source: "vault", status: "applied", created_by: "alice", created_at: "2026-10-01T00:00:00Z" },
  { id: "b-done", source: "adcs", status: "rolled_back", created_by: "bob", created_at: "2026-09-01T00:00:00Z" },
];

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Migration />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.migrationSources).mockResolvedValue({
    data: ["adcs", "certcentral", "keyfactor", "vault", "venafi"],
  } as never);
  vi.mocked(api.migrationBatches).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.migrationDryRun).mockResolvedValue({ data: diff } as never);
});

async function pickVault(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByRole("option", { name: "Vault" });
  await user.selectOptions(screen.getByLabelText("Source system"), "vault");
}

async function uploadAndDryRun(user: ReturnType<typeof userEvent.setup>) {
  await pickVault(user);
  const file = new File(['{"roles":[]}'], "roles.json", { type: "application/json" });
  await user.upload(screen.getByLabelText("Export file"), file);
  await waitFor(() => expect(screen.getByLabelText("Paste export")).toHaveValue('{"roles":[]}'));
  await user.click(screen.getByRole("button", { name: "Dry run" }));
  await screen.findByText("2 create");
}

describe("Migration", () => {
  it("renders the source options from the API", async () => {
    renderPage();
    for (const n of ["Adcs", "Certcentral", "Keyfactor", "Vault", "Venafi"]) {
      expect(await screen.findByRole("option", { name: n })).toBeInTheDocument();
    }
  });

  it("dry run shows the diff counts and rows", async () => {
    const user = userEvent.setup();
    renderPage();
    await pickVault(user);
    await user.type(screen.getByLabelText("Paste export"), "x");
    await user.click(screen.getByRole("button", { name: "Dry run" }));
    expect(await screen.findByText("2 create")).toBeInTheDocument();
    expect(screen.getByText("1 conflict")).toBeInTheDocument();
    expect(screen.getByText("1 unmapped fields")).toBeInTheDocument();
    expect(screen.getByText("template exists with different settings")).toBeInTheDocument();
    expect(screen.getByText("1 mapped / 1 partial / 1 unmapped")).toBeInTheDocument();
  });

  it("acceptance flow: upload, dry run, submit for approval, planned report", async () => {
    const user = userEvent.setup();
    vi.mocked(api.migrationApply).mockResolvedValue({
      data: { status: "pending_approval", pending_action_id: "pa-1", diff },
    } as never);
    renderPage();
    await uploadAndDryRun(user);
    expect(api.migrationDryRun).toHaveBeenCalledWith({ source: "vault", content: '{"roles":[]}' });
    await user.click(screen.getByRole("button", { name: "Submit for approval" }));
    await waitFor(() =>
      expect(api.migrationApply).toHaveBeenCalledWith({ source: "vault", content: '{"roles":[]}' }),
    );
    expect(await screen.findByText(/Submitted for approval \(id pa-1\)/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Pending Actions/ })).toHaveAttribute("href", "/pending-actions");
    expect(screen.getByText("Planned report")).toBeInTheDocument();
    expect(screen.getAllByText("Mapped (1)").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Partial \(/).length).toBeGreaterThan(0);
    expect(screen.getAllByText("ext_custom").length).toBeGreaterThan(0);
  });

  it("credential_ref path for adcs", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("option", { name: "Adcs" });
    await user.selectOptions(screen.getByLabelText("Source system"), "adcs");
    const dry = screen.getByRole("button", { name: "Dry run" });
    expect(dry).toBeDisabled();
    await user.type(screen.getByLabelText("Credential reference"), "cred-1");
    await user.type(screen.getByLabelText("Base DN"), "DC=corp,DC=example");
    expect(dry).toBeEnabled();
    await user.click(dry);
    await waitFor(() =>
      expect(api.migrationDryRun).toHaveBeenCalledWith({
        source: "adcs",
        credential_ref: "cred-1",
        options: { base_dn: "DC=corp,DC=example" },
      }),
    );
  });

  it("submit disabled until a dry run with creates; editing clears the diff", async () => {
    const user = userEvent.setup();
    renderPage();
    await pickVault(user);
    expect(screen.getByRole("button", { name: "Submit for approval" })).toBeDisabled();
    await user.type(screen.getByLabelText("Paste export"), "abc");
    expect(screen.getByRole("button", { name: "Submit for approval" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Dry run" }));
    await screen.findByText("2 create");
    expect(screen.getByRole("button", { name: "Submit for approval" })).toBeEnabled();
    await user.type(screen.getByLabelText("Paste export"), "d");
    expect(screen.queryByText("2 create")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Submit for approval" })).toBeDisabled();
  });

  it("submit stays disabled when the dry run would create nothing", async () => {
    const user = userEvent.setup();
    vi.mocked(api.migrationDryRun).mockResolvedValue({
      data: { ...diff, counts: { create: 0, skip: 1, conflict: 0 } },
    } as never);
    renderPage();
    await pickVault(user);
    await user.type(screen.getByLabelText("Paste export"), "abc");
    await user.click(screen.getByRole("button", { name: "Dry run" }));
    await screen.findByText("0 create");
    expect(screen.getByRole("button", { name: "Submit for approval" })).toBeDisabled();
  });

  it("an update-only dry run can be submitted and shows the key-size note", async () => {
    const user = userEvent.setup();
    const note = 'key size raised from 2048 to 3072 to meet policy "Baseline"';
    vi.mocked(api.migrationDryRun).mockResolvedValue({
      data: {
        ...diff,
        entries: [{ source_key: "k9", name: "Workstation", action: "update", reason: "re-applied", notes: [note], fields: [] }],
        counts: { create: 0, skip: 0, conflict: 0, update: 1 },
      },
    } as never);
    renderPage();
    await pickVault(user);
    await user.type(screen.getByLabelText("Paste export"), "abc");
    await user.click(screen.getByRole("button", { name: "Dry run" }));
    expect(await screen.findByText("1 update")).toBeInTheDocument();
    expect(screen.getByText(note)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Submit for approval" })).toBeEnabled();
  });

  it("undo requires confirmation", async () => {
    const user = userEvent.setup();
    vi.mocked(api.migrationBatches).mockResolvedValue({ data: batches } as never);
    vi.mocked(api.migrationRollback).mockResolvedValue({
      data: { batch_id: "b-applied", already_rolled_back: false, disabled: 3, restored: 2, kept: 1, items: [] },
    } as never);
    renderPage();
    await screen.findByText("b-applied");
    expect(screen.getAllByRole("button", { name: /Undo migration/ })).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Undo migration b-applied" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/Nothing is deleted/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(api.migrationRollback).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Undo migration b-applied" }));
    const dialog2 = await screen.findByRole("dialog");
    await user.click(within(dialog2).getByRole("button", { name: "Undo migration" }));
    await waitFor(() => expect(api.migrationRollback).toHaveBeenCalledWith("b-applied"));
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith(
        "Disabled 3 template(s); restored 2; kept 1 with pending approvals.",
      ),
    );
  });

  it("view report loads the batch report", async () => {
    const user = userEvent.setup();
    vi.mocked(api.migrationBatches).mockResolvedValue({ data: batches } as never);
    vi.mocked(api.migrationReport).mockResolvedValue({
      data: { batch: batches[0], report: { batch_id: "b-applied", created: 1, entries: [diff.entries[0]] } },
    } as never);
    renderPage();
    await user.click(await screen.findByRole("button", { name: "View report for b-applied" }));
    await waitFor(() => expect(api.migrationReport).toHaveBeenCalledWith("b-applied"));
    expect(await screen.findByText("Report for batch b-applied")).toBeInTheDocument();
    expect(screen.getByText("web-role")).toBeInTheDocument();
  });
});
