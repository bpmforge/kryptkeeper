import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    templates: vi.fn(),
    templateRevisions: vi.fn(),
    updateTemplate: vi.fn(),
    createTemplate: vi.fn(),
    deleteTemplate: vi.fn(),
  },
}));

import Templates from "./Templates";
import { api } from "../lib/api";

const tpl = (over: Record<string, unknown> = {}) => ({
  id: "tpl-1",
  name: "web",
  display_name: "Web Server",
  key_usage: ["digitalSignature"],
  extended_key_usage: ["serverAuth"],
  allowed_algorithms: ["ECDSA"],
  validity_period: "90d",
  auto_enroll: false,
  active: true,
  revision: 3,
  issued_count: 0,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-02T00:00:00Z",
  ...over,
});

const revs = [
  { revision: 1, changed_at: "2026-01-01T00:00:00Z", snapshot: tpl(), changes: [] },
  {
    revision: 2,
    changed_at: "2026-01-02T00:00:00Z",
    snapshot: tpl(),
    changes: [{ field: "validity_period", old: "365d", new: "90d" }],
  },
  {
    revision: 3,
    changed_at: "2026-01-03T00:00:00Z",
    snapshot: tpl(),
    changes: [
      { field: "enrollment_permissions", old: null, new: { enroll: ["pki-admin"] } },
    ],
  },
];

function setup(templates: unknown[] = [tpl()]) {
  vi.mocked(api.templates).mockResolvedValue({
    data: templates,
    meta: {},
  } as unknown as never);
  vi.mocked(api.templateRevisions).mockResolvedValue({
    data: revs,
  } as unknown as never);
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <Templates />
    </QueryClientProvider>,
  );
}

async function openEdit(user: ReturnType<typeof userEvent.setup>, name = "Web Server") {
  await user.click((await screen.findAllByText(name))[0]);
  await user.click(await screen.findByRole("button", { name: /^edit$/i }));
  return await screen.findByRole("dialog");
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Templates enrollment permissions and history (W23-45)", () => {
  it("shows enrollment roles in the detail panel", async () => {
    const user = userEvent.setup();
    setup([
      tpl({ enrollment_permissions: { enroll: ["pki-admin"] } }),
      tpl({ id: "tpl-2", name: "ssh", display_name: "SSH Hosts" }),
    ]);
    await user.click((await screen.findAllByText("Web Server"))[0]);
    const cell = (await screen.findByText("Enrollment roles")).parentElement!;
    expect(within(cell).getByText("pki-admin")).toBeInTheDocument();
    await user.click(screen.getAllByText("SSH Hosts")[0]);
    expect(
      within((await screen.findByText("Enrollment roles")).parentElement!).getByText("Any role"),
    ).toBeInTheDocument();
  });

  it("edit dialog saves allowed roles and sends If-Match", async () => {
    const user = userEvent.setup();
    vi.mocked(api.updateTemplate).mockResolvedValue({ data: tpl() } as unknown as never);
    setup();
    const dlg = await openEdit(user);
    await user.type(within(dlg).getByLabelText(/roles allowed to enroll/i), "pki-admin, pki-operator");
    await user.click(within(dlg).getByRole("button", { name: /save|update/i }));
    await vi.waitFor(() => expect(api.updateTemplate).toHaveBeenCalled());
    const [id, body, rev] = vi.mocked(api.updateTemplate).mock.calls[0];
    expect(id).toBe("tpl-1");
    expect(body).toMatchObject({
      enrollment_permissions: { enroll: ["pki-admin", "pki-operator"] },
    });
    expect(rev).toBe(3);
  });

  it("quick-add role button appends once", async () => {
    const user = userEvent.setup();
    setup();
    const dlg = await openEdit(user);
    const input = within(dlg).getByLabelText(/roles allowed to enroll/i);
    await user.click(within(dlg).getByRole("button", { name: "auditor" }));
    await user.click(within(dlg).getByRole("button", { name: "auditor" }));
    await user.click(within(dlg).getByRole("button", { name: "viewer" }));
    expect(input).toHaveValue("auditor,viewer");
  });

  it("empty roles field sends an empty enroll list", async () => {
    const user = userEvent.setup();
    vi.mocked(api.updateTemplate).mockResolvedValue({ data: tpl() } as unknown as never);
    setup([tpl({ enrollment_permissions: { enroll: ["pki-admin"] } })]);
    const dlg = await openEdit(user);
    await user.clear(within(dlg).getByLabelText(/roles allowed to enroll/i));
    await user.click(within(dlg).getByRole("button", { name: /save|update/i }));
    await vi.waitFor(() => expect(api.updateTemplate).toHaveBeenCalled());
    expect(vi.mocked(api.updateTemplate).mock.calls[0][1]).toMatchObject({
      enrollment_permissions: { enroll: [] },
    });
  });

  it("renders revision history newest first with field diffs", async () => {
    const user = userEvent.setup();
    setup();
    await user.click((await screen.findAllByText("Web Server"))[0]);
    await screen.findByText("Initial revision");
    const headings = screen
      .getAllByRole("heading", { level: 4 })
      .map((h) => h.textContent ?? "");
    expect(headings.map((h) => h.match(/Revision (\d)/)![1])).toEqual(["3", "2", "1"]);
    const rows = screen.getAllByTestId("rev-change-row");
    expect(rows).toHaveLength(2);
    const row = rows.find((r) => r.textContent?.includes("validity_period"))!;
    expect(within(row).getByText("365d")).toBeInTheDocument();
    expect(within(row).getByText("90d")).toBeInTheDocument();
    expect(api.templateRevisions).toHaveBeenCalledWith("tpl-1");
    // CB-10: timestamps go through the shared formatter, never raw ISO.
    expect(screen.queryByText(/2026-01-03T00:00:00Z/)).not.toBeInTheDocument();
    expect(headings[0]).toMatch(/Jan \d+, 2026/);
  });

  it("history error shows History unavailable", async () => {
    const user = userEvent.setup();
    setup();
    vi.mocked(api.templateRevisions).mockRejectedValue(
      new Error("revision history not supported by this provider"),
    );
    await user.click((await screen.findAllByText("Web Server"))[0]);
    await screen.findByText("History unavailable");
    expect(screen.getByText(/not supported by this provider/)).toBeInTheDocument();
  });

  it("stale revision error shows reload message", async () => {
    const user = userEvent.setup();
    vi.mocked(api.updateTemplate).mockRejectedValue(new Error("if-match header required"));
    setup();
    const dlg = await openEdit(user);
    await user.click(within(dlg).getByRole("button", { name: /save|update/i }));
    await screen.findAllByText(/changed since you opened it\. Reload and retry\./);
    expect(vi.mocked(api.templates).mock.calls.length).toBeGreaterThan(1);
  });

  it("labels EKUs, shows neutral active status and auto-selects the first template", async () => {
    setup([
      tpl({ extended_key_usage: ["serverAuth", "clientAuth", "codeSigning"] }),
      tpl({ id: "tpl-2", name: "other", display_name: "Other" }),
    ]);
    expect(
      (await screen.findAllByText("Server auth, Client auth, Code signing"))
        .length,
    ).toBeGreaterThan(0);
    expect(screen.queryByText("serverAuth")).not.toBeInTheDocument();
    expect(screen.queryByText("No template selected")).not.toBeInTheDocument();
    expect(await screen.findByText("Enrollment roles")).toBeInTheDocument();
  });
});
