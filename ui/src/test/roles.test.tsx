import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/rolesApi", async (orig) => {
  const actual = await orig<typeof import("../lib/rolesApi")>();
  return {
    ...actual,
    rolesApi: {
      list: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      remove: vi.fn(),
      sod: vi.fn(),
      preview: vi.fn(),
    },
  };
});
vi.mock("../lib/api", () => ({ api: { authzCheck: vi.fn() } }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import Roles from "../pages/Roles";
import { PERMISSIONS, rolesApi, sodViolations } from "../lib/rolesApi";
import { api } from "../lib/api";
import { toast } from "sonner";

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Roles />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const builtinSod = { permission_a: "action.propose", permission_b: "action.approve", builtin: true };

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue({
    principal: "admin@example.com",
    role: "pki-admin",
    scopes: ["*"],
  } as never);
  vi.mocked(rolesApi.list).mockResolvedValue({
    data: [
      { name: "pki-admin", builtin: true },
      { name: "ops-lead", builtin: false, permissions: ["certificate.read"], tenant_id: "acme" },
    ],
  });
  vi.mocked(rolesApi.sod).mockResolvedValue({ data: [builtinSod] });
});

async function openNewRole(name: string) {
  renderPage();
  await screen.findByText("ops-lead");
  await userEvent.click(screen.getByRole("button", { name: /new role/i }));
  await userEvent.type(screen.getByLabelText(/role name/i), name);
}

describe("Roles page", () => {
  it("builds a role from the permission list and creates it", async () => {
    vi.mocked(rolesApi.create).mockResolvedValue({ data: { name: "viewer", description: "", permissions: [] } });
    await openNewRole("viewer");
    await userEvent.type(screen.getByLabelText(/description/i), "read only");
    await userEvent.click(screen.getByLabelText("certificate.read"));
    await userEvent.click(screen.getByLabelText("report.read"));
    await userEvent.click(screen.getByRole("button", { name: /create role/i }));
    await waitFor(() =>
      expect(rolesApi.create).toHaveBeenCalledWith({
        name: "viewer",
        description: "read only",
        permissions: ["certificate.read", "report.read"],
      }),
    );
  });

  it("shows the SoD alert and disables Save before any API call", async () => {
    await openNewRole("both");
    await screen.findByText("ops-lead");
    await waitFor(() => expect(rolesApi.sod).toHaveBeenCalled());
    await userEvent.click(screen.getByLabelText("action.propose"));
    await userEvent.click(screen.getByLabelText("action.approve"));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "action.propose and action.approve cannot be held by one role",
    );
    expect(screen.getByRole("button", { name: /create role/i })).toBeDisabled();
    expect(rolesApi.create).not.toHaveBeenCalled();
  });

  it("honours a custom constraint from the server", async () => {
    vi.mocked(rolesApi.sod).mockResolvedValue({
      data: [builtinSod, { id: "c1", permission_a: "ca.manage", permission_b: "key.manage" }],
    });
    await openNewRole("keys");
    await userEvent.click(screen.getByLabelText("ca.manage"));
    await userEvent.click(screen.getByLabelText("key.manage"));
    expect(await screen.findByRole("alert")).toHaveTextContent("ca.manage and key.manage");
    expect(screen.getByRole("button", { name: /create role/i })).toBeDisabled();
  });

  it("surfaces the server's refusal verbatim", async () => {
    vi.mocked(rolesApi.create).mockRejectedValue(new Error("you do not hold user.manage"));
    await openNewRole("grant");
    await userEvent.click(screen.getByLabelText("user.manage"));
    await userEvent.click(screen.getByRole("button", { name: /create role/i }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith("you do not hold user.manage"));
  });

  it("rejects a name that is a built-in role", async () => {
    await openNewRole("pki-admin");
    expect(await screen.findByText(/built-in role/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /create role/i })).toBeDisabled();
  });

  it("offers no edit or delete on built-in rows", async () => {
    renderPage();
    await screen.findByText("ops-lead");
    expect(screen.queryByRole("button", { name: /delete pki-admin/i })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /delete ops-lead/i })).toBeInTheDocument();
    expect(screen.getByText("Tenant acme")).toBeInTheDocument();
  });

  it("shows Not permitted to a non-admin", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({
      principal: "ops@example.com",
      role: "pki-operator",
      scopes: [],
    } as never);
    renderPage();
    await screen.findByText("Not permitted");
    expect(rolesApi.list).not.toHaveBeenCalled();
  });

  it("pins the 16-entry permission vocabulary", () => {
    expect(PERMISSIONS.length).toBe(16);
  });
});

describe("sodViolations", () => {
  const cs = [builtinSod, { permission_a: "ca.manage", permission_b: "key.manage" }];
  it("returns none when no pair is complete", () => {
    expect(sodViolations(["action.propose", "ca.manage"], cs)).toEqual([]);
  });
  it("returns the matching constraint", () => {
    expect(sodViolations(["ca.manage", "key.manage"], cs)).toEqual([cs[1]]);
  });
  it("catches the builtin pair", () => {
    expect(sodViolations(["action.approve", "action.propose"], cs)).toEqual([builtinSod]);
  });
  it("does not repeat a duplicated constraint", () => {
    const dup = [...cs, { permission_a: "key.manage", permission_b: "ca.manage" }];
    expect(sodViolations(["ca.manage", "key.manage"], dup)).toHaveLength(1);
  });
});
