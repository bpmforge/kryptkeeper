import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    cas: vi.fn(),
    revokeCa: vi.fn(),
    blastRadius: vi.fn(),
    activateCa: vi.fn(),
    suspendCa: vi.fn(),
    updateCa: vi.fn(),
    createCa: vi.fn(),
  },
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import CAs from "../pages/CAs";
import { api } from "../lib/api";
import { toast } from "sonner";

function setup(role: string, status = "active") {
  vi.mocked(api.authzCheck).mockResolvedValue({
    authenticated: true,
    role,
    scopes: role === "pki-admin" ? ["*"] : [],
  } as unknown as never);
  vi.mocked(api.cas).mockResolvedValue({
    data: {
      items: [
        {
          id: "ca-1",
          display_name: "Issuing CA",
          type: "intermediate",
          key_storage_type: "software",
          status,
        },
      ],
    },
  } as unknown as never);
  vi.mocked(api.blastRadius).mockResolvedValue({
    data: {
      severity: "high",
      total_affected: 2,
      affected_by_kind: { cert: ["c1", "c2"] },
    },
  } as unknown as never);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <CAs />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => vi.clearAllMocks());

async function openRevoke(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: /issuing ca/i }));
  await user.click(await screen.findByRole("button", { name: /^revoke ca$/i }));
}

describe("CA revoke (W23-36)", () => {
  it("shows blast-radius preview before confirm", async () => {
    const user = userEvent.setup();
    setup("pki-admin");
    await openRevoke(user);
    const confirm = screen.getByRole("button", { name: /propose revocation/i });
    expect(confirm).toBeDisabled();
    await screen.findByText(/2 affected/i);
    expect(api.blastRadius).toHaveBeenCalledWith("retire_ca", "ca-1");
    expect(confirm).toBeDisabled(); // preview loaded but id not typed
    await user.type(screen.getByPlaceholderText("CA id"), "ca-1");
    expect(confirm).toBeEnabled();
  });

  it("shows pending state on 202 and never marks the CA revoked", async () => {
    vi.mocked(api.revokeCa).mockResolvedValue({
      proposed: true,
      actionId: "act-9",
    });
    const user = userEvent.setup();
    setup("pki-admin");
    await openRevoke(user);
    await screen.findByText(/2 affected/i);
    await user.type(screen.getByPlaceholderText("CA id"), "ca-1");
    await user.click(screen.getByRole("button", { name: /propose revocation/i }));
    await waitFor(() => expect(api.revokeCa).toHaveBeenCalledWith("ca-1"));
    await waitFor(() =>
      expect(vi.mocked(toast.success).mock.calls[0][0]).toMatch(/proposed/i),
    );
    expect(await screen.findByText(/act-9/)).toBeInTheDocument();
    expect(screen.queryByText("revoked")).not.toBeInTheDocument();
    expect(screen.getAllByText("Active").length).toBeGreaterThan(0);
  });

  it("revoked CA hides issuance actions", async () => {
    const user = userEvent.setup();
    setup("pki-admin", "revoked");
    await user.click(await screen.findByRole("button", { name: /issuing ca/i }));
    expect(await screen.findByText("CA revoked")).toBeInTheDocument();
    for (const n of [/^activate$/i, /^suspend$/i, /^update$/i, /^revoke ca$/i, /^re-key$/i]) {
      expect(screen.queryByRole("button", { name: n })).not.toBeInTheDocument();
    }
  });

  it("non-admin does not see Revoke", async () => {
    const user = userEvent.setup();
    setup("pki-operator");
    await user.click(await screen.findByRole("button", { name: /issuing ca/i }));
    await screen.findByRole("button", { name: /^suspend$/i });
    expect(
      screen.queryByRole("button", { name: /^revoke ca$/i }),
    ).not.toBeInTheDocument();
  });
});
