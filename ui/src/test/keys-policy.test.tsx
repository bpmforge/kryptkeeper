import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    keys: vi.fn(),
    keyPolicy: vi.fn(),
    setKeyPolicy: vi.fn(),
    compromiseKey: vi.fn(),
    blastRadius: vi.fn(),
  },
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import Keys from "../pages/Keys";
import { api } from "../lib/api";
import { toast } from "sonner";

function setup() {
  vi.mocked(api.authzCheck).mockResolvedValue({
    authenticated: true,
    role: "pki-admin",
    scopes: ["*"],
  } as unknown as never);
  vi.mocked(api.keys).mockResolvedValue({
    data: [
      { id: "key-1", algorithm: "ECDSA-P256", created_at: "2026-04-01T00:00:00Z" },
    ],
  } as unknown as never);
  vi.mocked(api.keyPolicy).mockResolvedValue({ data: null });
  vi.mocked(api.blastRadius).mockResolvedValue({
    data: {
      severity: "high",
      total_affected: 3,
      affected_by_kind: { cert: ["c1", "c2", "c3"] },
    },
  } as unknown as never);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Keys />
    </QueryClientProvider>,
  );
}

beforeEach(() => vi.clearAllMocks());

async function openPolicy(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "Policy key-1" }));
  await waitFor(() => expect(api.keyPolicy).toHaveBeenCalledWith("key-1"));
  await waitFor(() => expect(screen.getByLabelText("Owner")).toBeEnabled());
}

describe("Keys policy and compromise (W23-40)", () => {
  it("policy form saves owner ACL and max age", async () => {
    vi.mocked(api.setKeyPolicy).mockResolvedValue({
      data: { key_id: "key-1", owner: "alice", acl: ["bob", "carol"], max_age_days: 90 },
    });
    const user = userEvent.setup();
    setup();
    await openPolicy(user);
    await user.type(screen.getByLabelText("Owner"), "alice");
    await user.type(screen.getByLabelText("ACL"), "bob, carol, bob");
    await user.clear(screen.getByLabelText("Max age days"));
    await user.type(screen.getByLabelText("Max age days"), "90");
    await user.click(screen.getByRole("button", { name: /save policy/i }));
    await waitFor(() =>
      expect(api.setKeyPolicy).toHaveBeenCalledWith("key-1", {
        owner: "alice",
        acl: ["bob", "carol"],
        max_age_days: 90,
      }),
    );
    expect(toast.success).toHaveBeenCalledWith("Key policy saved");
  });

  it("rejects negative max age and empty owner", async () => {
    const user = userEvent.setup();
    setup();
    await openPolicy(user);
    await user.click(screen.getByRole("button", { name: /save policy/i }));
    expect(await screen.findByText(/owner is required/i)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Owner"), "alice");
    fireEvent.change(screen.getByLabelText("Max age days"), {
      target: { value: "-5" },
    });
    await user.click(screen.getByRole("button", { name: /save policy/i }));
    expect(await screen.findByText(/0 or more/i)).toBeInTheDocument();
    expect(api.setKeyPolicy).not.toHaveBeenCalled();
  });

  async function openCompromise(user: ReturnType<typeof userEvent.setup>) {
    await user.click(
      await screen.findByRole("button", { name: "Compromised key-1" }),
    );
    await screen.findByText(/3 affected/i);
  }

  it("compromise shows blast radius then pending state", async () => {
    vi.mocked(api.compromiseKey).mockResolvedValue({
      proposed: true,
      actionId: "act-7",
    });
    const user = userEvent.setup();
    setup();
    await openCompromise(user);
    expect(api.blastRadius).toHaveBeenCalledWith("revoke", "key-1");
    const confirm = screen.getByRole("button", { name: /propose compromise/i });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText("Confirm key id"), "key-1");
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    await waitFor(() => expect(api.compromiseKey).toHaveBeenCalledWith("key-1"));
    await waitFor(() =>
      expect(vi.mocked(toast.success).mock.calls[0][0]).toMatch(/proposed/i),
    );
    expect(await screen.findByText(/act-7/)).toBeInTheDocument();
    expect(screen.queryByText("compromised")).not.toBeInTheDocument();
  });

  it("compromise error is surfaced", async () => {
    vi.mocked(api.compromiseKey).mockRejectedValue(new Error("key has no policy"));
    const user = userEvent.setup();
    setup();
    await openCompromise(user);
    await user.type(screen.getByLabelText("Confirm key id"), "key-1");
    await user.click(screen.getByRole("button", { name: /propose compromise/i }));
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith("key has no policy"),
    );
    expect(toast.success).not.toHaveBeenCalled();
  });
});
