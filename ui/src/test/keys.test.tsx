import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    keys: vi.fn(),
    generateKey: vi.fn(),
    rotateKey: vi.fn(),
    exportKey: vi.fn(),
    importKey: vi.fn(),
    deleteKey: vi.fn(),
    cancelKeyDeletion: vi.fn(),
  },
}));

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

import Keys from "../pages/Keys";
import { api } from "../lib/api";
import { toast } from "sonner";

function renderWithQuery() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <Keys />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

const keysMock = [
  { id: "key-1", algorithm: "ECDSA-P256", created_at: "2026-04-01T00:00:00Z" },
  { id: "key-2", algorithm: "ECDSA-P256", created_at: "2026-04-02T00:00:00Z" },
];

describe("Keys page bulk actions (W8-11)", () => {
  it("selects multiple keys and bulk rotates, reporting per-item partial failure", async () => {
    vi.mocked(api.keys).mockResolvedValue({
      data: keysMock,
    } as unknown as never);
    vi.mocked(api.rotateKey)
      .mockResolvedValueOnce({ data: {} } as unknown as never)
      .mockRejectedValueOnce(new Error("HSM unavailable"));

    const user = userEvent.setup();
    renderWithQuery();

    const checkboxes = await screen.findAllByRole("checkbox", {
      name: /select key-/i,
    });
    expect(checkboxes).toHaveLength(2);
    await user.click(checkboxes[0]);
    await user.click(checkboxes[1]);
    expect(screen.getByText(/2 selected/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /bulk rotate/i }));
    const dialog = screen.getByRole("dialog", {
      name: /bulk rotate 2 keys/i,
    });
    await user.click(
      within(dialog).getByRole("button", { name: /^rotate 2$/i }),
    );

    await waitFor(() => expect(api.rotateKey).toHaveBeenCalledTimes(2));
    expect(api.rotateKey).toHaveBeenNthCalledWith(1, "key-1", "ECDSA-P256");
    expect(api.rotateKey).toHaveBeenNthCalledWith(2, "key-2", "ECDSA-P256");

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        expect.stringMatching(/1 of 2 rotations failed/i),
      ),
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("selects multiple keys and bulk deletes after confirmation", async () => {
    vi.mocked(api.keys).mockResolvedValue({
      data: keysMock,
    } as unknown as never);
    vi.mocked(api.deleteKey).mockResolvedValue(undefined as unknown as never);

    const user = userEvent.setup();
    renderWithQuery();

    await user.click(
      await screen.findByRole("button", { name: /^select all$/i }),
    );
    expect(screen.getByText(/2 selected/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /bulk delete/i }));
    const dialog = screen.getByRole("dialog", {
      name: /bulk delete 2 keys/i,
    });
    await user.click(
      within(dialog).getByRole("button", { name: /^delete 2$/i }),
    );

    await waitFor(() => expect(api.deleteKey).toHaveBeenCalledTimes(2));
    expect(api.deleteKey).toHaveBeenCalledWith("key-1");
    expect(api.deleteKey).toHaveBeenCalledWith("key-2");
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith(
        expect.stringMatching(/2 keys deleted/i),
      ),
    );
  });
});

describe("Keys page pending deletion (W23-23)", () => {
  const listed = [
    { id: "live-key", algorithm: "ECDSA-P256", created_at: "2026-01-01T00:00:00Z" },
    {
      id: "gone-key",
      algorithm: "RSA-3072",
      created_at: "2026-01-01T00:00:00Z",
      state: "pending_deletion",
      deletion_scheduled_at: "2026-11-01T12:00:00Z",
    },
  ];

  function rowOf(id: string) {
    return screen.getByText(id).closest("tr") as HTMLElement;
  }

  it("shows pending_deletion badge and scheduled date for a pending key", async () => {
    vi.mocked(api.keys).mockResolvedValue({ data: listed } as unknown as never);
    renderWithQuery();
    await screen.findByText("gone-key");
    const pending = rowOf("gone-key");
    expect(within(pending).getByText("Pending deletion")).toBeInTheDocument();
    expect(
      within(pending).getByText(
        `Deletes ${new Date("2026-11-01T12:00:00Z").toLocaleDateString()}`,
      ),
    ).toBeInTheDocument();
    expect(within(pending).queryByTitle("Delete key")).toBeNull();
    expect(within(pending).queryByTitle("Rotate key")).toBeNull();
    expect(within(pending).getByTitle("Cancel deletion")).toBeInTheDocument();
    const live = rowOf("live-key");
    expect(within(live).queryByText("Pending deletion")).toBeNull();
    expect(within(live).getByTitle("Delete key")).toBeInTheDocument();
    expect(within(live).queryByTitle("Cancel deletion")).toBeNull();
  });

  it("cancel deletion proposes via dual control and points to Pending Actions", async () => {
    vi.mocked(api.keys).mockResolvedValue({ data: listed } as unknown as never);
    vi.mocked(api.cancelKeyDeletion).mockResolvedValue({
      data: { status: "proposed", action_id: "a1" },
    } as unknown as never);
    const user = userEvent.setup();
    renderWithQuery();
    await screen.findByText("gone-key");
    await user.click(within(rowOf("gone-key")).getByTitle("Cancel deletion"));
    const dialog = screen.getByRole("dialog", { name: /cancel deletion/i });
    await user.click(
      within(dialog).getByRole("button", { name: /confirm cancel deletion/i }),
    );
    await waitFor(() => expect(api.cancelKeyDeletion).toHaveBeenCalledWith("gone-key"));
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith(
        expect.stringContaining("Pending Actions"),
      ),
    );
    expect(toast.success).not.toHaveBeenCalledWith(
      expect.stringMatching(/re-enabled/i),
    );
  });

  it("cancel deletion reports re-enabled only when dual control is off (direct)", async () => {
    vi.mocked(api.keys).mockResolvedValue({ data: listed } as unknown as never);
    vi.mocked(api.cancelKeyDeletion).mockResolvedValue(undefined as unknown as never);
    const user = userEvent.setup();
    renderWithQuery();
    await screen.findByText("gone-key");
    await user.click(within(rowOf("gone-key")).getByTitle("Cancel deletion"));
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: /confirm cancel deletion/i }),
    );
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith("Deletion cancelled. Key re-enabled."),
    );
  });

  it("cancel deletion surfaces a 409 from the server", async () => {
    vi.mocked(api.keys).mockResolvedValue({ data: listed } as unknown as never);
    vi.mocked(api.cancelKeyDeletion).mockRejectedValue(new Error("outside provider window"));
    const user = userEvent.setup();
    renderWithQuery();
    await screen.findByText("gone-key");
    await user.click(within(rowOf("gone-key")).getByTitle("Cancel deletion"));
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: /confirm cancel deletion/i }),
    );
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith("outside provider window"),
    );
  });
});
