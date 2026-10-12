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
