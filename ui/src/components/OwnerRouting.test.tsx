import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      notificationTeamRoutes: vi.fn(),
      createNotificationTeamRoute: vi.fn(),
      deleteNotificationTeamRoute: vi.fn(),
      ownerlessCertificates: vi.fn(),
    },
  };
});

import OwnerRouting from "./OwnerRouting";
import { api } from "../lib/api";

function renderPanel(canManage: boolean) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <OwnerRouting canManage={canManage} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.notificationTeamRoutes).mockResolvedValue({
    data: {
      items: [
        {
          id: "a",
          owner_team: "!ownerless",
          channel: "slack",
          target: "#nobody",
        },
        {
          id: "b",
          owner_team: "*",
          channel: "email",
          target: "ops@example.com",
        },
      ],
    },
  } as unknown as never);
  vi.mocked(api.ownerlessCertificates).mockResolvedValue({
    data: {
      items: [
        {
          fingerprint_sha256: "fp1",
          common_name: "orphan.example.com",
          valid_until: "2026-11-01T00:00:00Z",
          days_left: 6,
        },
        {
          fingerprint_sha256: "fp2",
          common_name: "gone.example.com",
          valid_until: "2026-10-20T00:00:00Z",
          days_left: -5,
        },
      ],
    },
    meta: { total: 2 },
  } as unknown as never);
  vi.mocked(api.createNotificationTeamRoute).mockResolvedValue({
    data: {},
  } as unknown as never);
});

describe("OwnerRouting (W32-30)", () => {
  it("names the ownerless queue and the global inbox and lists ownerless certificates", async () => {
    renderPanel(true);
    expect(
      await screen.findByText("Ownerless queue", { selector: "li span" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Global inbox", { selector: "li span" }),
    ).toBeInTheDocument();
    expect(await screen.findByText("orphan.example.com")).toBeInTheDocument();
    expect(screen.getByText("6d left")).toBeInTheDocument();
    expect(screen.getByText("expired")).toBeInTheDocument();
  });

  it("creates an ownerless-queue route with the reserved owner_team value", async () => {
    const user = userEvent.setup();
    renderPanel(true);
    await screen.findByText("Global inbox", { selector: "li span" });
    await user.selectOptions(
      screen.getByLabelText("Route applies to"),
      "!ownerless",
    );
    await user.type(screen.getByLabelText("Route target"), "#unowned");
    await user.click(screen.getByRole("button", { name: "Add route" }));
    await waitFor(() =>
      expect(api.createNotificationTeamRoute).toHaveBeenCalledWith({
        owner_team: "!ownerless",
        channel: "slack",
        target: "#unowned",
      }),
    );
  });

  it("hides editing from a read-only viewer", async () => {
    renderPanel(false);
    await screen.findByText("Global inbox", { selector: "li span" });
    expect(screen.queryByRole("button", { name: "Add route" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Delete route/ })).toBeNull();
  });
});
