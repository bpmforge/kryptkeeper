import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    ceremonies: vi.fn(),
    startCeremony: vi.fn(),
    approveCeremony: vi.fn(),
    abortCeremony: vi.fn(),
    authzCheck: vi.fn(),
  },
}));

import Ceremonies from "./Ceremonies";
import { api } from "../lib/api";
import type { Ceremony } from "../lib/models";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Ceremonies />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const base: Ceremony = {
  id: "cer-1",
  ca_id: "ca-9",
  ca_name: "Root Alpha",
  common_name: "Alpha Root CA",
  algorithm: "ECDSA-P256",
  validity_days: 3650,
  initiator: "carol",
  approvers: ["alice", "bob", "carol"],
  quorum: 2,
  approvals: [],
  status: "pending",
  created_at: "2026-10-01T00:00:00Z",
  expires_at: "2026-10-04T00:00:00Z",
};

function mockList(...items: Ceremony[]) {
  vi.mocked(api.ceremonies).mockResolvedValue({ data: items } as never);
}

function mockPrincipal(principal: string, role = "pki-admin") {
  vi.mocked(api.authzCheck).mockResolvedValue({
    service: "x",
    authenticated: true,
    principal,
    role,
  } as never);
}

beforeEach(() => {
  vi.resetAllMocks();
  mockPrincipal("alice");
});

describe("Ceremonies page", () => {
  it("lists ceremonies with quorum progress", async () => {
    mockList({ ...base, approvals: ["bob"] });
    renderPage();
    expect(await screen.findByText("1 of 2 approvals")).toBeInTheDocument();
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "1");
    expect(screen.getByText(/Expires/)).toBeInTheDocument();
    expect(
      within(screen.getByRole("list", { name: "Approvers" })).getByText("bob")
        .textContent,
    ).toContain("(approved)");
  });

  it("start ceremony submits the form", async () => {
    mockList();
    vi.mocked(api.startCeremony).mockResolvedValue({ data: base } as never);
    renderPage();
    await userEvent.click(
      await screen.findByRole("button", { name: /start ceremony/i }),
    );
    const dlg = await screen.findByRole("dialog");
    await userEvent.type(within(dlg).getByLabelText("Name"), "Root Alpha");
    await userEvent.type(within(dlg).getByLabelText("Common name"), "Alpha Root CA");
    await userEvent.type(
      within(dlg).getByLabelText("Approvers"),
      "alice, bob, bob, carol",
    );
    await userEvent.click(within(dlg).getByRole("button", { name: /^start$/i }));
    await waitFor(() =>
      expect(api.startCeremony).toHaveBeenCalledWith({
        name: "Root Alpha",
        common_name: "Alpha Root CA",
        algorithm: "ECDSA-P256",
        validity_days: 3650,
        approvers: ["alice", "bob", "carol"],
        quorum: 2,
      }),
    );
  });

  it("rejects quorum 1 client side", async () => {
    mockList();
    renderPage();
    await userEvent.click(
      await screen.findByRole("button", { name: /start ceremony/i }),
    );
    const dlg = await screen.findByRole("dialog");
    await userEvent.type(within(dlg).getByLabelText("Approvers"), "alice, bob");
    const quorum = within(dlg).getByLabelText("Quorum");
    await userEvent.clear(quorum);
    await userEvent.type(quorum, "1");
    await userEvent.click(within(dlg).getByRole("button", { name: /^start$/i }));
    expect(
      await within(dlg).findByText(/Quorum must be at least 2/),
    ).toBeInTheDocument();
    expect(api.startCeremony).not.toHaveBeenCalled();
  });

  it("approve calls the API and refreshes", async () => {
    mockList(base);
    vi.mocked(api.approveCeremony).mockResolvedValue({ data: base } as never);
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /^approve/i }));
    await waitFor(() => expect(api.approveCeremony).toHaveBeenCalledWith("cer-1"));
    await waitFor(() => expect(api.ceremonies).toHaveBeenCalledTimes(2));
  });

  it("abort asks for confirmation then calls the API", async () => {
    mockList(base);
    vi.mocked(api.abortCeremony).mockResolvedValue({ data: base } as never);
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /^abort/i }));
    expect(api.abortCeremony).not.toHaveBeenCalled();
    await userEvent.click(
      await screen.findByRole("button", { name: /confirm abort/i }),
    );
    await waitFor(() => expect(api.abortCeremony).toHaveBeenCalledWith("cer-1"));
  });

  it("approve is disabled for a principal who already approved", async () => {
    mockList({ ...base, approvals: ["alice"] });
    renderPage();
    const btn = await screen.findByRole("button", { name: /^approve/i });
    await waitFor(() => expect(btn).toBeDisabled());
    expect(screen.getByTitle("You have already approved")).toBeInTheDocument();
  });

  it("API error from approve is surfaced", async () => {
    mockList(base);
    vi.mocked(api.approveCeremony).mockRejectedValue(
      new Error('ceremony cer-1: "alice" has already approved'),
    );
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /^approve/i }));
    expect(
      await screen.findByText('ceremony cer-1: "alice" has already approved'),
    ).toBeInTheDocument();
  });

  it("expired ceremony shows the expired state and no actions", async () => {
    mockList({ ...base, status: "expired" });
    renderPage();
    expect(
      await screen.findByText("Expired: the parked CA was never activated."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^approve/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /^abort/i })).toBeNull();
  });

  it("completed and aborted show no actions", async () => {
    mockList(
      { ...base, id: "c1", ca_name: "Done", status: "completed", approvals: ["alice", "bob"] },
      { ...base, id: "c2", ca_name: "Gone", status: "aborted" },
    );
    renderPage();
    await screen.findByText("Done");
    expect(screen.queryByRole("button", { name: /^approve/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /^abort/i })).toBeNull();
  });

  it("non-designated principal sees Approve disabled", async () => {
    mockPrincipal("mallory");
    mockList(base);
    renderPage();
    const btn = await screen.findByRole("button", { name: /^approve/i });
    await waitFor(() => expect(btn).toBeDisabled());
    expect(screen.getByTitle("You are not a designated approver")).toBeInTheDocument();
  });

  it("shows the empty state", async () => {
    mockList();
    renderPage();
    expect(await screen.findByText("No ceremonies yet")).toBeInTheDocument();
  });

  it("shows the admin message on 403", async () => {
    vi.mocked(api.ceremonies).mockRejectedValue(
      Object.assign(new Error("forbidden"), { status: 403 }),
    );
    renderPage();
    expect(
      await screen.findByText("Key ceremonies need an administrator role."),
    ).toBeInTheDocument();
  });
});
