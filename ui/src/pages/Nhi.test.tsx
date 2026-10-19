import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  fetchJSON: vi.fn(),
  api: { authzCheck: vi.fn() },
}));

import Nhi from "./Nhi";
import { api, fetchJSON } from "../lib/api";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Nhi />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const pending = {
  id: "nhi-1",
  name: "checkout-agent",
  kind: "ai_agent",
  spiffe_id: "spiffe://example.org/nhi/ai_agent/checkout-agent",
  scopes: ["certificate.read", "action.propose"],
  status: "pending",
  created_by: "alice",
  created_at: "2026-10-16T00:00:00Z",
};

function mockApi(
  items: unknown[],
  handler?: (path: string, init?: RequestInit) => unknown,
) {
  vi.mocked(fetchJSON).mockImplementation((async (
    path: string,
    init?: RequestInit,
  ) => {
    if (path === "/nhi/identities" && (!init || !init.method)) {
      return { data: items };
    }
    if (handler) return handler(path, init);
    return undefined;
  }) as never);
}

function mockPrincipal(principal: string) {
  vi.mocked(api.authzCheck).mockResolvedValue({
    service: "x",
    authenticated: true,
    principal,
    role: "pki-admin",
  } as never);
}

function posts(): [string, RequestInit | undefined][] {
  return vi
    .mocked(fetchJSON)
    .mock.calls.filter(([, init]) => init?.method === "POST") as never;
}

beforeEach(() => {
  vi.resetAllMocks();
  mockPrincipal("bob");
});

describe("Nhi page", () => {
  it("lists identities with status and scopes", async () => {
    mockApi([pending]);
    renderPage();
    expect(await screen.findByText("checkout-agent")).toBeInTheDocument();
    expect(screen.getByText("pending")).toBeInTheDocument();
    expect(screen.getByText("certificate.read")).toBeInTheDocument();
    expect(screen.getByText("action.propose")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
  });

  it("proposes with scopes from the shared vocabulary", async () => {
    const user = userEvent.setup();
    mockApi([], () => ({ data: pending }));
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: /Propose identity/ }),
    );
    const submit = screen.getByRole("button", { name: "Propose" });
    expect(submit).toBeDisabled(); // no name, no scope

    await user.type(screen.getByLabelText("Name"), "Bad_Name");
    await user.click(screen.getByLabelText("certificate.read"));
    expect(submit).toBeDisabled(); // invalid name

    await user.clear(screen.getByLabelText("Name"));
    await user.type(screen.getByLabelText("Name"), "new-agent");
    await user.click(screen.getByLabelText("certificate.read")); // untick
    expect(submit).toBeDisabled(); // zero scopes
    await user.click(screen.getByLabelText("certificate.read"));
    expect(submit).toBeEnabled();
    await user.click(submit);

    await waitFor(() => expect(posts()).toHaveLength(1));
    const [path, init] = posts()[0];
    expect(path).toBe("/nhi/identities");
    expect(JSON.parse(String(init?.body))).toEqual({
      name: "new-agent",
      kind: "ai_agent",
      scopes: ["certificate.read"],
    });
  });

  it("approve is disabled for the proposer and enabled for others", async () => {
    mockPrincipal("alice");
    mockApi([pending]);
    const first = renderPage();
    const btn = await screen.findByRole("button", {
      name: "Approve checkout-agent",
    });
    await waitFor(() => expect(btn).toBeDisabled());
    first.unmount();

    mockPrincipal("bob");
    renderPage();
    const other = await screen.findByRole("button", {
      name: "Approve checkout-agent",
    });
    await waitFor(() => expect(other).toBeEnabled());
  });

  it("self-approve 403 shows the server message", async () => {
    const user = userEvent.setup();
    mockApi([pending], () => {
      throw Object.assign(
        new Error("self-approval is not permitted: you proposed this"),
        { status: 403 },
      );
    });
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Approve checkout-agent" }),
    );
    expect(
      await screen.findByText(/self-approval is not permitted/),
    ).toBeInTheDocument();
  });

  it("join token is shown once", async () => {
    const user = userEvent.setup();
    mockApi([pending], () => ({
      data: {
        id: "nhi-1",
        spiffe_id: pending.spiffe_id,
        join_token: "tok-secret-123",
        token_expires_at: "2026-10-17T00:00:00Z",
      },
    }));
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Approve checkout-agent" }),
    );
    expect(await screen.findByText("tok-secret-123")).toBeInTheDocument();
    expect(screen.getByText(/shown once/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() =>
      expect(screen.queryByText("tok-secret-123")).not.toBeInTheDocument(),
    );
    // The refetch after the mutation must not bring it back.
    await screen.findByText("checkout-agent");
    expect(screen.queryByText("tok-secret-123")).not.toBeInTheDocument();
  });

  it("revoke asks for confirmation", async () => {
    const user = userEvent.setup();
    mockApi([{ ...pending, status: "approved" }]);
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Revoke checkout-agent" }),
    );
    expect(posts()).toHaveLength(0);
    expect(screen.getByText(/cannot be undone/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(posts()).toHaveLength(1));
    expect(posts()[0][0]).toBe("/nhi/identities/nhi-1/revoke");
  });
});
