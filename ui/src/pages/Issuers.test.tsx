import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    connectors: vi.fn(),
    cas: vi.fn(),
    testConnector: vi.fn(),
    deleteConnector: vi.fn(),
    createConnector: vi.fn(),
    createCredential: vi.fn(),
    createExternalCa: vi.fn(),
  },
}));

import Issuers from "./Issuers";
import { api } from "../lib/api";

const vault = {
  id: "c1",
  name: "Prod Vault",
  type: "vault_pki",
  tenant: "default",
  health: { status: "healthy" },
};

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Issuers />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Issuers", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(api.authzCheck).mockResolvedValue({
      principal: "a",
      role: "pki-admin",
      scopes: [],
    } as unknown as never);
    vi.mocked(api.cas).mockResolvedValue({
      data: [
        { id: "ca1", name: "Vault CA", type: "external", connector_id: "c1" },
      ],
    } as unknown as never);
  });

  it("explains the empty state", async () => {
    vi.mocked(api.connectors).mockResolvedValue({ data: [] });
    renderPage();
    expect(
      await screen.findByText(/Add the CA you already use/),
    ).toBeInTheDocument();
  });

  it("lists issuers with type, health and the CAs that use them", async () => {
    vi.mocked(api.connectors).mockResolvedValue({ data: [vault] });
    renderPage();
    expect(await screen.findByText("Prod Vault")).toBeInTheDocument();
    expect(screen.getByText("HashiCorp Vault PKI")).toBeInTheDocument();
    expect(screen.getByText("healthy")).toBeInTheDocument();
    expect(await screen.findByText("Vault CA")).toBeInTheDocument();
  });

  it("tests a connection and shows the result", async () => {
    vi.mocked(api.connectors).mockResolvedValue({ data: [vault] });
    vi.mocked(api.testConnector).mockResolvedValue({
      status: "degraded",
      detail: "slow",
    });
    renderPage();
    await userEvent.click(
      await screen.findByRole("button", { name: "Test Prod Vault" }),
    );
    expect(await screen.findByText("degraded: slow")).toBeInTheDocument();
  });

  it("shows the server message when delete is blocked with a 409", async () => {
    vi.mocked(api.connectors).mockResolvedValue({ data: [vault] });
    vi.mocked(api.deleteConnector).mockRejectedValue(
      Object.assign(new Error("In use by CA Vault CA"), { status: 409 }),
    );
    renderPage();
    await userEvent.click(
      await screen.findByRole("button", { name: "Delete Prod Vault" }),
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Delete issuer" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "In use by CA Vault CA",
    );
  });

  it("hides write actions for non-admins", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({
      principal: "a",
      role: "viewer",
      scopes: [],
    } as unknown as never);
    vi.mocked(api.connectors).mockResolvedValue({ data: [vault] });
    renderPage();
    await screen.findByText("Prod Vault");
    expect(
      screen.queryByRole("button", { name: "Add issuer" }),
    ).not.toBeInTheDocument();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Delete Prod Vault" }),
      ).toBeDisabled(),
    );
  });
});
