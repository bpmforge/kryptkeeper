import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    tenantContext: vi.fn(),
    tenants: vi.fn(),
    createTenant: vi.fn(),
    mapCATenant: vi.fn(),
    mapTemplateTenant: vi.fn(),
    cas: vi.fn(),
    templates: vi.fn(),
  },
}));

import Tenants from "../pages/Tenants";
import { api } from "../lib/api";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Tenants />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const superCtx = {
  data: {
    enabled: true,
    super_admin: true,
    tenant: "default",
    scoped: false,
    tenants: [{ id: "acme", name: "Acme Corp", created_at: "2026-06-18" }],
  },
};

beforeEach(() => {
  vi.clearAllMocks();
  (api.cas as ReturnType<typeof vi.fn>).mockResolvedValue({
    data: { items: [{ id: "ca-1", display_name: "Root CA" }] },
  });
  (api.templates as ReturnType<typeof vi.fn>).mockResolvedValue({
    data: { items: [{ id: "tpl-1", display_name: "TLS Server" }] },
  });
});

describe("Tenants page", () => {
  it("shows the off-state when multi-tenancy is disabled", async () => {
    (api.tenantContext as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: {
        enabled: false,
        super_admin: true,
        tenant: "default",
        scoped: false,
        tenants: [],
      },
    });
    renderPage();
    expect(
      await screen.findByText(/Multi-tenancy is off/i),
    ).toBeInTheDocument();
  });

  it("no longer labels multi-tenancy experimental (W22-03)", async () => {
    (api.tenantContext as ReturnType<typeof vi.fn>).mockResolvedValue(superCtx);
    renderPage();
    await screen.findAllByText("Acme Corp");
    expect(screen.queryByText(/experimental/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/not a security boundary/i)).not.toBeInTheDocument();
  });

  it("renders the tenant list and create form for a super-admin", async () => {
    (api.tenantContext as ReturnType<typeof vi.fn>).mockResolvedValue(superCtx);
    renderPage();
    expect((await screen.findAllByText("Acme Corp")).length).toBeGreaterThan(0);
    expect(
      screen.getByRole("button", { name: /Create tenant/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Assign CA/i }),
    ).toBeInTheDocument();
  });

  it("creates a tenant", async () => {
    (api.tenantContext as ReturnType<typeof vi.fn>).mockResolvedValue(superCtx);
    (api.createTenant as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { id: "globex", name: "Globex", created_at: "x" },
    });
    renderPage();
    await screen.findAllByText("Acme Corp");
    await userEvent.type(screen.getByPlaceholderText("acme"), "globex");
    await userEvent.type(screen.getByPlaceholderText("Acme Corp"), "Globex");
    await userEvent.click(
      screen.getByRole("button", { name: /Create tenant/i }),
    );
    await waitFor(() =>
      expect(api.createTenant).toHaveBeenCalledWith({
        id: "globex",
        name: "Globex",
      }),
    );
  });

  it("shows a read-only badge for a non-super principal", async () => {
    (api.tenantContext as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: {
        enabled: true,
        super_admin: false,
        tenant: "acme",
        scoped: true,
        tenants: [],
      },
    });
    renderPage();
    expect(
      await screen.findByText(/Tenant administration is restricted/i),
    ).toBeInTheDocument();
    // CB-12: say why a named admin cannot administer tenants.
    expect(screen.getByText(/only the raw bootstrap/i)).toBeInTheDocument();
  });
});
