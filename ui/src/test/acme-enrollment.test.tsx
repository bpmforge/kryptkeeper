import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import axe from "axe-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: { authzCheck: vi.fn(), cas: vi.fn(), templates: vi.fn() },
}));
vi.mock("../lib/acmeApi", async (orig) => {
  const actual = await orig<typeof import("../lib/acmeApi")>();
  return {
    ...actual,
    acmeApi: {
      eabList: vi.fn(),
      eabCreate: vi.fn(),
      eabRevoke: vi.fn(),
      provList: vi.fn(),
      provCreate: vi.fn(),
      provUpdate: vi.fn(),
      provDelete: vi.fn(),
    },
  };
});

import AcmeEnrollment from "../pages/AcmeEnrollment";
import { api } from "../lib/api";
import { acmeApi, validateAllowEntry } from "../lib/acmeApi";

const m = <T,>(f: T) => f as unknown as ReturnType<typeof vi.fn>;

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AcmeEnrollment />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const keys = [
  { kid: "kid", label: "ci runner", provisioner: "internal", created_by: "a", created_at: "2026-10-01T10:00:00Z", last_used_at: null, revoked_at: null, uses: 0 },
  { kid: "kid2", label: "old", created_at: "2026-09-01T10:00:00Z", last_used_at: "2026-09-15T12:00:00Z", revoked_at: null, uses: 3 },
  { kid: "kid3", label: "dead", created_at: "2026-08-01T10:00:00Z", revoked_at: "2026-08-02T10:00:00Z", uses: 1 },
];
const provs = [
  { name: "internal", ca_id: "ca-1", allow_names: ["*.internal"], challenges: [], directory_url: "https://pki.example/acme/internal/directory" },
];

beforeEach(() => {
  vi.clearAllMocks();
  m(api.authzCheck).mockResolvedValue({ role: "pki-admin", scopes: [] });
  m(api.cas).mockResolvedValue({ data: { items: [{ id: "ca-1", display_name: "Root CA" }] } });
  m(api.templates).mockResolvedValue({ data: { items: [{ id: "tpl-1", display_name: "TLS" }] } });
  m(acmeApi.eabList).mockResolvedValue({ data: keys });
  m(acmeApi.provList).mockResolvedValue({ data: provs });
});

describe("ACME enrollment page", () => {
  it("lists keys with last used", async () => {
    renderPage();
    const row = (await screen.findByText("ci runner")).closest("tr")!;
    expect(within(row).getByText("never")).toBeInTheDocument();
    const row2 = screen.getByText("old").closest("tr")!;
    expect(within(row2).queryByText("never")).toBeNull();
    expect(within(row2).getByText(/Sep 15, 2026/)).toBeInTheDocument();
    expect(within(screen.getByText("dead").closest("tr")!).getByText("revoked")).toBeInTheDocument();
  });

  it("creating a key shows the secret once", async () => {
    m(acmeApi.eabCreate).mockResolvedValue({
      data: { kid: "newkid", hmac_key: "SECRET-HMAC-VALUE", created_at: "2026-10-16T00:00:00Z" },
    });
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    renderPage();
    await screen.findByText("ci runner");
    await user.click(screen.getByRole("button", { name: /new key/i }));
    await user.type(screen.getByLabelText("Label"), "laptop");
    await user.click(screen.getByRole("button", { name: "Create key" }));
    expect(acmeApi.eabCreate).toHaveBeenCalledWith({ label: "laptop" });
    const secret = await screen.findByDisplayValue("SECRET-HMAC-VALUE");
    expect(secret).toBeInTheDocument();
    expect(screen.getByText(/shown once and cannot be retrieved again/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Copy HMAC key" }));
    expect(writeText).toHaveBeenCalledWith("SECRET-HMAC-VALUE");
    await user.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByDisplayValue("SECRET-HMAC-VALUE")).toBeNull());
    expect(document.body.textContent).not.toContain("SECRET-HMAC-VALUE");
    // A refetch (the API never returns key material) cannot bring it back.
    expect(JSON.stringify(m(acmeApi.eabList).mock.results)).not.toContain("SECRET-HMAC-VALUE");
  });

  it("revoke asks for confirmation", async () => {
    m(acmeApi.eabRevoke).mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("ci runner");
    await user.click(screen.getByRole("button", { name: "Revoke kid" }));
    expect(screen.getByText(/can no longer register accounts/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(acmeApi.eabRevoke).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Revoke kid" }));
    await user.click(screen.getByRole("button", { name: "Revoke key" }));
    await waitFor(() => expect(acmeApi.eabRevoke).toHaveBeenCalledWith("kid"));
  });

  it("provisioner form rejects bad allow entries", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("tab", { name: "Provisioners" }));
    await user.click(await screen.findByRole("button", { name: /new provisioner/i }));
    await user.type(screen.getByLabelText("Name"), "edge");
    await user.selectOptions(screen.getByLabelText("CA"), "ca-1");
    const area = screen.getByLabelText(/Allowed names/);
    const save = screen.getByRole("button", { name: "Save" });
    expect(save).toBeDisabled();
    for (const bad of ["example..com", "*.", "10.0.0.1", "-a.internal"]) {
      await user.clear(area);
      await user.type(area, bad);
      expect(area).toHaveAttribute("aria-invalid", "true");
      expect(area).toHaveAttribute("aria-describedby");
      expect(save).toBeDisabled();
    }
    await user.clear(area);
    await user.type(area, "*.internal{Enter}host.example.com");
    expect(area).not.toHaveAttribute("aria-invalid");
    expect(save).toBeEnabled();
  });

  it("validateAllowEntry mirrors the server", () => {
    for (const ok of ["*.internal", "host.example.com", "A.Example.com"]) expect(validateAllowEntry(ok)).toBeNull();
    for (const bad of ["example..com", "*.", "10.0.0.1", "-a.internal", "localhost", "a.com:80", "a b.com", "*.*.com"])
      expect(validateAllowEntry(bad)).not.toBeNull();
  });

  it("non-admin sees the role message", async () => {
    m(api.authzCheck).mockResolvedValue({ role: "pki-operator", scopes: [] });
    renderPage();
    expect(await screen.findByText("pki-admin role required")).toBeInTheDocument();
    expect(acmeApi.eabList).not.toHaveBeenCalled();
  });

  it("no serious or critical axe violations", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    await screen.findByText("ci runner");
    const run = async () => {
      const r = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
      return r.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
    };
    expect(await run()).toEqual([]);
    await user.click(screen.getByRole("tab", { name: "Provisioners" }));
    await screen.findByText("*.internal");
    expect(await run()).toEqual([]);
  });
});
