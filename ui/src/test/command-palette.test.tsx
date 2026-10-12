import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    search: vi.fn(),
    templates: vi.fn(),
    cas: vi.fn(),
    issueCertificate: vi.fn(),
    renewCertificate: vi.fn(),
    revokeCertificate: vi.fn(),
  },
}));

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

import { CommandPalette } from "../components/CommandPalette";
import { api } from "../lib/api";
import { toast } from "sonner";

// cmdk measures/scrolls its list via APIs jsdom does not implement.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal("ResizeObserver", ResizeObserverStub);
Element.prototype.scrollIntoView = vi.fn();

function renderPalette() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <CommandPalette />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function openPalette() {
  fireEvent.keyDown(document, { key: "k", metaKey: true });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("CommandPalette", () => {
  it("hides mutating actions from a role that cannot manage certificates", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({
      role: "auditor",
      scopes: [],
    } as unknown as never);

    renderPalette();
    openPalette();

    await screen.findByText("Dashboard");
    await waitFor(() => expect(api.authzCheck).toHaveBeenCalled());
    expect(screen.queryByText(/issue certificate…/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/renew certificate…/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/revoke certificate…/i)).not.toBeInTheDocument();
  });

  it("issues a certificate from the palette, routed through the approval+audit endpoint", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({
      role: "pki-operator",
      scopes: [],
    } as unknown as never);
    vi.mocked(api.templates).mockResolvedValue({
      data: {
        items: [
          { id: "tpl-1", name: "server-tls", display_name: "Server TLS" },
        ],
      },
    } as unknown as never);
    vi.mocked(api.cas).mockResolvedValue({
      data: { items: [{ id: "ca-root", display_name: "Root CA" }] },
    } as unknown as never);
    vi.mocked(api.issueCertificate).mockResolvedValue({
      data: { fingerprint_sha256: "fp-new" },
    } as unknown as never);

    const user = userEvent.setup();
    renderPalette();
    openPalette();

    await user.click(await screen.findByText(/issue certificate…/i));
    expect(await screen.findByText("Issue certificate")).toBeInTheDocument();

    const [templateSelect, caSelect] = screen.getAllByRole("combobox");
    await waitFor(() =>
      expect(screen.getByText("Server TLS")).toBeInTheDocument(),
    );
    await user.selectOptions(templateSelect, "tpl-1");
    await user.selectOptions(caSelect, "ca-root");
    await user.type(
      screen.getByPlaceholderText(/certificate request/i),
      "NEW-CSR",
    );
    await user.click(screen.getByRole("button", { name: /^issue$/i }));

    await waitFor(() =>
      expect(api.issueCertificate).toHaveBeenCalledWith({
        template_id: "tpl-1",
        ca_id: "ca-root",
        csr_pem: "NEW-CSR",
      }),
    );
    await waitFor(() => expect(toast.success).toHaveBeenCalled());
    // Palette resets and closes on success.
    expect(screen.queryByText("Issue certificate")).not.toBeInTheDocument();
  });

  it("surfaces a pending-approval outcome distinctly from an immediate issuance", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({
      role: "pki-operator",
      scopes: [],
    } as unknown as never);
    vi.mocked(api.templates).mockResolvedValue({
      data: {
        items: [
          { id: "tpl-1", name: "server-tls", display_name: "Server TLS" },
        ],
      },
    } as unknown as never);
    vi.mocked(api.cas).mockResolvedValue({
      data: { items: [{ id: "ca-root", display_name: "Root CA" }] },
    } as unknown as never);
    vi.mocked(api.issueCertificate).mockResolvedValue({
      status: "pending_approval",
      approval_id: "appr-1",
    } as unknown as never);

    const user = userEvent.setup();
    renderPalette();
    openPalette();

    await user.click(await screen.findByText(/issue certificate…/i));
    const [templateSelect, caSelect] = screen.getAllByRole("combobox");
    await waitFor(() =>
      expect(screen.getByText("Server TLS")).toBeInTheDocument(),
    );
    await user.selectOptions(templateSelect, "tpl-1");
    await user.selectOptions(caSelect, "ca-root");
    await user.type(
      screen.getByPlaceholderText(/certificate request/i),
      "NEW-CSR",
    );
    await user.click(screen.getByRole("button", { name: /^issue$/i }));

    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith(
        expect.stringMatching(/submitted for approval/i),
      ),
    );
  });

  it("renews a certificate: search for a target, then submit a CSR against its fingerprint", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({
      role: "pki-operator",
      scopes: [],
    } as unknown as never);
    vi.mocked(api.search).mockResolvedValue({
      data: [
        {
          kind: "certificate",
          id: "fp-1",
          label: "api.example.com",
          description: "Issued: 2026-01-01",
          url: "/certificates/fp-1",
        },
      ],
    } as unknown as never);
    vi.mocked(api.renewCertificate).mockResolvedValue({
      data: { fingerprint_sha256: "fp-1" },
    } as unknown as never);

    const user = userEvent.setup();
    renderPalette();
    openPalette();

    await user.click(await screen.findByText(/renew certificate…/i));
    await user.type(
      screen.getByPlaceholderText(/search certificates to renew/i),
      "api.example",
    );
    await user.click(await screen.findByText("api.example.com"));

    expect(await screen.findByText(/renew certificate/i)).toBeInTheDocument();
    await user.type(
      screen.getByPlaceholderText(/certificate request/i),
      "RENEW-CSR",
    );
    await user.click(screen.getByRole("button", { name: /confirm renew/i }));

    await waitFor(() =>
      expect(api.renewCertificate).toHaveBeenCalledWith("fp-1", {
        csr_pem: "RENEW-CSR",
      }),
    );
  });

  it("blocks revoke until REVOKE is typed, then submits the reason and fingerprint", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({
      role: "pki-operator",
      scopes: [],
    } as unknown as never);
    vi.mocked(api.search).mockResolvedValue({
      data: [
        {
          kind: "certificate",
          id: "fp-1",
          label: "api.example.com",
          description: "Issued: 2026-01-01",
          url: "/certificates/fp-1",
        },
      ],
    } as unknown as never);
    vi.mocked(api.revokeCertificate).mockResolvedValue({
      data: { fingerprint_sha256: "fp-1" },
    } as unknown as never);

    const user = userEvent.setup();
    renderPalette();
    openPalette();

    await user.click(await screen.findByText(/revoke certificate…/i));
    await user.type(
      screen.getByPlaceholderText(/search certificates to revoke/i),
      "api.example",
    );
    await user.click(await screen.findByText("api.example.com"));

    const confirmButton = await screen.findByRole("button", {
      name: /confirm revoke/i,
    });
    await user.type(
      screen.getByPlaceholderText(/optional explanation/i),
      "compromised",
    );

    // Negative case: no confirmation text typed yet — the button must refuse the click.
    expect(confirmButton).toBeDisabled();
    await user.click(confirmButton);
    expect(api.revokeCertificate).not.toHaveBeenCalled();

    await user.type(screen.getByPlaceholderText("REVOKE"), "REVOKE");
    expect(confirmButton).toBeEnabled();
    await user.click(confirmButton);

    await waitFor(() =>
      expect(api.revokeCertificate).toHaveBeenCalledWith("fp-1", {
        reason_code: 0,
        reason_text: "compromised",
      }),
    );
  });
});
