import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    spiffeStatus: vi.fn(),
    mintSVID: vi.fn(),
    certificates: vi.fn(),
  },
}));

import Spiffe from "../pages/Spiffe";
import { api } from "../lib/api";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Spiffe />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.certificates).mockResolvedValue({
    data: [
      {
        fingerprint_sha256: "fp-svid",
        uri_sans: ["spiffe://example.org/ns/prod/sa/checkout"],
        valid_until: "2026-06-18T01:00:00Z",
      },
      { fingerprint_sha256: "fp-tls", sans: ["web.example.com"] },
    ],
  } as unknown as never);
});

describe("SPIFFE page", () => {
  it("shows the trust domain and lists only spiffe:// certs", async () => {
    vi.mocked(api.spiffeStatus).mockResolvedValue({
      data: {
        enabled: true,
        trust_domain: "example.org",
        signing_ca_id: "ca-spiffe-int",
        svid_ttl_seconds: 3600,
      },
    } as unknown as never);

    renderPage();

    await screen.findByText("example.org");
    // only the SVID cert appears in the inventory
    expect(
      screen.getByText("spiffe://example.org/ns/prod/sa/checkout"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/1 certificate with a spiffe/i),
    ).toBeInTheDocument();
  });

  it("mints an SVID from the form", async () => {
    vi.mocked(api.spiffeStatus).mockResolvedValue({
      data: {
        enabled: true,
        trust_domain: "example.org",
        signing_ca_id: "ca",
        svid_ttl_seconds: 3600,
      },
    } as unknown as never);
    vi.mocked(api.mintSVID).mockResolvedValue({
      data: {
        spiffe_id: "spiffe://example.org/ns/prod/sa/checkout",
        svid_pem: "-----BEGIN CERTIFICATE-----",
        key_pem: "-----BEGIN PRIVATE KEY-----",
        bundle_pem: "-----BEGIN CERTIFICATE-----",
        expires_at: "2026-06-18T01:00:00Z",
      },
    } as unknown as never);

    renderPage();

    const input = await screen.findByPlaceholderText(/ns\/prod\/sa\/checkout/i);
    await userEvent.clear(input);
    await userEvent.type(input, "ns/prod/sa/checkout");
    await userEvent.click(screen.getByRole("button", { name: /mint svid/i }));

    await waitFor(() =>
      expect(api.mintSVID).toHaveBeenCalledWith(
        "spiffe://example.org/ns/prod/sa/checkout",
      ),
    );
    await screen.findByText(/the private key is shown once/i);
  });

  it("shows a not-configured state when SPIFFE is disabled", async () => {
    vi.mocked(api.spiffeStatus).mockResolvedValue({
      data: {
        enabled: false,
        trust_domain: "",
        signing_ca_id: "",
        svid_ttl_seconds: 3600,
      },
    } as unknown as never);

    renderPage();

    await screen.findByText(/spiffe not configured/i);
  });
});
