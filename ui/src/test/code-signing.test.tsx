import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    codeSigningInventory: vi.fn(),
  },
}));

import CodeSigning from "../pages/CodeSigning";
import { api } from "../lib/api";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <CodeSigning />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("CodeSigning inventory page", () => {
  it("lists code-signing certs with status badges", async () => {
    vi.mocked(api.codeSigningInventory).mockResolvedValue({
      data: {
        generated_at: "2026-06-16T00:00:00Z",
        total: 2,
        expired: 1,
        revoked: 0,
        certs: [
          {
            fingerprint_sha256: "cs-1",
            common_name: "release-signing",
            issuer_cn: "Acme Code CA",
            public_key_algorithm: "ECDSA",
            key_size_bits: 256,
            valid_until: "2026-12-01T00:00:00Z",
            grade: "A",
            expired: false,
          },
          {
            fingerprint_sha256: "cs-2",
            common_name: "old-signing",
            valid_until: "2026-01-01T00:00:00Z",
            grade: "F",
            expired: true,
          },
        ],
      },
    } as unknown as never);

    renderPage();

    await screen.findByText("release-signing");
    expect(screen.getByText("old-signing")).toBeInTheDocument();
    expect(screen.getByText("Valid")).toBeInTheDocument();
    // "Expired" appears both as a metric label and a status badge.
    expect(screen.getAllByText("Expired").length).toBeGreaterThanOrEqual(2);
  });

  it("shows an empty state when no code-signing certs exist", async () => {
    vi.mocked(api.codeSigningInventory).mockResolvedValue({
      data: {
        generated_at: "2026-06-16T00:00:00Z",
        total: 0,
        expired: 0,
        revoked: 0,
        certs: [],
      },
    } as unknown as never);

    renderPage();

    await screen.findByText(/no code-signing certificates found/i);
  });
});
