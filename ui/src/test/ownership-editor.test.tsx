import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    updateCertOwnership: vi.fn(),
  },
}));

import { OwnershipEditor } from "../pages/Certificates";
import { api } from "../lib/api";
import type { CertificateRecord } from "../lib/models";

const cert: CertificateRecord = {
  fingerprint_sha256: "fp-1",
  common_name: "checkout.example.com",
  owner_email: "old@example.com",
  owner_team: "payments",
  service_name: "checkout-api",
  labels: ["prod", "pci"],
};

function renderEditor(canEdit: boolean) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <OwnershipEditor cert={cert} canEdit={canEdit} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("OwnershipEditor", () => {
  it("shows current ownership and hides Edit for read-only users", () => {
    renderEditor(false);
    expect(screen.getByText("old@example.com")).toBeInTheDocument();
    expect(screen.getByText("checkout-api")).toBeInTheDocument();
    expect(screen.getByText(/prod, pci/)).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /edit/i }),
    ).not.toBeInTheDocument();
  });

  it("edits ownership and submits parsed labels", async () => {
    vi.mocked(api.updateCertOwnership).mockResolvedValue({
      data: {},
    } as unknown as never);

    renderEditor(true);

    await userEvent.click(screen.getByRole("button", { name: /^edit$/i }));

    const email = screen.getByPlaceholderText(/owner@example.com/i);
    await userEvent.clear(email);
    await userEvent.type(email, "new@example.com");

    const labels = screen.getByPlaceholderText(/prod, pci, tier-1/i);
    await userEvent.clear(labels);
    await userEvent.type(labels, "prod , tier-1 ,");

    await userEvent.click(
      screen.getByRole("button", { name: /save ownership/i }),
    );

    await waitFor(() =>
      expect(api.updateCertOwnership).toHaveBeenCalledWith("fp-1", {
        owner_email: "new@example.com",
        owner_team: "payments",
        service_name: "checkout-api",
        labels: ["prod", "tier-1"],
      }),
    );
  });
});
