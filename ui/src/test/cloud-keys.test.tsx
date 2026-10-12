import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: { cloudKeyInventory: vi.fn() },
}));

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

import CloudKeys from "../pages/CloudKeys";
import { api } from "../lib/api";
import { cloudKeyInventory } from "../mocks/cloud-keys";
import { canReadKeyInventory } from "../lib/auth";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <CloudKeys />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("CloudKeys", () => {
  it("renders a row per key with per-source status", async () => {
    vi.mocked(api.cloudKeyInventory).mockResolvedValue(
      cloudKeyInventory as never,
    );
    renderPage();
    const table = await screen.findByRole("table");
    expect(within(table).getAllByRole("row")).toHaveLength(6); // header + 5
    expect(within(table).getAllByText("Quantum safe")).toHaveLength(1);
    expect(screen.getByText("AWS KMS: ok, 2 keys")).toBeInTheDocument();
    expect(screen.getByText("Azure Key Vault: ok, 1 key")).toBeInTheDocument();
    // Long ARNs are truncated in the cell; the full value is on hover.
    const full = cloudKeyInventory.data.keys[0].key_id;
    expect(screen.getByTitle(full).textContent).toContain("…");
  });

  it("filters by provider and by search text", async () => {
    vi.mocked(api.cloudKeyInventory).mockResolvedValue(
      cloudKeyInventory as never,
    );
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table");

    await user.selectOptions(screen.getByLabelText("Provider"), "gcp-kms");
    expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(
      3,
    );

    await user.selectOptions(screen.getByLabelText("Provider"), "");
    await user.type(screen.getByLabelText("Search keys"), "ml_dsa");
    expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(
      2,
    );

    await user.clear(screen.getByLabelText("Search keys"));
    await user.type(screen.getByLabelText("Search keys"), "nomatch");
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(
      screen.getByText("No keys match the current filters."),
    ).toBeInTheDocument();
  });

  it("sorts by a column header", async () => {
    vi.mocked(api.cloudKeyInventory).mockResolvedValue(
      cloudKeyInventory as never,
    );
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: "Algorithm" }));
    let rows = within(screen.getByRole("table")).getAllByRole("row");
    expect(
      within(rows[1]).getByText("EC_SIGN_P256_SHA256"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Algorithm" }));
    rows = within(screen.getByRole("table")).getAllByRole("row");
    expect(within(rows[1]).getByText("SYMMETRIC_DEFAULT")).toBeInTheDocument();
  });

  it("shows a failed source alongside the sources that worked", async () => {
    vi.mocked(api.cloudKeyInventory).mockResolvedValue({
      data: {
        ...cloudKeyInventory.data,
        total: 2,
        keys: cloudKeyInventory.data.keys.slice(0, 2),
        errors: ["cloud key inventory unavailable: azure-kv"],
      },
    } as never);
    renderPage();
    expect(
      await screen.findByText(/Partial result: some cloud sources failed/),
    ).toBeInTheDocument();
    expect(screen.getByText("AWS KMS: ok, 2 keys")).toBeInTheDocument();
    expect(
      screen.getByText(
        /Azure Key Vault: error — cloud key inventory unavailable: azure-kv/,
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("table")).toBeInTheDocument();
  });

  it("does not show the unconfigured empty state when every source failed", async () => {
    vi.mocked(api.cloudKeyInventory).mockResolvedValue({
      data: {
        total: 0,
        keys: [],
        providers: [],
        pqc_summary: {},
        errors: ["cloud key inventory unavailable: aws-kms"],
      },
    } as never);
    renderPage();
    expect(
      await screen.findByText(/Partial result: some cloud sources failed/),
    ).toBeInTheDocument();
    expect(screen.queryByText("No cloud keys found")).not.toBeInTheDocument();
  });

  it("explains how to configure sources when the inventory is empty", async () => {
    vi.mocked(api.cloudKeyInventory).mockResolvedValue({
      data: { total: 0, keys: [], providers: [], pqc_summary: {} },
    } as never);
    renderPage();
    expect(await screen.findByText("No cloud keys found")).toBeInTheDocument();
    expect(screen.getByText(/AWS_REGION/)).toBeInTheDocument();
    expect(screen.getByText(/AZURE_KEYVAULT_URL/)).toBeInTheDocument();
    expect(screen.getByText(/GCP_KMS_KEYRING/)).toBeInTheDocument();
  });

  it("shows the role message on a 403", async () => {
    vi.mocked(api.cloudKeyInventory).mockRejectedValue(
      Object.assign(
        new Error("key.manage or report.read permission required"),
        {
          status: 403,
        },
      ),
    );
    renderPage();
    await waitFor(() =>
      expect(
        screen.getByText("Your role can't view cloud keys."),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows a generic error for other failures", async () => {
    vi.mocked(api.cloudKeyInventory).mockRejectedValue(new Error("boom"));
    renderPage();
    expect(await screen.findByText("boom")).toBeInTheDocument();
  });
});

describe("canReadKeyInventory", () => {
  it("allows the roles the hub gate allows and refuses the rest", () => {
    for (const r of [
      "viewer",
      "pki-viewer",
      "auditor",
      "pki-operator",
      "pki-admin",
    ]) {
      expect(canReadKeyInventory(r), r).toBe(true);
    }
    for (const r of ["mcp-agent", "service-account", "", undefined]) {
      expect(canReadKeyInventory(r), String(r)).toBe(false);
    }
  });
});
