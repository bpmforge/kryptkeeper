import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    keys: vi.fn(),
    pendingActions: vi.fn(),
    escrowKey: vi.fn(),
    recoverEscrowedKey: vi.fn(),
    byokExport: vi.fn(),
  },
  fetchJSON: vi.fn(),
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import Keys from "./Keys";
import { api, fetchJSON } from "../lib/api";
import { toast } from "sonner";

const BUNDLE = '{"schema_version":1,"key_id":"root-1","shares":[]}';

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <Keys />
    </QueryClientProvider>,
  );
}

function pendingRow(status: string, params: Record<string, unknown> = {}) {
  return {
    data: [
      {
        id: "act-1",
        action_type: "key_recover",
        params,
        proposed_by: "alice",
        status,
        created_at: "2026-10-01T00:00:00Z",
      },
    ],
  } as unknown as never;
}

async function fillCustodians(dlg: HTMLElement, user: ReturnType<typeof userEvent.setup>) {
  await user.type(within(dlg).getByLabelText(/custodian a/i), "alpha-secret");
  await user.type(within(dlg).getByLabelText(/custodian b/i), "bravo-secret");
}

async function proposeRecover(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: /^recover$/i }));
  const dlg = await screen.findByRole("dialog");
  await user.click(within(dlg).getByLabelText(/escrow bundle/i));
  await user.paste(BUNDLE);
  await fillCustodians(dlg, user);
  await user.click(within(dlg).getByRole("button", { name: /submit for approval/i }));
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.keys).mockResolvedValue({
    data: [{ id: "root-1", algorithm: "ECDSA-P256", created_at: "2026-01-01T00:00:00Z" }],
  } as unknown as never);
  vi.mocked(api.pendingActions).mockResolvedValue(pendingRow("pending"));
});

describe("Keys escrow / recover / BYOK (W23-21)", () => {
  it("starts escrow and shows 202 pending with the action id", async () => {
    vi.mocked(api.escrowKey).mockResolvedValue({ state: "pending", actionId: "act-1" });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: /^escrow$/i }));
    const dlg = await screen.findByRole("dialog");
    await user.selectOptions(await within(dlg).findByLabelText(/key to escrow/i), "root-1");
    await fillCustodians(dlg, user);
    await user.click(within(dlg).getByRole("button", { name: /submit for approval/i }));

    const item = await screen.findByTestId("grant-act-1");
    expect(within(item).getByText("act-1")).toBeInTheDocument();
    expect(await within(item).findByText("Pending approval")).toBeInTheDocument();
    expect(api.escrowKey).toHaveBeenCalledWith({
      key_id: "root-1",
      custodian_a_passphrase: "alpha-secret",
      custodian_b_passphrase: "bravo-secret",
    });
    expect(within(item).queryByText("Redeemed")).toBeNull();
  });

  it("refuses identical custodian passphrases client-side", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: /^escrow$/i }));
    const dlg = await screen.findByRole("dialog");
    await user.selectOptions(await within(dlg).findByLabelText(/key to escrow/i), "root-1");
    await user.type(within(dlg).getByLabelText(/custodian a/i), "same");
    await user.type(within(dlg).getByLabelText(/custodian b/i), "same");
    await user.click(within(dlg).getByRole("button", { name: /submit for approval/i }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith(expect.stringMatching(/must differ/i)));
    expect(api.escrowKey).not.toHaveBeenCalled();
  });

  it("recover shows the bundle digest to the proposer", async () => {
    vi.mocked(api.recoverEscrowedKey).mockResolvedValue({ state: "pending", actionId: "act-1" });
    vi.mocked(api.pendingActions).mockResolvedValue(
      pendingRow("pending", { key_id: "root-1", bundle_sha256: "abc123" }),
    );
    const user = userEvent.setup();
    renderPage();
    await proposeRecover(user);
    expect(await screen.findByTestId("bundle-digest")).toHaveTextContent("abc123");
    expect(screen.getByText(/approver sees this same digest/i)).toBeInTheDocument();
    expect(api.recoverEscrowedKey).toHaveBeenCalledWith(
      expect.objectContaining({ bundle: JSON.parse(BUNDLE) }),
    );
  });

  it("shows Approved when approved and redeem calls the API with approved_action_id", async () => {
    vi.mocked(api.recoverEscrowedKey)
      .mockResolvedValueOnce({ state: "pending", actionId: "act-1" })
      .mockResolvedValueOnce({ state: "done", data: { id: "root-1" } });
    const user = userEvent.setup();
    renderPage();
    await proposeRecover(user);
    await screen.findByText("Pending approval");

    vi.mocked(api.pendingActions).mockResolvedValue(pendingRow("approved"));
    // The 5 s poll is not awaited in tests; a fresh page-level refetch is
    // forced by the query client via window focus.
    window.dispatchEvent(new Event("focus"));
    const redeem = await screen.findByRole("button", { name: /^redeem$/i }, { timeout: 7000 });
    expect(screen.getByText("Approved - redeem now")).toBeInTheDocument();

    await user.click(redeem);
    const dlg = await screen.findByRole("dialog");
    // Passphrases are never prefilled for a redeem.
    expect(within(dlg).getByLabelText(/custodian a/i)).toHaveValue("");
    await fillCustodians(dlg, user);
    await user.click(within(dlg).getByRole("button", { name: /redeem approved action/i }));
    await waitFor(() =>
      expect(api.recoverEscrowedKey).toHaveBeenLastCalledWith(
        expect.objectContaining({ approved_action_id: "act-1", bundle: JSON.parse(BUNDLE) }),
      ),
    );
    expect(await screen.findByText("Redeemed")).toBeInTheDocument();
  }, 15000);

  it("shows Redeemed after a successful redeem", async () => {
    vi.mocked(api.recoverEscrowedKey)
      .mockResolvedValueOnce({ state: "pending", actionId: "act-1" })
      .mockResolvedValueOnce({ state: "done", data: { id: "root-1" } });
    vi.mocked(api.pendingActions).mockResolvedValue(pendingRow("approved"));
    const user = userEvent.setup();
    renderPage();
    await proposeRecover(user);
    await user.click(await screen.findByRole("button", { name: /^redeem$/i }));
    const dlg = await screen.findByRole("dialog");
    await fillCustodians(dlg, user);
    await user.click(within(dlg).getByRole("button", { name: /redeem approved action/i }));
    const item = await screen.findByTestId("grant-act-1");
    expect(await within(item).findByText("Redeemed")).toBeInTheDocument();
    expect(within(item).queryByRole("button", { name: /^redeem$/i })).toBeNull();
  });

  it("BYOK export sends provider/region/key_id and shows 202 pending", async () => {
    vi.mocked(api.byokExport).mockResolvedValue({ state: "pending", actionId: "act-1" });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: /byok export/i }));
    const dlg = await screen.findByRole("dialog");
    await user.click(within(dlg).getByLabelText(/escrow bundle/i));
    await user.paste(BUNDLE);
    await user.type(within(dlg).getByLabelText(/region/i), "eu-west-1");
    await user.type(within(dlg).getByLabelText(/destination kms key id/i), "kms-key-9");
    await fillCustodians(dlg, user);
    await user.click(within(dlg).getByRole("button", { name: /submit for approval/i }));
    await screen.findByTestId("grant-act-1");
    expect(api.byokExport).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: "aws",
        region: "eu-west-1",
        key_id: "kms-key-9",
        bundle: JSON.parse(BUNDLE),
      }),
    );
    expect(screen.getByText("Pending approval")).toBeInTheDocument();
  });

  it("shows the server error when BYOK is refused (403 approver role required)", async () => {
    vi.mocked(api.byokExport).mockRejectedValue(new Error("approver role required"));
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: /byok export/i }));
    const dlg = await screen.findByRole("dialog");
    await user.click(within(dlg).getByLabelText(/escrow bundle/i));
    await user.paste(BUNDLE);
    await user.type(within(dlg).getByLabelText(/destination kms key id/i), "kms-key-9");
    await fillCustodians(dlg, user);
    await user.click(within(dlg).getByRole("button", { name: /submit for approval/i }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith("approver role required"));
    expect(screen.queryByTestId("grant-act-1")).toBeNull();
  });

  it("passphrases are cleared from state after submit", async () => {
    vi.mocked(api.recoverEscrowedKey).mockResolvedValue({ state: "pending", actionId: "act-1" });
    const user = userEvent.setup();
    renderPage();
    await proposeRecover(user);
    await screen.findByTestId("grant-act-1");
    await user.click(screen.getByRole("button", { name: /^recover$/i }));
    const dlg = await screen.findByRole("dialog");
    expect(within(dlg).getByLabelText(/custodian a/i)).toHaveValue("");
    expect(within(dlg).getByLabelText(/custodian b/i)).toHaveValue("");
    expect(within(dlg).getByLabelText(/escrow bundle/i)).toHaveValue("");
  });
});

describe("Keys PQC custody statement (W31-19)", () => {
  const STATEMENT =
    "ML-DSA and hybrid keys are generated and held in the software keystore only (Argon2id + AES-256-GCM). HSM, KMS and Vault backends refuse them with a citation of docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md (D-086). Hardware-backed PQC key custody is not provided.";

  function withPqcKey() {
    vi.mocked(api.keys).mockResolvedValue({
      data: [
        { id: "pq-1", algorithm: "ML-DSA-65", created_at: "2026-01-01T00:00:00Z" },
        { id: "root-1", algorithm: "ECDSA-P256", created_at: "2026-01-01T00:00:00Z" },
      ],
    } as unknown as never);
  }

  beforeEach(() => {
    vi.mocked(fetchJSON).mockResolvedValue({ fips: { mode_140_3: false } } as never);
  });

  it("shows the software-only statement and ADR citation when a PQC key exists", async () => {
    withPqcKey();
    renderPage();
    const region = await screen.findByRole("region", { name: "PQC key custody" });
    expect(region).toHaveTextContent(STATEMENT);
    expect(within(region).getByText("docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md")).toBeInTheDocument();
  });

  it("hides the panel when no PQC key is stored", async () => {
    renderPage();
    await screen.findByText("root-1");
    expect(screen.queryByRole("region", { name: "PQC key custody" })).toBeNull();
  });

  it.each([
    [
      { fips: { mode_140_3: false } },
      "FIPS 140-3 mode is off. ML-DSA runs in software and is not covered by a validated module.",
    ],
    [
      { fips: { mode_140_3: true, enforced: false, module_version: "v1.0.0" } },
      "FIPS 140-3 mode is on (module v1.0.0). ML-DSA runs in software outside the validated Go module; hybrid keys are refused.",
    ],
    [
      { fips: { mode_140_3: true, enforced: true, module_version: "v1.0.0" } },
      "FIPS 140-3 enforced mode: ML-DSA and hybrid keys are refused.",
    ],
  ])("FIPS line reflects meta %#", async (meta, text) => {
    withPqcKey();
    vi.mocked(fetchJSON).mockResolvedValue(meta as never);
    renderPage();
    const region = await screen.findByRole("region", { name: "PQC key custody" });
    await waitFor(() => expect(region).toHaveTextContent(text));
  });

  it("FIPS line says unavailable when meta fails", async () => {
    withPqcKey();
    vi.mocked(fetchJSON).mockRejectedValue(new Error("boom"));
    renderPage();
    const region = await screen.findByRole("region", { name: "PQC key custody" });
    expect(region).toHaveTextContent("FIPS posture unavailable.");
  });

  it("generate dialog shows the statement only for ML-DSA algorithms", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: /generate key/i }));
    const dlg = await screen.findByRole("dialog");
    expect(within(dlg).queryByRole("region", { name: "PQC key custody" })).toBeNull();
    await user.selectOptions(within(dlg).getByRole("combobox"), "ML-DSA-65");
    expect(await within(dlg).findByRole("region", { name: "PQC key custody" })).toHaveTextContent(
      STATEMENT,
    );
    await user.selectOptions(within(dlg).getByRole("combobox"), "ECDSA-P256");
    expect(within(dlg).queryByRole("region", { name: "PQC key custody" })).toBeNull();
  });

  it("never claims HSM PQC", async () => {
    withPqcKey();
    const { container } = renderPage();
    await screen.findByRole("region", { name: "PQC key custody" });
    expect(container.textContent).not.toMatch(
      /HSM-backed|hardware-backed PQC (is|are) (provided|supported)/i,
    );
  });
});
