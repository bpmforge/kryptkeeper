import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    cas: vi.fn(),
    importCa: vi.fn(),
    createCa: vi.fn(),
    caCsr: vi.fn(),
    completeCaCertificate: vi.fn(),
    removeCaTrustAnchor: vi.fn(),
    blastRadius: vi.fn(),
    rotateCaKey: vi.fn(),
    pendingActions: vi.fn(),
  },
}));

import CAs from "./CAs";
import { api } from "../lib/api";

const CSR = "-----BEGIN CERTIFICATE REQUEST-----\nQUJD\n-----END CERTIFICATE REQUEST-----";
const CERT = "-----BEGIN CERTIFICATE-----\nREVG\n-----END CERTIFICATE-----";

const root = {
  id: "ca-root",
  name: "Corp Root",
  type: "root",
  key_storage_type: "external",
  status: "active",
};
const pendingCa = {
  id: "ca-iss",
  name: "Issuing 1",
  type: "intermediate",
  key_storage_type: "software",
  status: "pending_certificate",
  parent_ca_id: "ca-root",
  csr_pem: CSR,
};

function asRole(role: string) {
  vi.mocked(api.authzCheck).mockResolvedValue({
    principal: "alice",
    role,
    scopes: [],
  } as unknown as never);
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <CAs />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function listOf(...cas: unknown[]) {
  vi.mocked(api.cas).mockResolvedValue({ data: cas, meta: {} } as unknown as never);
}

beforeEach(() => {
  vi.clearAllMocks();
  asRole("pki-admin");
  listOf(root);
  vi.mocked(api.pendingActions).mockResolvedValue({ data: [] } as unknown as never);
});

function grantAction(over: Record<string, unknown>) {
  return {
    id: "act-s",
    action_type: "key_ca_trust_anchor_remove",
    params: { key_id: "ca-root" },
    proposed_by: "alice",
    status: "approved",
    decided_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    ...over,
  };
}
function serverActions(...actions: unknown[]) {
  vi.mocked(api.pendingActions).mockImplementation(((status?: string) =>
    Promise.resolve({
      data: (actions as { status: string }[]).filter((a) => !status || a.status === status),
    })) as never);
}

describe("CA grants survive a reload (CB-08)", () => {
  it("derives the redeem prompt for a trust-anchor removal from server state and redeems it", async () => {
    const user = userEvent.setup();
    serverActions(grantAction({}));
    vi.mocked(api.removeCaTrustAnchor).mockResolvedValue(undefined);
    renderPage();
    await screen.findByText("Approved action ready to redeem");
    await user.click(screen.getByRole("button", { name: /redeem approved action/i }));
    await waitFor(() => expect(api.removeCaTrustAnchor).toHaveBeenCalledWith("ca-root", "act-s"));
    await screen.findByText("Trust anchor removed");
    await waitFor(() => expect(screen.queryByText("Approved action ready to redeem")).toBeNull());
  });

  it("an approved import asks for the original root again and submits with the grant", async () => {
    const user = userEvent.setup();
    serverActions(grantAction({ id: "act-i", action_type: "key_ca_import", params: { key_id: "fp1" } }));
    vi.mocked(api.importCa).mockResolvedValue({ data: root } as unknown as never);
    renderPage();
    await user.click(await screen.findByRole("button", { name: /redeem approved action/i }));
    const dlg = await screen.findByRole("dialog");
    await user.type(within(dlg).getByLabelText(/^name$/i), "Corp Root");
    await user.click(within(dlg).getByLabelText(/certificate pem/i));
    await user.paste(CERT);
    await user.click(within(dlg).getByRole("button", { name: /import root/i }));
    await waitFor(() =>
      expect(api.importCa).toHaveBeenCalledWith(expect.objectContaining({ approved_action_id: "act-i" })),
    );
  });

  it("a grant still waiting for approval has no redeem button; someone else's grant and expired approvals are ignored", async () => {
    serverActions(
      grantAction({ id: "act-w", status: "pending" }),
      grantAction({ id: "act-o", proposed_by: "bob" }),
      grantAction({ id: "act-e", decided_at: "2020-01-01T00:00:00Z" }),
    );
    renderPage();
    await screen.findByText("Waiting for a second approver");
    expect(screen.getByText(/act-w/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /redeem approved action/i })).toBeNull();
  });
});

describe("New CA parent picker (CB-06)", () => {
  it("offers active CAs by name instead of a free-text id and submits the chosen id", async () => {
    const user = userEvent.setup();
    listOf(root, { id: "ca-old", name: "Old Root", type: "root", key_storage_type: "software", status: "revoked" });
    vi.mocked(api.createCa).mockResolvedValue({ data: pendingCa } as unknown as never);
    renderPage();
    await user.click(await screen.findByRole("button", { name: /new ca/i }));
    const dlg = await screen.findByRole("dialog");
    await user.selectOptions(within(dlg).getByLabelText(/^type$/i), "intermediate");
    const parent = (await within(dlg).findByLabelText(/parent ca/i)) as HTMLSelectElement;
    expect(parent.tagName).toBe("SELECT");
    await within(dlg).findByRole("option", { name: /Corp Root/ });
    expect(within(dlg).queryByRole("option", { name: /Old Root/ })).toBeNull();
    await user.type(within(dlg).getByLabelText(/subject cn/i), "Issuing 2");
    await user.selectOptions(parent, "ca-root");
    await user.click(within(dlg).getByRole("button", { name: /create ca/i }));
    await waitFor(() =>
      expect(api.createCa).toHaveBeenCalledWith(
        expect.objectContaining({ type: "intermediate", parent_ca_id: "ca-root" }),
      ),
    );
  });
});

async function importRoot(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: /import external root/i }));
  const dlg = await screen.findByRole("dialog");
  await user.type(within(dlg).getByLabelText(/^name$/i), "Corp Root");
  await user.click(within(dlg).getByLabelText(/certificate pem/i));
  await user.paste(CERT);
  await user.click(within(dlg).getByRole("button", { name: /import root/i }));
}

describe("CAs offline-root workflow (W23-05)", () => {
  it("import root then request CSR then upload signed cert completes", async () => {
    const user = userEvent.setup();
    vi.mocked(api.importCa)
      .mockResolvedValueOnce({
        data: { status: "proposed", action_id: "act-1" },
      } as unknown as never)
      .mockResolvedValueOnce({ data: root } as unknown as never);
    vi.mocked(api.createCa).mockResolvedValue({ data: pendingCa } as unknown as never);
    vi.mocked(api.completeCaCertificate).mockResolvedValue({
      data: { ...pendingCa, status: "active" },
    } as unknown as never);

    renderPage();
    await importRoot(user);
    await screen.findByText(/waiting for a second approver/i);
    expect(api.importCa).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "root",
        key_storage_type: "external",
        certificate_pem: CERT,
      }),
    );

    await user.click(screen.getByRole("button", { name: /redeem approved action/i }));
    await screen.findByText("Root imported");
    expect(api.importCa).toHaveBeenLastCalledWith(
      expect.objectContaining({ approved_action_id: "act-1" }),
    );
    expect(screen.queryByText(/waiting for a second approver/i)).toBeNull();

    // The root is external: request an issuing CA.
    await user.click(await screen.findByRole("button", { name: /request issuing ca \(csr\)/i }));
    const csrDlg = await screen.findByRole("dialog");
    await user.type(within(csrDlg).getByLabelText(/subject cn/i), "Issuing 1");
    listOf(root, pendingCa);
    await user.click(within(csrDlg).getByRole("button", { name: /generate csr/i }));
    expect(api.createCa).toHaveBeenCalledWith(
      expect.objectContaining({ type: "intermediate", parent_ca_id: "ca-root" }),
    );

    // Pending CA is selected; upload the signed certificate.
    await user.click(await screen.findByRole("button", { name: /upload signed certificate/i }));
    const upDlg = await screen.findByRole("dialog");
    await user.click(within(upDlg).getByLabelText(/signed certificate pem/i));
    await user.paste(CERT);
    await user.click(within(upDlg).getByRole("button", { name: /upload certificate/i }));
    await waitFor(() =>
      expect(api.completeCaCertificate).toHaveBeenCalledWith("ca-iss", CERT),
    );
    await screen.findByText("CA activated");
  }, 20_000); // three dialogs of user-event typing; 5 s default flakes on a loaded CI runner

  it("shows pending-approval state with a link to Pending Actions after import", async () => {
    const user = userEvent.setup();
    vi.mocked(api.importCa).mockResolvedValue({
      data: { status: "proposed", action_id: "act-9" },
    } as unknown as never);
    renderPage();
    await importRoot(user);
    await screen.findByText(/waiting for a second approver/i);
    expect(screen.getByText(/act-9/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /pending actions/i })).toHaveAttribute(
      "href",
      "/pending-actions",
    );
    expect(screen.queryByText("Root imported")).toBeNull();
  });

  it("surfaces a 403 when redeeming an unapproved grant", async () => {
    const user = userEvent.setup();
    vi.mocked(api.importCa)
      .mockResolvedValueOnce({ data: { status: "proposed", action_id: "act-9" } } as unknown as never)
      .mockRejectedValueOnce(new Error("action not approved"));
    renderPage();
    await importRoot(user);
    await user.click(await screen.findByRole("button", { name: /redeem approved action/i }));
    await screen.findByText("action not approved");
  });

  it("trust anchor removal shows 202 pending state and link", async () => {
    const user = userEvent.setup();
    vi.mocked(api.removeCaTrustAnchor).mockResolvedValue({
      data: { status: "proposed", action_id: "act-r" },
    } as unknown as never);
    renderPage();
    await user.click(await screen.findByRole("button", { name: /remove trust anchor/i }));
    await user.click(await screen.findByRole("button", { name: /confirm removal/i }));
    await screen.findByText(/waiting for a second approver/i);
    expect(screen.getByRole("link", { name: /pending actions/i })).toHaveAttribute(
      "href",
      "/pending-actions",
    );
    expect(screen.queryByText("Trust anchor removed")).toBeNull();
  });

  it("trust anchor removal 409 shows the child-CA message", async () => {
    const user = userEvent.setup();
    vi.mocked(api.removeCaTrustAnchor).mockRejectedValue(
      new Error("trust anchor still has active child CAs"),
    );
    renderPage();
    await user.click(await screen.findByRole("button", { name: /remove trust anchor/i }));
    await user.click(await screen.findByRole("button", { name: /confirm removal/i }));
    await screen.findByText(/still has active child CAs/i);
  });

  it("trust anchor removal 204 reports success", async () => {
    const user = userEvent.setup();
    vi.mocked(api.removeCaTrustAnchor).mockResolvedValue(undefined);
    renderPage();
    await user.click(await screen.findByRole("button", { name: /remove trust anchor/i }));
    await user.click(await screen.findByRole("button", { name: /confirm removal/i }));
    await screen.findByText("Trust anchor removed");
  });

  it("CSR block offers copy and download", async () => {
    const user = userEvent.setup();
    listOf(pendingCa);
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
    const createUrl = vi.fn(() => "blob:csr");
    const revokeUrl = vi.fn();
    Object.assign(URL, { createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    renderPage();
    const pre = await screen.findByTestId("csr-pem");
    expect(pre.textContent).toBe(CSR);
    await user.click(screen.getByRole("button", { name: /^copy$/i }));
    expect(writeText).toHaveBeenCalledWith(CSR);
    await user.click(screen.getByRole("button", { name: /download \.csr/i }));
    expect(createUrl).toHaveBeenCalled();
    expect(revokeUrl).toHaveBeenCalledWith("blob:csr");
  });

  it("loads the CSR from the API when the list omits it", async () => {
    listOf({ ...pendingCa, csr_pem: undefined });
    vi.mocked(api.caCsr).mockResolvedValue({
      data: { ca_id: "ca-iss", csr_pem: CSR },
    } as unknown as never);
    renderPage();
    expect((await screen.findByTestId("csr-pem")).textContent).toBe(CSR);
    expect(api.caCsr).toHaveBeenCalledWith("ca-iss");
  });

  it("shows API warnings as compatibility warnings", async () => {
    listOf({ ...root, warnings: ["Ed25519 chains are not validated by ADCS"] });
    renderPage();
    await screen.findByText("Compatibility warning");
    expect(screen.getByText(/not validated by ADCS/)).toBeInTheDocument();
  });

  it("viewer role sees no import button", async () => {
    asRole("viewer");
    renderPage();
    await screen.findByText("CA detail");
    await screen.findAllByText("Corp Root");
    expect(screen.queryByRole("button", { name: /import external root/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /remove trust anchor/i })).toBeNull();
  });

  it("offers exactly the nine algorithms and Ed25519 shows the ADCS caveat", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: /new ca/i }));
    const dlg = await screen.findByRole("dialog");
    const select = within(dlg).getByLabelText(/algorithm/i) as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.value)).toEqual([
      "ECDSA-P256",
      "ECDSA-P384",
      "RSA-2048",
      "RSA-3072",
      "RSA-4096",
      "Ed25519",
      "ML-DSA-44",
      "ML-DSA-65",
      "ML-DSA-87",
    ]);
    expect(within(dlg).queryByText(/do not validate Ed25519/i)).toBeNull();
    await user.selectOptions(select, "Ed25519");
    expect(within(dlg).getByText(/do not validate Ed25519/i)).toBeInTheDocument();
  });
});

describe("CAs re-key wizard (W23-18)", () => {
  const radius = {
    data: {
      action: "retire_ca",
      target: "ca-root",
      severity: "medium",
      total_affected: 1,
      affected_by_kind: { endpoint: ["ep-1"] },
    },
  };

  async function openWizard(user: ReturnType<typeof userEvent.setup>) {
    await user.click(await screen.findByRole("button", { name: /^re-key$/i }));
    return await screen.findByRole("dialog");
  }
  async function toReview(
    user: ReturnType<typeof userEvent.setup>,
    dlg: HTMLElement,
    opts: { crossSign?: boolean } = {},
  ) {
    await user.click(await within(dlg).findByRole("button", { name: /acknowledge impact/i }));
    await user.click(within(dlg).getByRole("button", { name: /^next$/i }));
    if (opts.crossSign) {
      await user.click(within(dlg).getByLabelText(/cross-sign for zero-downtime/i));
    }
    await user.click(within(dlg).getByRole("button", { name: /^next$/i }));
  }

  beforeEach(() => {
    vi.mocked(api.blastRadius).mockResolvedValue(radius as unknown as never);
  });

  it("re-key button is hidden for read-only roles", async () => {
    asRole("viewer");
    renderPage();
    await screen.findByText(/read-only access/i);
    expect(screen.queryByRole("button", { name: /^re-key$/i })).toBeNull();
  });

  it("runs the blast-radius preview before any rotate and gates Next", async () => {
    const user = userEvent.setup();
    renderPage();
    const dlg = await openWizard(user);
    await within(dlg).findByText("ep-1");
    expect(api.blastRadius).toHaveBeenCalledWith("retire_ca", "ca-root");
    await user.click(within(dlg).getByRole("button", { name: /^next$/i }));
    expect(await within(dlg).findByRole("alert")).toHaveTextContent(/acknowledge/i);
    expect(api.rotateCaKey).not.toHaveBeenCalled();
  });

  it("submits a plain re-key and shows 202 as pending, not done", async () => {
    const user = userEvent.setup();
    vi.mocked(api.rotateCaKey).mockResolvedValue({ proposed: true, actionId: "act-1" });
    renderPage();
    const dlg = await openWizard(user);
    await toReview(user, dlg);
    expect(api.rotateCaKey).not.toHaveBeenCalled();
    await user.click(within(dlg).getByRole("button", { name: /finish/i }));
    await screen.findByText("Re-key pending approval");
    expect(screen.getByText(/act-1/)).toBeInTheDocument();
    expect(api.rotateCaKey).toHaveBeenCalledWith("ca-root", {
      mode: undefined,
      algorithm: "",
      approvedActionId: undefined,
    });
    expect(screen.queryByText("CA re-keyed")).toBeNull();
  });

  it("cross-sign checkbox sends mode=cross-sign and redeem sends the grant", async () => {
    const user = userEvent.setup();
    vi.mocked(api.rotateCaKey)
      .mockResolvedValueOnce({ proposed: true, actionId: "act-2" })
      .mockResolvedValueOnce({
        proposed: false,
        result: { key_id: "k-new", cross_cert_pem: "CROSS", old_cert_pem: "OLD" },
      });
    renderPage();
    const dlg = await openWizard(user);
    await toReview(user, dlg, { crossSign: true });
    await user.click(within(dlg).getByRole("button", { name: /finish/i }));
    expect(api.rotateCaKey).toHaveBeenLastCalledWith(
      "ca-root",
      expect.objectContaining({ mode: "cross-sign" }),
    );
    await user.click(await screen.findByRole("button", { name: /redeem approved action/i }));
    await screen.findByText("CA re-keyed");
    expect(api.rotateCaKey).toHaveBeenLastCalledWith("ca-root", {
      mode: "cross-sign",
      algorithm: "",
      approvedActionId: "act-2",
    });
    expect(screen.getByDisplayValue("CROSS")).toBeInTheDocument();
  });

  it("shows an error when rotate is refused", async () => {
    const user = userEvent.setup();
    vi.mocked(api.rotateCaKey).mockRejectedValue(new Error("admin role required"));
    renderPage();
    const dlg = await openWizard(user);
    await toReview(user, dlg);
    await user.click(within(dlg).getByRole("button", { name: /finish/i }));
    await screen.findByText("Re-key failed");
    expect(screen.getByText("admin role required")).toBeInTheDocument();
  });
});
