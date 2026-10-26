import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    connectors: vi.fn(),
    estateBulkTakeover: vi.fn(),
    estateRevert: vi.fn(),
  },
}));

import { BulkTakeoverDialog, RevertDialog, UpstreamRevokeControls } from "./Certificates";
import { UPSTREAM_REVOKE_NOTE, revokeScopeNote } from "../lib/revokeNotes";
import { api } from "../lib/api";
import type { CertificateRecord } from "../lib/models";

const certs: CertificateRecord[] = [
  { fingerprint_sha256: "aaaaaaaaaaaa1111", common_name: "a.example.com", management_state: "external" },
  { fingerprint_sha256: "bbbbbbbbbbbb2222", common_name: "b.example.com", management_state: "unmanaged" },
  { fingerprint_sha256: "cccccccccccc3333", common_name: "c.example.com", management_state: "managed" },
];

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.connectors).mockResolvedValue({
    data: [{ id: "conn1", name: "DigiCert prod", type: "digicert" }],
  } as never);
});

function bulk(c = certs, onDone = vi.fn()) {
  wrap(<BulkTakeoverDialog open certs={c} onClose={vi.fn()} onDone={onDone} />);
  return onDone;
}

describe("BulkTakeoverDialog", () => {
  it("submits one item per eligible cert and renders per-row results", async () => {
    const user = userEvent.setup();
    vi.mocked(api.estateBulkTakeover).mockResolvedValue({
      data: {
        total: 2,
        succeeded: 1,
        failed: 1,
        results: [
          { fingerprint: "aaaaaaaaaaaa1111", status: "ok" },
          { fingerprint: "bbbbbbbbbbbb2222", status: "error", code: "x", error: "unknown connector" },
        ],
      },
    } as never);
    const onDone = bulk();
    expect(screen.getByText(/2 of 3 selected certificates will be taken over/)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Takeover owner email"), "o@example.com");
    await user.type(screen.getByLabelText("Takeover owner team"), "platform");
    await user.click(screen.getByRole("button", { name: "Take over 2" }));
    await waitFor(() =>
      expect(api.estateBulkTakeover).toHaveBeenCalledWith({
        items: [
          { fingerprint: "aaaaaaaaaaaa1111", owner_email: "o@example.com", owner_team: "platform", renewal_path: { mode: "internal" } },
          { fingerprint: "bbbbbbbbbbbb2222", owner_email: "o@example.com", owner_team: "platform", renewal_path: { mode: "internal" } },
        ],
      }),
    );
    expect(await screen.findByText("1 succeeded, 1 failed")).toBeInTheDocument();
    expect(screen.getByText("unknown connector")).toBeInTheDocument();
    expect(screen.getByText("ok")).toBeInTheDocument();
    expect(screen.getByText("error")).toBeInTheDocument();
    expect(onDone).toHaveBeenCalled();
  });

  it("connector mode requires a connector and sends connector_id", async () => {
    const user = userEvent.setup();
    vi.mocked(api.estateBulkTakeover).mockResolvedValue({
      data: { total: 2, succeeded: 2, failed: 0, results: [] },
    } as never);
    bulk();
    await user.click(screen.getByRole("radio", { name: /original CA via a connector/ }));
    const submit = screen.getByRole("button", { name: "Take over 2" });
    expect(submit).toBeDisabled();
    await screen.findByRole("option", { name: /DigiCert prod/ });
    await user.selectOptions(screen.getByLabelText("Takeover connector"), "conn1");
    expect(submit).toBeEnabled();
    await user.click(submit);
    await waitFor(() => expect(api.estateBulkTakeover).toHaveBeenCalled());
    const body = vi.mocked(api.estateBulkTakeover).mock.calls[0][0];
    expect(body.items.every((i) => i.renewal_path.connector_id === "conn1" && i.renewal_path.mode === "connector")).toBe(true);
  });

  it("zero eligible offers no submit", () => {
    bulk([certs[2]]);
    expect(screen.queryByRole("button", { name: /Take over/ })).not.toBeInTheDocument();
    expect(screen.getByText(/already managed/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Close" })).toBeInTheDocument();
  });

  it("request error keeps the form and shows the message", async () => {
    const user = userEvent.setup();
    vi.mocked(api.estateBulkTakeover).mockRejectedValue(new Error("too many items"));
    const onDone = bulk();
    await user.click(screen.getByRole("button", { name: "Take over 2" }));
    expect(await screen.findByText("too many items")).toBeInTheDocument();
    expect(screen.getByLabelText("Takeover owner email")).toBeInTheDocument();
    expect(onDone).not.toHaveBeenCalled();
  });

  it("disables submit above 500 eligible certificates", () => {
    const many = Array.from({ length: 501 }, (_, i) => ({
      fingerprint_sha256: `fp${i}`,
      management_state: "external",
    }));
    bulk(many);
    expect(screen.getByText(/Select at most 500/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Take over 501" })).toBeDisabled();
  });
});

describe("RevertDialog", () => {
  const cert: CertificateRecord = { fingerprint_sha256: "fp", common_name: "m.example.com", management_state: "managed" };

  it("requires explicit confirm", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    vi.mocked(api.estateRevert).mockResolvedValue({ data: cert } as never);
    wrap(<RevertDialog open cert={cert} onClose={onClose} />);
    expect(api.estateRevert).not.toHaveBeenCalled();
    expect(screen.getByText(/not changed or revoked/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(api.estateRevert).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Revert to unmanaged" }));
    await waitFor(() => expect(api.estateRevert).toHaveBeenCalledWith("fp"));
    expect(await screen.findByText("Now unmanaged.")).toBeInTheDocument();
  });

  it("names external for a certificate synced from an inventory source", async () => {
    const user = userEvent.setup();
    const synced: CertificateRecord = { ...cert, origin: "synced" };
    vi.mocked(api.estateRevert).mockResolvedValue({ data: synced } as never);
    wrap(<RevertDialog open cert={synced} onClose={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Revert to external" }));
    expect(await screen.findByText("Now external.")).toBeInTheDocument();
  });

  it("shows revert errors", async () => {
    const user = userEvent.setup();
    vi.mocked(api.estateRevert).mockRejectedValue(new Error("certificate is not managed"));
    wrap(<RevertDialog open cert={cert} onClose={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Revert to unmanaged" }));
    expect(await screen.findByText("certificate is not managed")).toBeInTheDocument();
  });
});

describe("upstream revoke controls (W36-14)", () => {
  it("explains upstream-first revoke and offers record-only to pki-admin", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<UpstreamRevokeControls isAdmin recordOnly={false} onRecordOnlyChange={onChange} />);
    expect(screen.getByText(UPSTREAM_REVOKE_NOTE)).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "Record here only (I revoked it at the CA myself)" }));
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it("hides record-only for non-admins", () => {
    render(<UpstreamRevokeControls isAdmin={false} recordOnly={false} onRecordOnlyChange={vi.fn()} />);
    expect(screen.getByText(UPSTREAM_REVOKE_NOTE)).toBeInTheDocument();
    expect(screen.queryByRole("checkbox")).toBeNull();
  });

  it("describes the revocation scope", () => {
    expect(revokeScopeNote("upstream", "DigiCert prod")).toBe("Revoked at the issuing CA through DigiCert prod.");
    expect(revokeScopeNote("inventory_only")).toMatch(/revoke at the issuing CA/);
    expect(revokeScopeNote("ca")).toBe("");
  });
});
