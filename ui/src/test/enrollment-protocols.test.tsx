import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import axe from "axe-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({ api: { authzCheck: vi.fn() } }));
vi.mock("../lib/enrollmentApi", async (orig) => {
  const actual = await orig<typeof import("../lib/enrollmentApi")>();
  return {
    ...actual,
    enrollmentApi: {
      scepEnabled: vi.fn(),
      scepList: vi.fn(),
      scepCreate: vi.fn(),
      scepRevoke: vi.fn(),
      estList: vi.fn(),
      estCreate: vi.fn(),
      estRotate: vi.fn(),
      estPatch: vi.fn(),
      estDelete: vi.fn(),
      cmpList: vi.fn(),
      cmpCreatePbm: vi.fn(),
      cmpRegisterAnchor: vi.fn(),
      cmpRotate: vi.fn(),
      cmpRevoke: vi.fn(),
    },
  };
});

import EnrollmentProtocols from "../pages/EnrollmentProtocols";
import { api } from "../lib/api";
import { enrollmentApi as ea } from "../lib/enrollmentApi";

const m = <T,>(f: T) => f as unknown as ReturnType<typeof vi.fn>;

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <EnrollmentProtocols />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const future = "2099-01-01T00:00:00Z";
const challenges = [
  { id: "c1", ca_id: "ca", common_name: "fresh.example.com", dns_names: ["alt.example.com"], created_by: "a", created_at: "2026-10-01T00:00:00Z", expires_at: future, used_at: null },
  { id: "c2", ca_id: "ca", common_name: "used.example.com", dns_names: [], created_by: "a", created_at: "2026-10-01T00:00:00Z", expires_at: future, used_at: "2026-10-02T00:00:00Z" },
  { id: "c3", ca_id: "ca", common_name: "old.example.com", dns_names: null, created_by: "a", created_at: "2026-01-01T00:00:00Z", expires_at: "2026-01-01T01:00:00Z", used_at: null },
];
const users = [
  { username: "bob", allowed_dns_suffixes: [".dev.example.com"], disabled: false, created_by: "a", created_at: "2026-10-01T00:00:00Z", shadowed_by_file: false },
  { username: "eve", allowed_dns_suffixes: [".dev.example.com"], disabled: true, created_by: "a", created_at: "2026-10-01T00:00:00Z", shadowed_by_file: true },
];
const creds = [
  { id: "p1", kind: "pbm", label: "factory", reference: "ref-abc", allowed_dns_suffixes: [], created_at: "2026-10-01T00:00:00Z" },
  { id: "t1", kind: "trust_anchor", label: "vendor root", cert_sha256: "ab".repeat(32), enforced: false, created_at: "2026-10-01T00:00:00Z" },
];

beforeEach(() => {
  vi.clearAllMocks();
  m(api.authzCheck).mockResolvedValue({ role: "pki-admin", scopes: [] });
  m(ea.scepEnabled).mockResolvedValue({ data: { scep_enabled: true } });
  m(ea.scepList).mockResolvedValue({ data: challenges });
  m(ea.estList).mockResolvedValue({ data: users });
  m(ea.cmpList).mockResolvedValue({ data: creds });
});

async function openTab(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(await screen.findByRole("tab", { name }));
}

describe("Enrollment protocols page", () => {
  it("scep mints a challenge and shows the secret once", async () => {
    m(ea.scepCreate).mockResolvedValue({
      data: { ...challenges[0], id: "n", challenge: "CHALLENGE-SECRET-1" },
    });
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    renderPage();
    await screen.findByText("fresh.example.com", { selector: "td" });
    await user.click(screen.getByRole("button", { name: /new challenge/i }));
    await user.type(screen.getByLabelText("Common name"), "dev1.example.com");
    await user.type(screen.getByLabelText(/DNS names/), "dev1.example.com");
    await user.click(screen.getByRole("button", { name: "Create challenge" }));
    expect(ea.scepCreate).toHaveBeenCalledWith({ common_name: "dev1.example.com", dns_names: ["dev1.example.com"], ttl: "1h" });
    expect(await screen.findByDisplayValue("CHALLENGE-SECRET-1")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Copy Challenge" }));
    expect(writeText).toHaveBeenCalledWith("CHALLENGE-SECRET-1");
    await user.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByDisplayValue("CHALLENGE-SECRET-1")).toBeNull());
    expect(document.body.textContent).not.toContain("CHALLENGE-SECRET-1");
  });

  it("scep revoke only for unused challenges", async () => {
    m(ea.scepRevoke).mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("fresh.example.com", { selector: "td" });
    expect(screen.getAllByRole("button", { name: /^Revoke challenge for/ })).toHaveLength(1);
    expect(screen.queryByRole("button", { name: "Revoke challenge for used.example.com" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Revoke challenge for old.example.com" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "Revoke challenge for fresh.example.com" }));
    await user.click(screen.getByRole("button", { name: "Revoke challenge" }));
    await waitFor(() => expect(ea.scepRevoke).toHaveBeenCalledWith("c1"));
  });

  it("scep form rejects wildcard and spaces", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: /new challenge/i }));
    const cn = screen.getByLabelText("Common name");
    const create = screen.getByRole("button", { name: "Create challenge" });
    await user.type(cn, "*.example.com");
    expect(screen.getByText(/Wildcards are not allowed/)).toBeInTheDocument();
    expect(create).toBeDisabled();
    await user.clear(cn);
    await user.type(cn, "dev.example.com");
    expect(create).toBeEnabled();
    await user.type(screen.getByLabelText(/DNS names/), "bad name.example.com");
    expect(screen.getByText(/No spaces allowed/)).toBeInTheDocument();
    expect(create).toBeDisabled();
  });

  it("est create/rotate show a password once and not again after Done", async () => {
    m(ea.estCreate).mockResolvedValue({ data: { username: "carol", password: "PW-CREATE-1" } });
    m(ea.estRotate).mockResolvedValue({ data: { username: "bob", password: "PW-ROTATE-2" } });
    const user = userEvent.setup();
    renderPage();
    await openTab(user, "EST");
    await user.click(await screen.findByRole("button", { name: /new user/i }));
    await user.type(screen.getByLabelText("Username"), "carol");
    await user.type(screen.getByLabelText(/Allowed DNS suffixes/), ".dev.example.com");
    await user.click(screen.getByRole("button", { name: "Create user" }));
    expect(ea.estCreate).toHaveBeenCalledWith({ username: "carol", allowed_dns_suffixes: [".dev.example.com"] });
    expect(await screen.findByDisplayValue("PW-CREATE-1")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByDisplayValue("PW-CREATE-1")).toBeNull());

    await user.click(screen.getByRole("button", { name: "Rotate password for bob" }));
    await user.click(screen.getByRole("button", { name: "Rotate password" }));
    expect(await screen.findByDisplayValue("PW-ROTATE-2")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByDisplayValue("PW-ROTATE-2")).toBeNull());
    expect(document.body.textContent).not.toMatch(/PW-(CREATE|ROTATE)/);
  });

  it("est disable asks for confirmation", async () => {
    m(ea.estPatch).mockResolvedValue({ data: users[0] });
    const user = userEvent.setup();
    renderPage();
    await openTab(user, "EST");
    await user.click(await screen.findByRole("button", { name: "Disable bob" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(ea.estPatch).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Disable bob" }));
    await user.click(screen.getByRole("button", { name: "Disable user" }));
    await waitFor(() => expect(ea.estPatch).toHaveBeenCalledWith("bob", { disabled: true }));
    // enabling needs no confirmation
    await user.click(screen.getByRole("button", { name: "Enable eve" }));
    await waitFor(() => expect(ea.estPatch).toHaveBeenCalledWith("eve", { disabled: false }));
  });

  it("est username with a colon is rejected", async () => {
    const user = userEvent.setup();
    renderPage();
    await openTab(user, "EST");
    await user.click(await screen.findByRole("button", { name: /new user/i }));
    await user.type(screen.getByLabelText("Username"), "a:b");
    await user.type(screen.getByLabelText(/Allowed DNS suffixes/), ".dev.example.com");
    expect(screen.getByText(/no colon/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create user" })).toBeDisabled();
  });

  it("shadowed-by-file badge shown", async () => {
    const user = userEvent.setup();
    renderPage();
    await openTab(user, "EST");
    const row = (await screen.findByText("eve")).closest("tr")!;
    expect(within(row).getByText("file")).toBeInTheDocument();
    expect(within(row).getByTitle(/the file wins/)).toBeInTheDocument();
    expect(within(screen.getByText("bob").closest("tr")!).queryByText("file")).toBeNull();
  });

  it("cmp pbm secret shown once, reference stays visible", async () => {
    m(ea.cmpCreatePbm).mockResolvedValue({
      data: { id: "p2", kind: "pbm", label: "line2", reference: "ref-new", secret: "CMP-SECRET-9", created_at: "2026-10-16T00:00:00Z" },
    });
    m(ea.cmpList)
      .mockResolvedValueOnce({ data: creds })
      .mockResolvedValue({ data: [...creds, { id: "p2", kind: "pbm", label: "line2", reference: "ref-new", created_at: "2026-10-16T00:00:00Z" }] });
    const user = userEvent.setup();
    renderPage();
    await openTab(user, "CMP");
    await screen.findByText("ref-abc");
    await user.click(screen.getByRole("button", { name: /new pbm secret/i }));
    await user.type(screen.getByLabelText("Label"), "line2");
    await user.click(screen.getByRole("button", { name: "Create secret" }));
    expect(await screen.findByDisplayValue("CMP-SECRET-9")).toBeInTheDocument();
    expect(screen.getByText(/openssl cmp -cmd ir -ref ref-new -secret pass:CMP-SECRET-9/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByDisplayValue("CMP-SECRET-9")).toBeNull());
    expect(document.body.textContent).not.toContain("CMP-SECRET-9");
    expect(await screen.findByText("ref-new")).toBeInTheDocument();
  });

  it("cmp trust anchor note about enforcement", async () => {
    m(ea.cmpRegisterAnchor).mockResolvedValue({ data: creds[1] });
    const user = userEvent.setup();
    renderPage();
    await openTab(user, "CMP");
    await user.click(await screen.findByRole("button", { name: "Register trust anchor" }));
    await user.type(screen.getByLabelText("Label"), "root");
    await user.type(screen.getByLabelText(/Certificate/), "not a cert");
    expect(screen.getByRole("button", { name: "Register anchor" })).toBeDisabled();
    await user.clear(screen.getByLabelText(/Certificate/));
    await user.paste("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----");
    await user.click(screen.getByRole("button", { name: "Register anchor" }));
    expect(await screen.findByText(/signature verification is not enforced yet/)).toBeInTheDocument();
  });

  it("operator sees only SCEP", async () => {
    m(api.authzCheck).mockResolvedValue({ role: "pki-operator", scopes: [] });
    renderPage();
    expect(await screen.findByRole("tab", { name: "SCEP" })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "EST" })).toBeNull();
    expect(screen.queryByRole("tab", { name: "CMP" })).toBeNull();
    expect(ea.estList).not.toHaveBeenCalled();
    expect(ea.cmpList).not.toHaveBeenCalled();
  });

  it("SCEP off: shows Not enabled and never calls the challenges list", async () => {
    m(ea.scepEnabled).mockResolvedValue({ data: { scep_enabled: false } });
    renderPage();
    expect(await screen.findByText("Not enabled")).toBeInTheDocument();
    expect(ea.scepList).not.toHaveBeenCalled();
  });

  it("SCEP requested but not serving: the tab explains the reason (CB-15)", async () => {
    m(ea.scepEnabled).mockResolvedValue({
      data: { scep_enabled: false, scep_off_reason: "CA ca-ec does not have an RSA key" },
    });
    renderPage();
    expect(await screen.findByText(/SCEP is not running on this hub: CA ca-ec does not have an RSA key/)).toBeInTheDocument();
  });

  it("non-admin non-operator sees the role message", async () => {
    m(api.authzCheck).mockResolvedValue({ role: "pki-viewer", scopes: [] });
    renderPage();
    expect(await screen.findByText("pki-admin or pki-operator role required")).toBeInTheDocument();
    expect(ea.scepList).not.toHaveBeenCalled();
  });

  it("no serious or critical axe violations", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    const run = async () => {
      const r = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
      return r.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
    };
    await screen.findByText("fresh.example.com", { selector: "td" });
    expect(await run()).toEqual([]);
    await openTab(user, "EST");
    await screen.findByText("eve");
    expect(await run()).toEqual([]);
    await openTab(user, "CMP");
    await screen.findByText("ref-abc");
    expect(await run()).toEqual([]);
  });
});
