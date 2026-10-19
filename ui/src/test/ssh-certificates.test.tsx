import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import axe from "axe-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  fetchJSON: vi.fn(),
  api: { authzCheck: vi.fn(), templates: vi.fn() },
}));

import SshCertificates from "../pages/SshCertificates";
import { api, fetchJSON } from "../lib/api";

const m = <T,>(f: T) => f as unknown as ReturnType<typeof vi.fn>;

const CA = { authority_line: "ssh-ed25519 AAAACA ca@kk", authority_fingerprint: "SHA256:cafp" };
const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc user@laptop";
const tpls = [
  {
    id: "tpl-ssh", name: "ssh-ops", display_name: "SSH Ops", active: true,
    ssh_policy: { cert_types: ["user", "host"], allowed_principals: ["alice", "bob"], host_patterns: ["*.corp.example"], max_ttl_hours: 24 },
  },
  { id: "tpl-tls", name: "tls", display_name: "TLS Only", active: true },
];
const cert = (serial: string, created_at: string, valid_before = "2099-01-01T00:00:00Z") => ({
  serial, cert_type: "user", key_id: `kid-${serial}`, principals: ["alice"], valid_after: "2026-01-01T00:00:00Z",
  valid_before, subject_fingerprint: "SHA256:s", authority_fingerprint: "SHA256:cafp",
  certificate_line: `ssh-ed25519-cert-v01@openssh.com ${serial}`, tenant: "t", created_at, template_id: "tpl-ssh",
});

let certs: unknown[] = [];
const posts = () => m(fetchJSON).mock.calls.filter((c) => c[0] === "/ssh/certificates" && c[1]?.method === "POST");

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <SshCertificates />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function fill(user: ReturnType<typeof userEvent.setup>, o: { principals?: string; ttl?: string; key?: string } = {}) {
  await user.type(await screen.findByLabelText("Key ID"), "kid-1");
  await user.type(screen.getByLabelText(/Principals/), o.principals ?? "alice");
  await user.click(screen.getByLabelText(/Public key/));
  await user.paste(o.key ?? KEY);
  await user.clear(screen.getByLabelText("TTL hours"));
  await user.type(screen.getByLabelText("TTL hours"), o.ttl ?? "8");
}

beforeEach(() => {
  vi.clearAllMocks();
  certs = [];
  m(api.authzCheck).mockResolvedValue({ role: "pki-admin", scopes: [] });
  m(api.templates).mockResolvedValue({ data: { items: tpls } });
  m(fetchJSON).mockImplementation(async (path: string, init?: RequestInit) => {
    if (path === "/ssh/ca") return CA;
    if (path === "/ssh/certificates" && init?.method === "POST") return { data: cert("9", "2026-10-16T00:00:00Z") };
    if (path === "/ssh/certificates") return { data: certs };
    throw new Error("unexpected " + path);
  });
});

describe("SSH certificates page", () => {
  it("shows the CA key and copies it", async () => {
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    renderPage();
    expect(await screen.findByText("ssh-ed25519 AAAACA ca@kk")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Copy CA public key" }));
    expect(writeText).toHaveBeenCalledWith(CA.authority_line);
    expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
  });

  it("offers only templates with an ssh_policy", async () => {
    renderPage();
    const select = await screen.findByLabelText("Template");
    const names = within(select).getAllByRole("option").map((o) => o.textContent);
    expect(names).toEqual(["SSH Ops"]);
  });

  it("blocks a principal outside allowed_principals", async () => {
    const user = userEvent.setup();
    renderPage();
    await fill(user, { principals: "mallory" });
    await user.click(screen.getByRole("button", { name: "Issue certificate" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/mallory/);
    expect(posts()).toHaveLength(0);
  });

  it("blocks a TTL above the ceiling and accepts exactly the ceiling", async () => {
    const user = userEvent.setup();
    renderPage();
    await fill(user, { ttl: "25" });
    await user.click(screen.getByRole("button", { name: "Issue certificate" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/at most 24 hours/);
    expect(posts()).toHaveLength(0);
    await user.clear(screen.getByLabelText("TTL hours"));
    await user.type(screen.getByLabelText("TTL hours"), "24");
    await user.click(screen.getByRole("button", { name: "Issue certificate" }));
    await waitFor(() => expect(posts()).toHaveLength(1));
  });

  it("validates host patterns", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByLabelText("host"));
    await fill(user, { principals: "evil.example" });
    await user.click(screen.getByRole("button", { name: "Issue certificate" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/evil\.example/);
    expect(posts()).toHaveLength(0);
    await user.clear(screen.getByLabelText(/Principals/));
    await user.type(screen.getByLabelText(/Principals/), "web1.corp.example");
    await user.click(screen.getByRole("button", { name: "Issue certificate" }));
    await waitFor(() => expect(posts()).toHaveLength(1));
  });

  it("issues a cert and shows the line", async () => {
    const user = userEvent.setup();
    renderPage();
    await fill(user);
    await user.click(screen.getByRole("button", { name: "Issue certificate" }));
    const box = await screen.findByLabelText("Issued certificate");
    expect(box).toHaveValue("ssh-ed25519-cert-v01@openssh.com 9");
    expect(JSON.parse(posts()[0][1].body)).toEqual({
      template_id: "tpl-ssh", public_key: KEY, cert_type: "user", key_id: "kid-1", principals: ["alice"], ttl_hours: 8,
    });
    const listCalls = () => m(fetchJSON).mock.calls.filter((c) => c[0] === "/ssh/certificates" && !c[1]).length;
    await waitFor(() => expect(listCalls()).toBeGreaterThanOrEqual(2));
  });

  it("renders the pending approval state", async () => {
    m(fetchJSON).mockImplementation(async (path: string, init?: RequestInit) => {
      if (path === "/ssh/ca") return CA;
      if (init?.method === "POST") return { status: "pending_approval", approval_id: "appr-7", message: "needs approval" };
      return { data: [] };
    });
    const user = userEvent.setup();
    renderPage();
    await fill(user);
    await user.click(screen.getByRole("button", { name: "Issue certificate" }));
    expect(await screen.findAllByText("Pending approval")).not.toHaveLength(0);
    expect(screen.getAllByText("appr-7").length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "Approvals inbox" })).toHaveAttribute("href", "/inbox");
    expect(screen.queryByLabelText("Issued certificate")).toBeNull();
  });

  it("lists certs newest first", async () => {
    certs = [cert("1", "2026-01-01T00:00:00Z", "2020-01-01T00:00:00Z"), cert("2", "2026-06-01T00:00:00Z")];
    renderPage();
    const table = await screen.findByRole("table", { name: "Issued SSH certificates" });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("kid-2");
    expect(rows[1]).toHaveTextContent("kid-1");
    expect(rows[0]).toHaveTextContent("Active");
    expect(rows[1]).toHaveTextContent("Expired");
  });

  it("viewer role sees no issue form", async () => {
    m(api.authzCheck).mockResolvedValue({ role: "viewer", scopes: [] });
    renderPage();
    expect(await screen.findByText(/cannot issue SSH certificates/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Key ID")).toBeNull();
  });

  it("has no serious or critical axe violations", async () => {
    certs = [cert("1", "2026-01-01T00:00:00Z")];
    const { container } = renderPage();
    await screen.findByLabelText("Key ID");
    await screen.findByText("kid-1");
    const r = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(r.violations.filter((v) => v.impact === "serious" || v.impact === "critical")).toEqual([]);
  });
});
