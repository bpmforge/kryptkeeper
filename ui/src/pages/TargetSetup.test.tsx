import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    registerAgent: vi.fn(),
    mintAgentEnrollmentToken: vi.fn(),
    agentEnrollmentTokens: vi.fn().mockResolvedValue({ data: [] }),
    revokeAgentEnrollmentToken: vi.fn(),
    agents: vi.fn(),
    createTarget: vi.fn(),
    credentials: vi.fn(),
    createCredential: vi.fn(),
    preflightCredential: vi.fn(),
    probeTargetHostKey: vi.fn(),
    runtimeConfig: vi.fn(),
    privilegeBundle: vi.fn(),
  },
}));

import TargetSetup from "./TargetSetup";
import { api } from "../lib/api";

type User = ReturnType<typeof userEvent.setup>;

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <TargetSetup />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.mocked(api.createTarget).mockReset();
  vi.mocked(api.probeTargetHostKey).mockReset();
  vi.mocked(api.probeTargetHostKey).mockResolvedValue({
    data: {
      host: "web-01.example.com",
      port: 22,
      algorithm: "ssh-ed25519",
      ssh_host_key: "ssh-ed25519 AAAA",
      fingerprint_sha256: "SHA256:abc",
    },
  } as never);
  vi.mocked(api.runtimeConfig).mockReset();
  vi.mocked(api.runtimeConfig).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.createCredential).mockReset();
  vi.mocked(api.privilegeBundle).mockReset();
  vi.mocked(api.privilegeBundle).mockRejectedValue(new Error("bundle unavailable"));
  vi.mocked(api.credentials).mockResolvedValue({
    data: {
      items: [
        {
          id: "cred-ssh-1",
          name: "ops key",
          credential_type: "ssh_key",
          tenant: "default",
          created_at: "",
          updated_at: "",
        },
      ],
    },
  } as never);
});

// Walks host -> discovery -> install (ssh is the default) -> credential and
// lands on the Host key step.
async function reachHostKeyStep(user: User) {
  await user.click(screen.getByRole("radio", { name: /^Agentless/i }));
  await user.type(screen.getByLabelText(/target name/i), "web-01");
  await user.type(screen.getByLabelText(/^host$/i), "web-01.example.com");
  await user.click(screen.getByRole("button", { name: "Next" }));
  await user.click(screen.getByRole("button", { name: "Next" }));
  await user.click(screen.getByRole("button", { name: "Next" }));
  await user.selectOptions(screen.getByLabelText(/^credential$/i), "cred-ssh-1");
  await user.click(screen.getByRole("button", { name: "Next" }));
}

describe("TargetSetup — SSH host key confirmation (W24-10)", () => {
  it("shows the fingerprint after fetching the host key", async () => {
    const user = userEvent.setup();
    renderPage();
    await reachHostKeyStep(user);
    await user.click(screen.getByRole("button", { name: /fetch host key/i }));
    expect(await screen.findByText("SHA256:abc")).toBeInTheDocument();
    expect(api.probeTargetHostKey).toHaveBeenCalledWith({
      host: "web-01.example.com",
    });
  });

  it("blocks saving until the fingerprint is confirmed", async () => {
    const user = userEvent.setup();
    renderPage();
    await reachHostKeyStep(user);
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Fetch the host key first.",
    );
    await user.click(screen.getByRole("button", { name: /fetch host key/i }));
    await screen.findByText("SHA256:abc");
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Confirm the fingerprint before saving.",
    );
    expect(api.createTarget).not.toHaveBeenCalled();
  });

  it("saves the confirmed key", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createTarget).mockResolvedValue({
      data: {
        id: "t-1",
        name: "web-01",
        host: "web-01.example.com",
        discovery_mode: "network",
        install_mode: "ssh",
        renewal_method: "manual",
        ssh_host_key_fingerprint: "SHA256:abc",
        tenant: "default",
        created_at: "",
        updated_at: "",
      },
    } as never);
    renderPage();
    await reachHostKeyStep(user);
    await user.click(screen.getByRole("button", { name: /fetch host key/i }));
    await screen.findByText("SHA256:abc");
    await user.click(screen.getByLabelText(/i have verified this fingerprint/i));
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Finish" }));
    await waitFor(() =>
      expect(api.createTarget).toHaveBeenCalledWith(
        expect.objectContaining({ ssh_host_key: "ssh-ed25519 AAAA" }),
      ),
    );
    expect(await screen.findByText(/pinned host key/i)).toBeInTheDocument();
  });

  it("changing the host clears the confirmation", async () => {
    const user = userEvent.setup();
    renderPage();
    await reachHostKeyStep(user);
    await user.click(screen.getByRole("button", { name: /fetch host key/i }));
    await screen.findByText("SHA256:abc");
    await user.click(screen.getByLabelText(/i have verified this fingerprint/i));
    // Back to the Host step, change the host, return to the Host key step.
    for (let i = 0; i < 4; i++) {
      await user.click(screen.getByRole("button", { name: /back/i }));
    }
    await user.type(screen.getByLabelText(/^host$/i), "x");
    for (let i = 0; i < 4; i++) {
      await user.click(screen.getByRole("button", { name: "Next" }));
    }
    expect(screen.queryByText("SHA256:abc")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Fetch the host key first.",
    );
  });
});

// W34-14: the credential form offers the four sudo modes (D-209).
describe("TargetSetup — SSH credential privilege mode (W34-14)", () => {
  async function openNewCredential(user: User) {
    await user.click(screen.getByRole("radio", { name: /^Agentless/i }));
    await user.type(screen.getByLabelText(/target name/i), "web-01");
    await user.type(screen.getByLabelText(/^host$/i), "web-01.example.com");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.selectOptions(screen.getByLabelText(/^credential$/i), "__new__");
  }

  async function fillSSHFields(user: User) {
    await user.type(screen.getByLabelText(/^name$/i), "kkscan");
    await user.type(screen.getByLabelText(/ssh user/i), "kkscan");
    await user.type(screen.getByLabelText(/private key/i), "PEM");
    await user.type(screen.getByLabelText(/host public key/i), "ssh-ed25519 AAAA");
  }

  const SHA = "ab".repeat(32);
  const created = {
    data: { id: "c2", name: "kkscan", credential_type: "ssh_key", tenant: "default", created_at: "", updated_at: "" },
  } as never;

  it("offers four modes with consequences and preselects helper by default", async () => {
    const user = userEvent.setup();
    renderPage();
    await openNewCredential(user);

    expect(screen.getByRole("radio", { name: /helper \(recommended\)/i })).toBeChecked();
    expect(screen.getByRole("radio", { name: /raw sudo/i })).not.toBeChecked();
    expect(screen.getByRole("radio", { name: /sudo password/i })).not.toBeChecked();
    expect(screen.getByRole("radio", { name: /^none/i })).not.toBeChecked();
    expect(screen.getByText(/hash-pinned helper/i)).toBeInTheDocument();
    expect(screen.getByText(/effectively root read\/write/i)).toBeInTheDocument();
    expect(screen.getByText(/rotating it breaks scans/i)).toBeInTheDocument();
    expect(screen.getByText(/INSUFFICIENT_PRIVILEGE/)).toBeInTheDocument();
  });

  it("preselects the operator-configured default mode and keeps every mode selectable", async () => {
    vi.mocked(api.runtimeConfig).mockResolvedValue({
      data: [
        {
          key: "agentless.default_privilege_mode",
          category: "agentless",
          env_var: "KRYPTKEEPER_AGENTLESS_DEFAULT_PRIVILEGE_MODE",
          secret: false,
          source: "env_default",
          effective_source: "env",
          configured: true,
          value: "nopasswd",
        },
      ],
    } as never);
    const user = userEvent.setup();
    renderPage();
    await openNewCredential(user);
    await waitFor(() => expect(screen.getByRole("radio", { name: /raw sudo/i })).toBeChecked());
    await user.click(screen.getByRole("radio", { name: /^none/i }));
    expect(screen.getByRole("radio", { name: /^none/i })).toBeChecked();
  });

  it("sends the helper hash and blocks creation until it is valid", async () => {
    vi.mocked(api.createCredential).mockResolvedValue(created);
    const user = userEvent.setup();
    renderPage();
    await openNewCredential(user);
    await fillSSHFields(user);
    const create = screen.getByRole("button", { name: /create & use/i });
    expect(create).toBeDisabled();
    await user.type(screen.getByLabelText(/helper sha-256/i), SHA);
    expect(create).toBeEnabled();
    await user.click(create);
    await waitFor(() =>
      expect(api.createCredential).toHaveBeenCalledWith({
        name: "kkscan",
        credential_type: "ssh_key",
        payload: {
          user: "kkscan",
          private_key_pem: "PEM",
          host_public_key: "ssh-ed25519 AAAA",
          sudo_mode: "helper",
          helper_sha256: SHA,
        },
      }),
    );
  });

  it("sends only the sudo password in password mode", async () => {
    vi.mocked(api.createCredential).mockResolvedValue(created);
    const user = userEvent.setup();
    renderPage();
    await openNewCredential(user);
    await fillSSHFields(user);
    await user.click(screen.getByRole("radio", { name: /sudo password/i }));
    expect(screen.queryByLabelText(/helper sha-256/i)).not.toBeInTheDocument();
    const create = screen.getByRole("button", { name: /create & use/i });
    expect(create).toBeDisabled();
    await user.type(screen.getByLabelText(/^sudo password$/i), "pw-1");
    await user.click(create);
    await waitFor(() =>
      expect(api.createCredential).toHaveBeenCalledWith({
        name: "kkscan",
        credential_type: "ssh_key",
        payload: {
          user: "kkscan",
          private_key_pem: "PEM",
          host_public_key: "ssh-ed25519 AAAA",
          sudo_mode: "password",
          sudo_password: "pw-1",
        },
      }),
    );
  });

  it("shows the hub's privilege bundle and prefills the helper hash from it (W34-16)", async () => {
    vi.mocked(api.privilegeBundle).mockResolvedValue({
      data: {
        mode: "helper",
        user: "kkscan",
        sudoers: "kkscan ALL=(root) NOPASSWD: /usr/local/sbin/kryptkeeper-helper\n",
        helper: "#!/bin/sh\n",
        helper_sha256: SHA,
        helper_path: "/usr/local/sbin/kryptkeeper-helper",
        checklist: ["On the host, create the account: sudo useradd -m kkscan"],
        warnings: [],
      },
    } as never);
    vi.mocked(api.createCredential).mockResolvedValue(created);
    const user = userEvent.setup();
    renderPage();
    await openNewCredential(user);
    await fillSSHFields(user);

    const panel = await screen.findByTestId("privilege-bundle");
    expect(panel).toHaveTextContent(SHA);
    expect(panel).toHaveTextContent("useradd -m kkscan");
    expect(screen.getByRole("button", { name: /download sudoers/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /download helper/i })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByLabelText(/helper sha-256/i)).toHaveValue(SHA));

    await user.click(screen.getByRole("button", { name: /create & use/i }));
    await waitFor(() =>
      expect(api.createCredential).toHaveBeenCalledWith(
        expect.objectContaining({ payload: expect.objectContaining({ sudo_mode: "helper", helper_sha256: SHA }) }),
      ),
    );
  });

  it("warns about the glob caveat in raw mode (W34-16)", async () => {
    vi.mocked(api.privilegeBundle).mockResolvedValue({
      data: { mode: "nopasswd", user: "kkscan", sudoers: "x", checklist: ["step"], warnings: ["cat on a globbed path is root read/write"] },
    } as never);
    const user = userEvent.setup();
    renderPage();
    await openNewCredential(user);
    await user.click(screen.getByRole("radio", { name: /raw sudo/i }));
    expect(await screen.findByText(/root read\/write/i, { selector: "p[role='note']" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /download helper/i })).not.toBeInTheDocument();
  });
});
