import { describe, expect, it, vi, beforeEach } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    registerAgent: vi.fn(),
    agents: vi.fn(),
    createTarget: vi.fn(),
    credentials: vi.fn(),
    createCredential: vi.fn(),
  },
}));

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import TargetSetup from "../pages/TargetSetup";
import { api } from "../lib/api";

beforeEach(() => {
  vi.mocked(api.credentials).mockResolvedValue({ data: { items: [] } } as never);
});

// W18-04: the wizard used to present one POSIX-shaped install path for
// every host, so a Windows target could be configured in a way that could
// only fail at install time.

function renderWizard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <TargetSetup />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function goAgentless(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("radio", { name: /agentless/i }));
}

// Step 1 gates Next on a name and a host, so fill them before advancing.
async function fillHostStep(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText(/target name/i), "db-01.internal");
  await user.type(screen.getByLabelText(/^host$/i), "db-01.internal.example.com");
}

async function toInstallStep(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: /next/i })); // -> discovery
  await user.click(screen.getByRole("button", { name: /next/i })); // -> install
}

describe("target setup — OS awareness", () => {
  it("asks which operating system the host runs", async () => {
    const user = userEvent.setup();
    renderWizard();
    await goAgentless(user);
    expect(screen.getByRole("radio", { name: /Linux/i })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /Windows/i })).toBeInTheDocument();
  });

  // W18-05: macOS agentless is real now -- the System keychain over SSH --
  // and the old "agent-only" disclaimer must be gone.
  it("offers macOS agentless with the keychain install, and only for macOS", async () => {
    const user = userEvent.setup();
    renderWizard();
    await goAgentless(user);
    expect(screen.queryByText(/macOS is agent-only/i)).not.toBeInTheDocument();

    await fillHostStep(user);
    await user.click(screen.getByRole("radio", { name: /^macOS/i }));
    await toInstallStep(user);
    const install = screen.getByLabelText(/install mode/i);
    expect(within(install).getByRole("option", { name: /System keychain/i })).toBeInTheDocument();
    expect(within(install).queryByRole("option", { name: /SSH push/i })).not.toBeInTheDocument();
    expect(within(install).queryByRole("option", { name: /IIS/i })).not.toBeInTheDocument();
  });

  it("offers Windows install paths only for Windows hosts", async () => {
    const user = userEvent.setup();
    renderWizard();
    await goAgentless(user);

    // Linux is the default: SSH, never IIS.
    await fillHostStep(user);
    await toInstallStep(user);
    let install = screen.getByLabelText(/install mode/i);
    expect(within(install).queryByRole("option", { name: /IIS/i })).not.toBeInTheDocument();
    expect(within(install).getByRole("option", { name: /SSH push/i })).toBeInTheDocument();

    // Switch to Windows: IIS appears, SSH does not.
    await user.click(screen.getByRole("button", { name: /back/i }));
    await user.click(screen.getByRole("button", { name: /back/i }));
    await user.click(screen.getByRole("radio", { name: /Windows/i }));
    await toInstallStep(user);
    install = screen.getByLabelText(/install mode/i);
    expect(within(install).getByRole("option", { name: /IIS/i })).toBeInTheDocument();
    expect(within(install).queryByRole("option", { name: /SSH push/i })).not.toBeInTheDocument();
  });

  it("offers WinRM discovery only for Windows hosts", async () => {
    const user = userEvent.setup();
    renderWizard();
    await goAgentless(user);
    await fillHostStep(user);
    await user.click(screen.getByRole("radio", { name: /Windows/i }));
    await user.click(screen.getByRole("button", { name: /next/i }));
    const discovery = screen.getByLabelText(/discovery mode/i);
    expect(within(discovery).getByRole("option", { name: /WinRM/i })).toBeInTheDocument();
  });

  // k8s became storable in W17-11 but the wizard never offered it.
  it("offers the Kubernetes install mode the backend already accepts", async () => {
    const user = userEvent.setup();
    renderWizard();
    await goAgentless(user);
    await fillHostStep(user);
    await toInstallStep(user);
    const install = screen.getByLabelText(/install mode/i);
    expect(within(install).getByRole("option", { name: /Kubernetes/i })).toBeInTheDocument();
  });
});

// The dead end this wave fixed: the credential step referenced credentials
// nothing could create. It now creates one in place, shaped by the mode.
describe("target setup — credential picker", () => {
  it("creates a windows_password credential inline for an IIS target", async () => {
    const user = userEvent.setup();
    vi.mocked(api.credentials).mockResolvedValue({ data: { items: [] } } as never);
    vi.mocked(api.createCredential).mockResolvedValue({
      data: {
        id: "cred-new-1", name: "iis-web-01 winrm", credential_type: "windows_password",
        tenant: "default", created_at: "", updated_at: "",
      },
    } as never);

    renderWizard();
    await goAgentless(user);
    await fillHostStep(user);
    await user.click(screen.getByRole("radio", { name: /Windows/i }));
    await toInstallStep(user);
    await user.click(screen.getByRole("button", { name: /next/i })); // -> credential

    await user.selectOptions(screen.getByLabelText(/^credential$/i), "__new__");
    await user.type(screen.getByLabelText(/^name$/i), "iis-web-01 winrm");
    await user.type(screen.getByLabelText(/winrm endpoint/i), "https://iis-web-01:5986/wsman");
    await user.type(screen.getByLabelText(/^username$/i), "CORP\\svc-pki");
    await user.type(screen.getByLabelText(/^password$/i), "s3cret");
    await user.type(screen.getByLabelText(/https binding/i), "0.0.0.0:443");
    await user.click(screen.getByRole("button", { name: /create & use/i }));

    await waitFor(() =>
      expect(api.createCredential).toHaveBeenCalledWith({
        name: "iis-web-01 winrm",
        credential_type: "windows_password",
        payload: {
          base_url: "https://iis-web-01:5986/wsman",
          username: "CORP\\svc-pki",
          password: "s3cret",
          ipport: "0.0.0.0:443",
        },
      }),
    );
  });

  // The executor pins the host key and refuses a credential without one, so
  // a credential made here must carry it (W18-05 finding; applies to ssh too).
  it("creates an ssh_key credential with a pinned host key for a macOS keychain target", async () => {
    const user = userEvent.setup();
    vi.mocked(api.credentials).mockResolvedValue({ data: { items: [] } } as never);
    vi.mocked(api.createCredential).mockResolvedValue({
      data: {
        id: "cred-mac-1", name: "mac01 ssh", credential_type: "ssh_key",
        tenant: "default", created_at: "", updated_at: "",
      },
    } as never);

    renderWizard();
    await goAgentless(user);
    await fillHostStep(user);
    await user.click(screen.getByRole("radio", { name: /^macOS/i }));
    await toInstallStep(user);
    await user.click(screen.getByRole("button", { name: /next/i })); // -> credential

    await user.selectOptions(screen.getByLabelText(/^credential$/i), "__new__");
    await user.type(screen.getByLabelText(/^name$/i), "mac01 ssh");
    await user.type(screen.getByLabelText(/ssh user/i), "admin");
    await user.type(screen.getByLabelText(/private key/i), "PEM");
    await user.type(screen.getByLabelText(/host public key/i), "ssh-ed25519 AAAAC3");
    await user.click(screen.getByRole("button", { name: /create & use/i }));

    await waitFor(() =>
      expect(api.createCredential).toHaveBeenCalledWith({
        name: "mac01 ssh",
        credential_type: "ssh_key",
        payload: { user: "admin", private_key_pem: "PEM", host_public_key: "ssh-ed25519 AAAAC3" },
      }),
    );
  });
});
