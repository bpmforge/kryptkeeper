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
    credentialSources: vi.fn(),
    testCredentialSource: vi.fn(),
    preflightCredential: vi.fn(),
    probeTargetHostKey: vi.fn(),
    runtimeConfig: vi.fn(),
    privilegeBundle: vi.fn(),
  },
}));

import TargetSetup from "../pages/TargetSetup";
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

const SHA = "ab".repeat(32);

beforeEach(() => {
  vi.mocked(api.createCredential).mockReset();
  vi.mocked(api.testCredentialSource).mockReset();
  vi.mocked(api.runtimeConfig).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.privilegeBundle).mockRejectedValue(
    new Error("bundle unavailable"),
  );
  vi.mocked(api.credentials).mockResolvedValue({
    data: { items: [] },
  } as never);
  vi.mocked(api.credentialSources).mockResolvedValue({
    data: {
      items: [
        {
          id: "csrc-1",
          name: "prod vault",
          kind: "vault_kv2",
          tenant: "default",
          credential_ref: "c-login",
          config: { base_url: "https://vault.example.com" },
        },
        {
          id: "csrc-2",
          name: "ccp",
          kind: "plugin",
          tenant: "default",
          credential_ref: "c-ccp",
          config: { plugin_id: "kryptkeeper.cyberark-ccp" },
        },
      ],
    },
  } as never);
});

async function openNewCredential(user: User) {
  await user.click(screen.getByRole("radio", { name: /^Agentless/i }));
  await user.type(screen.getByLabelText(/target name/i), "web-01");
  await user.type(screen.getByLabelText(/^host$/i), "web-01.example.com");
  await user.click(screen.getByRole("button", { name: "Next" }));
  await user.click(screen.getByRole("button", { name: "Next" }));
  await user.click(screen.getByRole("button", { name: "Next" }));
  await user.selectOptions(screen.getByLabelText(/^credential$/i), "__new__");
  await user.type(screen.getByLabelText(/^name$/i), "web1 ssh");
}

describe("TargetSetup — fetch a credential from a secret manager (W38-07)", () => {
  it("stores the secret here by default and offers the secret manager as a choice", async () => {
    const user = userEvent.setup();
    renderPage();
    await openNewCredential(user);
    expect(screen.getByRole("radio", { name: /store it here/i })).toBeChecked();
    expect(screen.getByLabelText(/private key/i)).toBeInTheDocument();
    expect(
      screen.queryByTestId("external-credential-fields"),
    ).not.toBeInTheDocument();
    // The sources are not fetched until the operator asks for one.
    expect(api.credentialSources).not.toHaveBeenCalled();
  });

  it("sends a reference and fixed fields, never a payload or a secret", async () => {
    vi.mocked(api.createCredential).mockResolvedValue({
      data: {
        id: "c9",
        name: "web1 ssh",
        credential_type: "ssh_key",
        tenant: "default",
        created_at: "",
        updated_at: "",
        source: "external",
      },
    } as never);
    const user = userEvent.setup();
    renderPage();
    await openNewCredential(user);
    await user.click(
      screen.getByRole("radio", { name: /fetch it from a secret manager/i }),
    );

    // The secret fields are not asked for; the form says they are fetched.
    expect(screen.queryByLabelText(/private key/i)).not.toBeInTheDocument();
    expect(
      screen.getByText(
        /fetched from the manager at each use, never stored here: Private key/i,
      ),
    ).toBeInTheDocument();

    const create = screen.getByRole("button", { name: /create & use/i });
    expect(create).toBeDisabled();
    await user.selectOptions(
      await screen.findByLabelText(/^secret manager$/i),
      "csrc-1",
    );
    expect(create).toBeDisabled(); // a Vault source needs a path
    await user.type(screen.getByLabelText(/secret path/i), "ssh/web1");
    await user.type(screen.getByLabelText(/ssh user/i), "kkscan");
    await user.type(
      screen.getByLabelText(/host public key/i),
      "ssh-ed25519 AAAA",
    );
    await user.type(screen.getByLabelText(/helper sha-256/i), SHA);
    expect(create).toBeEnabled();
    await user.click(create);
    await waitFor(() =>
      expect(api.createCredential).toHaveBeenCalledWith({
        name: "web1 ssh",
        credential_type: "ssh_key",
        source: "external",
        source_id: "csrc-1",
        reference: { path: "ssh/web1" },
        static: {
          user: "kkscan",
          host_public_key: "ssh-ed25519 AAAA",
          sudo_mode: "helper",
          helper_sha256: SHA,
        },
      }),
    );
    const sent = JSON.stringify(
      vi.mocked(api.createCredential).mock.calls[0][0],
    );
    expect(sent).not.toMatch(/payload|private_key_pem|password/);
  });

  it("tests a reference and shows the field names or the clear failure", async () => {
    vi.mocked(api.testCredentialSource)
      .mockResolvedValueOnce({
        data: {
          ok: true,
          fields: ["host_public_key", "private_key_pem", "user"],
        },
      } as never)
      .mockResolvedValueOnce({
        data: {
          ok: false,
          error:
            "prod vault: nothing at secret/ssh/nope (missing path, deleted or destroyed version)",
        },
      } as never);
    const user = userEvent.setup();
    renderPage();
    await openNewCredential(user);
    await user.click(
      screen.getByRole("radio", { name: /fetch it from a secret manager/i }),
    );
    await user.selectOptions(
      await screen.findByLabelText(/^secret manager$/i),
      "csrc-1",
    );
    await user.type(screen.getByLabelText(/secret path/i), "ssh/web1");
    await user.click(screen.getByRole("button", { name: /test reference/i }));
    expect(
      await screen.findByTestId("external-credential-test"),
    ).toHaveTextContent("provides: host_public_key, private_key_pem, user");
    expect(api.testCredentialSource).toHaveBeenCalledWith(
      "csrc-1",
      expect.objectContaining({
        credential_type: "ssh_key",
        reference: { path: "ssh/web1" },
      }),
    );

    await user.click(screen.getByRole("button", { name: /test reference/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "nothing at secret/ssh/nope",
    );
  });

  it("takes key=value reference lines for a plugin source", async () => {
    vi.mocked(api.createCredential).mockResolvedValue({
      data: {
        id: "c9",
        name: "web1 ssh",
        credential_type: "ssh_key",
        tenant: "default",
        created_at: "",
        updated_at: "",
      },
    } as never);
    const user = userEvent.setup();
    renderPage();
    await openNewCredential(user);
    await user.click(
      screen.getByRole("radio", { name: /fetch it from a secret manager/i }),
    );
    await user.selectOptions(
      await screen.findByLabelText(/^secret manager$/i),
      "csrc-2",
    );
    await user.click(screen.getByLabelText(/reference \(one key=value/i));
    await user.paste(
      "safe=Infra\nobject=web1-root\nmap=Content:private_key_pem,UserName:user",
    );
    await user.type(screen.getByLabelText(/helper sha-256/i), SHA);
    await user.type(
      screen.getByLabelText(/host public key/i),
      "ssh-ed25519 AAAA",
    );
    await user.click(screen.getByRole("button", { name: /create & use/i }));
    await waitFor(() =>
      expect(api.createCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          source_id: "csrc-2",
          reference: {
            safe: "Infra",
            object: "web1-root",
            map: "Content:private_key_pem,UserName:user",
          },
        }),
      ),
    );
  });

  it("points at the API when there are no sources yet", async () => {
    vi.mocked(api.credentialSources).mockResolvedValue({
      data: { items: [] },
    } as never);
    const user = userEvent.setup();
    renderPage();
    await openNewCredential(user);
    await user.click(
      screen.getByRole("radio", { name: /fetch it from a secret manager/i }),
    );
    expect(
      await screen.findByText(/no credential sources yet/i),
    ).toBeInTheDocument();
  });
});
