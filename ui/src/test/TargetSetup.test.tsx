import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    registerAgent: vi.fn(),
    agents: vi.fn(),
    createTarget: vi.fn(),
    credentials: vi.fn(),
    createCredential: vi.fn(),
    preflightCredential: vi.fn(),
  },
}));

import TargetSetup from "../pages/TargetSetup";
import { api } from "../lib/api";

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
  vi.mocked(api.registerAgent).mockReset();
  vi.mocked(api.agents).mockReset();
  vi.mocked(api.createTarget).mockReset();
  vi.mocked(api.credentials).mockReset();
  vi.mocked(api.credentials).mockResolvedValue({
    data: {
      items: [
        {
          id: "cred-f5-1", name: "prod f5", credential_type: "api_token",
          tenant: "default", created_at: "", updated_at: "",
        },
        {
          id: "cred-win-1", name: "iis svc", credential_type: "windows_password",
          tenant: "default", created_at: "", updated_at: "",
        },
      ],
    },
  } as never);
});

describe("TargetSetup — agent mode (acceptance #1)", () => {
  it("generates a real token (not a static snippet) and reflects the live pairing transition", async () => {
    const user = userEvent.setup();
    vi.mocked(api.registerAgent).mockResolvedValue({
      agent_id: "agent-abc",
      token: "tok-secret-xyz",
    });
    // First poll: agent has never checked in (last_seen null) -- still
    // waiting. Second poll (after "Check now"): the agent has heartbeated.
    vi.mocked(api.agents)
      .mockResolvedValueOnce({
        agents: [
          {
            id: "agent-abc",
            name: "web-01",
            type: "linux",
            registered_at: "2026-07-28T00:00:00Z",
            last_seen: null,
            status: "offline",
            inventory_count: 0,
          },
        ],
      } as never)
      .mockResolvedValueOnce({
        agents: [
          {
            id: "agent-abc",
            name: "web-01",
            type: "linux",
            registered_at: "2026-07-28T00:00:00Z",
            last_seen: "2026-07-28T00:05:00Z",
            status: "active",
            inventory_count: 0,
          },
        ],
      } as never);

    renderPage();

    await user.type(screen.getByLabelText(/agent name/i), "web-01");
    await user.click(screen.getByRole("button", { name: /generate token/i }));

    await waitFor(() =>
      expect(api.registerAgent).toHaveBeenCalledWith({
        name: "web-01",
        type: "linux",
      }),
    );

    // The install command embeds the real, freshly generated credentials --
    // not a static placeholder snippet (board acceptance #1).
    expect(screen.getByText(/agent-abc/)).toBeInTheDocument();
    expect(screen.getByText(/tok-secret-xyz/)).toBeInTheDocument();

    await screen.findByText(/waiting for agent/i);
    expect(screen.queryByText(/paired/i)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /check now/i }));

    await screen.findByText(/paired/i);
    expect(screen.getByText(/web-01/)).toBeInTheDocument();
    expect(api.agents).toHaveBeenCalledTimes(2);
  });

  it("surfaces a registration error inline", async () => {
    const user = userEvent.setup();
    vi.mocked(api.registerAgent).mockRejectedValue(
      new Error("name is required"),
    );
    renderPage();

    await user.type(screen.getByLabelText(/agent name/i), "web-01");
    await user.click(screen.getByRole("button", { name: /generate token/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /name is required/i,
    );
  });
});

describe("TargetSetup — agentless mode (acceptance #2)", () => {
  async function switchToAgentless(user: ReturnType<typeof userEvent.setup>) {
    await user.click(screen.getByRole("radio", { name: /^Agentless/i }));
  }

  it("walks host -> discovery_mode -> install_mode -> credential and writes the W5-09 model", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createTarget).mockResolvedValue({
      data: {
        id: "target-1",
        name: "db-01",
        host: "db-01.internal.example.com",
        discovery_mode: "cloud",
        install_mode: "f5",
        renewal_method: "acme",
        credential_ref: "cred-f5-1",
        tenant: "default",
        created_at: "2026-07-28T00:00:00Z",
        updated_at: "2026-07-28T00:00:00Z",
      },
    } as never);

    renderPage();
    await switchToAgentless(user);

    // Step 1: host
    await user.type(screen.getByLabelText(/target name/i), "db-01");
    await user.type(
      screen.getByLabelText(/^host$/i),
      "db-01.internal.example.com",
    );
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Step 2: discovery_mode — pick a non-default value so the assertion
    // below actually proves the field is wired, not just present.
    await user.selectOptions(screen.getByLabelText(/discovery mode/i), "cloud");
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Step 3: install_mode — f5 requires a credential (known trap).
    await user.selectOptions(screen.getByLabelText(/install mode/i), "f5");
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Step 4: credential — blocked until filled for f5.
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      /credential reference is required for f5/i,
    );
    expect(api.createTarget).not.toHaveBeenCalled();

    // The step is now a picker over credentials that actually exist —
    // the old free-text reference had nothing behind it to reference.
    await user.selectOptions(
      screen.getByLabelText(/^credential$/i),
      "cred-f5-1",
    );
    // Credential step's Next lands on the Review summary; Finish submits.
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Finish" }));

    await waitFor(() =>
      expect(api.createTarget).toHaveBeenCalledWith({
        name: "db-01",
        host: "db-01.internal.example.com",
        discovery_mode: "cloud",
        install_mode: "f5",
        credential_ref: "cred-f5-1",
        schedule: undefined,
        renewal_method: "manual",
        auto_renew: false,
        install_server_type: undefined,
        install_cert_path: undefined,
        install_key_path: undefined,
      }),
    );

    expect(await screen.findByText(/db-01 declared/i)).toBeInTheDocument();
  });

  it("does not require a credential for acme install mode", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createTarget).mockResolvedValue({
      data: {
        id: "target-2",
        name: "web-02",
        host: "web-02.example.com",
        discovery_mode: "network",
        install_mode: "acme",
        renewal_method: "acme",
        tenant: "default",
        created_at: "2026-07-28T00:00:00Z",
        updated_at: "2026-07-28T00:00:00Z",
      },
    } as never);

    renderPage();
    await switchToAgentless(user);

    await user.type(screen.getByLabelText(/target name/i), "web-02");
    await user.type(screen.getByLabelText(/^host$/i), "web-02.example.com");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Next" }));

    await user.selectOptions(screen.getByLabelText(/install mode/i), "acme");
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Credential step's Next lands on the Review summary; Finish submits.
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Finish" }));

    await waitFor(() =>
      expect(api.createTarget).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "web-02",
          install_mode: "acme",
          credential_ref: undefined,
        }),
      ),
    );
  });
});

// W18-11: a Windows credential can be tested from the picker, and the
// verdict says whether it can only discover or also install.
describe("TargetSetup — credential preflight (W18-11)", () => {
  it("tests a windows_password credential and shows a discover-only verdict", async () => {
    const user = userEvent.setup();
    vi.mocked(api.preflightCredential).mockResolvedValue({
      data: {
        credential_id: "cred-win-1",
        level: "discover",
        can_discover: true,
        can_install: false,
        detail: "the session runs with a standard (Medium integrity) token",
      },
    } as never);

    renderPage();
    await user.click(screen.getByRole("radio", { name: /^Agentless/i }));
    // WinRM discovery and IIS install are Windows-only choices.
    await user.click(screen.getByRole("radio", { name: /Windows/i }));
    await user.type(screen.getByLabelText(/target name/i), "iis-01");
    await user.type(screen.getByLabelText(/^host$/i), "iis-01.example.com");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.selectOptions(screen.getByLabelText(/discovery mode/i), "winrm");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.selectOptions(screen.getByLabelText(/install mode/i), "iis");
    await user.click(screen.getByRole("button", { name: "Next" }));

    // No button until a Windows credential is picked.
    expect(screen.queryByRole("button", { name: /test credential/i })).toBeNull();
    await user.selectOptions(screen.getByLabelText(/^credential$/i), "cred-win-1");
    await user.click(screen.getByRole("button", { name: /test credential/i }));

    await waitFor(() =>
      expect(api.preflightCredential).toHaveBeenCalledWith("cred-win-1"),
    );
    const panel = await screen.findByTestId("credential-preflight");
    expect(panel).toHaveTextContent(/discover only/i);
    expect(panel).toHaveTextContent(/needs a local administrator/i);
    expect(panel).toHaveTextContent(/medium integrity/i);
  });
});
