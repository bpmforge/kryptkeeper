import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    siemStatus: vi.fn(),
    siemTest: vi.fn(),
    evidenceSchedules: vi.fn(),
    createEvidenceSchedule: vi.fn(),
    deleteEvidenceSchedule: vi.fn(),
    sendEvidenceNow: vi.fn(),
    reportScheduleCatalog: vi.fn(),
    reportSchedules: vi.fn(),
    createReportSchedule: vi.fn(),
    deleteReportSchedule: vi.fn(),
    runtimeConfig: vi.fn(),
    setRuntimeConfig: vi.fn(),
    resetRuntimeConfig: vi.fn(),
    credentials: vi.fn(),
    setCredentialPrivileged: vi.fn(),
  },
}));

import Settings from "./Settings";
import { api } from "../lib/api";

type Setting = {
  key: string;
  category: string;
  env_var: string;
  secret: boolean;
  source: string;
  value?: string;
  configured: boolean;
};

function setting(key: string, value: string | undefined, over: Partial<Setting> = {}): Setting {
  return {
    key,
    category: "discovery",
    env_var: "X",
    secret: false,
    source: value === undefined ? "unset" : "database",
    value,
    configured: value !== undefined,
    ...over,
  };
}

function mockConfig(settings: Setting[]) {
  vi.mocked(api.runtimeConfig).mockResolvedValue({ data: settings } as never);
}

function renderSettings() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Settings />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.siemStatus).mockResolvedValue({
    data: { enabled: false, webhook_enabled: false, webhook_has_token: false, syslog_enabled: false },
  } as never);
  vi.mocked(api.evidenceSchedules).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.reportScheduleCatalog).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.reportSchedules).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.setRuntimeConfig).mockResolvedValue(undefined as never);
  vi.mocked(api.resetRuntimeConfig).mockResolvedValue(undefined as never);
  vi.mocked(api.credentials).mockResolvedValue({
    data: {
      items: [
        { id: "cred-1", name: "prod token", credential_type: "api_token", tenant: "default", created_at: "", updated_at: "" },
        { id: "cred-x", name: "a password", credential_type: "windows_password", tenant: "default", created_at: "", updated_at: "" },
      ],
    },
  } as never);
  mockConfig([]);
});

describe("Settings — discovery sources (W24-25)", () => {
  it("adds a kube cluster and saves the JSON list", async () => {
    const user = userEvent.setup();
    renderSettings();
    await user.click(await screen.findByRole("button", { name: /add cluster/i }));
    await user.type(screen.getByLabelText("Cluster name"), "prod");
    await user.selectOptions(await screen.findByLabelText("Cluster credential"), "cred-1");
    expect(
      within(screen.getByLabelText("Cluster credential")).queryByText("a password"),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save Kubernetes clusters" }));
    await waitFor(() =>
      expect(api.setRuntimeConfig).toHaveBeenCalledWith(
        "discovery.kube_clusters",
        '[{"name":"prod","credential_ref":"cred-1","namespace":""}]',
      ),
    );
  });

  it("edits and removes an entry", async () => {
    const user = userEvent.setup();
    mockConfig([
      setting("discovery.kube_clusters", '[{"name":"prod","credential_ref":"cred-1","namespace":""}]'),
    ]);
    renderSettings();
    const name = await screen.findByDisplayValue("prod");
    await user.clear(name);
    await user.type(name, "staging");
    await user.click(screen.getByRole("button", { name: "Save Kubernetes clusters" }));
    await waitFor(() =>
      expect(api.setRuntimeConfig).toHaveBeenCalledWith(
        "discovery.kube_clusters",
        '[{"name":"staging","credential_ref":"cred-1","namespace":""}]',
      ),
    );
    await user.click(screen.getByRole("button", { name: "Remove staging" }));
    await user.click(screen.getByRole("button", { name: "Save Kubernetes clusters" }));
    await waitFor(() =>
      expect(api.resetRuntimeConfig).toHaveBeenCalledWith("discovery.kube_clusters"),
    );
  });

  it("values persist across reload", async () => {
    mockConfig([
      setting("discovery.kube_clusters", '[{"name":"prod","credential_ref":"cred-1","namespace":"kk"}]'),
      setting("discovery.saas_endpoints", '["api.example.com:443"]'),
      setting("ct.domains", "example.com,example.org"),
      setting("discovery.cloud_scopes", '[{"provider":"aws-acm","region":"us-east-1","profile":"prod"}]'),
    ]);
    const first = renderSettings();
    expect(await screen.findByLabelText("Cluster name")).toHaveValue("prod");
    first.unmount();
    renderSettings();
    expect(await screen.findByLabelText("Cluster name")).toHaveValue("prod");
    expect(screen.getByDisplayValue("kk")).toBeInTheDocument();
    expect(screen.getByDisplayValue("api.example.com:443")).toBeInTheDocument();
    expect(screen.getByDisplayValue("example.com")).toBeInTheDocument();
    expect(screen.getByDisplayValue("example.org")).toBeInTheDocument();
    expect(screen.getByDisplayValue("us-east-1")).toBeInTheDocument();
    expect(screen.getByLabelText("AWS profile")).toHaveValue("prod");
  });

  it("saves CT domains as the comma-separated list the monitor parses", async () => {
    const user = userEvent.setup();
    renderSettings();
    await user.click(await screen.findByRole("button", { name: /add domain/i }));
    await user.type(screen.getByLabelText("CT domain"), "Example.com");
    await user.click(screen.getByRole("button", { name: "Save CT monitor domains" }));
    await waitFor(() =>
      expect(api.setRuntimeConfig).toHaveBeenCalledWith("ct.domains", "example.com"),
    );
  });

  it("saves a cloud scope with only the provider's fields", async () => {
    const user = userEvent.setup();
    renderSettings();
    await user.click(await screen.findByRole("button", { name: /add cloud source/i }));
    await user.type(screen.getByLabelText("Cloud region"), "eu-west-1");
    await user.click(screen.getByRole("button", { name: "Save Cloud sources" }));
    await waitFor(() =>
      expect(api.setRuntimeConfig).toHaveBeenCalledWith(
        "discovery.cloud_scopes",
        '[{"provider":"aws-acm","region":"eu-west-1"}]',
      ),
    );
  });

  it("invalid SaaS endpoint disables Save", async () => {
    const user = userEvent.setup();
    renderSettings();
    await user.click(await screen.findByRole("button", { name: /add endpoint/i }));
    await user.type(screen.getByLabelText("SaaS endpoint"), "https://api.example.com");
    expect(screen.getByRole("button", { name: "Save SaaS / API endpoints" })).toBeDisabled();
    await user.clear(screen.getByLabelText("SaaS endpoint"));
    await user.type(screen.getByLabelText("SaaS endpoint"), "api.example.com:443");
    expect(screen.getByRole("button", { name: "Save SaaS / API endpoints" })).toBeEnabled();
  });

  it("secret setting is masked", async () => {
    mockConfig([
      setting("discovery.saas_endpoints", "supersecret", { secret: true, configured: true }),
    ]);
    renderSettings();
    expect(await screen.findByText("Configured (write-only)")).toBeInTheDocument();
    expect(screen.queryByText("supersecret")).toBeNull();
    for (const input of document.querySelectorAll("input")) {
      expect((input as HTMLInputElement).value).not.toBe("supersecret");
    }
    expect(screen.queryByDisplayValue("supersecret")).toBeNull();
  });

  it("malformed stored JSON shows warning and does not crash", async () => {
    mockConfig([setting("discovery.kube_clusters", "{not json")]);
    renderSettings();
    expect((await screen.findAllByText(/stored value could not be parsed/i)).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /add cluster/i })).toBeInTheDocument();
  });
});

describe("Settings — privileged credentials (W34-11)", () => {
  it("shows the auto badge and toggles the manual flag", async () => {
    vi.mocked(api.credentials).mockResolvedValue({
      data: {
        items: [
          { id: "k1", name: "ops root", credential_type: "ssh_key", tenant: "default", created_at: "", updated_at: "",
            privileged: true, privileged_reason: "sudo -l grants (ALL) ALL", privileged_set_by: "auto:preflight" },
          { id: "k2", name: "scan user", credential_type: "ssh_key", tenant: "default", created_at: "", updated_at: "" },
        ],
      },
    } as never);
    vi.mocked(api.setCredentialPrivileged).mockResolvedValue({ data: {} } as never);
    const user = userEvent.setup();
    renderSettings();
    expect(await screen.findByText("Privileged (auto)")).toBeInTheDocument();
    expect(screen.getByText("sudo -l grants (ALL) ALL")).toBeInTheDocument();
    expect(screen.getByLabelText("Privileged: ops root")).toBeChecked();
    await user.click(screen.getByLabelText("Privileged: scan user"));
    await waitFor(() =>
      expect(api.setCredentialPrivileged).toHaveBeenCalledWith("k2", true, "marked privileged in Settings"),
    );
  });
});
