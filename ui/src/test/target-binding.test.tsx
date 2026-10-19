import { MemoryRouter } from "react-router-dom";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
    certificates: vi.fn(),
    certTargetBindings: vi.fn(),
    bindCertToTarget: vi.fn(),
    unbindCertFromTarget: vi.fn(),
    targets: vi.fn(),
    updateTarget: vi.fn(),
    renewalSchedulerStatus: vi.fn(),
    createDiscoveryScan: vi.fn(),
    targetPolicy: vi.fn(),
    upsertTargetGroup: vi.fn(),
  },
}));

import TargetSetup from "../pages/TargetSetup";
import RenewalPolicy from "../pages/RenewalPolicy";
import { api } from "../lib/api";

const WILDCARD_FP = "a".repeat(64);

function wrap(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>
    </MemoryRouter>,
  );
}

function target(id: string, name: string, host: string) {
  return {
    id,
    name,
    host,
    discovery_mode: "network",
    install_mode: "ssh",
    renewal_method: "manual",
    ssh_host_key_fingerprint: "SHA256:abc",
    tenant: "default",
    created_at: "",
    updated_at: "",
  };
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.probeTargetHostKey).mockResolvedValue({
    data: {
      host: "web-a.example.com",
      port: 22,
      algorithm: "ssh-ed25519",
      ssh_host_key: "ssh-ed25519 AAAA",
      fingerprint_sha256: "SHA256:abc",
    },
  } as never);
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
  vi.mocked(api.certificates).mockResolvedValue({
    data: {
      items: [
        { fingerprint_sha256: WILDCARD_FP, common_name: "*.example.com" },
      ],
    },
  } as never);
});

afterEach(() => {
  window.history.pushState({}, "", "/");
});

async function seriousViolations(container: HTMLElement) {
  const axe = (await import("axe-core")).default;
  // color-contrast is disabled because jsdom cannot compute rendered colours.
  const r = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  return r.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
}

type User = ReturnType<typeof userEvent.setup>;

async function fillWizardToHostKey(user: User, name: string, host: string, firstTarget: boolean) {
  if (firstTarget) {
    await user.click(screen.getByRole("radio", { name: /^Agentless/i }));
  }
  await user.type(screen.getByLabelText(/target name/i), name);
  await user.type(screen.getByLabelText(/^host$/i), host);
  await user.click(screen.getByRole("button", { name: "Next" }));
  await user.click(screen.getByRole("button", { name: "Next" }));
  await user.click(screen.getByRole("button", { name: "Next" }));
  await user.selectOptions(screen.getByLabelText(/^credential$/i), "cred-ssh-1");
  await user.click(screen.getByRole("button", { name: "Next" }));
}

async function finishWizard(user: User) {
  await user.click(screen.getByRole("button", { name: /fetch host key/i }));
  await screen.findByText("SHA256:abc");
  await user.click(screen.getByLabelText(/i have verified this fingerprint/i));
  await user.click(screen.getByRole("button", { name: "Next" }));
  await user.click(screen.getByRole("button", { name: "Finish" }));
}

describe("TargetSetup — certificate bindings (W27-05)", () => {
  it("binds a wildcard cert to two targets and posts the payload", async () => {
    const user = userEvent.setup();
    const bound: Record<string, string[]> = {};
    vi.mocked(api.createTarget)
      .mockResolvedValueOnce({ data: target("tgt-a", "web-a", "web-a.example.com") } as never)
      .mockResolvedValueOnce({ data: target("tgt-b", "web-b", "web-b.example.com") } as never);
    vi.mocked(api.bindCertToTarget).mockImplementation(async (tid, fp) => {
      (bound[tid] ??= []).push(fp);
      return { data: {} } as never;
    });
    vi.mocked(api.certTargetBindings).mockImplementation(async (tid) => ({
      data: (bound[tid] ?? []).map((fp) => ({ cert_fingerprint: fp, target_id: tid })),
    }) as never);

    wrap(<TargetSetup />);
    await fillWizardToHostKey(user, "web-a", "web-a.example.com", true);
    await finishWizard(user);

    for (const [i, tid] of ["tgt-a", "tgt-b"].entries()) {
      const panel = await screen.findByRole("region", { name: "Bind certificates" });
      await user.click(await within(panel).findByRole("checkbox", { name: /\*\.example\.com/ }));
      await user.click(within(panel).getByRole("button", { name: "Bind selected" }));
      const list = await within(panel).findByRole("list", { name: "Bound certificates" });
      expect(within(list).getByText("*.example.com")).toBeInTheDocument();
      expect(api.bindCertToTarget).toHaveBeenLastCalledWith(tid, WILDCARD_FP);
      if (i === 0) {
        await user.click(screen.getByRole("button", { name: "Add another target" }));
        await fillWizardToHostKey(user, "web-b", "web-b.example.com", false);
        await finishWizard(user);
      }
    }
    expect(vi.mocked(api.bindCertToTarget).mock.calls).toEqual([
      ["tgt-a", WILDCARD_FP],
      ["tgt-b", WILDCARD_FP],
    ]);
  });

  it("binds the certificate handed off by takeover when the wizard saves", async () => {
    const user = userEvent.setup();
    window.history.pushState({}, "", `/targets/setup?host=web-a.example.com&certificate=${WILDCARD_FP}`);
    vi.mocked(api.createTarget).mockResolvedValue({
      data: target("tgt-a", "web-a", "web-a.example.com"),
    } as never);
    vi.mocked(api.bindCertToTarget).mockResolvedValue({ data: {} } as never);
    vi.mocked(api.certTargetBindings).mockResolvedValue({
      data: [{ cert_fingerprint: WILDCARD_FP, target_id: "tgt-a" }],
    } as never);

    wrap(<TargetSetup />);
    await user.click(screen.getByRole("radio", { name: /^Agentless/i }));
    expect(screen.getByLabelText("Certificate")).toHaveValue(WILDCARD_FP);
    expect(screen.getByLabelText("Certificate")).toHaveAttribute("readonly");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.selectOptions(screen.getByLabelText(/^credential$/i), "cred-ssh-1");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await finishWizard(user);

    await waitFor(() =>
      expect(api.bindCertToTarget).toHaveBeenCalledWith("tgt-a", WILDCARD_FP),
    );
    expect(await screen.findByRole("list", { name: "Bound certificates" })).toBeInTheDocument();
  });

  it("a failed handed-off bind does not undo the created target", async () => {
    const user = userEvent.setup();
    window.history.pushState({}, "", `/targets/setup?host=web-a.example.com&certificate=${WILDCARD_FP}`);
    vi.mocked(api.createTarget).mockResolvedValue({
      data: target("tgt-a", "web-a", "web-a.example.com"),
    } as never);
    vi.mocked(api.bindCertToTarget).mockRejectedValue(new Error("tenant cannot use this CA"));
    vi.mocked(api.certTargetBindings).mockResolvedValue({ data: [] } as never);

    wrap(<TargetSetup />);
    await user.click(screen.getByRole("radio", { name: /^Agentless/i }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.selectOptions(screen.getByLabelText(/^credential$/i), "cred-ssh-1");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await finishWizard(user);

    expect(await screen.findByText(/web-a declared/)).toBeInTheDocument();
    expect(await screen.findByText(/tenant cannot use this CA/)).toBeInTheDocument();
  });

  it("passes axe with 0 serious or critical violations (bind panel)", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createTarget).mockResolvedValue({
      data: target("tgt-a", "web-a", "web-a.example.com"),
    } as never);
    vi.mocked(api.certTargetBindings).mockResolvedValue({ data: [] } as never);
    const { container } = wrap(<TargetSetup />);
    await fillWizardToHostKey(user, "web-a", "web-a.example.com", true);
    await finishWizard(user);
    await screen.findByRole("region", { name: "Bind certificates" });
    expect(await seriousViolations(container)).toEqual([]);
  });

  it("blocks Create until the host-key fingerprint is confirmed", async () => {
    const user = userEvent.setup();
    wrap(<TargetSetup />);
    await fillWizardToHostKey(user, "web-a", "web-a.example.com", true);
    await user.click(screen.getByRole("button", { name: /fetch host key/i }));
    expect(await screen.findByText("SHA256:abc")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Confirm the fingerprint before saving.");
    expect(api.createTarget).not.toHaveBeenCalled();
    await user.click(screen.getByLabelText(/i have verified this fingerprint/i));
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("button", { name: "Finish" })).toBeEnabled();
  });
});

const T1 = {
  id: "t1", name: "db-01", host: "db-01.example.com", discovery_mode: "network",
  install_mode: "ssh", renewal_method: "acme", tenant: "default", created_at: "", updated_at: "",
};
const T2 = { ...T1, id: "t2", name: "web-02", host: "web-02.example.com" };
const T3 = { ...T1, id: "t3", name: "app-03", host: "app-03.example.com" };

function policyRow(t: typeof T1, source: "target" | "group" | "default", effective: number) {
  return {
    target_id: t.id, name: t.name, host: t.host, group: source === "group" ? "web-fleet" : "",
    own_days: source === "target" ? effective : 0, group_days: source === "group" ? effective : 0,
    default_days: 30, effective_days: effective, source,
  };
}

describe("RenewalPolicy — effective threshold (W27-05)", () => {
  beforeEach(() => {
    vi.mocked(api.targets).mockResolvedValue({ data: [T1, T2, T3] } as never);
    vi.mocked(api.renewalSchedulerStatus).mockResolvedValue({
      data: { has_run: true, status: { threshold_days: 30 } },
    } as never);
    vi.mocked(api.targetPolicy).mockResolvedValue({
      data: [policyRow(T1, "target", 10), policyRow(T2, "group", 21), policyRow(T3, "default", 30)],
    } as never);
  });

  it("shows the effective threshold with its source", async () => {
    wrap(<RenewalPolicy />);
    const cases: [string, string, string][] = [
      ["t1", "10 days", "target"],
      ["t2", "21 days", "group"],
      ["t3", "30 days", "default"],
    ];
    for (const [id, days, source] of cases) {
      const cell = await screen.findByTestId(`threshold-${id}`);
      expect(cell).toHaveTextContent(`Threshold: ${days}`);
      expect(within(cell).getByText(source)).toBeInTheDocument();
    }
  });

  it("passes axe with 0 serious or critical violations", async () => {
    const { container } = wrap(<RenewalPolicy />);
    await screen.findByTestId("threshold-t1");
    expect(await seriousViolations(container)).toEqual([]);
  });

  it("saves a group and shows the server message on a 400", async () => {
    const user = userEvent.setup();
    vi.mocked(api.upsertTargetGroup)
      .mockRejectedValueOnce(new Error("unknown target id t9"))
      .mockResolvedValueOnce({ data: {} } as never);
    wrap(<RenewalPolicy />);
    await user.type(await screen.findByLabelText("Group name"), "web-fleet");
    await user.type(screen.getByLabelText("Group threshold days"), "21");
    await user.click(screen.getByRole("checkbox", { name: "web-02 (web-02.example.com)" }));
    await user.click(screen.getByRole("button", { name: "Save group" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("unknown target id t9");
    await user.click(screen.getByRole("button", { name: "Save group" }));
    await waitFor(() =>
      expect(api.upsertTargetGroup).toHaveBeenLastCalledWith("web-fleet", {
        renewal_threshold_days: 21,
        target_ids: ["t2"],
      }),
    );
    expect(await screen.findByText("Group saved.")).toBeInTheDocument();
  });
});
