import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    cas: vi.fn(),
    templates: vi.fn(),
    issueCertificate: vi.fn(),
    downloadCertificatePem: vi.fn(),
    teamPolicy: vi.fn(),
  },
}));

import IssueWizard from "../pages/IssueWizard";
import { api } from "../lib/api";

function renderWizard() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/certificates/issue"]}>
        <Routes>
          <Route path="/certificates/issue" element={<IssueWizard />} />
          <Route path="/targets/setup" element={<div>target setup stub</div>} />
          <Route
            path="/targets/renewal-policy"
            element={<div>renewal policy stub</div>}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const adminAuthz = {
  service: "kryptkeeper",
  authenticated: true,
  principal: "admin@example.com",
  role: "pki-admin",
  scopes: ["*"],
};

const auditorAuthz = {
  service: "kryptkeeper",
  authenticated: true,
  principal: "auditor@example.com",
  role: "pki-auditor",
  scopes: [],
};

const cas = [{ id: "ca-root", name: "Root CA", type: "root" }];
const templates = [
  { id: "tpl-1", name: "server-tls", active: true },
  // Offered-then-refused is the failure this guards against: an inactive
  // template walked a real user four steps to a "template policy
  // violation" at Finish. It must not appear at all.
  { id: "tpl-off", name: "retired-tls", active: false },
  {
    id: "tpl-np",
    name: "corp-tls",
    active: true,
    name_policy: { allowed_dns_suffixes: [".corp.example"] },
  },
  {
    id: "tpl-ap",
    name: "gated-tls",
    active: true,
    approval_roles: ["pki-approver"],
  },
];

beforeEach(() => {
  vi.mocked(api.authzCheck).mockReset();
  vi.mocked(api.cas).mockReset();
  vi.mocked(api.templates).mockReset();
  vi.mocked(api.issueCertificate).mockReset();
  vi.mocked(api.downloadCertificatePem).mockReset();
  vi.mocked(api.authzCheck).mockResolvedValue(adminAuthz as never);
  vi.mocked(api.cas).mockResolvedValue({
    data: { items: cas },
    meta: { total: cas.length },
  } as never);
  vi.mocked(api.templates).mockResolvedValue({
    data: { items: templates },
    meta: { total: templates.length },
  } as never);
});

type User = ReturnType<typeof userEvent.setup>;
const CSR =
  "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----";

async function goToSubjectStep(user: User, tpl = "tpl-1", tplName = "server-tls") {
  await screen.findByText("Root CA");
  await user.selectOptions(
    screen.getByLabelText(/certificate authority/i),
    "ca-root",
  );
  await user.click(screen.getByRole("button", { name: "Next" }));
  await screen.findByText(tplName);
  await user.selectOptions(screen.getByLabelText(/issuance template/i), tpl);
  await user.click(screen.getByRole("button", { name: "Next" }));
}

async function submitSubject(user: User, sans: string) {
  await user.type(
    screen.getByLabelText(/subject common name/i),
    "api.example.com",
  );
  if (sans) await user.type(screen.getByLabelText(/subject alternative names/i), sans);
  await user.click(screen.getByRole("button", { name: "Next" }));
}

async function issueWith(user: User, tpl: string, tplName: string) {
  await goToSubjectStep(user, tpl, tplName);
  await submitSubject(user, "");
  await user.click(screen.getByRole("button", { name: "I already have a CSR" }));
  await user.type(screen.getByLabelText(/csr pem/i), CSR);
  await user.click(screen.getByRole("button", { name: "Next" }));
  await user.click(screen.getByRole("button", { name: "Finish" }));
}

async function goToKeyOrCsrStep(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByText("Root CA");
  await user.selectOptions(
    screen.getByLabelText(/certificate authority/i),
    "ca-root",
  );
  await user.click(screen.getByRole("button", { name: "Next" }));

  await screen.findByText("server-tls");
  await user.selectOptions(
    screen.getByLabelText(/issuance template/i),
    "tpl-1",
  );
  await user.click(screen.getByRole("button", { name: "Next" }));

  await user.type(
    screen.getByLabelText(/subject common name/i),
    "api.example.com",
  );
  await user.click(screen.getByRole("button", { name: "Next" }));
}

describe("IssueWizard (W8-05)", () => {
  it("blocks a read-only role from the wizard entirely", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue(auditorAuthz as never);
    renderWizard();

    expect(await screen.findByText(/read-only access/i)).toBeInTheDocument();
    expect(screen.queryByRole("list")).not.toBeInTheDocument();
  });

  it("blocks Next on the CA step until a CA is chosen", async () => {
    const user = userEvent.setup();
    renderWizard();

    await screen.findByText("Root CA");
    await user.click(screen.getByRole("button", { name: "Next" }));

    expect(screen.getByRole("alert")).toHaveTextContent(
      /choose a ca to continue/i,
    );
  });

  it("blocks Next on the key-or-csr step until a valid CSR PEM is provided", async () => {
    const user = userEvent.setup();
    renderWizard();
    await goToKeyOrCsrStep(user);

    // No mode chosen yet. This is not the wizard's last step (a summary/
    // review step follows), so the gating button here is "Next", not
    // "Finish" -- Finish only appears on the review step.
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      /choose whether you already have a csr/i,
    );

    await user.click(
      screen.getByRole("button", { name: "I already have a CSR" }),
    );
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      /paste the csr pem to continue/i,
    );

    await user.type(screen.getByLabelText(/csr pem/i), "not-a-real-csr");
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      /doesn't look like a pem-encoded csr/i,
    );

    expect(api.issueCertificate).not.toHaveBeenCalled();
  });

  it("walks the full flow and submits only {ca_id, template_id, csr_pem} -- no subject/SAN fields (G-56 discipline)", async () => {
    vi.mocked(api.issueCertificate).mockResolvedValue({
      data: {
        fingerprint_sha256: "fp-new",
        common_name: "api.example.com",
        cert_pem:
          "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
      },
    } as never);

    const user = userEvent.setup();
    renderWizard();
    await goToKeyOrCsrStep(user);

    await user.click(
      screen.getByRole("button", { name: "I already have a CSR" }),
    );
    await user.type(
      screen.getByLabelText(/csr pem/i),
      "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----",
    );
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Review/summary step.
    expect(screen.getByText("api.example.com")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Finish" }));

    await waitFor(() =>
      expect(api.issueCertificate).toHaveBeenCalledWith({
        ca_id: "ca-root",
        template_id: "tpl-1",
        csr_pem:
          "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----",
      }),
    );

    expect(await screen.findByText(/certificate issued/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /download certificate/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /view in inventory/i }),
    ).toBeInTheDocument();
  });

  it("downloads the issued certificate PEM from the download endpoint, not the issue response (S-69)", async () => {
    // The issue response deliberately carries no PEM: CertificateItem has no
    // such field on the wire, so the download must fetch real bytes.
    vi.mocked(api.issueCertificate).mockResolvedValue({
      data: {
        fingerprint_sha256: "fp-new",
        common_name: "api.example.com",
      },
    } as never);
    const pem =
      "-----BEGIN CERTIFICATE-----\nserver-provided-bytes\n-----END CERTIFICATE-----\n";
    vi.mocked(api.downloadCertificatePem).mockResolvedValue(pem as never);

    const savedBlobs: Blob[] = [];
    const createObjectURL = vi.fn((blob: Blob) => {
      savedBlobs.push(blob);
      return "blob:test-url";
    });
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", {
      ...URL,
      createObjectURL,
      revokeObjectURL,
    });

    try {
      const user = userEvent.setup();
      renderWizard();
      await goToKeyOrCsrStep(user);
      await user.click(
        screen.getByRole("button", { name: "I already have a CSR" }),
      );
      await user.type(
        screen.getByLabelText(/csr pem/i),
        "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----",
      );
      await user.click(screen.getByRole("button", { name: "Next" }));
      await user.click(screen.getByRole("button", { name: "Finish" }));
      expect(
        await screen.findByText(/certificate issued/i),
      ).toBeInTheDocument();

      await user.click(
        screen.getByRole("button", { name: /download certificate/i }),
      );

      await waitFor(() =>
        expect(api.downloadCertificatePem).toHaveBeenCalledWith("fp-new"),
      );
      await waitFor(() => expect(savedBlobs).toHaveLength(1));
      // The saved file must hold the endpoint's bytes — this fails if the
      // download is wired to anything else (e.g. an absent response field).
      expect(await savedBlobs[0].text()).toBe(pem);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("surfaces a download failure without pretending a file was saved (S-69)", async () => {
    vi.mocked(api.issueCertificate).mockResolvedValue({
      data: {
        fingerprint_sha256: "fp-new",
        common_name: "api.example.com",
      },
    } as never);
    vi.mocked(api.downloadCertificatePem).mockRejectedValue(
      new Error("certificate not found"),
    );

    const user = userEvent.setup();
    renderWizard();
    await goToKeyOrCsrStep(user);
    await user.click(
      screen.getByRole("button", { name: "I already have a CSR" }),
    );
    await user.type(
      screen.getByLabelText(/csr pem/i),
      "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----",
    );
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Finish" }));
    expect(await screen.findByText(/certificate issued/i)).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: /download certificate/i }),
    );

    expect(
      await screen.findByText(/certificate not found/i),
    ).toBeInTheDocument();
  });

  it("shows the generate-key hint and still requires a pasted CSR before Finish", async () => {
    const user = userEvent.setup();
    renderWizard();
    await goToKeyOrCsrStep(user);

    await user.click(
      screen.getByRole("button", { name: "Generate a new key" }),
    );
    expect(screen.getByText(/openssl req -new/i)).toBeInTheDocument();
    expect(screen.getByText(/CN=api.example.com/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      /paste the csr pem to continue/i,
    );
  });

  it("renders a pending-approval terminal state instead of claiming issuance (202 path)", async () => {
    vi.mocked(api.issueCertificate).mockResolvedValue({
      status: "pending_approval",
      approval_id: "appr-1",
      message: "issuance requires approval — check /api/v1/approvals/appr-1",
    } as never);

    const user = userEvent.setup();
    renderWizard();
    await goToKeyOrCsrStep(user);

    await user.click(
      screen.getByRole("button", { name: "I already have a CSR" }),
    );
    await user.type(
      screen.getByLabelText(/csr pem/i),
      "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----",
    );
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Finish" }));

    expect(await screen.findByText(/approval requested/i)).toBeInTheDocument();
    expect(screen.getByText(/approval id: appr-1/i)).toBeInTheDocument();
    expect(screen.queryByText(/certificate issued/i)).not.toBeInTheDocument();
  });

  it("surfaces an issuance API error inline on the review step without a false success state", async () => {
    vi.mocked(api.issueCertificate).mockRejectedValue(
      new Error("ca_id is not visible to this tenant"),
    );

    const user = userEvent.setup();
    renderWizard();
    await goToKeyOrCsrStep(user);

    await user.click(
      screen.getByRole("button", { name: "I already have a CSR" }),
    );
    await user.type(
      screen.getByLabelText(/csr pem/i),
      "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----",
    );
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Finish" }));

    expect(
      await screen.findByText(/ca_id is not visible to this tenant/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/certificate issued/i)).not.toBeInTheDocument();
  });

  it("shows policy name, rule and observed value on a policy refusal (W22-16)", async () => {
    vi.mocked(api.issueCertificate).mockRejectedValue(
      new Error(
        'issue certificate: issuance policy "Baseline": rule min_rsa_bits: requested RSA modulus is 2048 bits, floor is 3072',
      ),
    );

    const user = userEvent.setup();
    renderWizard();
    await goToKeyOrCsrStep(user);

    await user.click(
      screen.getByRole("button", { name: "I already have a CSR" }),
    );
    await user.type(
      screen.getByLabelText(/csr pem/i),
      "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----",
    );
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Finish" }));

    const policy = await screen.findByText("Baseline");
    expect(policy.tagName).toBe("DD");
    expect(screen.getByText("min_rsa_bits").tagName).toBe("DD");
    expect(screen.getByText(/2048 bits/).tagName).toBe("DD");
    expect(screen.getByText("Policy:")).toBeInTheDocument();
    expect(screen.getByText("Rule:")).toBeInTheDocument();
    expect(screen.getByText("Observed:")).toBeInTheDocument();
  });
});

it("does not offer inactive templates the server would refuse", async () => {
  renderWizard();
  const user = userEvent.setup();
  await user.selectOptions(await screen.findByLabelText(/certificate authority/i), "ca-root");
  await user.click(screen.getByRole("button", { name: "Next" }));
  const select = await screen.findByLabelText(/template/i);
  expect(within(select).getByRole("option", { name: "server-tls" })).toBeInTheDocument();
  expect(within(select).queryByRole("option", { name: "retired-tls" })).not.toBeInTheDocument();
});

describe("IssueWizard (W26-26)", () => {
  it("blocks an invalid SAN in the subject step", async () => {
    const user = userEvent.setup();
    renderWizard();
    await goToSubjectStep(user);
    await submitSubject(user, "bad_host!");
    expect(screen.getByRole("alert")).toHaveTextContent(
      /is not a valid DNS name or IP/,
    );
    expect(screen.getByLabelText(/subject common name/i)).toBeInTheDocument();
  });

  it("accepts DNS, wildcard and IP SANs", async () => {
    const user = userEvent.setup();
    renderWizard();
    await goToSubjectStep(user);
    await submitSubject(user, "a.example.com, *.example.com, 10.0.0.1, 2001:db8::1");
    await user.click(screen.getByRole("button", { name: "Generate a new key" }));
    expect(screen.getByText(/DNS:a\.example\.com/)).toBeInTheDocument();
    expect(screen.getByText(/IP:10\.0\.0\.1/)).toBeInTheDocument();
  });

  it("blocks a SAN outside the template name policy", async () => {
    const user = userEvent.setup();
    renderWizard();
    await goToSubjectStep(user, "tpl-np", "corp-tls");
    await submitSubject(user, "api.example.com");
    expect(screen.getByRole("alert")).toHaveTextContent(
      /outside this template's allowed domains/,
    );
  });

  it("pending state names the approvers", async () => {
    vi.mocked(api.issueCertificate).mockResolvedValue({
      status: "pending_approval",
      approval_id: "appr-2",
      message: "issuance requires approval",
    } as never);
    const user = userEvent.setup();
    renderWizard();
    await issueWith(user, "tpl-ap", "gated-tls");
    expect(
      await screen.findByText(/Waiting for approval from: pki-approver/),
    ).toBeInTheDocument();
    expect(screen.getByText(/cannot approve your own request/)).toBeInTheDocument();
  });

  it("pending state falls back to pki-admin without approval roles", async () => {
    vi.mocked(api.issueCertificate).mockResolvedValue({
      status: "pending_approval",
      approval_id: "appr-3",
      message: "issuance requires approval",
    } as never);
    const user = userEvent.setup();
    renderWizard();
    await issueWith(user, "tpl-1", "server-tls");
    expect(
      await screen.findByText(/Waiting for approval from: pki-admin/),
    ).toBeInTheDocument();
  });

  it("issued result links to deploy and renewal", async () => {
    vi.mocked(api.issueCertificate).mockResolvedValue({
      data: { fingerprint_sha256: "fp-new", common_name: "api.example.com" },
    } as never);
    const user = userEvent.setup();
    renderWizard();
    await issueWith(user, "tpl-1", "server-tls");
    await user.click(await screen.findByRole("button", { name: "Deploy to a target" }));
    expect(await screen.findByText("target setup stub")).toBeInTheDocument();
  });

  it("links to renewal policy after issuance", async () => {
    vi.mocked(api.issueCertificate).mockResolvedValue({
      data: { fingerprint_sha256: "fp-new", common_name: "api.example.com" },
    } as never);
    const user = userEvent.setup();
    renderWizard();
    await issueWith(user, "tpl-1", "server-tls");
    await user.click(await screen.findByRole("button", { name: "Set up renewal" }));
    expect(await screen.findByText("renewal policy stub")).toBeInTheDocument();
  });

  it("shows the rule name for a template policy refusal", async () => {
    vi.mocked(api.issueCertificate).mockRejectedValue(
      new Error(
        "policy violation [extended_key_usage]: EKU 3 is not allowed by template tpl-1",
      ),
    );
    const user = userEvent.setup();
    renderWizard();
    await issueWith(user, "tpl-1", "server-tls");
    const rule = await screen.findByText("extended_key_usage");
    expect(rule.tagName).toBe("DD");
    expect(screen.getByText("Rule:")).toBeInTheDocument();
  });
});

describe("IssueWizard for a requester (W33-22)", () => {
  it("offers only the CAs and templates the team policy allows", async () => {
    vi.mocked(api.teamPolicy).mockResolvedValue({
      team: "team-a", allowed_cas: ["ca-root"], allowed_templates: ["tpl-1"],
    } as never);
    vi.mocked(api.authzCheck).mockResolvedValue({
      service: "kryptkeeper", authenticated: true, principal: "team-a", role: "requester", scopes: [],
    } as never);
    vi.mocked(api.cas).mockResolvedValue({
      data: { items: [...cas, { id: "ca-other", name: "Other CA", type: "root" }] },
    } as never);
    const user = userEvent.setup();
    renderWizard();
    await screen.findByText("Root CA");
    await waitFor(() => expect(screen.queryByText("Other CA")).not.toBeInTheDocument());
    expect(screen.queryByText(/read-only access/i)).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText(/certificate authority/i), "ca-root");
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText("server-tls")).toBeInTheDocument();
    expect(screen.queryByText("corp-tls")).not.toBeInTheDocument();
    expect(screen.queryByText("gated-tls")).not.toBeInTheDocument();
  });
});
