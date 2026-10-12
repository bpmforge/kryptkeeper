import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    cas: vi.fn(),
    templates: vi.fn(),
    issueCertificate: vi.fn(),
    downloadCertificatePem: vi.fn(),
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
        <IssueWizard />
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
