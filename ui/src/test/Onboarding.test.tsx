import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    createCa: vi.fn(),
    createTemplate: vi.fn(),
    issueCertificate: vi.fn(),
  },
}));

import Onboarding from "../pages/Onboarding";
import { api } from "../lib/api";

function renderOnboarding(onComplete = vi.fn()) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Onboarding onComplete={onComplete} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { onComplete };
}

const createdCa = { id: "ca-onboard-1", name: "Onboard Root CA", type: "root" };
const createdTemplate = { id: "tmpl-onboard-1", name: "onboard-template" };
const issuedCert = {
  fingerprint_sha256: "aa:bb",
  common_name: "onboard.example.com",
  cert_pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
};

beforeEach(() => {
  vi.mocked(api.createCa).mockReset();
  vi.mocked(api.createTemplate).mockReset();
  vi.mocked(api.issueCertificate).mockReset();
});

describe("Onboarding wizard (W8-02)", () => {
  it("blocks Next on the CA step until create succeeds, then posts the wire-shaped body", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createCa).mockResolvedValue({ data: createdCa } as never);
    renderOnboarding();

    // Next is blocked before the CA is created.
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      /create the root ca to continue/i,
    );

    await user.type(
      screen.getByLabelText(/subject common name/i),
      "Onboard Root CA",
    );
    await user.click(screen.getByRole("button", { name: "Create root CA" }));

    await waitFor(() => expect(api.createCa).toHaveBeenCalledTimes(1));
    expect(api.createCa).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "root",
        subject_cn: "Onboard Root CA",
        algorithm: "ECDSA-P256",
      }),
    );

    await screen.findByText(/root ca created/i);
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText(/a reusable issuance policy/i)).toBeTruthy();
  });

  it("walks all 4 steps end to end and calls onComplete", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createCa).mockResolvedValue({ data: createdCa } as never);
    vi.mocked(api.createTemplate).mockResolvedValue({
      data: createdTemplate,
    } as never);
    vi.mocked(api.issueCertificate).mockResolvedValue({
      data: issuedCert,
    } as never);
    const { onComplete } = renderOnboarding();

    // Step 1: CA
    await user.type(
      screen.getByLabelText(/subject common name/i),
      "Onboard Root CA",
    );
    await user.click(screen.getByRole("button", { name: "Create root CA" }));
    await screen.findByText(/root ca created/i);
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Step 2: template
    await user.type(screen.getByLabelText(/^name$/i), "onboard-template");
    await user.click(screen.getByRole("button", { name: "Create template" }));
    await waitFor(() => expect(api.createTemplate).toHaveBeenCalledTimes(1));
    expect(api.createTemplate).toHaveBeenCalledWith(
      expect.objectContaining({ name: "onboard-template", active: true }),
    );
    await screen.findByText(/template created/i);
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Step 3: issuance
    await user.type(screen.getByLabelText(/csr pem/i), "FAKE-CSR-PEM");
    await user.click(screen.getByRole("button", { name: "Issue certificate" }));
    await waitFor(() => expect(api.issueCertificate).toHaveBeenCalledTimes(1));
    expect(api.issueCertificate).toHaveBeenCalledWith({
      ca_id: createdCa.id,
      template_id: createdTemplate.id,
      csr_pem: "FAKE-CSR-PEM",
    });
    await screen.findByRole("button", { name: /certificate issued/i });
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Step 4: mode choice is the LAST step, so Wizard shows Finish, not
    // Next. Finish is blocked until a mode is chosen -- this exercises
    // S-18's fix to Wizard.tsx (Finish now validates the active step, same
    // as Next), which closed G-80.
    await user.click(screen.getByRole("button", { name: "Finish" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      /choose how this hub manages targets/i,
    );
    expect(onComplete).not.toHaveBeenCalled();
    await user.click(
      screen.getByRole("button", { name: /choose agent mode/i }),
    );

    await user.click(screen.getByRole("button", { name: "Finish" }));
    expect(onComplete).toHaveBeenCalledTimes(1);
  });

  it("surfaces a create-CA API error inline without advancing", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createCa).mockRejectedValue(
      new Error("subject_cn is required"),
    );
    renderOnboarding();

    await user.type(screen.getByLabelText(/subject common name/i), "X");
    await user.click(screen.getByRole("button", { name: "Create root CA" }));

    expect(
      await screen.findByText(/subject_cn is required/i),
    ).toBeInTheDocument();
    // Still on step 1 -- the CA step's own content, not step 2.
    expect(screen.getByLabelText(/subject common name/i)).toBeInTheDocument();
  });
});
