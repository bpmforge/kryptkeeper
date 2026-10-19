import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/policiesApi", async (orig) => {
  const actual = await orig<typeof import("../lib/policiesApi")>();
  return {
    ...actual,
    policiesApi: {
      list: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      remove: vi.fn(),
      dryRun: vi.fn(),
    },
  };
});
vi.mock("../lib/api", () => ({ api: { authzCheck: vi.fn() } }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import Policies from "../pages/Policies";
import { parsePolicyViolation, policiesApi } from "../lib/policiesApi";
import { api } from "../lib/api";
import { toast } from "sonner";

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Policies />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const baseline = {
  id: "pol-1",
  name: "Baseline",
  enabled: true,
  ca_id: "",
  rules: { allowed_algorithms: ["ECDSA-P256"], min_rsa_bits: 3072, max_validity_days: 90 },
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue({
    principal: "admin@example.com",
    role: "pki-admin",
    scopes: ["*"],
  } as never);
  vi.mocked(policiesApi.list).mockResolvedValue({ data: [baseline] });
});

describe("Policies page", () => {
  it("lists policies with scope and rules summary", async () => {
    renderPage();
    await screen.findByText("Baseline");
    expect(screen.getByText("All CAs")).toBeInTheDocument();
    expect(screen.getByText("Enabled")).toBeInTheDocument();
    expect(screen.getByText("RSA ≥ 3072")).toBeInTheDocument();
  });

  it("creates a policy with the right body", async () => {
    vi.mocked(policiesApi.create).mockResolvedValue({ data: baseline });
    renderPage();
    await screen.findByText("Baseline");
    await userEvent.click(screen.getByRole("button", { name: /new policy/i }));
    await userEvent.type(screen.getByLabelText(/^name/i), "Strict");
    await userEvent.type(screen.getByLabelText(/allowed algorithms/i), "Ed25519, ECDSA-P384");
    await userEvent.type(screen.getByLabelText(/min rsa bits/i), "4096");
    await userEvent.type(screen.getByLabelText(/max validity days/i), "30");
    await userEvent.click(screen.getByRole("button", { name: /create policy/i }));
    await waitFor(() =>
      expect(policiesApi.create).toHaveBeenCalledWith({
        name: "Strict",
        enabled: true,
        ca_id: "",
        rules: {
          allowed_algorithms: ["Ed25519", "ECDSA-P384"],
          min_rsa_bits: 4096,
          max_validity_days: 30,
        },
      }),
    );
    await waitFor(() => expect(policiesApi.list).toHaveBeenCalledTimes(2));
  });

  it("rejects an empty name client-side", async () => {
    renderPage();
    await screen.findByText("Baseline");
    await userEvent.click(screen.getByRole("button", { name: /new policy/i }));
    await userEvent.click(screen.getByRole("button", { name: /create policy/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/name is required/i);
    expect(policiesApi.create).not.toHaveBeenCalled();
  });

  it("edit sends only the changed fields", async () => {
    vi.mocked(policiesApi.update).mockResolvedValue({ data: { ...baseline, enabled: false } });
    renderPage();
    await screen.findByText("Baseline");
    await userEvent.click(screen.getByRole("button", { name: /edit baseline/i }));
    await userEvent.click(screen.getByLabelText("Enabled"));
    await userEvent.click(screen.getByRole("button", { name: /save changes/i }));
    await waitFor(() =>
      expect(policiesApi.update).toHaveBeenCalledWith("pol-1", { enabled: false }),
    );
  });

  it("shows Pending approval on a 202 and does not refetch the row", async () => {
    vi.mocked(policiesApi.update).mockResolvedValue({
      data: { status: "pending_approval", pending_action_id: "act-9", reasons: ["lowers floor"] },
    });
    renderPage();
    await screen.findByText("Baseline");
    await userEvent.click(screen.getByRole("button", { name: /edit baseline/i }));
    await userEvent.clear(screen.getByLabelText(/min rsa bits/i));
    await userEvent.type(screen.getByLabelText(/min rsa bits/i), "2048");
    await userEvent.click(screen.getByRole("button", { name: /save changes/i }));
    await screen.findByText("Pending approval");
    expect(toast.success).toHaveBeenCalledWith("Loosening needs a second approver");
    expect(policiesApi.list).toHaveBeenCalledTimes(1);
  });

  it("dry-run cites the violated rule, and says Allowed otherwise", async () => {
    vi.mocked(policiesApi.dryRun).mockResolvedValueOnce({
      data: {
        allowed: false,
        evaluated_policies: ["Baseline"],
        violations: [
          {
            policy_id: "pol-1",
            policy: "Baseline",
            rule: "max_validity_days",
            detail: "requested 365 days, ceiling is 90",
            observed: "365",
          },
        ],
      },
    });
    vi.mocked(policiesApi.dryRun).mockResolvedValueOnce({
      data: { allowed: true, evaluated_policies: ["Baseline"], violations: [] },
    });
    renderPage();
    await screen.findByText("Baseline");
    await userEvent.selectOptions(screen.getByLabelText(/^algorithm/i), "ECDSA-P256");
    await userEvent.click(screen.getByRole("button", { name: /run dry run/i }));
    await screen.findByText("max_validity_days");
    expect(screen.getByText("365")).toBeInTheDocument();
    expect(policiesApi.dryRun).toHaveBeenCalledWith({
      algorithm: "ECDSA-P256",
      validity_days: 365,
      is_ca: false,
    });
    await userEvent.click(screen.getByRole("button", { name: /run dry run/i }));
    await screen.findByText("Allowed");
  });

  it("shows Not permitted to a non-admin", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue({
      principal: "ops@example.com",
      role: "pki-operator",
      scopes: [],
    } as never);
    renderPage();
    await screen.findByText("Not permitted");
    expect(policiesApi.list).not.toHaveBeenCalled();
  });
});

describe("parsePolicyViolation", () => {
  it("parses the server refusal", () => {
    expect(
      parsePolicyViolation('issuance policy "Baseline": rule min_rsa_bits: floor is 3072'),
    ).toEqual({ policy: "Baseline", rule: "min_rsa_bits", detail: "floor is 3072" });
  });
  it("tolerates a prefix", () => {
    expect(
      parsePolicyViolation('issue certificate: issuance policy "A B": rule x_y: why'),
    ).toEqual({ policy: "A B", rule: "x_y", detail: "why" });
  });
  it("returns null otherwise", () => {
    expect(parsePolicyViolation("ca_id is not visible")).toBeNull();
  });
});
