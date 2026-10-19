import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    approvals: vi.fn(),
    certificates: vi.fn(),
    teamQuota: vi.fn(),
    downloadCertificatePem: vi.fn(),
  },
}));
vi.mock("../lib/utils", async (orig) => ({
  ...(await orig<typeof import("../lib/utils")>()),
  savePemFile: vi.fn(),
}));

import MyRequests from "../pages/MyRequests";
import { api } from "../lib/api";
import { savePemFile } from "../lib/utils";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <MyRequests />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const FP = "ab".repeat(32);
// Wire shapes from docs/openapi.yaml: issued_fingerprint is null until issued.
const approvals = [
  { id: "a1", template_id: "tpl-1", ca_id: "ca-1", requester: "team-a", status: "pending", csr_pem: "x", requested_at: "2026-10-04T00:00:00Z", issued_fingerprint: null },
  { id: "a2", template_id: "tpl-2", ca_id: "ca-1", requester: "team-a", status: "approved", csr_pem: "x", requested_at: "2026-10-03T00:00:00Z", issued_fingerprint: null },
  { id: "a3", template_id: "tpl-3", ca_id: "ca-1", requester: "team-a", status: "approved", csr_pem: "x", requested_at: "2026-10-02T00:00:00Z", issued_fingerprint: FP },
  { id: "a4", template_id: "tpl-4", ca_id: "ca-1", requester: "team-a", status: "rejected", csr_pem: "x", requested_at: "2026-10-01T00:00:00Z", reject_reason: "wrong environment", issued_fingerprint: null },
];
const certs = [{ fingerprint_sha256: FP, common_name: "api.example.com", valid_from: "2026-10-02T01:00:00Z" }];

function quota(over: Record<string, unknown>) {
  return {
    data: { team_id: "team-a", period: "2026-10", limit: 10, used: 3, remaining: 7, warn: false, resets_at: "2026-11-01T00:00:00Z", ...over },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue({ service: "kk", authenticated: true, principal: "team-a", role: "requester", scopes: [] } as never);
  vi.mocked(api.approvals).mockResolvedValue({ data: { items: approvals } } as never);
  vi.mocked(api.certificates).mockResolvedValue({ data: { items: certs } } as never);
  vi.mocked(api.teamQuota).mockResolvedValue(quota({}) as never);
});

describe("MyRequests", () => {
  it("renders pending, approved, issued and denied states", async () => {
    renderPage();
    await screen.findByText("api.example.com");
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows).toHaveLength(4);
    expect(screen.getByText("Pending")).toBeInTheDocument();
    expect(screen.getByText("Approved")).toBeInTheDocument();
    expect(screen.getByText("Issued")).toBeInTheDocument();
    expect(screen.getByText("Denied")).toBeInTheDocument();
    expect(screen.getByText("wrong environment")).toBeInTheDocument();
  });

  it("offers download only for issued requests", async () => {
    const user = userEvent.setup();
    vi.mocked(api.downloadCertificatePem).mockResolvedValue("PEM");
    renderPage();
    const btn = await screen.findByRole("button", { name: "Download certificate api.example.com" });
    expect(screen.getAllByRole("button", { name: /Download certificate/ })).toHaveLength(1);
    await user.click(btn);
    await waitFor(() => expect(api.downloadCertificatePem).toHaveBeenCalledWith(FP));
    expect(savePemFile).toHaveBeenCalledWith("api.example.com.pem", "PEM");
  });

  it("lists a directly issued certificate that has no approval row", async () => {
    vi.mocked(api.approvals).mockResolvedValue({ data: { items: [] } } as never);
    renderPage();
    expect(await screen.findByText("api.example.com")).toBeInTheDocument();
    expect(screen.getByText("Issued")).toBeInTheDocument();
  });

  it("shows usage without a warning below 80 percent", async () => {
    renderPage();
    expect(await screen.findByText(/3 of 10 used this month/)).toBeInTheDocument();
    expect(screen.queryByText(/80% or more/)).not.toBeInTheDocument();
  });

  it("warns at 8 of 10", async () => {
    vi.mocked(api.teamQuota).mockResolvedValue(quota({ used: 8, remaining: 2, warn: true }) as never);
    renderPage();
    expect(await screen.findByText(/8 of 10 used this month/)).toBeInTheDocument();
    expect(screen.getByText("You have used 80% or more of your monthly quota")).toBeInTheDocument();
    expect(screen.queryByText("Quota reached")).not.toBeInTheDocument();
  });

  it("shows Quota reached at 10 of 10", async () => {
    vi.mocked(api.teamQuota).mockResolvedValue(quota({ used: 10, remaining: 0, warn: true }) as never);
    renderPage();
    expect(await screen.findByText("Quota reached")).toBeInTheDocument();
    expect(screen.queryByText(/80% or more/)).not.toBeInTheDocument();
  });

  it("shows Unlimited, never 0, when the quota is unlimited", async () => {
    vi.mocked(api.teamQuota).mockResolvedValue(quota({ limit: 0, used: 4, remaining: null, warn: false }) as never);
    renderPage();
    expect(await screen.findByText(/No monthly limit/)).toBeInTheDocument();
    expect(screen.getByText(/Unlimited/)).toBeInTheDocument();
    expect(screen.queryByText(/of 0 used/)).not.toBeInTheDocument();
    expect(screen.queryByText("Quota reached")).not.toBeInTheDocument();
  });
});
