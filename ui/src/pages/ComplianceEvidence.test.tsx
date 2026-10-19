import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: { authzCheck: vi.fn(), complianceEvidence: vi.fn() },
  downloadAuthedFile: vi.fn(),
}));
vi.mock("sonner", () => ({ toast: { error: vi.fn() } }));

import ComplianceEvidence from "./ComplianceEvidence";
import { api, downloadAuthedFile } from "../lib/api";
import { toast } from "sonner";

function asRole(role: string) {
  vi.mocked(api.authzCheck).mockResolvedValue({
    principal: "alice",
    role,
    scopes: [],
  } as unknown as never);
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ComplianceEvidence />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const CBOM_BUTTON = { name: /download cbom/i };

describe("ComplianceEvidence CBOM download", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(api.complianceEvidence).mockResolvedValue({
      data: {
        generated_at: "2026-10-16T00:00:00Z",
        framework: "all",
        controls: [],
        summary: { pass: 0, warn: 0, fail: 0 },
      },
    } as unknown as never);
    vi.mocked(downloadAuthedFile).mockResolvedValue(undefined as never);
  });

  it("shows Download CBOM for pki-admin and downloads /cbom as a .json file", async () => {
    asRole("pki-admin");
    renderPage();
    await userEvent.click(await screen.findByRole("button", CBOM_BUTTON));
    expect(downloadAuthedFile).toHaveBeenCalledTimes(1);
    expect(downloadAuthedFile).toHaveBeenCalledWith(
      "/cbom",
      expect.stringMatching(/^cbom-\d{4}-\d{2}-\d{2}\.json$/),
    );
  });

  it("shows Download CBOM for auditor", async () => {
    asRole("auditor");
    renderPage();
    expect(await screen.findByRole("button", CBOM_BUTTON)).toBeTruthy();
  });

  it.each(["service-account", "mcp-agent"])(
    "hides Download CBOM for %s",
    async (role) => {
      asRole(role);
      renderPage();
      await waitFor(() => expect(api.authzCheck).toHaveBeenCalled());
      await screen.findByRole("button", { name: /evidence pack/i });
      await waitFor(() => expect(api.authzCheck).toHaveBeenCalled());
      expect(screen.queryByRole("button", CBOM_BUTTON)).toBeNull();
    },
  );

  it("hides Download CBOM while the role is unknown", async () => {
    vi.mocked(api.authzCheck).mockRejectedValue(new Error("nope"));
    renderPage();
    await screen.findByRole("button", { name: /evidence pack/i });
    await waitFor(() => expect(api.authzCheck).toHaveBeenCalled());
    expect(screen.queryByRole("button", CBOM_BUTTON)).toBeNull();
  });

  it("surfaces a download failure as a toast", async () => {
    asRole("pki-admin");
    vi.mocked(downloadAuthedFile).mockRejectedValue(new Error("boom"));
    renderPage();
    await userEvent.click(await screen.findByRole("button", CBOM_BUTTON));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith("boom"));
  });
});
