import { render, screen, waitFor } from "@testing-library/react";
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
  },
}));

import Settings from "../pages/Settings";
import { api } from "../lib/api";

const disabledSiem = {
  data: {
    enabled: false,
    webhook_enabled: false,
    webhook_has_token: false,
    syslog_enabled: false,
  },
};

function renderSettings() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Settings />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.siemStatus).mockResolvedValue(disabledSiem as unknown as never);
  vi.mocked(api.evidenceSchedules).mockResolvedValue({
    data: [],
  } as unknown as never);
});

describe("Settings — SIEM panel", () => {
  it("shows configured targets and masked webhook", async () => {
    vi.mocked(api.siemStatus).mockResolvedValue({
      data: {
        enabled: true,
        webhook_enabled: true,
        webhook_target: "https://hec.example.com",
        webhook_has_token: true,
        syslog_enabled: true,
        syslog_addr: "10.0.0.5:514",
        syslog_proto: "tcp",
      },
    } as unknown as never);

    renderSettings();

    await screen.findByText("Enabled");
    expect(screen.getByText("https://hec.example.com")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.5:514")).toBeInTheDocument();
  });

  it("sends a test event and shows per-target results", async () => {
    vi.mocked(api.siemStatus).mockResolvedValue({
      data: {
        enabled: true,
        webhook_enabled: true,
        webhook_target: "https://hec.example.com",
        webhook_has_token: false,
        syslog_enabled: false,
      },
    } as unknown as never);
    vi.mocked(api.siemTest).mockResolvedValue({
      data: {
        enabled: true,
        webhook_tested: true,
        webhook_ok: true,
        syslog_tested: false,
        syslog_ok: false,
      },
    } as unknown as never);

    renderSettings();

    const testBtn = await screen.findByRole("button", {
      name: /send test event/i,
    });
    await userEvent.click(testBtn);

    await waitFor(() => expect(api.siemTest).toHaveBeenCalled());
    await screen.findByText(/test result/i);
    expect(screen.getByText("OK")).toBeInTheDocument();
  });

  it("disables the test button when SIEM is not configured", async () => {
    renderSettings();
    await screen.findByText("Not configured");
    expect(
      screen.getByRole("button", { name: /send test event/i }),
    ).toBeDisabled();
  });
});
