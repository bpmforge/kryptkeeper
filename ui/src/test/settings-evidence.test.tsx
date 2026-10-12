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
  vi.mocked(api.siemStatus).mockResolvedValue({
    data: {
      enabled: false,
      webhook_enabled: false,
      webhook_has_token: false,
      syslog_enabled: false,
    },
  } as unknown as never);
});

describe("Settings — Evidence Delivery", () => {
  it("lists existing schedules", async () => {
    vi.mocked(api.evidenceSchedules).mockResolvedValue({
      data: [
        {
          id: "esc-1",
          framework: "pci",
          cadence: "monthly",
          recipients: ["auditor@example.com"],
          enabled: true,
          created_at: "2026-06-17T00:00:00Z",
        },
      ],
    } as unknown as never);

    renderSettings();

    // Await the recipients cell (unique to the table row, unlike the framework
    // label which also appears as a <Select> option).
    expect(await screen.findByText("auditor@example.com")).toBeInTheDocument();
  });

  it("sends an ad-hoc evidence pack via Send now", async () => {
    vi.mocked(api.evidenceSchedules).mockResolvedValue({
      data: [],
    } as unknown as never);
    vi.mocked(api.sendEvidenceNow).mockResolvedValue({
      status: "sent",
      recipients: 1,
    } as unknown as never);

    renderSettings();

    await screen.findByText(/no scheduled deliveries/i);
    await userEvent.type(
      screen.getByPlaceholderText(/auditor@example.com/i),
      "ciso@example.com",
    );
    await userEvent.click(screen.getByRole("button", { name: /send now/i }));

    await waitFor(() =>
      expect(api.sendEvidenceNow).toHaveBeenCalledWith({
        framework: "all",
        recipients: ["ciso@example.com"],
      }),
    );
  });

  it("creates a schedule from the form", async () => {
    vi.mocked(api.evidenceSchedules).mockResolvedValue({
      data: [],
    } as unknown as never);
    vi.mocked(api.createEvidenceSchedule).mockResolvedValue({
      data: {},
    } as unknown as never);

    renderSettings();

    await screen.findByText(/no scheduled deliveries/i);
    await userEvent.type(
      screen.getByPlaceholderText(/auditor@example.com/i),
      "a@x.com, b@x.com",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /add schedule/i }),
    );

    await waitFor(() =>
      expect(api.createEvidenceSchedule).toHaveBeenCalledWith({
        framework: "all",
        cadence: "monthly",
        recipients: ["a@x.com", "b@x.com"],
        enabled: true,
      }),
    );
  });
});
