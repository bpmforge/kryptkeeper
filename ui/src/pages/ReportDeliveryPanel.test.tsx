import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    reportScheduleCatalog: vi.fn(),
    reportSchedules: vi.fn(),
    createReportSchedule: vi.fn(),
    deleteReportSchedule: vi.fn(),
  },
}));

import { ReportDeliveryPanel } from "./ReportDeliveryPanel";
import { api } from "../lib/api";

function renderPanel() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ReportDeliveryPanel />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.reportScheduleCatalog).mockResolvedValue({
    data: [
      {
        report: "executive-summary",
        title: "Executive summary",
        formats: ["pdf"],
      },
      {
        report: "inventory",
        title: "Certificate inventory",
        formats: ["csv", "xlsx"],
      },
    ],
  } as never);
  vi.mocked(api.reportSchedules).mockResolvedValue({
    data: [
      {
        id: "rsc-1",
        report: "inventory",
        format: "xlsx",
        cadence: "daily",
        recipients: ["a@example.com"],
        enabled: true,
        created_at: "2026-10-01T00:00:00Z",
      },
    ],
  } as never);
  vi.mocked(api.createReportSchedule).mockResolvedValue({ data: {} } as never);
  vi.mocked(api.deleteReportSchedule).mockResolvedValue({ status: "deleted" });
});

describe("ReportDeliveryPanel", () => {
  it("lists schedules with the catalog title", async () => {
    renderPanel();
    expect(await screen.findByText("XLSX")).toBeInTheDocument();
    expect(screen.getAllByText("Certificate inventory").length).toBeGreaterThan(
      0,
    );
    expect(screen.getByText("a@example.com")).toBeInTheDocument();
  });

  it("offers only the formats of the chosen report and creates a schedule", async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByText("XLSX");
    const report = screen.getByLabelText("Report");
    await waitFor(() => expect(report).toHaveValue("executive-summary"));
    // executive-summary has only PDF
    expect(screen.getByLabelText("Format")).toHaveValue("pdf");
    await user.selectOptions(report, "inventory");
    await user.selectOptions(screen.getByLabelText("Format"), "xlsx");
    await user.selectOptions(screen.getByLabelText("Cadence"), "monthly");
    await user.type(
      screen.getByLabelText(/Recipients/),
      "board@example.com, ciso@example.com",
    );
    await user.click(
      screen.getByRole("button", { name: /add report schedule/i }),
    );
    await waitFor(() =>
      expect(api.createReportSchedule).toHaveBeenCalledWith({
        report: "inventory",
        format: "xlsx",
        cadence: "monthly",
        recipients: ["board@example.com", "ciso@example.com"],
        enabled: true,
      }),
    );
  });

  it("deletes a schedule", async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.click(
      await screen.findByRole("button", {
        name: /delete certificate inventory schedule/i,
      }),
    );
    await waitFor(() =>
      expect(api.deleteReportSchedule).toHaveBeenCalledWith("rsc-1"),
    );
  });
});
