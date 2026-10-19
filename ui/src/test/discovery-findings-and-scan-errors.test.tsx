import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// Phase 3 of discovery: an endpoint that answered but could not be read
// (plain HTTP on a TLS port, a TLS 1.0-only server) is in the inventory with a
// finding, "risky" follows the documented rule instead of a bare score >= 70,
// the Findings widget shows the hub's count, and a scan job that finished with
// problems says so and says why.
vi.mock("../lib/api", async (importOriginal) => {
  const mod = (await importOriginal()) as Record<string, unknown>;
  return {
    ...mod,
    api: {
      ...(mod.api as Record<string, unknown>),
      authzCheck: vi.fn(),
      discoverySummary: vi.fn(),
      discoveryEndpoints: vi.fn(),
      discoveryScanJobs: vi.fn(),
      createDiscoveryScan: vi.fn(),
      targets: vi.fn(),
    },
  };
});

import Discovery from "../pages/Discovery";
import { api } from "../lib/api";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Discovery />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.mocked(api.authzCheck).mockResolvedValue({
    role: "pki-admin",
    scopes: [],
  } as never);
  vi.mocked(api.discoverySummary).mockResolvedValue({
    data: {
      discovered_endpoints: 3,
      risky_endpoints: 2,
      findings: { raw: 7, effective: 7, suppressed: 0 },
    },
  } as never);
  vi.mocked(api.discoveryEndpoints).mockResolvedValue({
    data: {
      endpoints: [
        {
          id: "ep-ss",
          hostname: "selfsigned.lab",
          port: 443,
          protocol: "https",
          // Scored 40: under the old >= 70 cut-off, yet SELF_SIGNED.
          risk_score: 40,
          risky: true,
        },
        {
          id: "ep-http",
          hostname: "plainhttp.lab",
          port: 443,
          protocol: "https",
          risk_score: 0,
          risky: true,
          issues: ["NOT_TLS: first record does not look like a TLS handshake"],
        },
        {
          id: "ep-ok",
          hostname: "healthy.lab",
          port: 443,
          protocol: "https",
          risk_score: 10,
          risky: false,
        },
      ],
    },
    meta: { total: 3 },
  } as never);
  vi.mocked(api.discoveryScanJobs).mockResolvedValue({
    data: {
      scan_jobs: [
        {
          id: "scan-1",
          scan_type: "full",
          target: "10.0.0.0/27",
          status: "completed_with_errors",
          queued_at: "2026-10-14T10:00:00Z",
          error:
            "1 endpoint(s) answered but failed (10.0.0.5:443 NOT_TLS); 30 closed or filtered port(s) not recorded",
        },
        {
          id: "scan-2",
          scan_type: "targeted",
          target: "10.0.0.9",
          status: "failed",
          queued_at: "2026-10-14T10:05:00Z",
          error: "10.0.0.9:443: tls dial: connection refused",
        },
      ],
    },
    meta: { total: 2 },
  } as never);
  vi.mocked(api.targets).mockResolvedValue({ data: [] } as never);
});

describe("discovery — findings, risky rule and scan errors", () => {
  it("badges a self-signed 40-score endpoint as risky using the hub's rule", async () => {
    renderPage();
    const row = (
      await screen.findByRole("button", { name: "selfsigned.lab" })
    ).closest("tr");
    if (!row) throw new Error("expected a table row");
    // The score cell reads 40, but the danger badge is driven by `risky`.
    const badge = within(row).getByText("40");
    expect(badge.className).toMatch(/danger|rose|over/);

    const okRow = (
      await screen.findByRole("button", { name: "healthy.lab" })
    ).closest("tr");
    if (!okRow) throw new Error("expected a table row");
    expect(within(okRow).getByText("10").className).not.toMatch(
      /danger|rose|over/,
    );
  });

  it("shows the hub's findings count in the Findings widget", async () => {
    renderPage();
    expect(await screen.findByText("Total findings")).toBeInTheDocument();
    // effective is also 7 in this fixture, so read the Raw cell by test id.
    expect(await screen.findByTestId("funnel-raw")).toHaveTextContent("7");
  });

  it("lists an open-but-failed endpoint's finding in its detail panel", async () => {
    renderPage();
    await userEvent.click(
      await screen.findByRole("button", { name: "plainhttp.lab" }),
    );
    const list = await screen.findByTestId("endpoint-findings");
    expect(within(list).getByText(/Not TLS/)).toBeInTheDocument();
  });

  it("shows a partially failed scan job's status and reason", async () => {
    renderPage();
    const errors = await screen.findAllByTestId("scan-job-error");
    expect(errors.map((e) => e.textContent).join("\n")).toMatch(
      /10\.0\.0\.5:443 NOT_TLS/,
    );
    expect(errors.map((e) => e.textContent).join("\n")).toMatch(
      /10\.0\.0\.9:443/,
    );
    expect(screen.getByText("completed_with_errors")).toBeInTheDocument();
  });
});

describe("discovery — endpoint list indicators", () => {
  beforeEach(() => {
    vi.mocked(api.discoveryEndpoints).mockResolvedValue({
      data: {
        endpoints: [
          {
            id: "ep-a",
            hostname: "expired.lab",
            port: 443,
            protocol: "https",
            risk_score: 55,
            risky: true,
            mapped_certs: [
              {
                fingerprint: "fp1",
                risk_score: 55,
                trust_class: "private_other",
                risk_flags: [
                  "PQC_VULNERABLE",
                  "EXPIRED",
                  "SELF_SIGNED",
                  "WEAK_KEY",
                ],
              },
            ],
          },
          {
            id: "ep-b",
            hostname: "plain.lab",
            port: 443,
            protocol: "tls",
            risk_score: 20,
            risky: true,
            issues: [
              "NOT_TLS: first record does not look like a TLS handshake",
            ],
          },
        ],
      },
      meta: { total: 2 },
    } as never);
  });

  it("shows trust class, top two flags, the overflow count and a risky marker", async () => {
    renderPage();
    const row = (
      await screen.findByRole("button", { name: "expired.lab" })
    ).closest("tr") as HTMLElement;
    expect(within(row).getByText("other private CA")).toBeInTheDocument();
    expect(within(row).getByText("Expired")).toBeInTheDocument();
    expect(within(row).getByText("Self signed")).toBeInTheDocument();
    expect(within(row).queryByText("Weak key")).toBeNull();
    expect(within(row).getByText("+1")).toBeInTheDocument();
    expect(within(row).getByText("risky")).toBeInTheDocument();
  });

  it("shows the observed protocol for a NOT_TLS endpoint, not the scan's intent", async () => {
    renderPage();
    const row = (
      await screen.findByRole("button", { name: "plain.lab" })
    ).closest("tr") as HTMLElement;
    expect(within(row).getByText("not TLS")).toBeInTheDocument();
    expect(within(row).queryByText("tls")).toBeNull();
  });
});
