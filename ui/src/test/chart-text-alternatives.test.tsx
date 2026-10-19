import { render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    expiryTimeline: vi.fn(),
    issuanceVelocity: vi.fn(),
    cas: vi.fn(),
    templates: vi.fn(),
    cryptoPosture: vi.fn(),
    cryptoPostureTrend: vi.fn(),
    cryptoPostureCsvUrl: () => "/x.csv",
    complianceEvidence: vi.fn(),
    complianceEvidencePdfUrl: () => "/x.pdf",
  },
}));

import ExpiryTimeline from "../pages/ExpiryTimeline";
import IssuanceVelocity from "../pages/IssuanceVelocity";
import { Horizon } from "../components/Horizon";
import { TrustBreakdown } from "../components/TrustBreakdown";
import CryptoPosture from "../pages/CryptoPosture";
import ComplianceEvidence from "../pages/ComplianceEvidence";
import { RiskGauge } from "../pages/Dashboard";
import { GradeLabel } from "../components/StatusCue";
import { RISK_GRADES, GRADE_CUE } from "../lib/trustClass";
import { api } from "../lib/api";

const NOW = new Date("2026-08-20T12:00:00Z");

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.mocked(api.cas).mockResolvedValue({ data: { items: [] }, meta: { total: 0 } } as never);
  vi.mocked(api.templates).mockResolvedValue({ data: { items: [] }, meta: { total: 0 } } as never);
});

describe("chart text alternatives (W33-14)", () => {
  it("horizon chart has name and table", () => {
    const d = (days: number) => {
      const x = new Date(NOW);
      x.setDate(x.getDate() + days);
      return x.toISOString();
    };
    wrap(
      <Horizon
        now={NOW}
        certificates={[
          { fingerprint_sha256: "a", common_name: "a", valid_until: d(3), renewal_method: "manual" },
          { fingerprint_sha256: "b", common_name: "b", valid_until: d(10), renewal_method: "acme" },
        ]}
      />,
    );
    expect(screen.getByRole("img", { name: /certificates expiring per day/i })).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText(/Certificates expiring in the next 90 days/)).toBeInTheDocument();
    // header row + one row per non-empty day
    expect(within(table).getAllByRole("row")).toHaveLength(3);
  });

  it("expiry distribution chart has name and table", async () => {
    const report = {
      generated_at: "2026-08-01T00:00:00Z",
      total_certs: 8,
      buckets: [
        { label: "0–7 days", days_from: 0, days_to: 7, count: 3 },
        { label: "8–30 days", days_from: 8, days_to: 30, count: 5 },
      ],
      by_ca: {},
      by_owner_team: {},
    };
    vi.mocked(api.expiryTimeline).mockResolvedValue({ data: report } as never);
    wrap(<ExpiryTimeline />);
    expect(await screen.findByRole("img", { name: /expiry distribution/i })).toBeInTheDocument();
    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows.map((r) => r.textContent)).toEqual(["0–7 days3", "8–30 days5"]);
  });

  it("issuance velocity chart has name and table", async () => {
    const report = {
      generated_at: "2026-08-01T00:00:00Z",
      total_issued: 7,
      windows: { last_7d: 7, last_30d: 7, last_90d: 7 },
      daily_buckets: [
        { date: "2026-07-30", count: 0 },
        { date: "2026-07-31", count: 2 },
        { date: "2026-08-01", count: 5 },
      ],
      by_ca: {},
      by_team: {},
      by_template: {},
      anomaly_days: ["2026-08-01"],
    };
    vi.mocked(api.issuanceVelocity).mockResolvedValue({ data: report } as never);
    wrap(<IssuanceVelocity />);
    expect(await screen.findByRole("img", { name: /daily certificate issuance/i })).toBeInTheDocument();
    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);
    expect(rows[1]).toHaveTextContent("anomaly");
    expect(rows[0]).not.toHaveTextContent("anomaly");
    expect(screen.getAllByTestId("issuance-bar")).toHaveLength(3);
  });

  it("trust breakdown is a named group", () => {
    wrap(
      <TrustBreakdown
        counts={{ managed: 4, public: 0, private_other: 0, self_signed: 2, unknown: 0 }}
      />,
    );
    expect(screen.getByRole("group", { name: /seen on the network/i })).toBeInTheDocument();
    expect(screen.getByTestId("trust-self_signed")).toHaveTextContent("Needs a decision");
    expect(screen.getByTestId("trust-managed")).not.toHaveTextContent("Needs a decision");
    expect(screen.getByTestId("trust-unknown")).not.toHaveTextContent("Needs a decision");
  });

  it("risk gauge has a sentence name and a visible level word", () => {
    wrap(<RiskGauge critical={2} high={1} medium={0} total={4} />);
    expect(
      screen.getByRole("img", { name: /risk score 65 out of 100, high risk/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/risk score · high/)).toBeInTheDocument();
  });

  it("compliance score ring has a name and a status word", async () => {
    vi.mocked(api.complianceEvidence).mockResolvedValue({
      data: {
        generated_at: "2026-06-17T00:00:00Z",
        framework: "all",
        controls: [
          { id: "1", framework: "pci", title: "A", status: "pass", evidence: "ok" },
          { id: "2", framework: "pci", title: "B", status: "fail", evidence: "no" },
        ],
        summary: { pass: 1, warn: 0, fail: 1 },
      },
    } as never);
    wrap(<ComplianceEvidence />);
    expect(
      await screen.findByRole("img", { name: /compliance score 50 percent, needs attention/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Status: Needs attention/)).toBeInTheDocument();
  });

  it("crypto posture donut is hidden from AT beside a text legend, trend has a table, grades carry cues", async () => {
    const report = {
      generated_at: "2026-06-15T00:00:00Z",
      total_certs: 10,
      algorithm_breakdown: { RSA: 6, ECDSA: 4 },
      pqc_readiness: {
        quantum_safe: 2, quantum_safe_leaf_only: 0, quantum_safe_percent: 20,
        migration_ready: 1, vulnerable: 5, not_applicable: 2, pqc_score_percent: 30,
      },
      expiry_buckets: { expired: 1, expiring_47d: 2, expiring_90d: 1, expiring_200d: 1, expiring_1yr: 1 },
      grade_distribution: { A: 4, F: 6 },
      automation_coverage: { automated: 5, manual: 5, automation_percent: 50 },
      risk_breakdown: { critical: 1, high: 2, medium: 3, low: 4 },
    };
    const snap = (d: string, p: number, a: number) => ({
      id: d, captured_at: d, total_certs: 10, pqc_score_percent: p, automation_percent: a,
      risk_critical: 1, risk_high: 2, risk_medium: 3, risk_low: 4, expired: 1, expiring_47d: 2, report,
    });
    vi.mocked(api.cryptoPosture).mockResolvedValue({ data: report } as never);
    vi.mocked(api.cryptoPostureTrend).mockResolvedValue({
      data: { snapshots: [snap("2026-06-01T00:00:00Z", 20, 40), snap("2026-06-02T00:00:00Z", 30, 50)] },
    } as never);
    const { container } = wrap(<CryptoPosture />);
    const trend = await screen.findByRole("img", { name: /posture trend over time.*pqc score %/i });
    expect(trend).toBeInTheDocument();
    const table = screen.getByRole("table", { name: /daily snapshots/i });
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    // donut svg is aria-hidden and its legend gives label + count as text
    expect(container.querySelector('svg[aria-hidden="true"].-rotate-90')).not.toBeNull();
    expect(screen.getByText("RSA")).toBeInTheDocument();
    // grade badges carry the text cue
    expect(screen.getByText(/Strong:/)).toBeInTheDocument();
    expect(screen.getByText(/Failing:/)).toBeInTheDocument();
  });

  it("GradeLabel renders the cue for every grade and for none", () => {
    for (const g of RISK_GRADES) {
      const { unmount } = render(<GradeLabel grade={g} />);
      expect(screen.getByText(`${GRADE_CUE[g].text}:`, { exact: false })).toBeInTheDocument();
      unmount();
    }
    render(<GradeLabel grade={undefined} />);
    expect(screen.getByText(/Not graded:/)).toBeInTheDocument();
  });
});
