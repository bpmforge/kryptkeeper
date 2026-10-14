import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Download, Layers, RefreshCw, Send } from "lucide-react";
import { toast } from "sonner";
import { api, downloadAuthedFile } from "../lib/api";
import type { CryptoPostureReport } from "../lib/models";
import type { components } from "../generated/api-types";
import {
  NOTIFY_CHANNELS,
  isNotifyChannel,
  notifyOwnerTeam,
  openPqcWave,
  expiredCertificatesPath,
  type NotifyChannel,
} from "../lib/actions";
import {
  Badge,
  Button,
  Dialog,
  formatDateTime,
  Input,
  MetricCard,
  Panel,
  Select,
  SectionLabel,
  StateMessage,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";

// ui/src/lib/models.ts is a hand-written mirror of the OpenAPI spec and is
// out of write_scope for this ticket (W3-02); CryptoPostureReport there
// predates the `findings` field W2-11 added to the spec. Read it straight
// from the generated types instead of widening scope to models.ts.
type FindingFunnelSummary = components["schemas"]["FindingFunnelSummary"];
type CryptoPostureReportWithFindings = CryptoPostureReport & {
  findings?: FindingFunnelSummary;
};

// ---------------------------------------------------------------------------
// Mini SVG donut chart — no external dependency
// ---------------------------------------------------------------------------

type DonutSlice = { label: string; value: number; color: string };

function DonutChart({ slices }: { slices: DonutSlice[] }) {
  const total = slices.reduce((s, d) => s + d.value, 0);
  if (total === 0) {
    return (
      <svg viewBox="0 0 64 64" className="w-32 h-32">
        <circle
          cx="32"
          cy="32"
          r="22"
          fill="none"
          stroke="#334155"
          strokeWidth="12"
        />
      </svg>
    );
  }

  const r = 22;
  const cx = 32;
  const cy = 32;
  const circ = 2 * Math.PI * r;

  type Seg = (typeof slices)[0] & { dash: number; offset: number };
  const segments = slices.reduce<Seg[]>((acc, s) => {
    const dash = (s.value / total) * circ;
    const offset = acc.reduce((sum, seg) => sum + seg.dash, 0);
    return [...acc, { ...s, dash, offset }];
  }, []);

  return (
    <svg viewBox="0 0 64 64" className="w-32 h-32 -rotate-90">
      {segments.map((s) => (
        <circle
          key={s.label}
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke={s.color}
          strokeWidth="12"
          strokeDasharray={`${s.dash} ${circ - s.dash}`}
          strokeDashoffset={-s.offset}
        />
      ))}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Progress bar
// ---------------------------------------------------------------------------

function ProgressBar({
  value,
  max,
  color = "bg-primary",
}: {
  value: number;
  max: number;
  color?: string;
}) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div className="h-2 rounded-full bg-muted overflow-hidden">
      <div
        className={`h-full rounded-full transition-all ${color}`}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Algorithm colours
// ---------------------------------------------------------------------------

const ALGO_COLORS: Record<string, string> = {
  ECDSA: "#06b6d4",
  RSA: "#f59e0b",
  "ML-DSA-44": "#10b981",
  "ML-DSA-65": "#10b981",
  "ML-DSA-87": "#10b981",
  Ed25519: "#8b5cf6",
  Unknown: "#475569",
};

function algoColor(algo: string): string {
  return ALGO_COLORS[algo] ?? "#94a3b8";
}

// ---------------------------------------------------------------------------
// Grade colours
// ---------------------------------------------------------------------------

const GRADE_TONE: Record<string, "success" | "neutral" | "warning" | "danger"> =
  {
    A: "success",
    B: "success",
    C: "warning",
    D: "danger",
    F: "danger",
  };

// ---------------------------------------------------------------------------
// Mini SVG line chart — posture trend over time, no external dependency
// ---------------------------------------------------------------------------

type TrendSeries = { label: string; color: string; values: number[] };

function TrendChart({
  series,
  labels,
}: {
  series: TrendSeries[];
  labels: string[];
}) {
  const n = labels.length;
  // viewBox: 0..100 wide, 0..100 tall (percentages, top = 100%).
  const x = (i: number) => (n <= 1 ? 0 : (i / (n - 1)) * 100);
  const y = (v: number) => 100 - Math.max(0, Math.min(100, v));

  return (
    <div>
      <svg
        viewBox="0 0 100 100"
        preserveAspectRatio="none"
        className="w-full h-40"
        role="img"
        aria-label="Posture trend over time"
      >
        {/* gridlines at 25/50/75% */}
        {[25, 50, 75].map((g) => (
          <line
            key={g}
            x1="0"
            x2="100"
            y1={y(g)}
            y2={y(g)}
            stroke="#1e293b"
            strokeWidth="0.5"
          />
        ))}
        {series.map((s) => (
          <polyline
            key={s.label}
            fill="none"
            stroke={s.color}
            strokeWidth="1.5"
            vectorEffect="non-scaling-stroke"
            points={s.values.map((v, i) => `${x(i)},${y(v)}`).join(" ")}
          />
        ))}
      </svg>
      <div className="mt-2 flex flex-wrap items-center gap-4 text-xs">
        {series.map((s) => (
          <span key={s.label} className="flex items-center gap-1.5">
            <span
              className="inline-block h-2 w-3 rounded-sm"
              style={{ background: s.color }}
            />
            <span className="text-foreground">{s.label}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Findings summary (raw count; exceptions/suppression planned for v0.10)
// ---------------------------------------------------------------------------

function FindingFunnelPanel({ findings }: { findings?: FindingFunnelSummary }) {
  // Finding exceptions (risk acceptance) are not available until v0.10, so
  // only the raw count is shown; effective/suppressed would be misleading.
  const raw = findings?.raw ?? 0;

  return (
    <Panel title="Findings" subtitle="Risk findings computed across the certificate inventory">
      <div className="text-center">
        <div className="text-3xl font-bold text-foreground">{raw}</div>
        <div className="mt-1 text-xs uppercase tracking-[0.2em] text-muted-foreground">
          Total findings
        </div>
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function CryptoPosture() {
  const navigate = useNavigate();
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["crypto-posture"],
    queryFn: api.cryptoPosture,
    staleTime: 60_000,
  });

  const trendQuery = useQuery({
    queryKey: ["crypto-posture-trend"],
    queryFn: () => api.cryptoPostureTrend(),
    staleTime: 60_000,
  });

  const [banner, setBanner] = useState<string | null>(null);

  const [notifyOpen, setNotifyOpen] = useState(false);
  const [notifyTeam, setNotifyTeam] = useState("");
  const [notifyChannel, setNotifyChannel] = useState<NotifyChannel>("email");
  const [notifyTarget, setNotifyTarget] = useState("");
  const [notifyError, setNotifyError] = useState<string | null>(null);

  const notifyMutation = useMutation({
    mutationFn: () => notifyOwnerTeam(notifyTeam, notifyChannel, notifyTarget),
    onSuccess: (outcome) => {
      if (outcome.ok) {
        setNotifyOpen(false);
        setNotifyTeam("");
        setNotifyTarget("");
        setNotifyError(null);
        setBanner(outcome.message);
      } else {
        setNotifyError(outcome.message);
      }
    },
  });

  const [waveConfirmOpen, setWaveConfirmOpen] = useState(false);
  const [waveError, setWaveError] = useState<string | null>(null);

  const waveMutation = useMutation({
    mutationFn: openPqcWave,
    onSuccess: (outcome) => {
      if (outcome.ok) {
        setWaveConfirmOpen(false);
        setWaveError(null);
        setBanner(outcome.message);
        navigate("/reports/pqc-migration");
      } else {
        setWaveError(outcome.message);
      }
    },
  });

  const report: CryptoPostureReportWithFindings | undefined = data?.data;
  const snapshots = trendQuery.data?.data?.snapshots ?? [];

  if (isLoading) {
    return (
      <div className="p-6">
        <StateMessage
          title="Loading crypto posture"
          message="Analysing certificate inventory…"
        />
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="p-6">
        <StateMessage
          tone="error"
          title="Report unavailable"
          message="The crypto posture report could not be loaded."
        />
      </div>
    );
  }

  const algoSlices: DonutSlice[] = Object.entries(report.algorithm_breakdown)
    .filter(([, v]) => v > 0)
    .map(([label, value]) => ({ label, value, color: algoColor(label) }));

  const pqcTotal =
    report.pqc_readiness.quantum_safe +
    (report.pqc_readiness.quantum_safe_leaf_only ?? 0) +
    report.pqc_readiness.migration_ready +
    report.pqc_readiness.vulnerable +
    report.pqc_readiness.not_applicable;

  const riskTotal =
    report.risk_breakdown.critical +
    report.risk_breakdown.high +
    report.risk_breakdown.medium +
    report.risk_breakdown.low;

  const gradeEntries = Object.entries(report.grade_distribution).sort(
    ([a], [b]) => a.localeCompare(b),
  );

  const expiryRows = [
    {
      label: "Expired",
      value: report.expiry_buckets.expired,
      tone: "danger" as const,
    },
    {
      label: "Within 47 days",
      value: report.expiry_buckets.expiring_47d,
      tone: "danger" as const,
    },
    {
      label: "Within 90 days",
      value: report.expiry_buckets.expiring_90d,
      tone: "warning" as const,
    },
    {
      label: "Within 200 days",
      value: report.expiry_buckets.expiring_200d,
      tone: "warning" as const,
    },
    {
      label: "Within 1 year",
      value: report.expiry_buckets.expiring_1yr,
      tone: "neutral" as const,
    },
  ];

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Reports"
        title="Crypto Posture"
        description={`Generated ${formatDateTime(report.generated_at)} · ${report.total_certs} certificates`}
        actions={
          <div className="flex gap-2 shrink-0">
            <Button
              tone="secondary"
              onClick={() => {
                setNotifyError(null);
                setNotifyOpen(true);
              }}
            >
              <Send size={13} aria-hidden="true" />
              Notify owner
            </Button>
            <Button
              tone="secondary"
              onClick={() => {
                setWaveError(null);
                setWaveConfirmOpen(true);
              }}
            >
              <Layers size={13} aria-hidden="true" />
              Open PQC wave
            </Button>
            <Button
              tone="secondary"
              onClick={() => refetch()}
              disabled={isFetching}
            >
              <RefreshCw size={13} aria-hidden="true" />
              Refresh
            </Button>
            <Button
              tone="primary"
              onClick={() =>
                void downloadAuthedFile(
                  "/reports/crypto-posture?format=csv",
                  "crypto-posture.csv",
                ).catch((err: Error) => toast.error(err.message))
              }
            >
              <Download size={13} aria-hidden="true" />
              Export CSV
            </Button>
          </div>
        }
      />

      {banner && (
        <StateMessage tone="success" title="Action complete" message={banner} />
      )}

      {/* Top metrics */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <MetricCard label="Total certificates" value={report.total_certs} />
        <MetricCard
          label="Quantum-safe today"
          // Full-chain PQC only; the broader readiness figure is the same
          // pqc_score_percent the PQC Readiness panel shows. Both numbers
          // or "ready to migrate" reads as "done". Tone follows the honest one.
          value={`${(report.pqc_readiness.quantum_safe_percent ?? 0)}%`}
          hint={`${report.pqc_readiness.pqc_score_percent}% PQC readiness (incl. leaf-only and migration-ready)`}
          tone={
            (report.pqc_readiness.quantum_safe_percent ?? 0) >= 80
              ? "success"
              : (report.pqc_readiness.quantum_safe_percent ?? 0) >= 40
                ? "warning"
                : "danger"
          }
        />
        <MetricCard
          label="Automation"
          value={`${report.automation_coverage.automation_percent}%`}
          hint={`${report.automation_coverage.automated} auto-renewed`}
          tone={
            report.automation_coverage.automation_percent >= 80
              ? "success"
              : report.automation_coverage.automation_percent >= 40
                ? "warning"
                : "danger"
          }
        />
        <MetricCard
          label="Expiring ≤47 days"
          value={
            report.expiry_buckets.expired + report.expiry_buckets.expiring_47d
          }
          hint={`${report.expiry_buckets.expired} already expired`}
          tone={
            report.expiry_buckets.expired + report.expiry_buckets.expiring_47d >
            0
              ? "danger"
              : "success"
          }
        />
      </div>

      {/* Posture trend */}
      {snapshots.length >= 2 && (
        <Panel
          title="Posture Trend"
          subtitle={`Daily snapshots · ${snapshots.length} captured`}
        >
          <TrendChart
            labels={snapshots.map((s) => s.captured_at)}
            series={[
              {
                label: "PQC score %",
                color: "#22d3ee",
                values: snapshots.map((s) => s.pqc_score_percent),
              },
              {
                label: "Automation %",
                color: "#34d399",
                values: snapshots.map((s) => s.automation_percent),
              },
            ]}
          />
        </Panel>
      )}
      {trendQuery.isSuccess && snapshots.length < 2 && (
        <Panel title="Posture Trend">
          <p className="text-sm text-muted-foreground">
            Trend data is accumulating. A snapshot is captured daily — the chart
            appears once at least two days are recorded.
          </p>
        </Panel>
      )}

      {/* Row 2 */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Algorithm breakdown */}
        <Panel title="Algorithm Breakdown">
          {algoSlices.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No certificates in inventory yet. Issue a certificate to populate
              the algorithm breakdown.
            </p>
          ) : (
            <div className="flex items-center gap-6">
              <DonutChart slices={algoSlices} />
              <ul className="space-y-2 text-sm">
                {algoSlices.map((s) => (
                  <li key={s.label} className="flex items-center gap-2">
                    <span
                      className="inline-block h-3 w-3 rounded-full shrink-0"
                      style={{ background: s.color }}
                    />
                    <span className="text-foreground">{s.label}</span>
                    <span className="ml-auto font-medium text-foreground">
                      {s.value}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Panel>

        {/* PQC Readiness */}
        <Panel title="PQC Readiness">
          <div className="space-y-4">
            <div className="flex items-baseline justify-between">
              <span className="text-4xl font-bold text-primary">
                {report.pqc_readiness.pqc_score_percent}%
              </span>
              <span className="text-sm text-muted-foreground">
                PQC readiness (leaf-only + migration-ready + quantum-safe)
              </span>
            </div>
            <ProgressBar
              value={report.pqc_readiness.pqc_score_percent}
              max={100}
              color="bg-primary"
            />
            <ul className="space-y-2 text-sm">
              {[
                {
                  label: "Quantum-safe",
                  n: report.pqc_readiness.quantum_safe,
                  tone: "success" as const,
                },
                {
                  label: "Leaf-only PQC",
                  n: report.pqc_readiness.quantum_safe_leaf_only ?? 0,
                  tone: "info" as const,
                },
                {
                  label: "Migration-ready",
                  n: report.pqc_readiness.migration_ready,
                  tone: "info" as const,
                },
                {
                  label: "Vulnerable",
                  n: report.pqc_readiness.vulnerable,
                  tone: "danger" as const,
                },
                {
                  label: "Not applicable",
                  n: report.pqc_readiness.not_applicable,
                  tone: "neutral" as const,
                },
              ].map(({ label, n, tone }) => (
                <li key={label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge tone={tone}>{label}</Badge>
                  </div>
                  <span className="font-medium text-foreground">
                    {n}
                    <span className="ml-1 text-muted-foreground text-xs">
                      ({pqcTotal > 0 ? Math.round((n / pqcTotal) * 100) : 0}%)
                    </span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </Panel>

        {/* Risk Breakdown */}
        <Panel title="Risk Breakdown">
          <div className="space-y-3">
            {[
              {
                label: "Critical",
                n: report.risk_breakdown.critical,
                color: "bg-state-over",
                textColor: "text-state-over",
              },
              {
                label: "High",
                n: report.risk_breakdown.high,
                color: "bg-state-attn",
                textColor: "text-state-attn",
              },
              {
                label: "Medium",
                n: report.risk_breakdown.medium,
                color: "bg-state-attn",
                textColor: "text-state-attn",
              },
              {
                label: "Low",
                n: report.risk_breakdown.low,
                color: "bg-state-auto",
                textColor: "text-state-auto",
              },
            ].map(({ label, n, color, textColor }) => (
              <div key={label} className="space-y-1">
                <div className="flex items-center justify-between text-sm">
                  <span className={`font-medium ${textColor}`}>{label}</span>
                  <span className="text-foreground">
                    {n}
                    <span className="ml-1 text-muted-foreground text-xs">
                      ({riskTotal > 0 ? Math.round((n / riskTotal) * 100) : 0}%)
                    </span>
                  </span>
                </div>
                <ProgressBar value={n} max={riskTotal} color={color} />
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* Row 3 */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Expiry urgency */}
        <Panel title="Expiry Urgency">
          <SectionLabel>Certificate expiry windows</SectionLabel>
          <table className="w-full text-sm mt-2">
            <tbody className="divide-y divide-border">
              {expiryRows.map(({ label, value, tone }) => (
                <tr key={label}>
                  <td className="py-2 text-foreground">{label}</td>
                  <td className="py-2 text-right">
                    <div className="flex items-center justify-end gap-3">
                      <Badge tone={value > 0 ? tone : "neutral"}>{value}</Badge>
                      {/* "expired" is the only bucket with an exact-match
                          server-side status filter; the day-window buckets
                          have no equivalent, so only this row links out. */}
                      {label === "Expired" && (
                        <Button
                          tone="secondary"
                          onClick={() => navigate(expiredCertificatesPath())}
                        >
                          <RefreshCw size={12} aria-hidden="true" />
                          Renew
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>

        {/* Grade distribution */}
        <Panel title="Grade Distribution">
          <SectionLabel>Certificate quality grades</SectionLabel>
          {gradeEntries.length === 0 ? (
            <p className="mt-3 text-sm text-muted-foreground">
              No certificates in inventory yet. Grades appear once certificates
              are issued.
            </p>
          ) : (
            <div className="mt-3 space-y-3">
              {gradeEntries.map(([grade, count]) => (
                <div key={grade} className="space-y-1">
                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <Badge tone={GRADE_TONE[grade] ?? "neutral"}>
                        {grade}
                      </Badge>
                    </div>
                    <span className="text-foreground">
                      {count}
                      <span className="ml-1 text-muted-foreground text-xs">
                        (
                        {report.total_certs > 0
                          ? Math.round((count / report.total_certs) * 100)
                          : 0}
                        %)
                      </span>
                    </span>
                  </div>
                  <ProgressBar
                    value={count}
                    max={report.total_certs}
                    color={
                      grade === "A" || grade === "B"
                        ? "bg-state-auto"
                        : grade === "C"
                          ? "bg-state-attn"
                          : "bg-state-over"
                    }
                  />
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {/* Row 4 */}
      <FindingFunnelPanel findings={report.findings} />

      <Dialog
        open={notifyOpen}
        title="Notify owner"
        description="Send a real delivery about this posture report to a team. This report doesn't break certificates down by owner team, so name the team you're notifying."
        onClose={() => setNotifyOpen(false)}
        size="sm"
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            notifyMutation.mutate();
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Owner team</span>
            <Input
              value={notifyTeam}
              onChange={(e) => setNotifyTeam(e.target.value)}
              placeholder="platform-eng"
              aria-label="Owner team"
            />
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>Channel</span>
            <Select
              value={notifyChannel}
              onChange={(e) => {
                const v = e.target.value;
                if (isNotifyChannel(v)) setNotifyChannel(v);
              }}
            >
              {NOTIFY_CHANNELS.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </Select>
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>Delivery target</span>
            <Input
              value={notifyTarget}
              onChange={(e) => setNotifyTarget(e.target.value)}
              placeholder="owner@example.com"
              aria-label="Delivery target"
            />
          </label>
          {notifyError && (
            <p role="alert" className="text-xs text-state-over">
              {notifyError}
            </p>
          )}
          <div className="flex gap-2">
            <Button
              tone="primary"
              type="submit"
              disabled={notifyMutation.isPending}
            >
              {notifyMutation.isPending ? "Sending…" : "Confirm send"}
            </Button>
            <Button onClick={() => setNotifyOpen(false)}>Cancel</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={waveConfirmOpen}
        title="Open PQC wave"
        description="This re-derives post-quantum migration waves from the current certificate inventory. Continue?"
        onClose={() => setWaveConfirmOpen(false)}
        size="sm"
      >
        <div className="space-y-4">
          {waveError && (
            <p role="alert" className="text-xs text-state-over">
              {waveError}
            </p>
          )}
          <div className="flex gap-2">
            <Button
              tone="primary"
              onClick={() => waveMutation.mutate()}
              disabled={waveMutation.isPending}
            >
              {waveMutation.isPending ? "Opening…" : "Confirm"}
            </Button>
            <Button onClick={() => setWaveConfirmOpen(false)}>Cancel</Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
