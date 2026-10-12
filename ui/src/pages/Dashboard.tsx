import { useQuery } from "@tanstack/react-query";
import { Horizon } from "../components/Horizon";
import { useNavigate } from "react-router-dom";
import {
  ShieldCheck,
  AlertTriangle,
  XCircle,
  Radar,
  Bell,
  ArrowRight,
  Building2,
  Activity,
  FileText,
} from "lucide-react";
import { toast } from "sonner";
import { api, downloadAuthedFile } from "../lib/api";
import { extractList } from "../lib/models";
import type { CertificateRecord } from "../lib/models";
import type { CaRecord, AuditRow } from "../lib/models";
import { useFirstRun } from "../lib/firstrun";
import Onboarding from "./Onboarding";
import { Badge, StateMessage } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { DashboardSkeleton, TableRowsSkeleton } from "../components/Skeletons";
import { auditOutcomeDotClass } from "../lib/auditOutcome";

// ─── Stat Tile ───────────────────────────────────────────────────
type StatTileProps = {
  label: string;
  value: number | string;
  sub?: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  tone: "cyan" | "rose" | "amber" | "emerald" | "violet";
  onClick?: () => void;
};

const TONE_MAP = {
  cyan: {
    bg: "stat-cyan",
    icon: "text-primary",
    value: "text-primary",
    glow: "hover:shadow-cyan-500/10",
    border: "hover:border-primary/30",
  },
  rose: {
    bg: "stat-rose",
    icon: "text-state-over",
    value: "text-state-over",
    glow: "hover:shadow-rose-500/10",
    border: "hover:border-state-over/30",
  },
  amber: {
    bg: "stat-amber",
    icon: "text-state-attn",
    value: "text-state-attn",
    glow: "hover:shadow-amber-500/10",
    border: "hover:border-state-attn/30",
  },
  emerald: {
    bg: "stat-emerald",
    icon: "text-state-auto",
    value: "text-state-auto",
    glow: "hover:shadow-emerald-500/10",
    border: "hover:border-state-auto/30",
  },
  violet: {
    bg: "stat-violet",
    icon: "text-primary",
    value: "text-primary",
    glow: "hover:shadow-violet-500/10",
    border: "hover:border-primary/30",
  },
};

function StatTile({
  label,
  value,
  sub,
  icon: Icon,
  tone,
  onClick,
}: StatTileProps) {
  const t = TONE_MAP[tone];
  return (
    <button
      type="button"
      onClick={onClick}
      className={`group glass gradient-border rounded-2xl p-5 text-left transition-all duration-200 hover:shadow-lg ${t.glow} ${t.border} focus:outline-none focus:ring-2 focus:ring-ring/50 ${t.bg}`}
    >
      <div className="flex items-start justify-between mb-3">
        <div
          className={`w-9 h-9 rounded-xl flex items-center justify-center bg-background/40`}
        >
          <Icon size={16} className={t.icon} />
        </div>
        <ArrowRight
          size={13}
          className="text-muted-foreground group-hover:text-muted-foreground group-hover:translate-x-0.5 transition-all"
        />
      </div>
      <div className={`text-4xl font-black tracking-tight count-up ${t.value}`}>
        {value}
      </div>
      <div className="text-xs font-semibold uppercase tracking-widest text-muted-foreground mt-1">
        {label}
      </div>
      {sub && <div className="text-xs text-muted-foreground mt-0.5">{sub}</div>}
    </button>
  );
}

// ─── Risk Gauge ──────────────────────────────────────────────────
function RiskGauge({
  critical,
  high,
  medium,
  total,
}: {
  critical: number;
  high: number;
  medium: number;
  total: number;
}) {
  if (total === 0)
    return (
      <div className="flex items-center justify-center h-24 text-sm text-muted-foreground">
        No certificates
      </div>
    );
  const critPct = (critical / total) * 100;
  const highPct = (high / total) * 100;
  const medPct = (medium / total) * 100;
  const safePct = 100 - critPct - highPct - medPct;
  const riskScore = Math.round(
    (critical * 100 + high * 60 + medium * 30) / total,
  );

  return (
    <div className="space-y-3">
      {/* Gauge arc */}
      <div className="relative mx-auto w-28 h-14 overflow-hidden">
        <svg viewBox="0 0 100 50" className="w-full">
          <path
            d="M 10 45 A 40 40 0 0 1 90 45"
            fill="none"
            stroke="#1e293b"
            strokeWidth="10"
            strokeLinecap="round"
          />
          <path
            d="M 10 45 A 40 40 0 0 1 90 45"
            fill="none"
            stroke={
              riskScore > 60
                ? "#f87171"
                : riskScore > 30
                  ? "#fbbf24"
                  : "#34d399"
            }
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${(riskScore / 100) * 126} 126`}
          />
        </svg>
        <div className="absolute bottom-0 left-0 right-0 text-center">
          <span
            className={`text-xl font-black ${riskScore > 60 ? "text-state-over" : riskScore > 30 ? "text-state-attn" : "text-state-auto"}`}
          >
            {riskScore}
          </span>
          <span className="text-xs text-muted-foreground block -mt-0.5">
            risk score
          </span>
        </div>
      </div>

      {/* Stacked bar */}
      <div className="h-2 rounded-full overflow-hidden flex">
        <div
          className="bg-state-over transition-all"
          style={{ width: `${critPct}%` }}
          title={`Critical: ${critical}`}
        />
        <div
          className="bg-state-attn transition-all"
          style={{ width: `${highPct}%` }}
          title={`High: ${high}`}
        />
        <div
          className="bg-state-attn transition-all"
          style={{ width: `${medPct}%` }}
          title={`Medium: ${medium}`}
        />
        <div
          className="bg-state-auto/40 flex-1"
          title={`Safe: ${Math.round((safePct * total) / 100)}`}
        />
      </div>

      <div className="flex justify-between text-xs text-muted-foreground">
        <span>
          <span className="text-state-over font-semibold">{critical}</span>{" "}
          critical
        </span>
        <span>
          <span className="text-state-attn font-semibold">{high}</span> high
        </span>
        <span>
          <span className="text-state-attn font-semibold">{medium}</span> medium
        </span>
      </div>
    </div>
  );
}

// ─── PQC Readiness Bar ───────────────────────────────────────────
function PQCBar({
  quantumSafe,
  migrationReady,
  vulnerable,
  total,
}: {
  quantumSafe: number;
  migrationReady: number;
  vulnerable: number;
  total: number;
}) {
  if (total === 0) return null;
  const safePct = Math.round(((quantumSafe + migrationReady) / total) * 100);
  return (
    <div className="space-y-2">
      <div className="flex justify-between items-end">
        <span className="text-xs text-muted-foreground uppercase tracking-widest">
          PQC Readiness
        </span>
        <span
          className={`text-lg font-black ${safePct >= 80 ? "text-state-auto" : safePct >= 40 ? "text-state-attn" : "text-state-over"}`}
        >
          {safePct}%
        </span>
      </div>
      <div className="h-2.5 rounded-full bg-muted overflow-hidden flex">
        <div
          className="bg-gradient-to-r from-state-auto to-primary rounded-full transition-all duration-700"
          style={{ width: `${safePct}%` }}
        />
      </div>
      <div className="flex justify-between text-xs text-muted-foreground">
        <span>
          <span className="text-state-auto">{quantumSafe}</span> quantum-safe
        </span>
        <span>
          <span className="text-state-over">{vulnerable}</span> vulnerable
        </span>
      </div>
    </div>
  );
}

// ─── CA Status Row ───────────────────────────────────────────────
function caStatusTone(
  status: string,
): "success" | "warning" | "danger" | "neutral" {
  if (status === "active") return "success";
  if (status === "suspended") return "warning";
  if (status === "revoked" || status === "expired") return "danger";
  return "neutral";
}

// ─── Dashboard ───────────────────────────────────────────────────
export default function Dashboard() {
  const navigate = useNavigate();

  // W8-02: a fresh, unconfigured hub (zero CAs) renders the onboarding
  // wizard in place of the normal dashboard content instead of dead-ending
  // on an empty dashboard. Deliberately NOT a new App.tsx route (App.tsx is
  // W8-08's territory this wave) -- Onboarding is rendered through this
  // existing "/" route.
  const firstRun = useFirstRun();

  const summaryQ = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: api.dashboardSummary,
  });
  // The horizon reads valid_until + renewal_method per certificate, so it
  // needs the list rather than the pre-aggregated summary.
  // The server clamps limit to 100 — a single {limit: 5000} call silently
  // returned a 100-cert horizon presented as the whole estate. Walk the
  // cursor chain (capped) and let the Horizon label any truncation.
  const certsQ = useQuery({
    queryKey: ["dashboard-horizon-certs"],
    queryFn: async () => {
      const all: CertificateRecord[] = [];
      let nextCursor: string | number | null | undefined = undefined;
      let total = 0;
      for (let page = 0; page < 10; page++) {
        const res = await api.certificates({
          limit: 100,
          ...(nextCursor != null ? { cursor: nextCursor } : {}),
        });
        const items = extractList<CertificateRecord>(res.data, ["items"]);
        all.push(...items);
        total = res.meta?.total ?? all.length;
        const next = res.meta?.next_cursor;
        if (next == null) break;
        nextCursor = next;
      }
      return { items: all, total };
    },
  });

  const casQ = useQuery({
    queryKey: ["dashboard-cas"],
    queryFn: () => api.cas({ limit: 6 }),
  });
  const auditQ = useQuery({
    queryKey: ["dashboard-audit"],
    queryFn: () => api.auditList({ limit: 8, order: "desc" }),
  });
  const postureQ = useQuery({
    queryKey: ["dashboard-posture"],
    queryFn: api.cryptoPosture,
  });

  const s = summaryQ.data?.data;
  const cas = extractList<CaRecord>(casQ.data?.data);
  const auditRows: AuditRow[] = Array.isArray(auditQ.data?.data)
    ? (auditQ.data.data as AuditRow[])
    : [];
  const posture = postureQ.data?.data;

  const total = s?.certificates?.total ?? 0;
  const expiring30 = s?.certificates?.expiring_30_days ?? 0;
  const expired = s?.certificates?.expired ?? 0;
  // W11-08 estate split (W11-01 backend); zeros on file-backed summaries.
  const estateManaged = s?.certificates?.managed ?? 0;
  const estateExternal = s?.certificates?.external ?? 0;
  const estateUnmanaged = s?.certificates?.unmanaged ?? 0;
  const riskBreakdown = posture?.risk_breakdown ?? {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  if (firstRun.loading || summaryQ.isLoading) return <DashboardSkeleton />;
  if (firstRun.isFirstRun) {
    return <Onboarding onComplete={firstRun.dismiss} />;
  }

  return (
    <div className="p-6 space-y-6 fade-in-up">
      <PageHeader
        eyebrow="Overview"
        title="What needs a human"
        description={`Real-time PKI posture · ${new Date().toLocaleDateString(
          "en-US",
          {
            weekday: "long",
            month: "long",
            day: "numeric",
          },
        )}`}
        actions={
          <>
            <button
              type="button"
              onClick={() =>
                void downloadAuthedFile(
                  "/reports/executive-summary?format=pdf",
                  "executive-summary.pdf",
                ).catch((err: Error) => toast.error(err.message))
              }
              aria-label="Download executive one-pager PDF"
              className="flex items-center gap-2 rounded-xl border border-border bg-foreground/5 px-4 py-2 text-sm font-semibold text-foreground hover:bg-foreground/10 transition"
            >
              <FileText size={14} /> One-pager (PDF)
            </button>
            <button
              type="button"
              onClick={() => navigate("/certificates")}
              className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-primary to-primary px-4 py-2 text-sm font-semibold text-primary-foreground hover:from-primary hover:to-primary transition glow-cyan"
            >
              <ShieldCheck size={14} /> Open Inventory
            </button>
          </>
        }
      />

      <Horizon certificates={certsQ.data?.items ?? []} />
      {certsQ.data && certsQ.data.items.length < certsQ.data.total ? (
        <p className="text-xs text-muted-foreground -mt-3">
          Horizon shows the first {certsQ.data.items.length} of{" "}
          {certsQ.data.total} certificates.
        </p>
      ) : null}

      {/* Estate split (W11-08): who manages what */}
      <div
        data-testid="estate-strip"
        className="flex flex-wrap items-center gap-4 rounded-xl border border-border bg-background/60 px-4 py-3 text-sm"
      >
        <span className="text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground">
          Estate
        </span>
        <button
          type="button"
          className="text-state-auto hover:underline"
          onClick={() => navigate("/certificates?management_state=managed")}
        >
          {estateManaged} managed
        </button>
        <button
          type="button"
          className="text-primary hover:underline"
          onClick={() => navigate("/certificates?management_state=external")}
        >
          {estateExternal} externally managed
        </button>
        <button
          type="button"
          // Colour means state, so zero unmanaged must not look like a
          // problem: it is the best possible reading of this number.
          className={
            (estateUnmanaged > 0 ? "text-state-attn" : "text-muted-foreground") +
            " hover:underline"
          }
          onClick={() => navigate("/certificates?management_state=unmanaged")}
        >
          {estateUnmanaged} unmanaged
        </button>
      </div>

      {/* ── Primary stat tiles ──────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
        <StatTile
          label="Total Certs"
          value={total}
          sub="in inventory"
          icon={ShieldCheck}
          tone="cyan"
          onClick={() => navigate("/certificates")}
        />
        <StatTile
          label="Expiring 30d"
          value={expiring30}
          sub={expiring30 > 0 ? "needs renewal" : "all current"}
          icon={AlertTriangle}
          tone={expiring30 > 0 ? "amber" : "emerald"}
          onClick={() => navigate("/reports/expiry-timeline")}
        />
        <StatTile
          label="Expired"
          value={expired}
          sub={expired > 0 ? "action required" : "none"}
          icon={XCircle}
          tone={expired > 0 ? "rose" : "emerald"}
          onClick={() => navigate("/certificates?status=expired")}
        />
        <StatTile
          label="Endpoints"
          value={s?.discovery?.discovered_endpoints ?? 0}
          sub="discovered"
          icon={Radar}
          tone="violet"
          onClick={() => navigate("/discovery")}
        />
        <StatTile
          label="Risky"
          value={s?.discovery?.risky_endpoints ?? 0}
          sub="endpoints"
          icon={AlertTriangle}
          tone={(s?.discovery?.risky_endpoints ?? 0) > 0 ? "rose" : "emerald"}
          onClick={() => navigate("/discovery")}
        />
        <StatTile
          label="Alerts"
          value={s?.notifications?.pending_notifications ?? 0}
          sub="pending"
          icon={Bell}
          tone={
            (s?.notifications?.pending_notifications ?? 0) > 0
              ? "amber"
              : "emerald"
          }
          onClick={() => navigate("/alerts")}
        />
      </div>

      {/* ── Main grid ───────────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* ── Left column: Risk gauge + PQC ─────────────────── */}
        <div className="space-y-4">
          <div className="glass gradient-border rounded-2xl p-5 space-y-5">
            <div className="flex items-center gap-2">
              <Activity size={14} className="text-primary" />
              <span className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                Risk Overview
              </span>
            </div>
            <RiskGauge
              critical={riskBreakdown.critical ?? 0}
              high={riskBreakdown.high ?? 0}
              medium={riskBreakdown.medium ?? 0}
              total={total}
            />
          </div>

          {posture && (
            <div className="glass rounded-2xl p-5">
              <PQCBar
                quantumSafe={posture.pqc_readiness?.quantum_safe ?? 0}
                migrationReady={posture.pqc_readiness?.migration_ready ?? 0}
                vulnerable={posture.pqc_readiness?.vulnerable ?? 0}
                total={total}
              />
            </div>
          )}

          {/* Quick links to reports */}
          <div className="glass rounded-2xl p-4 space-y-1">
            <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-2">
              Reports
            </p>
            {[
              { label: "CA Health", to: "/reports/ca-health" },
              { label: "Expiry Timeline", to: "/reports/expiry-timeline" },
              {
                label: "Compliance Evidence",
                to: "/reports/compliance-evidence",
              },
              { label: "Algorithm Sunset", to: "/reports/algorithm-sunset" },
            ].map(({ label, to }) => (
              <button
                key={to}
                type="button"
                onClick={() => navigate(to)}
                className="w-full flex items-center justify-between rounded-lg px-3 py-2 text-xs text-muted-foreground hover:bg-foreground/5 hover:text-primary transition group"
              >
                <span>{label}</span>
                <ArrowRight
                  size={11}
                  className="group-hover:translate-x-0.5 transition-transform"
                />
              </button>
            ))}
          </div>
        </div>

        {/* ── Centre: CA health ─────────────────────────────── */}
        <div className="glass gradient-border rounded-2xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Building2 size={14} className="text-state-auto" />
              <span className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                Certificate Authorities
              </span>
            </div>
            <button
              type="button"
              onClick={() => navigate("/cas")}
              className="text-xs text-primary hover:text-primary transition"
            >
              View all →
            </button>
          </div>
          {casQ.isLoading && <TableRowsSkeleton rows={3} />}
          {casQ.error && (
            <StateMessage tone="error" title="Could not load CAs" />
          )}
          {cas.length === 0 && !casQ.isLoading && (
            <StateMessage
              title="No CAs configured"
              message="Create a root CA to get started."
            />
          )}
          <div className="space-y-2">
            {cas.map((ca) => (
              <button
                key={ca.id}
                type="button"
                onClick={() => navigate(`/cas/${ca.id}`)}
                className="w-full flex items-center justify-between rounded-xl border border-border/50 bg-background/40 px-3.5 py-2.5 text-left text-sm transition hover:border-primary/20 hover:bg-primary/5 group"
              >
                <div>
                  <p className="font-medium text-foreground group-hover:text-primary transition text-sm">
                    {ca.display_name || ca.name || ca.id}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {ca.type} · {ca.active_issued_certificates ?? 0} certs
                  </p>
                </div>
                <Badge tone={caStatusTone(ca.status)}>{ca.status}</Badge>
              </button>
            ))}
          </div>
        </div>

        {/* ── Right: Live activity feed ─────────────────────── */}
        <div className="glass rounded-2xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity size={14} className="text-primary" />
              <span className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                Live Activity
              </span>
              <span className="w-1.5 h-1.5 rounded-full bg-state-auto pulse-glow" />
            </div>
            <button
              type="button"
              onClick={() => navigate("/audit")}
              className="text-xs text-primary hover:text-primary transition"
            >
              Full log →
            </button>
          </div>
          {auditQ.isLoading && <TableRowsSkeleton rows={4} />}
          {auditQ.error && (
            <StateMessage tone="error" title="Could not load activity" />
          )}
          {auditRows.length === 0 && !auditQ.isLoading && (
            <StateMessage
              title="No activity yet"
              message="Actions will appear here."
            />
          )}
          <div className="space-y-1.5">
            {auditRows.map((row, i) => (
              <div
                key={row.id ?? i}
                className="flex items-start gap-2.5 rounded-xl px-3 py-2 hover:bg-foreground/[0.03] transition group"
              >
                <div
                  className={`mt-1 w-1.5 h-1.5 rounded-full shrink-0 ${auditOutcomeDotClass(row.outcome)}`}
                />
                <div className="min-w-0 flex-1">
                  <p className="text-xs text-foreground truncate">
                    {row.action}
                  </p>
                  <p className="text-[11px] text-muted-foreground truncate">
                    {row.actor_id} ·{" "}
                    {row.timestamp
                      ? new Date(row.timestamp).toLocaleTimeString()
                      : ""}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Bottom action strip ─────────────────────────────── */}
      {(expiring30 > 0 ||
        expired > 0 ||
        (s?.discovery?.risky_endpoints ?? 0) > 0) && (
        <div className="glass rounded-2xl border border-state-attn/30 bg-state-attn/10 p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle
              size={16}
              className="text-state-attn shrink-0 mt-0.5"
            />
            <div className="flex-1">
              <p className="text-sm font-semibold text-state-attn">
                Attention required
              </p>
              <div className="mt-2 flex flex-wrap gap-2">
                {expired > 0 && (
                  <button
                    type="button"
                    onClick={() => navigate("/certificates?status=expired")}
                    className="flex items-center gap-1.5 text-xs rounded-lg bg-state-over/10 border border-state-over/40 px-3 py-1.5 text-state-over hover:bg-state-over/15 transition"
                  >
                    <XCircle size={11} /> {expired} expired
                  </button>
                )}
                {expiring30 > 0 && (
                  <button
                    type="button"
                    onClick={() => navigate("/reports/expiry-timeline")}
                    className="flex items-center gap-1.5 text-xs rounded-lg bg-state-attn/10 border border-state-attn/40 px-3 py-1.5 text-state-attn hover:bg-state-attn/15 transition"
                  >
                    <AlertTriangle size={11} /> {expiring30} expiring in 30d
                  </button>
                )}
                {(s?.discovery?.risky_endpoints ?? 0) > 0 && (
                  <button
                    type="button"
                    onClick={() => navigate("/discovery")}
                    className="flex items-center gap-1.5 text-xs rounded-lg bg-state-over/10 border border-state-over/40 px-3 py-1.5 text-state-over hover:bg-state-over/10 transition"
                  >
                    <Radar size={11} /> {s?.discovery?.risky_endpoints} risky
                    endpoints
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
