import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import { api } from "../lib/api";
import { Badge, Panel, StateMessage } from "../components/ui";
import { extractList } from "../lib/models";
import type { CaRecord, TemplateRecord } from "../lib/models";
import { PageHeader } from "../components/PageHeader";
import { ReportSkeleton } from "../components/Skeletons";

type DailyBucket = { date: string; count: number };
type IVData = {
  generated_at: string;
  total_issued: number;
  windows: { last_7d: number; last_30d: number; last_90d: number };
  daily_buckets: DailyBucket[];
  by_ca: Record<string, number>;
  by_team: Record<string, number>;
  by_template: Record<string, number>;
  anomaly_days: string[];
  // S-47/S-64: the detector's minimum-sample floor and, below it, the
  // backend's explanation for why nothing fires.
  anomaly_minimum_sample?: number;
  anomaly_threshold_note?: string;
};

// S-46: a group key resolves to a human name when one is on record;
// otherwise it falls through to the raw identifier, marked as such.
// `ready` gates the fall-through so an in-flight lookup renders the raw
// key unmarked rather than flashing a false "no name exists".
type NameLookup = { names: Map<string, string>; ready: boolean };

function resolveGroupLabel(
  key: string,
  sentinels: readonly string[],
  lookup: NameLookup,
): { label: string; isIdentifier: boolean } {
  if (sentinels.includes(key))
    return { label: SENTINEL_LABELS[key] ?? key, isIdentifier: false };
  const name = lookup.names.get(key);
  if (name) return { label: name, isIdentifier: false };
  if (!lookup.ready) return { label: key, isIdentifier: false };
  return { label: key, isIdentifier: true };
}

const CA_SENTINELS = ["unknown"];
const TEMPLATE_SENTINELS = ["none"];

const SENTINEL_LABELS: Record<string, string> = {
  unknown: "Unknown CA",
  none: "No template",
};

// Day buckets are server-side UTC calendar days and cannot be re-bucketed in
// the browser's zone, so labels say "UTC" instead of pretending to be local
// (the Dashboard header date is browser-local).
// Format without a spurious clock time.
function formatDay(d: string): string {
  const t = new Date(d);
  if (Number.isNaN(t.getTime())) return d;
  return new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeZone: "UTC" }).format(t);
}

function GroupRow({
  entryKey,
  count,
  label,
  isIdentifier,
  countCls,
  to,
}: {
  entryKey: string;
  count: number;
  label: string;
  isIdentifier: boolean;
  countCls: string;
  to?: string;
}) {
  const labelEl = (
    <span
      className={
        isIdentifier
          ? "font-mono text-xs text-muted-foreground truncate"
          : "text-foreground truncate"
      }
      title={
        isIdentifier
          ? "No display name on record — showing the raw identifier"
          : undefined
      }
    >
      {label}
    </span>
  );
  return (
    <div
      key={entryKey}
      className="flex justify-between items-center gap-2 py-1.5 border-b border-border/40 last:border-0 text-sm"
    >
      <span className="flex items-center gap-1.5 min-w-0">
        {isIdentifier && <Badge tone="neutral">ID</Badge>}
        {to ? (
          <Link to={to} className="min-w-0 hover:text-primary hover:underline">
            {labelEl}
          </Link>
        ) : (
          labelEl
        )}
      </span>
      <span className={`${countCls} font-semibold ml-2 shrink-0`}>{count}</span>
    </div>
  );
}

export default function IssuanceVelocity() {
  const q = useQuery({
    queryKey: ["report-issuance-velocity"],
    queryFn: api.issuanceVelocity,
  });
  const report = q.data?.data as IVData | undefined;

  const casQuery = useQuery({
    queryKey: ["cas", { limit: 200 }],
    queryFn: () => api.cas({ limit: 200 }),
  });
  const templatesQuery = useQuery({
    queryKey: ["templates", { limit: 200 }],
    queryFn: () => api.templates({ limit: 200 }),
  });
  const cas = extractList<CaRecord>(casQuery.data?.data, ["items"]);
  const templates = extractList<TemplateRecord>(templatesQuery.data?.data, [
    "items",
  ]);
  const caLookup: NameLookup = {
    names: new Map(
      cas
        .filter((c) => c.display_name || c.name)
        .map((c) => [c.id, (c.display_name || c.name) as string]),
    ),
    ready: !casQuery.isLoading,
  };
  const templateLookup: NameLookup = {
    names: new Map(
      templates
        .filter((t) => t.display_name || t.name)
        .map((t) => [t.id, t.display_name || t.name]),
    ),
    ready: !templatesQuery.isLoading,
  };

  const buckets = report?.daily_buckets ?? [];
  const maxDay = Math.max(1, ...buckets.map((b) => b.count));

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto fade-in-up">
      <PageHeader
        eyebrow="Reports"
        title="Issuance Velocity"
        description="Certificate issuance rate and anomaly detection."
      />

      {q.isLoading && <ReportSkeleton tiles={3} />}
      {q.error && (
        <StateMessage
          tone="error"
          title="Report unavailable"
          message={(q.error as Error).message}
        />
      )}

      {report && (
        <>
          {/* Window stats */}
          <div className="grid grid-cols-3 gap-3">
            {[
              {
                label: "Last 7 days",
                value: report.windows.last_7d,
                cls: "text-primary",
              },
              {
                label: "Last 30 days",
                value: report.windows.last_30d,
                cls: "text-primary",
              },
              {
                label: "Last 90 days",
                value: report.windows.last_90d,
                cls: "text-primary",
              },
            ].map(({ label, value, cls }) => (
              <div
                key={label}
                className="glass rounded-2xl p-4 gradient-border text-center"
              >
                <div className={`text-4xl font-black ${cls} count-up`}>
                  {value}
                </div>
                <div className="text-xs text-muted-foreground mt-1">{label}</div>
              </div>
            ))}
          </div>

          {/* Anomaly alert */}
          {report.anomaly_days.length > 0 && (
            <div className="flex items-start gap-3 rounded-xl border border-state-attn/50 bg-state-attn/10 px-4 py-3">
              <AlertTriangle
                size={16}
                className="text-state-attn shrink-0 mt-0.5"
              />
              <div>
                <p className="text-sm font-semibold text-state-attn">
                  Anomaly detected
                </p>
                <p className="text-xs text-state-attn mt-0.5">
                  Unusual issuance spikes on:{" "}
                  {[...report.anomaly_days].sort().map(formatDay).join(", ")} (UTC)
                </p>
                {/* S-64: state the floor WHERE the warning renders, from
                    the payload — the S-47 detector requires it before
                    anything fires, and a reader deciding whether to trust
                    this panel needs that context here, not in the docs. */}
                {report.anomaly_minimum_sample != null && (
                  <p className="text-xs text-muted-foreground mt-1">
                    Spikes are only flagged once at least{" "}
                    {report.anomaly_minimum_sample} certificates were issued in
                    the last 30 days.
                  </p>
                )}
              </div>
            </div>
          )}

          {/* S-64: below the floor the backend explains itself — render
              that instead of silence. */}
          {report.anomaly_days.length === 0 &&
            report.anomaly_threshold_note && (
              <div className="rounded-xl border border-border bg-card/40 px-4 py-3">
                <p className="text-xs text-muted-foreground">
                  {report.anomaly_threshold_note}
                </p>
              </div>
            )}

          {/* Sparkline bars */}
          <Panel
            title={`Daily Issuance — Last ${buckets.length} Day${buckets.length === 1 ? "" : "s"}`}
            subtitle="Bar height proportional to daily count. Days are UTC calendar days."
          >
            <div
              role="img"
              aria-label={`Bar chart: daily certificate issuance over the last ${buckets.length} day${buckets.length === 1 ? "" : "s"}, ${buckets.reduce((s, b) => s + b.count, 0)} in total, peak ${Math.max(0, ...buckets.map((b) => b.count))}${report.anomaly_days.length > 0 ? `, ${report.anomaly_days.length} anomaly day${report.anomaly_days.length === 1 ? "" : "s"}` : ""}. A table with the same data follows.`}
              className="flex gap-0.5 h-24 overflow-x-auto"
            >
              {buckets.map((b) => {
                const isAnomaly = report.anomaly_days.includes(b.date);
                const pct = (b.count / maxDay) * 100;
                return (
                  <div
                    key={b.date}
                    aria-hidden="true"
                    className="flex-1 min-w-[5px] h-full flex flex-col items-center justify-end group relative"
                    title={`${b.date} (UTC): ${b.count}`}
                  >
                    <div
                      data-testid="issuance-bar"
                      className={`w-full rounded-sm transition-all ${isAnomaly ? "bg-state-attn" : "bg-primary/60 group-hover:bg-primary"}`}
                      style={{ height: `${Math.max(4, pct)}%` }}
                    />
                    {/* Tooltip */}
                    <div className="absolute bottom-full mb-1 hidden group-hover:block bg-muted text-xs text-foreground px-2 py-1 rounded whitespace-nowrap z-10">
                      {b.date} (UTC): {b.count}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="sr-only">
              <table>
                <caption>
                  Daily certificate issuance over the last {buckets.length} day
                  {buckets.length === 1 ? "" : "s"}; days with no issuance are omitted.
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Date (UTC)</th>
                    <th scope="col">Issued</th>
                    <th scope="col">Flag</th>
                  </tr>
                </thead>
                <tbody>
                  {buckets
                    .filter((b) => b.count > 0)
                    .map((b) => (
                      <tr key={b.date}>
                        <td>{b.date}</td>
                        <td>{b.count}</td>
                        <td>{report.anomaly_days.includes(b.date) ? "anomaly" : ""}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <Panel title="By CA">
              {Object.keys(report.by_ca).length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No issuance recorded in this window yet.
                </p>
              ) : null}
              {Object.entries(report.by_ca)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 8)
                .map(([k, v]) => {
                  const { label, isIdentifier } = resolveGroupLabel(
                    k,
                    CA_SENTINELS,
                    caLookup,
                  );
                  return (
                    <GroupRow
                      key={k}
                      entryKey={k}
                      count={v}
                      label={label}
                      isIdentifier={isIdentifier}
                      countCls="text-primary"
                      to={
                        CA_SENTINELS.includes(k)
                          ? undefined
                          : `/certificates?ca_id=${encodeURIComponent(k)}`
                      }
                    />
                  );
                })}
            </Panel>
            {/* S-46: team_id is a free-form string that IS the team's name
                in this product's data model (there is no teams registry or
                /teams API to join against) — render it as the label, not as
                a marked identifier. A teams registry would change this. */}
            <Panel title="By Team">
              {Object.keys(report.by_team).length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No issuance recorded in this window yet.
                </p>
              ) : null}
              {Object.entries(report.by_team)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 8)
                .map(([k, v]) => (
                  <GroupRow
                    key={k}
                    entryKey={k}
                    count={v}
                    label={k}
                    isIdentifier={false}
                    countCls="text-primary"
                  />
                ))}
            </Panel>
            <Panel title="By Template">
              {Object.keys(report.by_template).length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No issuance recorded in this window yet.
                </p>
              ) : null}
              {Object.entries(report.by_template)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 8)
                .map(([k, v]) => {
                  const { label, isIdentifier } = resolveGroupLabel(
                    k,
                    TEMPLATE_SENTINELS,
                    templateLookup,
                  );
                  return (
                    <GroupRow
                      key={k}
                      entryKey={k}
                      count={v}
                      label={label}
                      isIdentifier={isIdentifier}
                      countCls="text-primary"
                    />
                  );
                })}
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}
