import { useQuery } from "@tanstack/react-query";
import type { components } from "../generated/api-types";
import { Badge, Panel, formatDateTime } from "./ui";
import { listExceptions } from "../lib/exceptionsApi";
import { humanizeEnum } from "../lib/utils";

export type FindingFunnelSummary = components["schemas"]["FindingFunnelSummary"];

const NA = "—";

// Posture snapshots written before W22-29 decode deduped/in_scope as 0, so a
// zero beside a non-zero raw means "unknown", never "none".
function stage(value: number | undefined, raw: number, zeroIsUnknown: boolean): string {
  if (value === undefined || value === null) return NA;
  if (zeroIsUnknown && value === 0 && raw > 0) return NA;
  return String(value);
}

export function FindingFunnel({ findings }: { findings?: FindingFunnelSummary }) {
  const raw = findings?.raw ?? 0;
  const cells = [
    { id: "raw", label: "Raw", value: String(raw), caption: "Total findings" },
    { id: "deduped", label: "Deduped", value: stage(findings?.deduped, raw, true), caption: "one per target and code" },
    { id: "in_scope", label: "In scope", value: stage(findings?.in_scope, raw, true), caption: "your tenant" },
    { id: "effective", label: "Effective", value: stage(findings?.effective, raw, false), caption: "still counting" },
    { id: "suppressed", label: "Suppressed", value: stage(findings?.suppressed, raw, false), caption: "accepted risk" },
  ];
  return (
    <div className="grid grid-cols-2 gap-4 text-center md:grid-cols-5">
      {cells.map((c) => (
        <div key={c.id} data-testid={`funnel-${c.id}`}>
          <div className="text-xs uppercase tracking-[0.2em] text-muted-foreground">{c.label}</div>
          <div className="text-3xl font-bold text-foreground">{c.value}</div>
          <div className="mt-1 text-xs text-muted-foreground">{c.caption}</div>
        </div>
      ))}
    </div>
  );
}

// Pending proposals are listed next to active ones so a 202 is visibly not
// yet a suppression. Hidden when the caller cannot read exceptions.
export function ExceptionsList() {
  const q = useQuery({ queryKey: ["exceptions"], queryFn: listExceptions, retry: false });
  const items = q.data?.data ?? [];
  if (items.length === 0) return null;
  return (
    <div className="mt-6 border-t border-border pt-4" data-testid="exceptions-list">
      <div className="mb-2 text-xs uppercase tracking-[0.2em] text-muted-foreground">Accepted-risk exceptions</div>
      <ul className="space-y-1 text-sm">
        {items.map((e) => (
          <li key={e.id ?? `${e.target_id}:${e.finding_code}`} className="flex flex-wrap items-center gap-2">
            <Badge tone={e.status === "active" ? "success" : "warning"}>
              {e.status === "active" ? "Active" : "Pending approval"}
            </Badge>
            <span className="font-medium text-foreground">{humanizeEnum(e.finding_code)}</span>
            <span className="font-mono text-xs text-muted-foreground" title={e.target_id}>
              {e.target_label ?? (e.target_id ?? "").slice(0, 16)}
            </span>
            {e.expires_at ? (
              <span className="text-xs text-muted-foreground">expires {formatDateTime(e.expires_at)}</span>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function FindingFunnelPanel({
  title,
  subtitle,
  findings,
  actions,
}: {
  title: string;
  subtitle: string;
  findings?: FindingFunnelSummary;
  actions?: React.ReactNode;
}) {
  return (
    <Panel title={title} subtitle={subtitle}>
      <FindingFunnel findings={findings} />
      {actions ? <div className="mt-4 flex justify-end">{actions}</div> : null}
      <ExceptionsList />
    </Panel>
  );
}
