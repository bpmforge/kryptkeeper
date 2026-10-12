import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Badge, Input, Panel, Select, StateMessage } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { ReportSkeleton } from "../components/Skeletons";
import { auditOutcomeTone } from "../lib/auditOutcome";

type AuditEvent = {
  timestamp: string;
  action: string;
  actor_id: string;
  actor_type: string;
  resource_id: string;
  outcome: string;
  source_ip?: string;
  change_summary?: string;
};
type ChangeAuditData = {
  generated_at: string;
  window_days: number;
  fingerprint?: string;
  total_events: number;
  by_action: Record<string, number>;
  by_actor: Record<string, number>;
  by_outcome: Record<string, number>;
  events: AuditEvent[];
};

function outcomeBadge(o: string) {
  return <Badge tone={auditOutcomeTone(o)}>{o}</Badge>;
}

const ACTION_LABELS: Record<string, string> = {
  "certificate.issue": "Cert Issue",
  "certificate.revoke": "Cert Revoke",
  "certificate.renew": "Cert Renew",
  "certificate.ownership_update": "Ownership Update",
  "ca.create": "CA Create",
  "ca.suspend": "CA Suspend",
  "ca.activate": "CA Activate",
};

export default function ChangeAudit() {
  const [days, setDays] = useState(30);
  const [fpDraft, setFpDraft] = useState("");
  // Committed on Enter/blur, not per keystroke: each request emits its own
  // report.change_audit audit event, so pasting a 64-char fingerprint used
  // to fire ~64 backend calls and 64 audit rows.
  const [fp, setFp] = useState("");
  const q = useQuery({
    queryKey: ["report-change-audit", days, fp],
    queryFn: () => api.changeAudit({ days, fingerprint: fp || undefined }),
  });
  const report = q.data?.data as ChangeAuditData | undefined;

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto fade-in-up">
      <PageHeader
        eyebrow="Reports"
        title="Change Audit"
        description="Full mutation history with actor, IP, and change details."
        actions={
          <div className="flex gap-2">
            <Input
              placeholder="Filter by fingerprint (Enter to apply)…"
              className="w-56 text-xs"
              value={fpDraft}
              onChange={(e) => setFpDraft(e.target.value)}
              onBlur={() => setFp(fpDraft.trim())}
              onKeyDown={(e) => {
                if (e.key === "Enter") setFp(fpDraft.trim());
              }}
            />
            <Select
              className="w-36"
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
            >
              {[7, 14, 30, 90, 180, 365].map((d) => (
                <option key={d} value={d}>
                  Last {d} days
                </option>
              ))}
            </Select>
          </div>
        }
      />

      {q.isLoading && <ReportSkeleton tiles={2} />}
      {q.error && (
        <StateMessage
          tone="error"
          title="Report unavailable"
          message={(q.error as Error).message}
        />
      )}

      {report && (
        <>
          <div className="grid grid-cols-3 gap-3">
            <div className="glass rounded-xl p-4 gradient-border">
              <div className="text-xs text-muted-foreground uppercase tracking-widest mb-1">
                Total Events
              </div>
              <div className="text-3xl font-black text-foreground">
                {report.total_events}
              </div>
            </div>
            <div className="glass rounded-xl p-4">
              <div className="text-xs text-muted-foreground uppercase tracking-widest mb-2">
                By Outcome
              </div>
              {Object.entries(report.by_outcome).map(([o, n]) => (
                <div key={o} className="flex justify-between text-sm">
                  {outcomeBadge(o)}
                  <span className="text-foreground font-semibold">{n}</span>
                </div>
              ))}
            </div>
            <div className="glass rounded-xl p-4">
              <div className="text-xs text-muted-foreground uppercase tracking-widest mb-2">
                By Action
              </div>
              {Object.entries(report.by_action)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5)
                .map(([a, n]) => (
                  <div key={a} className="flex justify-between text-xs py-0.5">
                    <span className="text-muted-foreground">
                      {ACTION_LABELS[a] ?? a}
                    </span>
                    <span className="text-foreground font-semibold">{n}</span>
                  </div>
                ))}
            </div>
          </div>

          <Panel
            title="Events"
            subtitle={`${report.events.length} events shown (max 500)`}
          >
            {report.events.length === 0 && (
              <StateMessage
                title="No events"
                message="No mutation events in the selected window."
              />
            )}
            {report.events.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left">
                      {[
                        "Time",
                        "Action",
                        "Actor",
                        "Resource",
                        "IP",
                        "Outcome",
                        "Summary",
                      ].map((h) => (
                        <th
                          key={h}
                          className="pb-3 pr-3 text-xs font-semibold uppercase tracking-widest text-muted-foreground"
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {report.events.map((e, i) => (
                      <tr
                        key={i}
                        className="hover:bg-foreground/[0.02] transition align-top"
                      >
                        <td className="py-2.5 pr-3 text-xs text-muted-foreground whitespace-nowrap">
                          {new Date(e.timestamp).toLocaleString()}
                        </td>
                        <td className="py-2.5 pr-3 text-xs text-primary whitespace-nowrap">
                          {ACTION_LABELS[e.action] ?? e.action}
                        </td>
                        <td className="py-2.5 pr-3 text-xs text-foreground whitespace-nowrap">
                          {e.actor_id}
                        </td>
                        <td className="py-2.5 pr-3 font-mono text-xs text-muted-foreground max-w-[120px] truncate">
                          {e.resource_id}
                        </td>
                        <td className="py-2.5 pr-3 text-xs text-muted-foreground">
                          {e.source_ip || "—"}
                        </td>
                        <td className="py-2.5 pr-3">
                          {outcomeBadge(e.outcome)}
                        </td>
                        <td
                          className="py-2.5 text-xs text-muted-foreground max-w-[160px] truncate"
                          title={e.change_summary}
                        >
                          {e.change_summary || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
