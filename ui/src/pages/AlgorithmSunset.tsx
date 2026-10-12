import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { XCircle, Clock, CheckCircle2 } from "lucide-react";
import { api } from "../lib/api";
import { Badge, Panel, StateMessage } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { ReportSkeleton } from "../components/Skeletons";
import type { components } from "../generated/api-types";

// S-39: this page used to declare its own SunsetData and reach it through an
// `as` cast, because api.ts typed the response Record<string, unknown>. The
// hand-written type said `sunset_summary` and `recommended`; the server sends
// `summary` and `recommended_replacement`. Nothing compared the two, so the
// page threw on every render and blanked the whole app.
//
// Both names now come from the spec, so a future rename fails the build here
// instead of at runtime. Every field is optional in the generated type, which
// is why the reads below are guarded rather than trusted.
type SunsetData = components["schemas"]["AlgorithmSunsetReport"];
type SunsetGroup = NonNullable<SunsetData["groups"]>[number];

function urgencyBadge(u: SunsetGroup["urgency"]) {
  if (u === "immediate") return <Badge tone="danger">Immediate</Badge>;
  if (u === "high") return <Badge tone="warning">High</Badge>;
  if (u === "medium") return <Badge tone="info">Medium</Badge>;
  return <Badge>Low</Badge>;
}

function statusIcon(s: SunsetGroup["status"]) {
  if (s === "banned") return <XCircle size={15} className="text-state-over" />;
  if (s === "sunset_2030")
    return <Clock size={15} className="text-state-attn" />;
  return <CheckCircle2 size={15} className="text-state-auto" />;
}

export default function AlgorithmSunset() {
  const q = useQuery({
    queryKey: ["report-algorithm-sunset"],
    queryFn: api.algorithmSunset,
  });
  const report: SunsetData | undefined = q.data?.data;
  const summary = report?.summary;
  const groups = report?.groups ?? [];

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto fade-in-up">
      <PageHeader
        eyebrow="Reports"
        title="Algorithm Sunset"
        description="NIST 800-131A · CA/B Forum · CNSA 2.0 deprecation timeline."
      />

      {q.isLoading && <ReportSkeleton tiles={4} />}
      {q.error && (
        <StateMessage
          tone="error"
          title="Report unavailable"
          message={(q.error as Error).message}
        />
      )}

      {report && (
        <>
          {/* Summary */}
          <div className="grid grid-cols-3 gap-3">
            {[
              {
                label: "Banned Now",
                value: summary?.banned_now ?? 0,
                cls: "text-state-over",
                bg: "stat-rose",
              },
              {
                label: "Sunset 2030",
                value: summary?.sunset_2030 ?? 0,
                cls: "text-state-attn",
                bg: "stat-amber",
              },
              {
                label: "Compliant",
                value: summary?.compliant ?? 0,
                cls: "text-state-auto",
                bg: "stat-emerald",
              },
            ].map(({ label, value, cls, bg }) => (
              <div
                key={label}
                className={`glass rounded-2xl p-4 gradient-border ${bg}`}
              >
                <div className="text-xs text-muted-foreground uppercase tracking-widest mb-1">
                  {label}
                </div>
                <div className={`text-4xl font-black ${cls} count-up`}>
                  {value}
                </div>
              </div>
            ))}
          </div>

          {groups.length === 0 &&
            ((summary?.compliant ?? 0) > 0 ? (
              <StateMessage
                tone="success"
                title="All algorithms compliant"
                message={`No certificates using deprecated or sunset algorithms across ${summary?.compliant} inventoried certificate${(summary?.compliant ?? 0) === 1 ? "" : "s"}.`}
              />
            ) : (
              // A green all-clear derived from an EMPTY inventory would be a
              // false assurance — nothing has been checked yet.
              <StateMessage
                title="Nothing inventoried yet"
                message="No certificates to assess. Issue or discover certificates first — then this page reports deprecated and sunset algorithms."
              />
            ))}

          {/* Groups */}
          <div className="space-y-4">
            {groups.map((g, i) => (
              <Panel key={g.algorithm ?? i}>
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div className="flex items-start gap-3">
                    {statusIcon(g.status)}
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-foreground">
                          {g.algorithm ?? "Unknown algorithm"}
                        </span>
                        {urgencyBadge(g.urgency)}
                        <span className="text-xs text-muted-foreground">
                          {g.standard}
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        Deadline:{" "}
                        <span className="text-state-attn font-medium">
                          {g.deadline
                            ? new Date(g.deadline).toLocaleDateString()
                            : "—"}
                        </span>
                        {" · "}Recommended:{" "}
                        <span className="text-primary">
                          {g.recommended_replacement ?? "—"}
                        </span>
                      </p>
                      {(g.fingerprints?.length ?? 0) > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {g.fingerprints!.slice(0, 5).map((fp) => (
                            <Link
                              key={fp}
                              to={`/certificates/${fp}`}
                              className="font-mono text-[10px] text-muted-foreground bg-muted rounded px-1.5 py-0.5 truncate max-w-[140px] hover:text-primary"
                            >
                              {fp}
                            </Link>
                          ))}
                          {g.fingerprints!.length > 5 && (
                            <Link
                              to={`/certificates?q=${encodeURIComponent(g.algorithm ?? "")}`}
                              className="text-xs text-primary hover:underline"
                            >
                              +{g.fingerprints!.length - 5} more — search the
                              inventory
                            </Link>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <div
                      className={`text-4xl font-black ${g.urgency === "immediate" ? "text-state-over" : g.urgency === "high" ? "text-state-attn" : "text-foreground"}`}
                    >
                      {g.count ?? 0}
                    </div>
                    <div className="text-xs text-muted-foreground">certificates</div>
                  </div>
                </div>
              </Panel>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
