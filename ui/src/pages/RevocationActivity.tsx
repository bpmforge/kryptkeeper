import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Badge, Panel, Select, StateMessage } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { ReportSkeleton } from "../components/Skeletons";

type RevokedEntry = {
  fingerprint_sha256: string;
  common_name: string;
  ca_id: string;
  revoked_at: string;
  reason_code: number;
  reason_label: string;
  owner_email?: string;
  owner_team?: string;
};
type RevData = {
  generated_at: string;
  window_days: number;
  total_revoked: number;
  by_reason_code: Record<string, number>;
  by_ca: Record<string, number>;
  recent_revocations: RevokedEntry[];
};

const REASON_LABELS: Record<string, string> = {
  unspecified: "Unspecified",
  keyCompromise: "Key Compromise",
  caCompromise: "CA Compromise",
  affiliationChanged: "Affiliation Changed",
  superseded: "Superseded",
  cessationOfOperation: "Cessation",
  certificateHold: "On Hold",
  privilegeWithdrawn: "Privilege Withdrawn",
  aACompromise: "AA Compromise",
};

export default function RevocationActivity() {
  const [days, setDays] = useState(30);
  const q = useQuery({
    queryKey: ["report-revocation-activity", days],
    queryFn: () => api.revocationActivity(days),
  });
  const report = q.data?.data as RevData | undefined;

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto fade-in-up">
      <PageHeader
        eyebrow="Reports"
        title="Revocation Activity"
        description="What was revoked, whose certificate it was, and why (the revoking actor is in the audit log)."
        actions={
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
        }
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
          <div className="glass rounded-2xl p-5 gradient-border">
            <div className="text-5xl font-black text-state-over count-up">
              {report.total_revoked}
            </div>
            <div className="text-sm text-muted-foreground mt-1">
              revocations in the last {report.window_days} days
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Panel title="By Reason">
              {Object.entries(report.by_reason_code).length === 0 && (
                <p className="text-sm text-muted-foreground">None</p>
              )}
              {Object.entries(report.by_reason_code)
                .sort((a, b) => b[1] - a[1])
                .map(([reason, count]) => (
                  <div
                    key={reason}
                    className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
                  >
                    <span className="text-sm text-foreground">
                      {REASON_LABELS[reason] ?? reason}
                    </span>
                    <span className="text-sm font-bold text-state-over">
                      {count}
                    </span>
                  </div>
                ))}
            </Panel>
            <Panel title="By CA">
              {Object.keys(report.by_ca).length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No revocations in this window.
              </p>
            ) : null}
            {Object.entries(report.by_ca)
                .sort((a, b) => b[1] - a[1])
                .map(([ca, count]) => (
                  <div
                    key={ca}
                    className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
                  >
                    <span className="text-sm text-foreground truncate">
                      {ca}
                    </span>
                    <span className="text-sm font-bold text-state-attn">
                      {count}
                    </span>
                  </div>
                ))}
            </Panel>
          </div>

          <Panel title="Recent Revocations">
            {report.recent_revocations.length === 0 && (
              <StateMessage
                title="No revocations"
                message={`No certificates revoked in the last ${days} days.`}
                tone="success"
              />
            )}
            {report.recent_revocations.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left">
                      {["Common Name", "Reason", "Revoked At", "Owner"].map(
                        (h) => (
                          <th
                            key={h}
                            className="pb-3 pr-4 text-xs font-semibold uppercase tracking-widest text-muted-foreground"
                          >
                            {h}
                          </th>
                        ),
                      )}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {report.recent_revocations.map((r) => (
                      <tr
                        key={r.fingerprint_sha256}
                        className="hover:bg-foreground/[0.02] transition"
                      >
                        <td className="py-3 pr-4 text-foreground">
                          {r.common_name}
                        </td>
                        <td className="py-3 pr-4">
                          <Badge tone="warning">
                            {REASON_LABELS[r.reason_label] ?? r.reason_label}
                          </Badge>
                        </td>
                        <td className="py-3 pr-4 text-muted-foreground text-xs">
                          {new Date(r.revoked_at).toLocaleString()}
                        </td>
                        <td className="py-3 pr-4 text-muted-foreground text-xs">
                          {r.owner_email || r.owner_team || "—"}
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
