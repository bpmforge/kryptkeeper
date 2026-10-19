import { useQuery } from "@tanstack/react-query";
import { scrollableProps } from "../lib/scrollable";
import { Link } from "react-router-dom";
import { CheckCircle2, AlertTriangle, XCircle, Clock } from "lucide-react";
import { api } from "../lib/api";
import { Badge, Panel, StateMessage, formatDateTime } from "../components/ui";
import { humanizeEnum } from "../lib/utils";
import { PageHeader } from "../components/PageHeader";
import { ReportSkeleton } from "../components/Skeletons";

type CAEntry = {
  id: string;
  name: string;
  status: string;
  algorithm: string;
  expires_at: string;
  days_until_expiry: number;
  algorithm_strength: string;
};
type CAHealthData = {
  generated_at: string;
  total_cas: number;
  items: CAEntry[];
  summary: {
    active: number;
    expiring_90d: number;
    expiring_1yr: number;
    weak_algorithm: number;
    sunset_algorithm: number;
  };
};

function strengthBadge(s: string) {
  if (s === "strong") return <Badge tone="success">Strong</Badge>;
  if (s === "acceptable") return <Badge tone="info">Acceptable</Badge>;
  if (s === "weak") return <Badge tone="danger">Weak</Badge>;
  if (s === "sunset") return <Badge tone="warning">Sunset 2030</Badge>;
  return <Badge>{s}</Badge>;
}

export default function CAHealth() {
  const q = useQuery({ queryKey: ["report-ca-health"], queryFn: api.caHealth });
  const report = q.data?.data as CAHealthData | undefined;

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto fade-in-up">
      <PageHeader
        eyebrow="Reports"
        title="CA Health"
        description="Certificate Authority expiry, algorithm strength, and chain status."
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
          {/* Summary tiles */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              {
                label: "Active CAs",
                value: report.summary.active,
                icon: CheckCircle2,
                cls: "text-state-auto",
              },
              {
                label: "Expiring <90d",
                value: report.summary.expiring_90d,
                icon: AlertTriangle,
                cls: "text-state-over",
              },
              {
                label: "Expiring <1yr",
                value: report.summary.expiring_1yr,
                icon: Clock,
                cls: "text-state-attn",
              },
              {
                label: "Weak Algorithm",
                value:
                  report.summary.weak_algorithm +
                  report.summary.sunset_algorithm,
                icon: XCircle,
                cls: "text-state-over",
              },
            ].map(({ label, value, icon: Icon, cls }) => (
              <div
                key={label}
                className="glass rounded-2xl p-4 gradient-border"
              >
                <div className="flex items-center gap-2 mb-2">
                  <Icon size={14} className={value === 0 ? "text-muted-foreground" : cls} />
                  <span className="text-xs text-muted-foreground uppercase tracking-widest">
                    {label}
                  </span>
                </div>
                <div className={`text-3xl font-bold ${value === 0 ? "text-foreground" : cls}`}>{value}</div>
              </div>
            ))}
          </div>

          {/* CA table */}
          <Panel
            title="Certificate Authorities"
            subtitle={`${report.total_cas} CAs · Generated ${formatDateTime(report.generated_at)}`}
          >
            <div className="overflow-x-auto" {...scrollableProps}>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left">
                    {[
                      "Name",
                      "Status",
                      "Algorithm",
                      "Strength",
                      "Expires",
                      "Days Left",
                    ].map((h) => (
                      <th
                        key={h}
                        className="pb-3 pr-4 text-xs font-semibold uppercase tracking-widest text-muted-foreground"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {report.items.map((ca) => (
                    <tr
                      key={ca.id}
                      className="hover:bg-foreground/[0.02] transition"
                    >
                      <td className="py-3 pr-4 font-medium text-foreground">
                        <Link
                          to={`/certificates?ca_id=${encodeURIComponent(ca.id)}`}
                          className="hover:text-primary hover:underline"
                        >
                          {ca.name}
                        </Link>
                      </td>
                      <td className="py-3 pr-4">
                        <Badge
                          tone={
                            ca.status === "active"
                              ? "success"
                              : ca.status === "revoked"
                                ? "danger"
                                : "warning"
                          }
                        >
                          {humanizeEnum(ca.status)}
                        </Badge>
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs text-foreground">
                        {ca.algorithm || "—"}
                      </td>
                      <td className="py-3 pr-4">
                        {strengthBadge(ca.algorithm_strength)}
                      </td>
                      <td className="py-3 pr-4 text-muted-foreground text-xs whitespace-nowrap">
                        {ca.expires_at
                          ? formatDateTime(ca.expires_at)
                          : "—"}
                      </td>
                      <td className="py-3 pr-4">
                        <span
                          className={`font-semibold text-sm ${
                            ca.days_until_expiry < 90
                              ? "text-state-over"
                              : ca.days_until_expiry < 365
                                ? "text-state-attn"
                                : "text-state-auto"
                          }`}
                        >
                          {ca.days_until_expiry > 0
                            ? `${ca.days_until_expiry}d`
                            : "Expired"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}
