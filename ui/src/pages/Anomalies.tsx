import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { fetchJSON } from "../lib/api";
import { Badge, Panel, StateMessage } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { useCaNames } from "../lib/useResourceNames";

// Wire shapes verified against internal/bootstrap (AnomalyFinding,
// PendingAction, anomalyParams). openapi.yaml leaves both bodies untyped.
type AnomalyFinding = {
  kind: string;
  severity: string;
  detail: string;
  evidence: string[];
  at: string;
};
type AnomalyReport = { findings: AnomalyFinding[]; scanned_at?: string };

type BlastRadius = { cas?: number; templates?: number; certificates?: number };
type Remediation = {
  id: string;
  action_type: string;
  status: string;
  proposed_by: string;
  rationale?: string;
  created_at: string;
  params?: { finding_kind?: string; blast_radius?: BlastRadius; truncated?: boolean };
};

const kindLabel: Record<string, string> = {
  volume_spike: "Volume spike",
  subject_churn: "Subject churn",
  requester_burst: "Requester burst",
};

const actionLabel: Record<string, string> = {
  "anomaly.suspend_ca": "Suspend CA",
  "anomaly.reactivate_ca": "Reactivate CA",
  "anomaly.disable_template": "Disable template",
  "anomaly.enable_template": "Enable template",
  "anomaly.revoke_batch": "Revoke recent certificates",
};

function severityTone(s: string): "danger" | "warning" | "neutral" {
  const v = s.toLowerCase();
  if (v === "high" || v === "critical") return "danger";
  if (v === "medium") return "warning";
  return "neutral";
}

// A remediation has only run once the queue's executor finished: status
// "approved". Everything else must not read as if something changed.
function statusView(status: string): {
  label: string;
  tone: "warning" | "success" | "danger" | "neutral" | "info";
} {
  switch (status) {
    case "pending":
      return { label: "Proposed - awaiting approval", tone: "warning" };
    case "executing":
      return { label: "Approved - executing", tone: "info" };
    case "approved":
      return { label: "Approved and executed", tone: "success" };
    case "rejected":
      return { label: "Rejected - nothing changed", tone: "neutral" };
    case "failed":
      return { label: "Approved but failed - not applied", tone: "danger" };
    default:
      return { label: status, tone: "neutral" };
  }
}

function blastText(b?: BlastRadius): string {
  if (!b) return "not recorded";
  return `${b.cas ?? 0} CA(s), ${b.templates ?? 0} template(s), ${b.certificates ?? 0} certificate(s)`;
}

function RemediationRow({ r }: { r: Remediation }) {
  const sv = statusView(r.status);
  return (
    <li className="rounded-xl border border-border bg-background/60 p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-foreground">
          {actionLabel[r.action_type] ?? r.action_type}
        </span>
        <Badge tone={sv.tone}>{sv.label}</Badge>
        {r.status === "pending" ? (
          <Link
            className="text-primary underline"
            to={`/inbox?focus=pending_action:${encodeURIComponent(r.id)}`}
          >
            Review in Approvals
          </Link>
        ) : null}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        Blast radius if approved: {blastText(r.params?.blast_radius)}
        {r.params?.truncated ? " (truncated to the first 100)" : ""} &middot; proposed by{" "}
        {r.proposed_by}
      </div>
      {r.rationale ? (
        <div className="mt-1 text-xs text-muted-foreground">{r.rationale}</div>
      ) : null}
    </li>
  );
}

// Findings embed raw CA ids in both the sentence and the evidence list; swap in the CA's name.
function withCaNames(text: string, caNames: Map<string, string>): string {
  let out = text;
  for (const [id, name] of caNames) out = out.split(id).join(name);
  return out;
}

export default function Anomalies() {
  const { names: caNames } = useCaNames();
  const report = useQuery({
    queryKey: ["anomalies"],
    queryFn: () => fetchJSON<{ data: AnomalyReport }>("/reports/anomalies"),
    refetchInterval: 60_000,
  });
  const remediations = useQuery({
    queryKey: ["anomaly-remediations"],
    queryFn: () => fetchJSON<{ data: Remediation[] }>("/anomalies/remediations"),
    refetchInterval: 60_000,
  });

  const findings = report.data?.data.findings ?? [];
  const scannedAt = report.data?.data.scanned_at;
  const proposals = remediations.data?.data ?? [];

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Reliability"
        title="Issuance anomalies"
        description="Unusual issuance patterns from the latest scan. Remediations are only ever proposed; a second person approves them."
      />
      <p className="text-sm text-muted-foreground">
        {scannedAt
          ? `Last scan: ${new Date(scannedAt).toLocaleString()}`
          : "No scan has completed yet"}
      </p>

      <Panel title="Findings" subtitle="Latest scheduled scan">
        {report.isLoading ? (
          <StateMessage title="Loading" message="Fetching anomaly findings..." />
        ) : report.error ? (
          <StateMessage tone="error" title="Unavailable" message="Could not load anomaly findings." />
        ) : findings.length === 0 && !scannedAt ? (
          <StateMessage title="No scan yet" message="Findings appear once the first scheduled scan completes." />
        ) : findings.length === 0 ? (
          <StateMessage title="No anomalies" message="The latest scan found nothing unusual." />
        ) : (
          <div className="space-y-3">
            {findings.map((f, i) => {
              const related = proposals.filter((p) => p.params?.finding_kind === f.kind);
              return (
                <div
                  key={`${f.kind}:${f.evidence[0] ?? ""}:${i}`}
                  className="rounded-2xl border border-border bg-background/60 p-4"
                  data-testid="anomaly-finding"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone="info">{kindLabel[f.kind] ?? f.kind}</Badge>
                    <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>
                    <span className="text-xs text-muted-foreground">
                      {new Date(f.at).toLocaleString()}
                    </span>
                  </div>
                  <p className="mt-2 text-sm text-foreground">{withCaNames(f.detail, caNames)}</p>
                  {f.evidence.some((e) => e.trim() !== "") ? (
                    <ul className="mt-2 list-disc pl-5 text-xs text-muted-foreground">
                      {f.evidence
                        .filter((e) => e.trim() !== "")
                        .map((e, j) => (
                          <li key={j}>{withCaNames(e, caNames)}</li>
                        ))}
                    </ul>
                  ) : null}
                  <div className="mt-3 text-sm">
                    {remediations.error ? (
                      <span className="text-muted-foreground">Remediation status unavailable</span>
                    ) : related.length === 0 ? (
                      <span className="text-muted-foreground">No remediation proposed</span>
                    ) : (
                      <ul className="space-y-2">
                        {related.map((r) => (
                          <RemediationRow key={r.id} r={r} />
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Panel>

      <Panel
        title="Proposed remediations"
        subtitle="Nothing is applied until a different approver approves it in the Approvals inbox"
      >
        {remediations.isLoading ? (
          <StateMessage title="Loading" message="Fetching remediation proposals..." />
        ) : remediations.error ? (
          <StateMessage
            tone="error"
            title="Unavailable"
            message="Could not load remediation proposals (your role may not read them)."
          />
        ) : proposals.length === 0 ? (
          <StateMessage title="None proposed" message="No remediation has been proposed." />
        ) : (
          <ul className="space-y-2">
            {proposals.map((r) => (
              <RemediationRow key={r.id} r={r} />
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
