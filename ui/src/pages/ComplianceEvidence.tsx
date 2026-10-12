import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, AlertTriangle, XCircle, Download } from "lucide-react";
import { toast } from "sonner";
import { api, downloadAuthedFile } from "../lib/api";
import { Button, Panel, Select, StateMessage } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { ReportSkeleton } from "../components/Skeletons";

type Control = {
  id: string;
  framework: string;
  title: string;
  status: string;
  evidence: string;
  remediation?: string;
};
type ComplianceData = {
  generated_at: string;
  framework: string;
  controls: Control[];
  summary: { pass: number; warn: number; fail: number };
};

function StatusIcon({ status }: { status: string }) {
  if (status === "pass")
    return <CheckCircle2 size={15} className="text-state-auto shrink-0" />;
  if (status === "warn")
    return <AlertTriangle size={15} className="text-state-attn shrink-0" />;
  return <XCircle size={15} className="text-state-over shrink-0" />;
}

const FRAMEWORK_LABELS: Record<string, string> = {
  all: "All Frameworks",
  soc2: "SOC 2",
  pci: "PCI DSS 4.0.1",
  nist: "NIST SP 800-57",
  dora: "DORA",
  nis2: "NIS2",
};

export default function ComplianceEvidence() {
  const [framework, setFramework] = useState("all");
  const q = useQuery({
    queryKey: ["report-compliance-evidence", framework],
    queryFn: () =>
      api.complianceEvidence(framework === "all" ? undefined : framework),
  });
  const report = q.data?.data as ComplianceData | undefined;

  const scorePercent = report
    ? Math.round(
        (report.summary.pass / Math.max(1, report.controls.length)) * 100,
      )
    : 0;

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto fade-in-up">
      <PageHeader
        eyebrow="Reports"
        title="Compliance Evidence"
        description="SOC 2 · PCI DSS 4.0.1 · NIST SP 800-57 mapped to your cert posture."
        actions={
          <div className="flex items-center gap-2">
            <Select
              className="w-48"
              value={framework}
              onChange={(e) => setFramework(e.target.value)}
            >
              {Object.entries(FRAMEWORK_LABELS).map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </Select>
            <Button
              tone="primary"
              onClick={() =>
                void downloadAuthedFile(
                  `/reports/compliance-evidence?format=pdf${framework !== "all" ? `&framework=${framework}` : ""}`,
                  `evidence-${framework}.pdf`,
                ).catch((err: Error) => toast.error(err.message))
              }
            >
              <Download size={13} aria-hidden="true" />
              Evidence pack (PDF)
            </Button>
          </div>
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
          {/* Score */}
          <div className="glass rounded-2xl p-6 gradient-border flex items-center gap-6">
            {/* Ring */}
            <div className="relative w-24 h-24 shrink-0">
              <svg viewBox="0 0 36 36" className="w-24 h-24 -rotate-90">
                <circle
                  cx="18"
                  cy="18"
                  r="15.9"
                  fill="none"
                  stroke="#1e293b"
                  strokeWidth="3.5"
                />
                <circle
                  cx="18"
                  cy="18"
                  r="15.9"
                  fill="none"
                  stroke={
                    scorePercent >= 80
                      ? "#34d399"
                      : scorePercent >= 50
                        ? "#fbbf24"
                        : "#f87171"
                  }
                  strokeWidth="3.5"
                  strokeDasharray={`${scorePercent} ${100 - scorePercent}`}
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-xl font-black text-foreground">
                  {scorePercent}%
                </span>
              </div>
            </div>
            <div>
              <div className="text-lg font-bold text-foreground">
                Compliance Score
              </div>
              <div className="text-sm text-muted-foreground mt-1">
                {FRAMEWORK_LABELS[framework]}
              </div>
              <div className="flex gap-4 mt-3">
                <div className="text-center">
                  <div className="text-xl font-bold text-state-auto">
                    {report.summary.pass}
                  </div>
                  <div className="text-xs text-muted-foreground">Pass</div>
                </div>
                <div className="text-center">
                  <div className="text-xl font-bold text-state-attn">
                    {report.summary.warn}
                  </div>
                  <div className="text-xs text-muted-foreground">Warn</div>
                </div>
                <div className="text-center">
                  <div className="text-xl font-bold text-state-over">
                    {report.summary.fail}
                  </div>
                  <div className="text-xs text-muted-foreground">Fail</div>
                </div>
              </div>
            </div>
          </div>

          {/* Controls */}
          <Panel title="Controls">
            <div className="space-y-3">
              {report.controls.map((ctrl) => (
                <div
                  key={ctrl.id}
                  className={`rounded-xl border p-4 transition ${
                    ctrl.status === "pass"
                      ? "border-state-auto/50 bg-state-auto/10"
                      : ctrl.status === "warn"
                        ? "border-state-attn/50 bg-state-attn/10"
                        : "border-state-over/50 bg-state-over/10"
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <StatusIcon status={ctrl.status} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-xs text-muted-foreground">
                          {ctrl.id}
                        </span>
                        <span className="text-xs text-muted-foreground bg-muted rounded px-1.5 py-0.5">
                          {ctrl.framework}
                        </span>
                      </div>
                      <p className="text-sm font-semibold text-foreground mt-0.5">
                        {ctrl.title}
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {ctrl.evidence}
                      </p>
                      {ctrl.remediation && (
                        <p className="text-xs text-state-attn mt-1.5 font-medium">
                          → {ctrl.remediation}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}
