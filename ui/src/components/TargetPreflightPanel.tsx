import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type PreflightRow } from "../lib/api";
import { Badge, Button } from "./ui";

const LABELS: Record<string, string> = {
  ssh_auth: "SSH login",
  sudo_present: "sudo installed",
  requiretty: "sudo without a tty",
  nopasswd: "sudo without a password",
  password: "stored sudo password accepted",
  helper_present: "helper installed",
  helper_sha: "helper hash matches the pin",
  helper_sudo: "sudo rule for the helper",
  privilege: "privilege mode",
};

function labelFor(capability: string): string {
  if (LABELS[capability]) return LABELS[capability];
  if (capability.startsWith("command:")) return `command ${capability.slice(8)}`;
  if (capability.startsWith("verb:")) return `helper verb ${capability.slice(5)}`;
  return capability;
}

function tone(status: PreflightRow["status"]): "success" | "danger" | "neutral" {
  return status === "ok" ? "success" : status === "fail" ? "danger" : "neutral";
}

// Test credential for an ssh target (W34-15): one row per capability with the
// fix line inline, so a red requiretty row shows the exact Defaults line.
export function TargetPreflightPanel({ targetId }: { targetId: string }) {
  const qc = useQueryClient();
  const last = useQuery({
    queryKey: ["target-preflight", targetId],
    queryFn: () => api.targetPreflight(targetId),
    retry: false,
  });
  const run = useMutation({
    mutationFn: () => api.preflightTarget(targetId),
    onSuccess: (res) => qc.setQueryData(["target-preflight", targetId], res),
  });
  const report = run.data?.data ?? last.data?.data;

  return (
    <div className="space-y-2" data-testid="target-preflight">
      <Button tone="secondary" disabled={run.isPending} onClick={() => run.mutate()}>
        {run.isPending ? "Testing…" : "Test credential"}
      </Button>
      {run.isError && (
        <p className="text-sm text-state-over" role="alert">
          {run.error instanceof Error ? run.error.message : "Preflight failed"}
        </p>
      )}
      {report && (
        <div className="space-y-1 rounded-lg border border-border bg-muted/30 p-3 text-sm">
          <p className="text-xs text-muted-foreground">
            Checked {report.checked_at} with sudo mode {report.mode}
            {report.roles?.length ? ` (${report.roles.join(", ")})` : ""}.
          </p>
          <ul className="space-y-1">
            {report.rows.map((row) => (
              <li key={row.capability} className="space-y-0.5">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={tone(row.status)}>{row.status}</Badge>
                  <span>{labelFor(row.capability)}</span>
                </div>
                {row.status === "fail" && row.detail ? (
                  <p className="pl-1 text-xs text-muted-foreground">{row.detail}</p>
                ) : null}
                {row.status === "fail" && row.fix ? (
                  <p className="pl-1 text-xs">
                    Fix: <code className="font-mono">{row.fix}</code>
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
