import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { scrollableProps } from "../lib/scrollable";
import { useState } from "react";
import { Link } from "react-router-dom";
import { RefreshCw } from "lucide-react";
import { api } from "../lib/api";
import {
  Badge,
  Button,
  MetricCard,
  Panel,
  StateMessage,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { canManageCertificates, useAuthz } from "../lib/auth";
import type { FailedRenewal } from "../lib/models";

function fmtTime(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function fmtDuration(secs: number): string {
  if (secs <= 0) return "—";
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  return `${(secs / 3600).toFixed(1)}h`;
}

function RenewalSchedulerPanel() {
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["renewal-scheduler-status"],
    queryFn: api.renewalSchedulerStatus,
    staleTime: 30_000,
  });

  const status = data?.data?.status;
  // has_run distinguishes "the scheduler has not completed a scan yet"
  // from "the scheduler is stopped" — a zero-valued status with a red
  // Stopped badge on a fresh install read as a failure.
  const hasRun = data?.data?.has_run ?? false;

  return (
    <Panel
      title="Renewal Scheduler"
      subtitle="Daily scan for certificates approaching expiry"
    >
      <div className="mb-4 flex items-center justify-between">
        <Link to="/reports/slo" className="text-sm text-primary underline">
          Open SLO dashboard
        </Link>
        <Button
          tone="secondary"
          onClick={() => refetch()}
          disabled={isFetching}
        >
          <RefreshCw size={13} aria-hidden="true" />
          Refresh
        </Button>
      </div>
      {isLoading ? (
        <StateMessage title="Loading" message="Fetching scheduler status…" />
      ) : error || !status ? (
        <StateMessage
          tone="error"
          title="Status unavailable"
          message="The renewal scheduler status could not be loaded."
        />
      ) : (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">State</span>
            <Badge
              tone={status.running ? "success" : hasRun ? "danger" : "neutral"}
            >
              {status.running ? "Running" : hasRun ? "Stopped" : "Not started"}
            </Badge>
          </div>

          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <MetricCard
              label="Renewal threshold"
              value={`${status.threshold_days}d`}
              hint="trigger window before expiry"
            />
            <MetricCard
              label="Scan interval"
              value={`${status.poll_interval_hours}h`}
            />
            <MetricCard
              label="Last scan"
              value={status.last_run_at ? fmtTime(status.last_run_at) : "—"}
            />
            <MetricCard
              label="Next scan"
              value={status.next_run_at ? fmtTime(status.next_run_at) : "—"}
            />
          </div>

          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <MetricCard
              label="Candidates (last)"
              value={status.last_candidates}
              hint="certs within threshold"
            />
            <MetricCard
              label="Auto-renew triggers"
              value={status.last_auto_renew_triggers}
              tone={status.last_auto_renew_triggers > 0 ? "success" : "neutral"}
            />
            <MetricCard
              label="Notifications sent"
              value={status.last_notifications}
            />
            <MetricCard
              label="Expired (skipped)"
              value={status.last_expired_skipped}
              tone={status.last_expired_skipped > 0 ? "warning" : "neutral"}
            />
          </div>

          {!status.last_run_at ? (
            <p className="text-sm text-muted-foreground">
              No scan has completed yet. The first scan runs at startup and then
              every {status.poll_interval_hours} hours.
            </p>
          ) : null}
        </div>
      )}
    </Panel>
  );
}

const FAILURE_TYPES: Record<
  string,
  { label: string; tone: "danger" | "warning" | "neutral" }
> = {
  execute_failure: { label: "Execute failure", tone: "danger" },
  notification_dead_letter: {
    label: "Notification dead letter",
    tone: "warning",
  },
  agent_result: { label: "Agent result", tone: "neutral" },
};

function FailedRenewalRow({
  f,
  canRetry,
}: {
  f: FailedRenewal;
  canRetry: boolean;
}) {
  const queryClient = useQueryClient();
  const [queued, setQueued] = useState(false);
  const retry = useMutation({
    mutationFn: () => api.renewalRetry(f.fingerprint),
    onSuccess: () => {
      setQueued(true);
      void queryClient.invalidateQueries({ queryKey: ["renewal-slo"] });
    },
  });
  const kind =
    FAILURE_TYPES[f.type ?? "agent_result"] ?? FAILURE_TYPES.agent_result;
  return (
    <tr className="border-b border-border">
      <td className="py-2 pr-4 font-mono text-xs text-foreground">
        {f.fingerprint.slice(0, 16) || "—"}
      </td>
      <td className="py-2 pr-4">
        <Badge tone={kind.tone}>{kind.label}</Badge>
      </td>
      <td className="py-2 pr-4 text-muted-foreground">
        {f.attempt ? `${f.attempt}/${f.max_attempts ?? "?"}` : "—"}
        {f.gave_up ? (
          <span className="ml-1 text-xs text-state-attn">gave up</span>
        ) : null}
      </td>
      <td className="py-2 pr-4">
        <Badge tone="danger">{f.outcome || "failed"}</Badge>
        {f.rolled_back ? (
          <span className="ml-1 text-xs text-state-attn">rolled back</span>
        ) : null}
      </td>
      <td className="py-2 pr-4 text-muted-foreground">{f.detail || "—"}</td>
      <td className="py-2 pr-4 text-muted-foreground">
        {fmtTime(f.reported_at)}
      </td>
      <td className="py-2 pr-4 text-muted-foreground">
        {fmtTime(f.next_attempt_at)}
      </td>
      <td className="py-2 pr-4">
        {canRetry && f.type === "execute_failure" ? (
          queued ? (
            <Badge tone="neutral">Retry queued</Badge>
          ) : (
            <>
              <Button
                tone="secondary"
                aria-label={`Retry renewal ${f.fingerprint.slice(0, 12)}`}
                disabled={retry.isPending}
                onClick={() => retry.mutate()}
              >
                Retry
              </Button>
              {retry.error ? (
                <div className="mt-1 text-xs text-state-over">
                  {retry.error instanceof Error
                    ? retry.error.message
                    : "Retry failed"}
                </div>
              ) : null}
            </>
          )
        ) : (
          "—"
        )}
      </td>
    </tr>
  );
}

function RenewalAutopilotPanel() {
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["renewal-slo"],
    queryFn: api.renewalSLO,
    staleTime: 30_000,
  });

  const slo = data?.data;
  const authz = useAuthz();
  const canRetry = canManageCertificates(authz.data?.role, authz.data?.scopes);

  return (
    <Panel
      title="Renewal Autopilot"
      subtitle="Agent-driven install + verify across the fleet"
    >
      <div className="mb-4 flex justify-end">
        <Button
          tone="secondary"
          onClick={() => refetch()}
          disabled={isFetching}
        >
          <RefreshCw size={13} aria-hidden="true" />
          Refresh
        </Button>
      </div>
      {isLoading ? (
        <StateMessage title="Loading" message="Fetching autopilot SLO…" />
      ) : error || !slo ? (
        <StateMessage
          tone="error"
          title="SLO unavailable"
          message="The renewal autopilot SLO could not be loaded."
        />
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <MetricCard
              label="Success rate"
              value={`${slo.success_rate_percent}%`}
              hint={`${slo.total_renewals} renewals`}
              tone={
                slo.total_renewals === 0
                  ? "neutral"
                  : slo.success_rate_percent >= 95
                    ? "success"
                    : slo.success_rate_percent >= 80
                      ? "warning"
                      : "danger"
              }
            />
            <MetricCard
              label="Mean time to renew"
              value={fmtDuration(slo.mean_time_to_renew_secs)}
              hint={`${slo.mttr_samples} samples`}
            />
            <MetricCard
              label="Endpoints managed"
              value={slo.endpoints_managed}
            />
            <MetricCard
              label="Agents"
              value={`${slo.agents_active}/${slo.agents_total}`}
              hint="active / total"
            />
          </div>

          {slo.queue ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                <MetricCard label="Queue depth" value={slo.queue.depth} />
                <MetricCard
                  label="Drain ETA"
                  value={
                    slo.queue.eta_known === false
                      ? "—"
                      : fmtDuration(slo.queue.eta_seconds)
                  }
                />
              </div>
              {slo.queue.connector_budgets.length > 0 ? (
                <div className="overflow-x-auto" {...scrollableProps}>
                  <table className="w-full text-sm">
                    <caption className="sr-only">Connector budgets</caption>
                    <thead>
                      <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                        <th scope="col" className="py-2 pr-4">
                          Connector
                        </th>
                        <th scope="col" className="py-2 pr-4">
                          In flight
                        </th>
                        <th scope="col" className="py-2 pr-4">
                          Daily
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {slo.queue.connector_budgets.map((b) => (
                        <tr
                          key={b.connector_id}
                          className="border-b border-border"
                        >
                          <td className="py-2 pr-4 font-mono text-xs text-foreground">
                            {b.connector_id}
                          </td>
                          <td className="py-2 pr-4 text-muted-foreground">
                            {`${b.in_flight}/${b.cap}`}
                          </td>
                          <td className="py-2 pr-4 text-muted-foreground">
                            {b.daily_limit
                              ? `${b.daily_used ?? 0}/${b.daily_limit}`
                              : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
            </div>
          ) : null}

          {slo.total_renewals === 0 ? (
            <p className="text-sm text-muted-foreground">
              No autopilot renewals reported yet. Enable the agent's install
              hints and sudoers drop-in to start closing the loop.
            </p>
          ) : null}

          <div>
            <div className="mb-2 text-sm font-medium text-foreground">
              Failed-renewal queue
            </div>
            {slo.failed_renewals.length === 0 ? (
              <p className="text-sm text-state-auto">
                No failed renewals — every install verified.
              </p>
            ) : (
              <div className="overflow-x-auto" {...scrollableProps}>
                <table className="w-full text-sm">
                  <caption className="sr-only">Failed renewals</caption>
                  <thead>
                    <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                      <th scope="col" className="py-2 pr-4">
                        Cert
                      </th>
                      <th scope="col" className="py-2 pr-4">
                        Type
                      </th>
                      <th scope="col" className="py-2 pr-4">
                        Attempt
                      </th>
                      <th scope="col" className="py-2 pr-4">
                        Outcome
                      </th>
                      <th scope="col" className="py-2 pr-4">
                        Reason
                      </th>
                      <th scope="col" className="py-2 pr-4">
                        When
                      </th>
                      <th scope="col" className="py-2 pr-4">
                        Next attempt
                      </th>
                      <th scope="col" className="py-2 pr-4">
                        Action
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {slo.failed_renewals.map((f) => (
                      <FailedRenewalRow
                        key={`${f.type ?? "agent"}-${f.fingerprint}-${f.agent_id}-${f.task_id}-${f.reported_at}`}
                        f={f}
                        canRetry={canRetry}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </Panel>
  );
}

export default function Automation() {
  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="System"
        title="Automation"
        description="Renewal scheduler health and autopilot install/verify SLO."
      />

      <RenewalAutopilotPanel />
      <RenewalSchedulerPanel />
    </div>
  );
}
