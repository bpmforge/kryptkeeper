import { useState } from "react";
import { scrollableProps } from "../lib/scrollable";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, X, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { api } from "../lib/api";
import { canDecidePendingActions, useAuthz } from "../lib/auth";
import type { PendingAction } from "../lib/models";
import { Badge, Button, Panel, Select, StateMessage } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { CapabilityList } from "../components/PluginCapabilities";
import { tierLabel, tierTone } from "../lib/plugins";
import {
  BlastRadiusImpact,
  approveEnabled,
  impactForPendingAction,
  type ImpactState,
} from "../components/BlastRadiusImpact";

// PluginEnableReview shows an approver exactly what enabling this plugin
// version allows, in the same fixed wording the installer saw (W20-21).
function PluginEnableReview({ params }: { params: unknown }) {
  const p = (params ?? {}) as {
    plugin_id?: string;
    version?: string;
    sha256?: string;
  };
  const q = useQuery({
    queryKey: ["delivery-plugins"],
    queryFn: api.deliveryPlugins,
    retry: false,
  });
  const version = q.data?.data
    ?.find((x) => x.id === p.plugin_id)
    ?.versions.find((v) => v.version === p.version);
  return (
    <div className="mt-2 space-y-2 rounded-lg border border-border bg-background/40 p-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="font-medium text-foreground">
          Enable delivery plugin {p.plugin_id} {p.version}
        </span>
        {version ? (
          <>
            <Badge tone={tierTone(version.capability_tier)}>
              {tierLabel(version.capability_tier)} capabilities
            </Badge>
            <Badge tone="info">Trust: {version.trust_tier}</Badge>
          </>
        ) : null}
      </div>
      {version && version.sha256 === p.sha256 ? (
        <CapabilityList manifest={version.manifest} />
      ) : (
        <p className="text-xs text-muted-foreground">
          {q.isLoading
            ? "Loading the plugin's capabilities…"
            : "The plugin version could not be shown; check Delivery Plugins."}
        </p>
      )}
    </div>
  );
}

function statusTone(
  s: PendingAction["status"],
): "warning" | "success" | "danger" | "neutral" {
  switch (s) {
    case "pending":
      return "warning";
    case "approved":
      return "success";
    case "rejected":
      return "neutral";
    default:
      return "danger";
  }
}

export default function PendingActions() {
  const authz = useAuthz();
  const role = authz.data?.role;
  const mayDecide = canDecidePendingActions(role);
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("");
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["pending-actions", statusFilter],
    queryFn: () => api.pendingActions(statusFilter || undefined),
    staleTime: 15_000,
  });
  const actions: PendingAction[] = data?.data ?? [];

  const [rejecting, setRejecting] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [impactState, setImpactState] = useState<Record<string, ImpactState>>(
    {},
  );

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["pending-actions"] });

  const approveMutation = useMutation({
    // pqc_migrate_wave actions are decided on their dedicated route — the
    // generic approve endpoint's executor has no case for them and answers
    // "unknown action type".
    mutationFn: (action: PendingAction) => {
      if (action.action_type === "pqc_migrate_wave") {
        const waveId = (action.params as { wave_id?: string } | null)?.wave_id;
        if (!waveId) {
          return Promise.reject(
            new Error("This migrate-wave action carries no wave_id."),
          );
        }
        return api.approvePqcWaveExecute(waveId, action.id);
      }
      return api.approvePendingAction(action.id);
    },
    onSuccess: invalidate,
  });
  const rejectMutation = useMutation({
    mutationFn: ({ id, r }: { id: string; r: string }) =>
      api.rejectPendingAction(id, r),
    onSuccess: async () => {
      setRejecting(null);
      setReason("");
      await invalidate();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Automation"
        title="Pending Actions"
        description="AI-proposed changes awaiting human approval — the AI proposes, you approve, the audit log records both."
        actions={
          <div className="flex items-center gap-2">
            <Select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="">All statuses</option>
              <option value="pending">Pending</option>
              <option value="approved">Approved</option>
              <option value="rejected">Rejected</option>
              <option value="failed">Failed</option>
            </Select>
            <Button
              tone="secondary"
              onClick={() => refetch()}
              disabled={isFetching}
            >
              <RefreshCw size={13} aria-hidden="true" />
              Refresh
            </Button>
          </div>
        }
      />

      {approveMutation.isError ? (
        <StateMessage
          tone="error"
          title="Approval failed"
          message={
            approveMutation.error instanceof Error
              ? approveMutation.error.message
              : "The action could not be executed."
          }
        />
      ) : null}

      <Panel title="Proposed actions">
        {isLoading ? (
          <StateMessage title="Loading" message="Fetching pending actions…" />
        ) : error ? (
          <StateMessage
            tone="error"
            title="Unavailable"
            message="Pending actions could not be loaded."
          />
        ) : actions.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Nothing proposed. AI-suggested changes (e.g. “revoke everything CA-7
            signed”) appear here for approval.
          </p>
        ) : (
          <div className="space-y-3">
            {actions.map((a) => {
              const imp =
                a.status === "pending" ? impactForPendingAction(a) : null;
              const gated = !approveEnabled(imp !== null, impactState[a.id]);
              const selfApprove = authz.data?.principal === a.proposed_by;
              return (
                <div
                  key={a.id}
                  className="rounded-xl border border-border bg-card/40 p-3"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <Badge tone="info">{a.action_type}</Badge>
                      <Badge tone={statusTone(a.status)}>{a.status}</Badge>
                      <span className="text-xs text-muted-foreground">
                        by {a.proposed_by}
                      </span>
                    </div>
                    {a.status === "pending" ? (
                      <div className="flex items-center gap-2">
                        <span
                          title={
                            !mayDecide
                              ? `Your role (${role}) cannot approve or reject pending actions; that needs pki-admin or pki-operator.`
                              : selfApprove
                              ? "You proposed this action — a second person must approve it."
                              : gated
                                ? "Waiting for the blast-radius preview"
                                : undefined
                          }
                        >
                          <Button
                            tone="primary"
                            onClick={() => approveMutation.mutate(a)}
                            disabled={
                              approveMutation.isPending || selfApprove || gated || !mayDecide
                            }
                          >
                            <Check size={13} aria-hidden="true" />
                            Approve
                          </Button>
                        </span>
                        <span
                          title={
                            mayDecide
                              ? undefined
                              : `Your role (${role}) cannot approve or reject pending actions.`
                          }
                        >
                          <Button
                            tone="danger"
                            onClick={() => setRejecting(a.id)}
                            disabled={rejectMutation.isPending || !mayDecide}
                          >
                            <X size={13} aria-hidden="true" />
                            Reject
                          </Button>
                        </span>
                      </div>
                    ) : null}
                  </div>
                  {a.rationale ? (
                    <p className="mt-2 text-sm text-foreground">
                      {a.rationale}
                    </p>
                  ) : null}
                  {a.action_type === "delivery_plugin.enable" ? (
                    <PluginEnableReview params={a.params} />
                  ) : null}
                  {imp ? (
                    <div className="mt-2">
                      <BlastRadiusImpact
                        {...imp}
                        onStateChange={(s) =>
                          setImpactState((m) =>
                            m[a.id] === s ? m : { ...m, [a.id]: s },
                          )
                        }
                      />
                    </div>
                  ) : null}
                  <pre className="mt-2 overflow-x-auto rounded-lg bg-background/60 p-2 text-xs text-muted-foreground" {...scrollableProps}>
                    {JSON.stringify(a.params, null, 2)}
                  </pre>
                  {a.result ? (
                    <div className="mt-1 text-xs text-state-auto">
                      Result: {JSON.stringify(a.result)}
                    </div>
                  ) : null}

                  {rejecting === a.id ? (
                    <div className="mt-2 flex items-center gap-2">
                      <input
                        className="flex-1 rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground"
                        placeholder="Reason for rejection"
                        value={reason}
                        onChange={(e) => setReason(e.target.value)}
                      />
                      <Button
                        tone="danger"
                        onClick={() =>
                          rejectMutation.mutate({ id: a.id, r: reason })
                        }
                        disabled={rejectMutation.isPending}
                      >
                        Confirm reject
                      </Button>
                      <Button
                        tone="secondary"
                        onClick={() => setRejecting(null)}
                      >
                        Cancel
                      </Button>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
      </Panel>
    </div>
  );
}
