import { Link } from "react-router-dom";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Radar, RefreshCw, RotateCcw } from "lucide-react";
import { api, type ManagedTarget } from "../lib/api";
import {
  Badge,
  Button,
  Input,
  Panel,
  Select,
  StateMessage,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { PluginBadge } from "../components/PluginCapabilities";

const RENEWAL_METHOD_OPTIONS = [
  { value: "acme", label: "ACME" },
  { value: "est", label: "EST" },
  { value: "scep", label: "SCEP" },
  { value: "manual", label: "Manual" },
];

function thresholdFieldValue(target: ManagedTarget): string {
  return target.renewal_threshold_days
    ? String(target.renewal_threshold_days)
    : "";
}

function TargetPolicyRow({
  target,
  envDefaultDays,
  onSaved,
}: {
  target: ManagedTarget;
  envDefaultDays?: number;
  onSaved: () => void;
}) {
  const [method, setMethod] = useState(target.renewal_method);
  const [thresholdInput, setThresholdInput] = useState(
    thresholdFieldValue(target),
  );

  // W18-12: a winrm target's discovery is a hub-side scan of the host's
  // certificate stores with its stored credential; the scheduler files
  // one per interval, this files one now.
  const discoverMutation = useMutation({
    mutationFn: () =>
      api.createDiscoveryScan({ scan_type: "winrm", target: target.id }),
  });

  const trimmed = thresholdInput.trim();
  const invalidThreshold = trimmed !== "" && !/^\d+$/.test(trimmed);
  const hasOverride = !!target.renewal_threshold_days;
  const dirty =
    method !== target.renewal_method || trimmed !== thresholdFieldValue(target);

  const saveMutation = useMutation({
    mutationFn: () =>
      api.updateTarget(target.id, {
        renewal_method: method,
        renewal_threshold_days: trimmed === "" ? 0 : Number(trimmed),
      }),
    onSuccess: onSaved,
  });

  const clearMutation = useMutation({
    mutationFn: () =>
      api.updateTarget(target.id, { renewal_threshold_days: 0 }),
    onSuccess: () => {
      setThresholdInput("");
      onSaved();
    },
  });

  return (
    <div className="space-y-2 rounded-xl border border-border bg-card/40 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-sm font-medium text-foreground">
            {target.name}
          </div>
          <div className="text-xs text-muted-foreground">{target.host}</div>
          {target.install_mode === "plugin" && target.plugin_id ? (
            <div className="mt-1">
              <PluginBadge pluginId={target.plugin_id} />
            </div>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {target.discovery_mode === "winrm" ? (
            <Button
              tone="secondary"
              aria-label={`${target.name} discover now`}
              disabled={discoverMutation.isPending}
              onClick={() => discoverMutation.mutate()}
            >
              <Radar size={13} aria-hidden="true" />
              {discoverMutation.isPending
                ? "Starting…"
                : discoverMutation.isSuccess
                  ? "Scan queued"
                  : "Discover now"}
            </Button>
          ) : null}
          <Badge tone={hasOverride ? "info" : "neutral"}>
            {hasOverride
              ? `${target.renewal_threshold_days}d override`
              : `env default${envDefaultDays ? ` (${envDefaultDays}d)` : ""}`}
          </Badge>
        </div>
      </div>
      {discoverMutation.isError ? (
        <p className="text-xs text-state-over">
          {discoverMutation.error instanceof Error
            ? discoverMutation.error.message
            : "Discovery could not be started."}
        </p>
      ) : null}

      <div className="flex flex-wrap items-end gap-2">
        <label className="block space-y-1 text-sm text-foreground">
          <span>Renewal method</span>
          <Select
            aria-label={`${target.name} renewal method`}
            value={method}
            onChange={(e) => setMethod(e.target.value)}
          >
            {RENEWAL_METHOD_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </label>
        <label className="block space-y-1 text-sm text-foreground">
          <span>Auto-renew threshold (days)</span>
          <Input
            type="number"
            min={0}
            aria-label={`${target.name} auto-renew threshold days`}
            value={thresholdInput}
            onChange={(e) => setThresholdInput(e.target.value)}
            placeholder={
              envDefaultDays ? `${envDefaultDays} (env default)` : "env default"
            }
            className="max-w-[10rem]"
          />
        </label>
        <Button
          tone="primary"
          disabled={!dirty || invalidThreshold || saveMutation.isPending}
          onClick={() => saveMutation.mutate()}
        >
          {saveMutation.isPending ? "Saving…" : "Save"}
        </Button>
        <Button
          tone="secondary"
          disabled={!hasOverride || clearMutation.isPending}
          onClick={() => clearMutation.mutate()}
        >
          <RotateCcw size={13} aria-hidden="true" />
          {clearMutation.isPending ? "Clearing…" : "Clear override"}
        </Button>
      </div>

      {invalidThreshold ? (
        <p className="text-xs text-state-over">
          Enter a whole number of days, or leave blank to use the env default.
        </p>
      ) : null}
      {saveMutation.isError ? (
        <p className="text-xs text-state-over">
          {saveMutation.error instanceof Error
            ? saveMutation.error.message
            : "Save failed."}
        </p>
      ) : null}
      {clearMutation.isError ? (
        <p className="text-xs text-state-over">
          {clearMutation.error instanceof Error
            ? clearMutation.error.message
            : "Clear failed."}
        </p>
      ) : null}
    </div>
  );
}

export default function RenewalPolicy() {
  const queryClient = useQueryClient();

  const targetsQuery = useQuery({
    queryKey: ["managed-targets"],
    queryFn: api.targets,
  });
  const schedulerQuery = useQuery({
    queryKey: ["renewal-scheduler-status"],
    queryFn: api.renewalSchedulerStatus,
    staleTime: 30_000,
  });

  const targets = targetsQuery.data?.data ?? [];
  const envDefaultDays = schedulerQuery.data?.data?.status.threshold_days;

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["managed-targets"] });

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Infrastructure"
        title="Renewal Policy"
        description={`Auto-renew threshold and method, per target — overrides the scheduler's${envDefaultDays ? ` ${envDefaultDays}-day` : ""} RENEWAL_THRESHOLD_DAYS env default. Leave the threshold blank (or clear it) to fall back to that default.`}
        actions={
          <Button
            tone="secondary"
            onClick={() => targetsQuery.refetch()}
            disabled={targetsQuery.isFetching}
          >
            <RefreshCw size={13} aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      {targetsQuery.isLoading ? (
        <StateMessage title="Loading" message="Fetching managed targets…" />
      ) : targetsQuery.error ? (
        <StateMessage
          tone="error"
          title="Unavailable"
          message="Managed targets could not be loaded."
        />
      ) : targets.length === 0 ? (
        <StateMessage
          title="No managed targets yet"
          message="Declare a target in Target Setup before configuring its renewal policy."
          action={
            <Link
              to="/targets/setup"
              className="text-sm font-medium text-primary hover:underline"
            >
              Open Target Setup →
            </Link>
          }
        />
      ) : (
        <Panel title="Fleet" subtitle={`${targets.length} managed target(s)`}>
          <div className="space-y-3">
            {targets.map((t) => (
              <TargetPolicyRow
                key={t.id}
                target={t}
                envDefaultDays={envDefaultDays}
                onSaved={invalidate}
              />
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}
