import { Link } from "react-router-dom";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Radar, RefreshCw, RotateCcw } from "lucide-react";
import { api, type ManagedTarget, type TargetPolicyRow as PolicyRow } from "../lib/api";
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
import { extractList, type CertificateRecord } from "../lib/models";

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

// The scheduler renews a certificate onto a target only when an operator bound them. A live
// certificate whose CN/SAN equals the target's host but has no binding is never renewed and
// the hub only logs it, so say so here (UI finding 13).
function UnboundHostMatches({ target, certs }: { target: ManagedTarget; certs: CertificateRecord[] }) {
  const bindingsQ = useQuery({
    queryKey: ["target-bindings", target.id],
    queryFn: () => api.certTargetBindings(target.id),
    enabled: target.auto_renew === true,
    retry: false,
  });
  if (target.auto_renew !== true || !bindingsQ.data) return null;
  const bound = new Set((bindingsQ.data.data ?? []).map((b) => b.cert_fingerprint));
  const host = target.host.trim().toLowerCase();
  const matches = certs.filter(
    (c) =>
      !bound.has(c.fingerprint_sha256) &&
      !c.revoked_at &&
      !["revoked", "expired", "superseded"].includes(c.status ?? "") &&
      [c.common_name, ...(c.subject_alt_names ?? [])].some((n) => (n ?? "").trim().toLowerCase() === host),
  );
  if (matches.length === 0) return null;
  return (
    <div role="status" className="rounded-lg border border-state-attn/50 bg-state-attn/10 px-3 py-2 text-xs text-foreground">
      <span className="font-medium">Not auto-renewed:</span>{" "}
      {matches.length === 1 ? "1 certificate matches" : `${matches.length} certificates match`} this host (
      {matches.map((c) => c.common_name || c.fingerprint_sha256.slice(0, 12)).join(", ")}) but{" "}
      {matches.length === 1 ? "is" : "are"} not bound to this target, so the scheduler will not renew{" "}
      {matches.length === 1 ? "it" : "them"} here.{" "}
      <Link to="/targets/setup" className="font-medium text-primary hover:underline">
        Bind in Target Setup
      </Link>
    </div>
  );
}

function TargetPolicyRow({
  target,
  envDefaultDays,
  policy,
  certs,
  onSaved,
}: {
  target: ManagedTarget;
  envDefaultDays?: number;
  policy?: PolicyRow;
  certs: CertificateRecord[];
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
          {policy ? (
            <span
              className="flex items-center gap-1.5 text-sm text-foreground"
              data-testid={`threshold-${target.id}`}
            >
              <span>Threshold: {policy.effective_days} days</span>
              <Badge tone={policy.source === "default" ? "neutral" : "info"}>
                {policy.source}
              </Badge>
              {policy.group ? (
                <span className="text-xs text-muted-foreground">
                  group {policy.group}
                </span>
              ) : null}
            </span>
          ) : (
            <Badge tone={hasOverride ? "info" : "neutral"}>
              {hasOverride
                ? `${target.renewal_threshold_days}d override`
                : `env default${envDefaultDays ? ` (${envDefaultDays}d)` : ""}`}
            </Badge>
          )}
        </div>
      </div>
      {discoverMutation.isError ? (
        <p className="text-xs text-state-over">
          {discoverMutation.error instanceof Error
            ? discoverMutation.error.message
            : "Discovery could not be started."}
        </p>
      ) : null}
      <UnboundHostMatches target={target} certs={certs} />

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

// TargetGroupEditor (W27-04/05): a named set of targets sharing one renewal
// threshold. A target's own override still wins; the server owns validation
// (1..398 days, tenant membership) and its message is shown verbatim.
function TargetGroupEditor({
  targets,
  onSaved,
}: {
  targets: ManagedTarget[];
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [days, setDays] = useState("");
  const [members, setMembers] = useState<string[]>([]);
  const mutation = useMutation({
    mutationFn: () =>
      api.upsertTargetGroup(name.trim(), {
        renewal_threshold_days: Number(days),
        target_ids: members,
      }),
    onSuccess: onSaved,
  });
  const validDays = /^\d+$/.test(days.trim());

  return (
    <Panel
      title="Target groups"
      subtitle="Share one threshold across several targets"
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
      >
        <div className="flex flex-wrap items-end gap-2">
          <label className="block space-y-1 text-sm text-foreground">
            <span>Group name</span>
            <Input
              aria-label="Group name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="web-fleet"
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Group threshold (days)</span>
            <Input
              type="number"
              min={1}
              max={398}
              aria-label="Group threshold days"
              value={days}
              onChange={(e) => setDays(e.target.value)}
              className="max-w-[10rem]"
            />
          </label>
        </div>
        <fieldset className="space-y-1">
          <legend className="text-sm text-foreground">Member targets</legend>
          {targets.map((t) => (
            <label
              key={t.id}
              className="flex items-center gap-2 text-sm text-foreground"
            >
              <input
                type="checkbox"
                checked={members.includes(t.id)}
                onChange={() =>
                  setMembers((cur) =>
                    cur.includes(t.id)
                      ? cur.filter((x) => x !== t.id)
                      : [...cur, t.id],
                  )
                }
              />
              <span>{`${t.name} (${t.host})`}</span>
            </label>
          ))}
        </fieldset>
        <Button
          type="submit"
          tone="primary"
          disabled={!name.trim() || !validDays || mutation.isPending}
        >
          {mutation.isPending ? "Saving…" : "Save group"}
        </Button>
        {mutation.isSuccess ? (
          <p className="text-xs text-state-auto">Group saved.</p>
        ) : null}
        {mutation.isError ? (
          <p className="text-xs text-state-over" role="alert">
            {mutation.error instanceof Error
              ? mutation.error.message
              : "Group could not be saved."}
          </p>
        ) : null}
      </form>
    </Panel>
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

  // W27-04: effective threshold + source per target. Optional — when the
  // call fails the rows fall back to the env-default text.
  const policyQuery = useQuery({
    queryKey: ["target-policy"],
    queryFn: () => api.targetPolicy(),
    retry: false,
  });
  const policyByTarget = new Map(
    (policyQuery.data?.data ?? []).map((p) => [p.target_id, p]),
  );

  const targets = targetsQuery.data?.data ?? [];
  const certsQuery = useQuery({
    queryKey: ["certificates", "bindable"],
    queryFn: () => api.certificates({ limit: 200 }),
    enabled: targets.some((t) => t.auto_renew === true),
    retry: false,
  });
  const certs = extractList<CertificateRecord>(certsQuery.data?.data, ["items"]);
  const envDefaultDays = schedulerQuery.data?.data?.status.threshold_days;

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["target-policy"] });
    return queryClient.invalidateQueries({ queryKey: ["managed-targets"] });
  };

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
                policy={policyByTarget.get(t.id)}
                certs={certs}
                onSaved={invalidate}
              />
            ))}
          </div>
        </Panel>
      )}
      {targets.length > 0 ? (
        <TargetGroupEditor targets={targets} onSaved={invalidate} />
      ) : null}
    </div>
  );
}
