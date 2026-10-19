import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { BlastRadiusAction, BlastRadiusResult } from "../lib/models";
import { Badge, Button, StateMessage } from "./ops-ui";

export type ImpactState = "loading" | "ready" | "error";

export interface BlastRadiusImpactProps {
  action: BlastRadiusAction;
  target: string;
  // Called on every transition, including the initial "loading".
  onStateChange?: (s: ImpactState) => void;
}

const MAX_SERVICES = 20;

function severityTone(s: BlastRadiusResult["severity"]) {
  if (s === "high" || s === "critical") return "danger";
  if (s === "medium") return "warning";
  return "success";
}

// Maps a pending action to the simulation that previews it; null means no
// simulation applies (the approve gate then stays open).
// eslint-disable-next-line react-refresh/only-export-components -- spec W31-16 keeps the pure helpers beside the component
export function impactForPendingAction(a: {
  action_type: string;
  params: unknown;
}): { action: BlastRadiusAction; target: string } | null {
  const p = (a.params ?? {}) as { fingerprint?: unknown; ca_id?: unknown };
  const str = (v: unknown) => (typeof v === "string" && v !== "" ? v : null);
  switch (a.action_type) {
    case "revoke": {
      const t = str(p.fingerprint);
      return t ? { action: "revoke", target: t } : null;
    }
    case "bulk_revoke":
    case "ca_revoke": {
      const t = str(p.ca_id);
      return t ? { action: "retire_ca", target: t } : null;
    }
    default:
      return null;
  }
}

// True only when the preview loaded successfully, or no preview applies.
// eslint-disable-next-line react-refresh/only-export-components -- spec W31-16 keeps the pure helpers beside the component
export function approveEnabled(
  applies: boolean,
  state: ImpactState | undefined,
): boolean {
  return !applies || state === "ready";
}

export function BlastRadiusImpact({
  action,
  target,
  onStateChange,
}: BlastRadiusImpactProps) {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["blast-radius", action, target],
    queryFn: () => api.blastRadius(action, target),
    retry: false,
    staleTime: 0,
  });

  const result = data?.data;
  const state: ImpactState = isError
    ? "error"
    : result && !isLoading
      ? "ready"
      : "loading";

  useEffect(() => {
    onStateChange?.(state);
  }, [state, onStateChange]);

  if (state === "loading") {
    return (
      <p role="status" className="text-sm text-muted-foreground">
        Calculating blast radius...
      </p>
    );
  }

  if (state === "error") {
    const status = (error as { status?: number } | null)?.status;
    if (status === 403) {
      return (
        <StateMessage
          tone="error"
          title="Blast radius not permitted"
          message="You are not permitted to see the blast radius for this target (403). It cannot be treated as safe."
        />
      );
    }
    if (status === 404) {
      return (
        <StateMessage
          tone="error"
          title="Blast radius target not found"
          message="The target is not in the dependency graph (404). Impact is unknown; it cannot be treated as safe."
        />
      );
    }
    return (
      <StateMessage
        tone="error"
        title="Blast radius unavailable"
        message={error instanceof Error ? error.message : String(error)}
        action={
          <Button onClick={() => void refetch()} aria-label="Retry">
            Retry
          </Button>
        }
      />
    );
  }

  const r = result as BlastRadiusResult;
  const certs = r.affected_by_kind?.cert?.length ?? 0;
  const services = r.affected_by_kind?.service ?? [];
  return (
    <div className="space-y-1" aria-label="Blast radius impact">
      <div className="flex items-center gap-2 text-sm">
        <Badge tone={severityTone(r.severity)}>{r.severity}</Badge>
        <span>
          {certs} certificates, {services.length} services affected
        </span>
      </div>
      {r.total_affected === 0 ? (
        <p className="text-sm text-muted-foreground">
          Nothing depends on this target in the inventory graph.
        </p>
      ) : null}
      {services.length > 0 ? (
        <details className="text-xs text-muted-foreground">
          <summary>Affected services</summary>
          <ul className="mt-1 list-disc pl-5">
            {services.slice(0, MAX_SERVICES).map((id) => (
              <li key={id}>{id}</li>
            ))}
          </ul>
          {services.length > MAX_SERVICES ? (
            <p className="pl-5">and {services.length - MAX_SERVICES} more</p>
          ) : null}
        </details>
      ) : null}
    </div>
  );
}
