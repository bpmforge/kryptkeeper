import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { BlastRadiusAction, BlastRadiusResult } from "../lib/models";
import { Badge, Button, Panel, StateMessage } from "./ops-ui";

export interface BlastRadiusPanelProps {
  // The server only knows revoke | retire_ca | deprecate_algorithm; callers
  // map UI verbs (rotate -> retire_ca, compromise -> revoke) before passing.
  action: BlastRadiusAction;
  target: string;
  confirmLabel: string;
  onConfirm: () => void;
  confirming?: boolean;
  // Extra caller gate (e.g. typed-id confirmation); preview must still load.
  confirmDisabled?: boolean;
  onCancel?: () => void;
}

const KIND_ORDER: [string, string][] = [
  ["endpoint", "Endpoints"],
  ["service", "Services"],
  ["key", "Keys"],
];
const OTHER_KIND_LABELS: Record<string, string> = {
  cert: "Certificates",
  ca: "CAs",
};

function severityTone(s: BlastRadiusResult["severity"]) {
  if (s === "high" || s === "critical") return "danger";
  if (s === "medium") return "warning";
  return "success";
}

function kindSections(byKind: Record<string, string[]>) {
  const known = new Set(KIND_ORDER.map(([k]) => k));
  const others: [string, string][] = Object.keys(byKind)
    .filter((k) => !known.has(k))
    .sort()
    .map((k) => [k, OTHER_KIND_LABELS[k] ?? k]);
  return [...KIND_ORDER, ...others].filter(
    ([k]) => (byKind[k] ?? []).length > 0,
  );
}

export function BlastRadiusPanel({
  action,
  target,
  confirmLabel,
  onConfirm,
  confirming = false,
  confirmDisabled = false,
  onCancel,
}: BlastRadiusPanelProps) {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["blast-radius", action, target],
    queryFn: () => api.blastRadius(action, target),
    retry: false,
    staleTime: 0,
  });

  const result = data?.data;
  // Never allow confirming blind: the preview must have loaded cleanly.
  const canConfirm = !!result && !isError && !confirming && !confirmDisabled;

  return (
    <Panel title="Blast radius" subtitle={`${action} - ${target}`}>
      <div className="flex flex-col gap-4">
        {isLoading ? (
          <p role="status" className="text-sm text-muted-foreground">
            Calculating blast radius...
          </p>
        ) : null}

        {isError ? (
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
        ) : null}

        {result && result.total_affected === 0 ? (
          <p className="text-sm">Nothing depends on this target.</p>
        ) : null}

        {result && result.total_affected > 0 ? (
          <>
            <div className="flex items-center gap-2">
              <Badge tone={severityTone(result.severity)}>
                {result.severity}
              </Badge>
              <span className="text-sm">{result.total_affected} affected</span>
            </div>
            {kindSections(result.affected_by_kind).map(([kind, label]) => (
              <section key={kind} aria-label={label}>
                <h4 className="text-sm font-semibold">{label}</h4>
                <ul className="mt-1 list-disc pl-5 text-sm">
                  {result.affected_by_kind[kind].map((id) => (
                    <li key={id}>{id}</li>
                  ))}
                </ul>
              </section>
            ))}
          </>
        ) : null}

        <div className="flex justify-end gap-2">
          {onCancel ? <Button onClick={onCancel}>Cancel</Button> : null}
          <Button
            tone={
              result &&
              (result.severity === "high" || result.severity === "critical")
                ? "danger"
                : "primary"
            }
            disabled={!canConfirm}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </Panel>
  );
}
