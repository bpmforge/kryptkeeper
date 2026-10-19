import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api } from "../lib/api";
import type { ExpiryBucket, ExpiryTimelineReport } from "../lib/models";
import {
  Button,
  Input,
  MetricCard,
  Panel,
  StateMessage,
} from "../components/ui";
import { expiryBucketClass } from "../lib/pageHelpers";
import { PageHeader } from "../components/PageHeader";

// Objective config keys and bounds mirror internal/bootstrap/config_store.go
// (sloObjectiveBounds); defaults mirror internal/metrics/slo.go.
type ObjectiveDef = {
  key: string;
  label: string;
  fallback: string;
  lo: number;
  hi: number;
  loInc: boolean;
  hiInc: boolean;
  hint: string;
};

const OBJECTIVES: ObjectiveDef[] = [
  {
    key: "slo.issuance_latency_p95_seconds",
    label: "Issuance latency p95 (seconds)",
    fallback: "5",
    lo: 0.01,
    hi: 3600,
    loInc: true,
    hiInc: true,
    hint: "Between 0.01 and 3600 seconds",
  },
  {
    key: "slo.renewal_success_objective",
    label: "Renewal success rate",
    fallback: "0.99",
    lo: 0.5,
    hi: 1,
    loInc: false,
    hiInc: false,
    hint: "Ratio above 0.5 and below 1",
  },
  {
    key: "slo.issuance_success_objective",
    label: "Issuance success rate",
    fallback: "0.995",
    lo: 0.5,
    hi: 1,
    loInc: false,
    hiInc: false,
    hint: "Ratio above 0.5 and below 1",
  },
];

function validateObjective(def: ObjectiveDef, raw: string): string | null {
  const v = Number(raw);
  if (raw.trim() === "" || !Number.isFinite(v)) return "Enter a number";
  const okLo = def.loInc ? v >= def.lo : v > def.lo;
  const okHi = def.hiInc ? v <= def.hi : v < def.hi;
  return okLo && okHi ? null : def.hint;
}

const fmtPct = (n: number | null | undefined) =>
  n == null || !Number.isFinite(n) ? "—" : `${n.toFixed(1)}%`;
const fmtBurn = (n: number | null | undefined) =>
  n == null || !Number.isFinite(n) ? "—" : `${n.toFixed(2)}×`;

function isForbidden(err: unknown): boolean {
  return (err as { status?: number } | null)?.status === 403;
}

function SLOCards() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["slo-report"],
    queryFn: api.renewalSLO,
    refetchInterval: 60_000,
  });

  if (isLoading) {
    return <StateMessage title="Loading" message="Fetching SLO budgets…" />;
  }
  if (isForbidden(error)) {
    return (
      <StateMessage
        title="Not available for tenant-scoped users"
        message="SLO budgets are an estate-wide aggregate. Ask an operator with global scope to view them."
      />
    );
  }
  if (error || !data) {
    return (
      <StateMessage
        tone="error"
        title="SLOs unavailable"
        message="The SLO report could not be loaded."
      />
    );
  }
  const slos = data.data.slos ?? [];
  if (slos.length === 0) {
    return (
      <StateMessage
        title="No SLO budgets yet"
        message="Error budgets appear after the first SLO sweep."
      />
    );
  }
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {slos.map((s) => {
        const noData = !s.has_data;
        const pct = noData ? null : s.budget_remaining_pct;
        const tone =
          pct == null
            ? "neutral"
            : pct <= 0
              ? "danger"
              : pct < 25
                ? "warning"
                : "success";
        return (
          <MetricCard
            key={s.name}
            label={s.name}
            value={fmtPct(pct)}
            tone={tone}
            hint={`Objective ${s.objective} · burn 1h ${fmtBurn(noData ? null : s.burn_rate_1h)} · 6h ${fmtBurn(noData ? null : s.burn_rate_6h)}`}
          />
        );
      })}
    </div>
  );
}

function ExpiryPanel() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["slo-expiry-distribution"],
    queryFn: api.expiryTimeline,
    refetchInterval: 60_000,
  });
  const buckets: ExpiryBucket[] =
    (data?.data as unknown as ExpiryTimelineReport | undefined)?.buckets ?? [];
  const max = Math.max(0, ...buckets.map((b) => b.count));
  return (
    <Panel title="Time to expiry" subtitle="Certificates by remaining lifetime">
      {isLoading ? (
        <StateMessage title="Loading" message="Fetching expiry distribution…" />
      ) : error ? (
        <StateMessage
          tone="error"
          title="Distribution unavailable"
          message="The expiry distribution could not be loaded."
        />
      ) : max === 0 ? (
        <p className="text-sm text-muted-foreground">
          No certificates with a known expiry yet.
        </p>
      ) : (
        <ul className="space-y-2">
          {buckets.map((b) => (
            <li key={b.label} className="flex items-center gap-3 text-sm">
              <span className="w-28 shrink-0 text-muted-foreground">
                {b.label}
              </span>
              <div className="h-3 flex-1 rounded bg-[var(--surface-2)]">
                <div
                  className={`h-3 rounded ${expiryBucketClass(b.label)}`}
                  style={{ width: `${(b.count / max) * 100}%` }}
                />
              </div>
              <span className="w-10 text-right font-mono text-foreground">
                {b.count}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function ObjectivesPanel() {
  const qc = useQueryClient();
  const { data } = useQuery({
    queryKey: ["runtime-config"],
    queryFn: api.runtimeConfig,
  });
  const [edits, setEdits] = useState<Record<string, string>>({});

  const stored = (def: ObjectiveDef): string => {
    const row = data?.data?.find((r) => r.key === def.key);
    return row?.value ? row.value : def.fallback;
  };
  const current = (def: ObjectiveDef) => edits[def.key] ?? stored(def);
  const changed = OBJECTIVES.filter(
    (d) => edits[d.key] !== undefined && edits[d.key].trim() !== stored(d),
  );
  const errors = Object.fromEntries(
    changed.map((d) => [d.key, validateObjective(d, edits[d.key])]),
  );
  const hasError = changed.some((d) => errors[d.key]);

  const save = useMutation({
    mutationFn: async () => {
      for (const d of changed) {
        await api.setRuntimeConfig(d.key, edits[d.key].trim());
      }
    },
    onSuccess: async () => {
      setEdits({});
      await Promise.all([
        qc.invalidateQueries({ queryKey: ["slo-report"] }),
        qc.invalidateQueries({ queryKey: ["runtime-config"] }),
      ]);
      toast.success("SLO objectives saved");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <Panel
      title="Objectives"
      subtitle="Saved through the runtime config store; no rebuild or restart"
    >
      <div className="grid gap-4 sm:grid-cols-3">
        {OBJECTIVES.map((d) => (
          <label
            key={d.key}
            className="block space-y-1 text-sm text-foreground"
          >
            <span>{d.label}</span>
            <Input
              type="number"
              step="any"
              aria-label={d.label}
              value={current(d)}
              onChange={(e) =>
                setEdits((prev) => ({ ...prev, [d.key]: e.target.value }))
              }
            />
            <span
              className={`block text-xs ${errors[d.key] ? "text-state-over" : "text-muted-foreground"}`}
            >
              {errors[d.key] ?? d.hint}
            </span>
          </label>
        ))}
      </div>
      <div className="mt-4 flex justify-end">
        <Button
          onClick={() => save.mutate()}
          disabled={changed.length === 0 || hasError || save.isPending}
        >
          Save objectives
        </Button>
      </div>
    </Panel>
  );
}

export default function SLO() {
  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto fade-in-up">
      <PageHeader
        eyebrow="Reliability"
        title="SLOs and error budget"
        description="How much of each 30-day error budget is left, and how fast it is being used up over the last 1 and 6 hours. A burn of 1.00× uses the budget at exactly the planned pace; higher means it will run out early."
      />
      <SLOCards />
      <ExpiryPanel />
      <ObjectivesPanel />
      <Link to="/automation" className="text-sm text-primary underline">
        Back to Automation
      </Link>
    </div>
  );
}
