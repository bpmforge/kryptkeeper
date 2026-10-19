import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { scrollableProps } from "../lib/scrollable";
import { useState } from "react";
import {
  RefreshCw,
  Layers,
  Trash2,
  Wand2,
  Download,
  CalendarClock,
  Rocket,
} from "lucide-react";
import { toast } from "sonner";
import { extractList } from "../lib/models";
import { useOperationEvents } from "../hooks/useOperationEvents";
import type { TemplateRecord } from "../lib/models";
import { api, downloadAuthedFile } from "../lib/api";
import type {
  PQCCountdownReport,
  PQCMigrationItem,
  PQCMigrationRoadmap,
  WaveProgress,
} from "../lib/models";
import {
  Badge,
  Button,
  MetricCard,
  Panel,
  StateMessage,
} from "../components/ui";
import { opLabel, opTone } from "../lib/operationStatus";
import { PageHeader } from "../components/PageHeader";
import { Wizard, type WizardStepDef } from "../components/Wizard";

const PQC_LABEL_EXPLANATIONS: Record<
  string,
  { title: string; text: string }
> = {
  quantum_safe: {
    title: "Quantum safe",
    text: "Leaf key and every signature up to the root use post-quantum algorithms.",
  },
  quantum_safe_leaf_only: {
    title: "Leaf-only PQC",
    text: "The certificate's own key is post-quantum, but a classical signature remains somewhere in its chain, so the chain can still be forged by a quantum attacker. This is NOT quantum safe.",
  },
  migration_ready: {
    title: "Migration ready",
    text: "Classical, but short-lived (100 days or less) or hybrid, so it can be rotated to post-quantum before the deadline.",
  },
  vulnerable: {
    title: "Vulnerable",
    text: "Long-lived classical certificate that needs active migration planning.",
  },
  not_applicable: {
    title: "Not applicable",
    text: "Key type not recognised or not subject to this assessment.",
  },
};

// Mirrors pqc.Timeline (GET /reports/pqc-migration). Optional so the UI
// degrades honestly against a hub that predates the field.
type PQCTimeline = {
  quarters: { quarter: string; due: number; migrated: number }[];
  expire_before_2030: number;
  expire_after_2030: number;
};

function TimelinePanel({ timeline }: { timeline?: PQCTimeline }) {
  return (
    <Panel
      title="Migration timeline to 2030"
      subtitle="Certificates by the quarter their validity ends, through the CNSA 2.0 deadline"
    >
      {!timeline ? (
        <p className="text-sm text-muted-foreground">
          Timeline not reported by this hub version.
        </p>
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <MetricCard
              label="Expire before 2030"
              value={timeline.expire_before_2030}
              hint="still to migrate; rotate at renewal"
            />
            <MetricCard
              label="Expire after 2030"
              value={timeline.expire_after_2030}
              hint="still to migrate; must be replaced early"
              tone={timeline.expire_after_2030 > 0 ? "danger" : "success"}
            />
          </div>
          <div className="overflow-x-auto" {...scrollableProps}>
          <table className="w-full min-w-[20rem] text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                <th className="py-2 pr-4">Quarter</th>
                <th className="py-2 pr-4">Due</th>
                <th className="py-2 pr-4">Migrated</th>
              </tr>
            </thead>
            <tbody>
              {timeline.quarters.map((q) => (
                <tr
                  key={q.quarter}
                  data-testid="pqc-quarter"
                  className="border-b border-border"
                >
                  <td className="py-2 pr-4 text-foreground">{q.quarter}</td>
                  <td className="py-2 pr-4 text-foreground">{q.due}</td>
                  <td className="py-2 pr-4 text-foreground">{q.migrated}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </div>
      )}
    </Panel>
  );
}

function ByAlgorithmPanel() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["crypto-posture"],
    queryFn: api.cryptoPosture,
    staleTime: 60_000,
  });
  const breakdown = data?.data?.algorithm_breakdown;
  const rows = Object.entries(breakdown ?? {}).sort((a, b) => b[1] - a[1]);

  return (
    <Panel
      title="By algorithm"
      subtitle="Certificates per public-key algorithm"
    >
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : error || !breakdown ? (
        <p className="text-sm text-muted-foreground">
          Algorithm breakdown unavailable.
        </p>
      ) : rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">No certificates.</p>
      ) : (
        <div className="space-y-1.5">
          {rows.map(([algo, count]) => (
            <div
              key={algo}
              data-testid="pqc-algorithm-row"
              className="flex items-center justify-between gap-2 text-sm"
            >
              <span className="text-foreground">{algo}</span>
              <span className="text-muted-foreground">{count}</span>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function priorityTone(
  p: PQCMigrationItem["priority"],
): "danger" | "warning" | "info" | "neutral" {
  switch (p) {
    case "critical":
      return "danger";
    case "high":
      return "warning";
    case "medium":
      return "info";
    default:
      return "neutral";
  }
}

const STATUS_LABEL: Record<PQCCountdownReport["status"], string> = {
  complete: "Complete",
  on_track: "On track",
  at_risk: "At risk",
  behind: "Behind",
};

function statusTone(
  s: PQCCountdownReport["status"],
): "success" | "warning" | "danger" {
  if (s === "complete" || s === "on_track") return "success";
  if (s === "at_risk") return "warning";
  return "danger";
}

function CountdownPanel() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["pqc-countdown"],
    queryFn: api.pqcCountdown,
    staleTime: 60_000,
  });
  const rep: PQCCountdownReport | undefined = data?.data;
  const nearest = rep?.deadlines.find((d) => !d.passed);

  return (
    <Panel
      title="CNSA 2.0 / NIST 800-131A Countdown"
      subtitle="Proof of post-quantum migration progress against the deadlines"
    >
      <div className="mb-4 flex justify-end">
        <Button
          tone="primary"
          onClick={() =>
            void downloadAuthedFile(
              "/reports/pqc-countdown?format=pdf",
              "pqc-countdown.pdf",
            ).catch((err: Error) => toast.error(err.message))
          }
        >
          <Download size={13} aria-hidden="true" />
          Countdown PDF
        </Button>
      </div>
      {isLoading ? (
        <StateMessage title="Loading" message="Computing countdown…" />
      ) : error || !rep ? (
        <StateMessage
          tone="error"
          title="Unavailable"
          message="The PQC countdown could not be loaded."
        />
      ) : (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Status</span>
            <Badge tone={statusTone(rep.status)}>
              {STATUS_LABEL[rep.status]}
            </Badge>
          </div>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
            <MetricCard
              label="PQC readiness"
              value={`${rep.pqc_score_percent}%`}
              tone={statusTone(rep.status)}
            />
            <MetricCard label="Vulnerable" value={rep.vulnerable} />
            <MetricCard
              label="Nearest deadline"
              value={nearest ? `${nearest.days_remaining}d` : "—"}
              hint={nearest ? nearest.date : "all passed"}
            />
            <MetricCard label="Quantum-safe" value={rep.quantum_safe} />
            <MetricCard
              label="Leaf-only PQC"
              value={rep.quantum_safe_leaf_only}
            />
          </div>
          <div className="space-y-1.5">
            {rep.deadlines.map((d) => (
              <div
                key={d.name}
                className="flex items-center justify-between gap-2 text-sm"
              >
                <span className="flex items-center gap-2 text-foreground">
                  <CalendarClock size={13} className="text-primary" />
                  {d.name}
                </span>
                <span className="text-muted-foreground">
                  {d.date} ·{" "}
                  {d.passed ? (
                    <span className="text-state-over">passed</span>
                  ) : (
                    `${d.days_remaining} days`
                  )}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}

function MigrationWavesPanel() {
  const queryClient = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ["pqc-waves"],
    queryFn: api.pqcWaves,
    staleTime: 30_000,
  });
  const waves: WaveProgress[] = data?.data ?? [];

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["pqc-waves"] });

  const { latest: migrateEvents } = useOperationEvents({
    kinds: ["migrate"],
    onEvent: () => void invalidate(),
    onResync: () => void invalidate(),
  });

  const deriveMutation = useMutation({
    mutationFn: api.autoDerivePqcWaves,
    onSuccess: invalidate,
    onError: (err: Error) => toast.error(err.message),
  });
  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deletePqcWave(id),
    onSuccess: invalidate,
    onError: (err: Error) => toast.error(err.message),
  });
  const acceptMutation = useMutation({
    mutationFn: (id: string) => api.acceptPqcWave(id),
    onSuccess: invalidate,
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <Panel
      title="Migration Waves"
      subtitle="Track PQC migration as ordered waves (test → internal → customer-facing)"
    >
      <div className="mb-4 flex items-center gap-2">
        <Button
          tone="primary"
          onClick={() => deriveMutation.mutate()}
          disabled={deriveMutation.isPending}
        >
          <Wand2 size={13} aria-hidden="true" />
          {waves.length > 0 ? "Re-derive waves" : "Auto-derive waves"}
        </Button>
        {waves.length > 0 ? (
          <span className="text-xs text-muted-foreground">
            Re-derive replaces all waves from the current inventory.
          </span>
        ) : null}
      </div>

      {isLoading ? (
        <StateMessage title="Loading" message="Fetching waves…" />
      ) : error ? (
        <StateMessage
          tone="error"
          title="Unavailable"
          message="Migration waves could not be loaded."
        />
      ) : waves.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No migration waves yet. Auto-derive groups vulnerable certificates
          into test / internal / customer-facing waves from naming, SANs, and
          labels.
        </p>
      ) : (
        <div className="space-y-4">
          {waves.map((wv) => (
            <div
              key={wv.id}
              className="rounded-xl border border-border bg-card/40 p-3"
            >
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Layers size={14} className="text-primary" />
                  <span className="font-medium text-foreground">{wv.name}</span>
                  {wv.status ? (
                    <Badge
                      tone={
                        wv.status === "accepted"
                          ? "success"
                          : wv.status === "regressed"
                            ? "danger"
                            : "neutral"
                      }
                    >
                      {wv.status}
                    </Badge>
                  ) : null}
                  {migrateEvents[wv.id] ? (
                    <Badge tone={opTone(migrateEvents[wv.id].status)}>
                      {opLabel(migrateEvents[wv.id].status)}
                    </Badge>
                  ) : null}
                  {wv.owner ? (
                    <Badge tone="neutral">owner: {wv.owner}</Badge>
                  ) : null}
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-sm text-foreground">
                    {wv.migrated}/{wv.total} migrated ({wv.progress_percent}%)
                  </span>
                  {wv.status && wv.status !== "accepted" ? (
                    <span title="Accept the wave (also clears a regressed state)">
                      <Button
                        tone="secondary"
                        onClick={() => acceptMutation.mutate(wv.id)}
                        disabled={acceptMutation.isPending}
                      >
                        Accept
                      </Button>
                    </span>
                  ) : null}
                  <Button
                    tone="danger"
                    aria-label={`Delete wave ${wv.name}`}
                    onClick={() => deleteMutation.mutate(wv.id)}
                    disabled={deleteMutation.isPending}
                  >
                    <Trash2 size={13} aria-hidden="true" />
                  </Button>
                </div>
              </div>
              <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-state-auto"
                  style={{ width: `${wv.progress_percent}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

// W8-09: the driven journey — plan → select certs → schedule → execute
// (propose). Finish creates the wave, adds the selected members, and
// proposes the W4-03 EXECUTE action. It deliberately ends at PROPOSED:
// the backend requires a DIFFERENT approver (proposer ≠ approver), and
// the UI must not pretend a one-click execute exists.
function MigrationJourneyPanel({
  items,
  onWaveCreated,
}: {
  items: PQCMigrationItem[];
  onWaveCreated: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [owner, setOwner] = useState("");
  const [targetDate, setTargetDate] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [templateId, setTemplateId] = useState("");
  const [result, setResult] = useState<{
    waveName: string;
    actionId: string | null;
    memberFailures: number;
    proposeError: string | null;
  } | null>(null);
  const [finishError, setFinishError] = useState<string | null>(null);
  // Execution requires a template whose allowed_algorithms carry ML-DSA
  // (plain or hybrid) — proposing without one is a guaranteed 400.
  const templatesQ = useQuery({
    queryKey: ["pqc-templates"],
    queryFn: () => api.templates({ limit: 100 }),
    staleTime: 60_000,
  });
  const pqcTemplates = extractList<TemplateRecord>(templatesQ.data?.data, [
    "items",
    "templates",
  ]).filter(
    (t) =>
      t.active !== false &&
      (t.allowed_algorithms ?? []).some((a) => a.includes("ML-DSA")),
  );

  const toggle = (fp: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(fp)) next.delete(fp);
      else next.add(fp);
      return next;
    });

  const reset = () => {
    setOpen(false);
    setName("");
    setOwner("");
    setTargetDate("");
    setSelected(new Set());
    setFinishError(null);
  };

  const finish = async () => {
    setFinishError(null);
    try {
      const created = await api.createPqcWave({
        name: name.trim(),
        owner: owner.trim() || undefined,
        target_date: targetDate ? `${targetDate}T00:00:00Z` : undefined,
      });
      const waveId = created.data.id;
      let memberFailures = 0;
      for (const fp of selected) {
        try {
          await api.addPqcWaveMember(waveId, fp);
        } catch {
          memberFailures += 1;
        }
      }
      // The wave and its members now exist regardless of what happens
      // below — a propose failure must not be reported as "wave could not
      // be created" (it was, and would sit orphaned).
      let actionId: string | null = null;
      let proposeError: string | null = null;
      if (templateId) {
        try {
          const proposed = await api.proposePqcWaveExecute(waveId, templateId);
          actionId = proposed.data.id;
        } catch (err) {
          proposeError =
            err instanceof Error ? err.message : "Execution proposal failed.";
        }
      } else {
        proposeError =
          "No PQC-capable template selected — create or pick a template allowing ML-DSA, then propose execution from a new wave.";
      }
      setResult({
        waveName: name.trim(),
        actionId,
        memberFailures,
        proposeError,
      });
      reset();
      onWaveCreated();
    } catch (err) {
      setFinishError(
        err instanceof Error
          ? err.message
          : "The migration wave could not be created.",
      );
    }
  };

  const steps: WizardStepDef[] = [
    {
      id: "plan",
      title: "Plan",
      validate: () => (name.trim() ? null : "Give the wave a name."),
      render: () => (
        <div className="space-y-3">
          <label className="block text-sm text-foreground">
            Wave name
            <input
              className="mt-1 w-full rounded-lg border border-border bg-card px-3 py-2 text-sm text-foreground"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. internal-services-wave-1"
            />
          </label>
          <label className="block text-sm text-foreground">
            Owner (optional)
            <input
              className="mt-1 w-full rounded-lg border border-border bg-card px-3 py-2 text-sm text-foreground"
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              placeholder="team or person driving this wave"
            />
          </label>
        </div>
      ),
    },
    {
      id: "select",
      title: "Select certificates",
      validate: () =>
        selected.size > 0 ? null : "Select at least one certificate.",
      render: () => (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              {selected.size} of {items.length} action-needed certificate(s)
              selected.
            </p>
            <Button
              tone="secondary"
              onClick={() =>
                setSelected(
                  selected.size === items.length
                    ? new Set()
                    : new Set(items.map((i) => i.fingerprint)),
                )
              }
            >
              {selected.size === items.length ? "Clear all" : "Select all"}
            </Button>
          </div>
          <div className="max-h-64 space-y-1 overflow-y-auto">
            {items.map((item) => (
              <label
                key={item.fingerprint}
                className="flex cursor-pointer items-center gap-2 rounded-lg border border-border bg-card/40 px-3 py-2 text-sm"
              >
                <input
                  type="checkbox"
                  checked={selected.has(item.fingerprint)}
                  onChange={() => toggle(item.fingerprint)}
                />
                <Badge tone={priorityTone(item.priority)}>
                  {item.priority}
                </Badge>
                <span className="text-foreground">
                  {item.common_name || item.fingerprint.slice(0, 16)}
                </span>
                <span className="ml-auto text-xs text-muted-foreground">
                  {item.reason}
                </span>
              </label>
            ))}
          </div>
        </div>
      ),
    },
    {
      id: "schedule",
      title: "Schedule",
      render: () => (
        <div className="space-y-2">
          <label className="block text-sm text-foreground">
            Target date (optional)
            <input
              type="date"
              className="mt-1 rounded-lg border border-border bg-card px-3 py-2 text-sm text-foreground"
              value={targetDate}
              onChange={(e) => setTargetDate(e.target.value)}
            />
          </label>
          <label className="block text-sm text-foreground">
            Issuance template (ML-DSA / hybrid)
            <select
              className="mt-1 block rounded-lg border border-border bg-card px-3 py-2 text-sm text-foreground"
              value={templateId}
              onChange={(e) => setTemplateId(e.target.value)}
            >
              <option value="">— select a PQC-capable template —</option>
              {pqcTemplates.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.display_name || t.name}
                </option>
              ))}
            </select>
          </label>
          {pqcTemplates.length === 0 ? (
            <p className="text-xs text-state-attn">
              No template allows an ML-DSA or hybrid algorithm yet. Create one
              in Templates first — execution cannot be proposed without it.
            </p>
          ) : null}
          <p className="text-xs text-muted-foreground">
            The wave is created now; execution is proposed at Finish and runs
            only after a second admin approves it.
          </p>
        </div>
      ),
    },
  ];

  return (
    <Panel
      title="Start a migration wave"
      subtitle="Plan → select certificates → schedule → propose execution"
    >
      {result ? (
        <div className="space-y-2" data-testid="journey-result">
          {result.actionId ? (
            <>
              <p className="text-sm text-state-auto">
                Wave “{result.waveName}” created and execution proposed.
              </p>
              <p className="text-sm text-foreground">
                Pending action <code>{result.actionId}</code> now needs approval
                by a <strong>different</strong> administrator — the proposer
                cannot approve their own action.
              </p>
            </>
          ) : (
            <>
              <p className="text-sm text-state-auto">
                Wave “{result.waveName}” created with its members.
              </p>
              <p className="text-sm text-state-attn" role="alert">
                Execution was NOT proposed: {result.proposeError}
              </p>
            </>
          )}
          {result.memberFailures > 0 ? (
            <p className="text-sm text-state-attn">
              {result.memberFailures} certificate(s) could not be added to the
              wave — review its membership before approval.
            </p>
          ) : null}
          <Button tone="secondary" onClick={() => setResult(null)}>
            Start another wave
          </Button>
        </div>
      ) : open ? (
        <>
          {finishError ? (
            <p className="mb-2 text-sm text-state-over" role="alert">
              {finishError}
            </p>
          ) : null}
          <Wizard
            steps={steps}
            onComplete={finish}
            onCancel={reset}
            summary={() => (
              <div className="space-y-1 text-sm text-foreground">
                <p>
                  Wave <strong>{name.trim()}</strong>
                  {owner.trim() ? ` · owner ${owner.trim()}` : ""}
                  {targetDate ? ` · target ${targetDate}` : ""}
                </p>
                <p>{selected.size} certificate(s) will be added.</p>
                <p className="text-muted-foreground">
                  Finishing proposes the migrate-wave execute action for
                  approval; nothing is re-issued until it is approved.
                </p>
              </div>
            )}
            summaryState={null}
          />
        </>
      ) : (
        <Button tone="primary" onClick={() => setOpen(true)}>
          <Rocket size={13} aria-hidden="true" />
          Start migration wave
        </Button>
      )}
    </Panel>
  );
}

const ROADMAP_PREVIEW = 15;

export default function PQCMigration() {
  const [showAllRoadmap, setShowAllRoadmap] = useState(false);
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["pqc-migration"],
    queryFn: api.pqcMigration,
    staleTime: 60_000,
  });

  const roadmap: PQCMigrationRoadmap | undefined = data?.data;
  // Rendered as computed by the backend (pqc.ReadinessTally) so this tile,
  // the countdown card and Crypto Posture can never disagree.
  const pqcReady = roadmap?.pqc_score_percent ?? 0;
  const timeline = (
    roadmap as (PQCMigrationRoadmap & { timeline?: PQCTimeline }) | undefined
  )?.timeline;

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Reports"
        title="PQC Migration"
        description="Prioritized roadmap to post-quantum (CNSA 2.0 mandate · 2030)."
        actions={
          <Button
            tone="secondary"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw size={13} aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      {isLoading ? (
        <StateMessage title="Loading" message="Analyzing PQC posture…" />
      ) : error || !roadmap ? (
        <StateMessage
          tone="error"
          title="Roadmap unavailable"
          message="The PQC migration roadmap could not be loaded."
        />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
            <MetricCard
              label="PQC readiness"
              value={`${pqcReady}%`}
              hint="quantum-safe + leaf-only + migration-ready"
              tone={
                pqcReady >= 80
                  ? "success"
                  : pqcReady >= 40
                    ? "warning"
                    : "danger"
              }
            />
            <MetricCard
              label="Quantum-safe"
              value={roadmap.quantum_safe}
              hint="full chain PQC"
              tone="success"
            />
            <MetricCard
              label="Leaf-only PQC"
              value={roadmap.quantum_safe_leaf_only}
              hint={PQC_LABEL_EXPLANATIONS.quantum_safe_leaf_only.title}
              tone="info"
            />
            <MetricCard
              label="Migration-ready"
              value={roadmap.migration_ready}
              tone="info"
            />
            <MetricCard
              label="Vulnerable"
              value={roadmap.vulnerable}
              tone={roadmap.vulnerable > 0 ? "danger" : "success"}
            />
          </div>

          <dl
            data-testid="pqc-label-explanations"
            className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2"
          >
            {Object.entries(PQC_LABEL_EXPLANATIONS).map(([key, e]) => (
              <div key={key}>
                <dt className="font-medium text-foreground">{e.title}</dt>
                <dd className="text-muted-foreground">{e.text}</dd>
              </div>
            ))}
          </dl>

          <CountdownPanel />

          <TimelinePanel timeline={timeline} />

          <ByAlgorithmPanel />

          <MigrationJourneyPanel
            items={roadmap.items}
            onWaveCreated={() => refetch()}
          />

          <Panel
            title="Migration roadmap"
            subtitle={`${roadmap.items.length} certificate{roadmap.items.length === 1 ? "" : "s"} need{roadmap.items.length === 1 ? "s" : ""} action, highest priority first`}
          >
            {roadmap.items.length === 0 ? (
              <p className="text-sm text-state-auto">
                Nothing to migrate — every certificate is migration-ready or
                quantum-safe.
              </p>
            ) : (
              <div className="overflow-x-auto" {...scrollableProps}>
                <table className="w-full min-w-[44rem] text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                      <th className="py-2 pr-4">Priority</th>
                      <th className="py-2 pr-4">Certificate</th>
                      <th className="py-2 pr-4 min-w-[14rem]">Why</th>
                      <th className="py-2 pr-4 min-w-[14rem]">Recommended action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(showAllRoadmap ? roadmap.items : roadmap.items.slice(0, ROADMAP_PREVIEW)).map((item) => (
                      <tr
                        key={item.fingerprint}
                        className="border-b border-border align-top"
                      >
                        <td className="py-2 pr-4">
                          <Badge tone={priorityTone(item.priority)}>
                            {item.priority}
                          </Badge>
                        </td>
                        <td className="py-2 pr-4 text-foreground">
                          {item.common_name || item.fingerprint.slice(0, 16)}
                        </td>
                        <td className="py-2 pr-4 text-muted-foreground">
                          {item.reason}
                        </td>
                        <td className="py-2 pr-4 text-foreground">
                          {item.action}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {roadmap.items.length > ROADMAP_PREVIEW ? (
                  <div className="pt-3">
                    <Button
                      tone="secondary"
                      onClick={() => setShowAllRoadmap((v) => !v)}
                    >
                      {showAllRoadmap
                        ? `Show first ${ROADMAP_PREVIEW}`
                        : `Show all ${roadmap.items.length}`}
                    </Button>
                  </div>
                ) : null}
              </div>
            )}
          </Panel>

          <MigrationWavesPanel />
        </>
      )}
    </div>
  );
}
