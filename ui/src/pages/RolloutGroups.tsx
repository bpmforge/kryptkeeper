import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { useAuthz } from "../lib/auth";
import { api, fetchJSON, type ManagedTarget } from "../lib/api";
import { Badge, Button, Dialog, Input, Panel, StateMessage } from "../components/ui";
import { PageHeader } from "../components/PageHeader";

// Groups are page-side drafts: the server has no group store (W27-15 added
// none), so they persist in this browser only.
const STORAGE_KEY = "kk.rollout-groups.v1";

type GroupNode = { target_id: string; is_canary: boolean };
type RolloutWindow = { start_hour: number; end_hour: number };
type Group = { name: string; nodes: GroupNode[]; window: RolloutWindow };

type Outcome = "installed" | "rolled_back" | "skipped" | "failed" | "rollback_failed";
type RolloutNodeOutcome = { node_id: string; is_canary: boolean; outcome: Outcome; detail?: string };
type RolloutResult = {
  group: string;
  deferred: boolean;
  halted: boolean;
  halt_reason?: string;
  mode?: "staged" | "sequential";
  new_fingerprint?: string;
  node_results: RolloutNodeOutcome[];
};

function loadGroups(): Group[] {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as Group[]) : [];
  } catch {
    return [];
  }
}

function saveGroups(groups: Group[]): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(groups));
  } catch {
    // Blocked storage: the list still works for this session.
  }
}

const OUTCOME_TONE: Record<Outcome, "success" | "warning" | "neutral" | "danger"> = {
  installed: "success",
  rolled_back: "warning",
  skipped: "neutral",
  failed: "danger",
  rollback_failed: "danger",
};

function windowText(w: RolloutWindow): string {
  return w.start_hour === 0 && w.end_hour === 0
    ? "any time"
    : `${String(w.start_hour).padStart(2, "0")}:00-${String(w.end_hour).padStart(2, "0")}:00 UTC`;
}

function parseHour(v: string): number | null {
  if (!/^\d{1,2}$/.test(v.trim())) return null;
  const n = Number(v);
  return n >= 0 && n <= 23 ? n : null;
}

function NewGroupDialog({
  open,
  targets,
  existing,
  onClose,
  onSave,
}: {
  open: boolean;
  targets: ManagedTarget[];
  existing: string[];
  onClose: () => void;
  onSave: (g: Group) => void;
}) {
  const [name, setName] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [canary, setCanary] = useState("");
  const [start, setStart] = useState("0");
  const [end, setEnd] = useState("0");
  const [error, setError] = useState<string | null>(null);

  // ssh nodes first: only they get the staged, cluster-atomic flip.
  const ordered = [...targets].sort(
    (a, b) => Number(b.install_mode === "ssh") - Number(a.install_mode === "ssh"),
  );

  function toggle(id: string) {
    setPicked((cur) => {
      const next = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
      if (!next.includes(canary)) setCanary(next[0] ?? "");
      return next;
    });
  }

  function submit() {
    const trimmed = name.trim();
    const s = parseHour(start);
    const e = parseHour(end);
    if (!trimmed) return setError("Name is required.");
    if (existing.includes(trimmed)) return setError("A group with that name already exists.");
    if (picked.length === 0) return setError("Pick at least one node.");
    if (!canary || !picked.includes(canary)) return setError("Choose exactly one canary node.");
    if (s === null || e === null) return setError("Window hours must be whole numbers from 0 to 23.");
    setError(null);
    onSave({
      name: trimmed,
      nodes: picked.map((id) => ({ target_id: id, is_canary: id === canary })),
      window: { start_hour: s, end_hour: e },
    });
    setName("");
    setPicked([]);
    setCanary("");
    setStart("0");
    setEnd("0");
  }

  return (
    <Dialog open={open} title="New rollout group" onClose={onClose}>
      <form
        noValidate
        className="space-y-4"
        onSubmit={(ev) => {
          ev.preventDefault();
          submit();
        }}
      >
        <label className="block text-xs text-muted-foreground">
          Group name
          <Input value={name} onChange={(ev) => setName(ev.target.value)} />
        </label>
        <fieldset className="space-y-1">
          <legend className="text-xs text-muted-foreground">Nodes</legend>
          <p className="text-xs text-muted-foreground">
            Only ssh nginx/apache/haproxy nodes get the staged, cluster-atomic flip; other modes roll out
            sequentially.
          </p>
          {targets.length === 0 ? (
            <p className="text-sm text-muted-foreground">No managed targets yet.</p>
          ) : (
            ordered.map((t) => (
              <label key={t.id} className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={picked.includes(t.id)} onChange={() => toggle(t.id)} />
                {t.name} <span className="text-xs text-muted-foreground">({t.install_mode})</span>
              </label>
            ))
          )}
        </fieldset>
        <fieldset className="space-y-1">
          <legend className="text-xs text-muted-foreground">Canary</legend>
          {picked.length === 0 ? (
            <p className="text-sm text-muted-foreground">Pick nodes first.</p>
          ) : (
            picked.map((id) => (
              <label key={id} className="flex items-center gap-2 text-sm">
                <input
                  type="radio"
                  name="canary"
                  checked={canary === id}
                  onChange={() => setCanary(id)}
                />
                {targets.find((t) => t.id === id)?.name ?? id}
              </label>
            ))
          )}
        </fieldset>
        <div className="grid grid-cols-2 gap-3">
          <label className="block text-xs text-muted-foreground">
            Window start (UTC)
            <Input type="number" min={0} max={23} value={start} onChange={(ev) => setStart(ev.target.value)} />
          </label>
          <label className="block text-xs text-muted-foreground">
            Window end (UTC)
            <Input type="number" min={0} max={23} value={end} onChange={(ev) => setEnd(ev.target.value)} />
          </label>
        </div>
        <p className="text-xs text-muted-foreground">0 and 0 means any time.</p>
        {error ? <StateMessage tone="error" title="Cannot save" message={error} /> : null}
        <Button type="submit" tone="primary">
          Save group
        </Button>
      </form>
    </Dialog>
  );
}

function ResultView({ result }: { result: RolloutResult }) {
  return (
    <div role="status" className="space-y-3">
      <p className="text-sm">
        Mode: {result.mode ?? "unknown"}
        {result.new_fingerprint ? ` · New certificate ${result.new_fingerprint.slice(0, 16)}` : ""}
      </p>
      {result.deferred ? (
        <StateMessage
          tone="neutral"
          title="Deferred"
          message="Deferred: outside the maintenance window. Nothing was renewed or touched."
        />
      ) : null}
      {result.halted ? (
        <StateMessage
          tone="error"
          title="Halted"
          message={result.halt_reason || "The rollout halted."}
        />
      ) : null}
      {result.node_results.length > 0 ? (
        <table className="w-full text-sm">
          <caption className="sr-only">Per-node rollout outcomes</caption>
          <thead>
            <tr className="text-left text-xs text-muted-foreground">
              <th scope="col" className="py-2">Node</th>
              <th scope="col">Role</th>
              <th scope="col">Outcome</th>
              <th scope="col">Detail</th>
            </tr>
          </thead>
          <tbody>
            {result.node_results.map((n) => (
              <tr key={n.node_id} className="border-t border-border">
                <td className="py-2 font-medium text-foreground">{n.node_id}</td>
                <td>{n.is_canary ? "Canary" : "Node"}</td>
                <td>
                  <Badge tone={OUTCOME_TONE[n.outcome] ?? "neutral"}>{n.outcome}</Badge>
                </td>
                <td>{n.detail ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </div>
  );
}

export default function RolloutGroups() {
  const authz = useAuthz();
  const canManage = authz.data?.role === "pki-admin";
  const [groups, setGroups] = useState<Group[]>(loadGroups);
  const [selected, setSelected] = useState<string | null>(null);
  const [dialog, setDialog] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [fingerprint, setFingerprint] = useState("");

  const targets = useQuery({
    queryKey: ["targets"],
    queryFn: () => api.targets(),
    enabled: canManage,
  });

  const run = useMutation({
    mutationFn: (g: Group) =>
      fetchJSON<{ data: RolloutResult }>("/renewal/rollout", {
        method: "POST",
        body: JSON.stringify({
          fingerprint: fingerprint.trim(),
          group: g.name,
          nodes: g.nodes,
          window: g.window,
        }),
      }),
  });

  if (authz.isLoading) return <StateMessage title="Loading" message="Checking permissions…" />;
  if (!canManage) {
    return (
      <div className="p-6">
        <StateMessage tone="error" title="Not permitted" message="Rollout groups are limited to administrators." />
      </div>
    );
  }

  const targetList = targets.data?.data ?? [];
  const nameOf = (id: string) => targetList.find((t) => t.id === id)?.name ?? id;
  const group = groups.find((g) => g.name === selected) ?? null;

  function update(next: Group[]) {
    setGroups(next);
    saveGroups(next);
  }

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Automation"
        title="Rollout Groups"
        description="Renew once and install the same certificate on every node of a cluster, canary first, inside an optional UTC maintenance window."
        actions={
          <Button tone="primary" onClick={() => setDialog(true)}>
            <Plus className="h-4 w-4" />
            New group
          </Button>
        }
      />

      <NewGroupDialog
        key={dialog ? "open" : "closed"}
        open={dialog}
        targets={targetList}
        existing={groups.map((g) => g.name)}
        onClose={() => setDialog(false)}
        onSave={(g) => {
          update([...groups, g]);
          setSelected(g.name);
          setDialog(false);
        }}
      />

      <div className="grid gap-6 lg:grid-cols-[22rem_1fr]">
        <Panel title="Groups" subtitle="Saved in this browser only">
          {targets.error ? (
            <StateMessage tone="error" title="Unavailable" message="Could not load managed targets." />
          ) : null}
          {groups.length === 0 ? (
            <StateMessage title="No groups" message="Create a group to roll a certificate out to a cluster." />
          ) : (
            <ul className="space-y-2">
              {groups.map((g) => {
                const canaryId = g.nodes.find((n) => n.is_canary)?.target_id ?? "";
                return (
                  <li key={g.name} className="flex items-start gap-2">
                    <button
                      type="button"
                      aria-pressed={selected === g.name}
                      onClick={() => {
                        setSelected(g.name);
                        run.reset();
                      }}
                      className={`flex-1 rounded-xl border px-3 py-2 text-left text-sm ${
                        selected === g.name ? "border-primary" : "border-border"
                      }`}
                    >
                      <span className="font-medium text-foreground">{g.name}</span>
                      <span className="block text-xs text-muted-foreground">
                        {g.nodes.length} nodes · canary {nameOf(canaryId)} · {windowText(g.window)}
                      </span>
                    </button>
                    <Button
                      tone="ghost"
                      aria-label={`Delete group ${g.name}`}
                      onClick={() => {
                        update(groups.filter((x) => x.name !== g.name));
                        if (selected === g.name) setSelected(null);
                      }}
                    >
                      Delete
                    </Button>
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>

        {group ? (
          <Panel title={`Run ${group.name}`} subtitle="Renews the certificate once, then installs it on every node">
            <div className="space-y-4">
              <label className="block text-xs text-muted-foreground">
                Certificate fingerprint
                <Input value={fingerprint} onChange={(e) => setFingerprint(e.target.value)} />
              </label>
              <Button
                tone="primary"
                disabled={!fingerprint.trim() || run.isPending}
                onClick={() => setConfirm(true)}
              >
                Run rollout
              </Button>
              {run.error ? (
                <StateMessage tone="error" title="Rollout failed" message={(run.error as Error).message} />
              ) : null}
              {run.data ? <ResultView result={run.data.data} /> : null}
            </div>
            <Dialog open={confirm} title="Run rollout?" onClose={() => setConfirm(false)} size="sm">
              <div className="space-y-3">
                <p className="text-sm">
                  Renews once and installs on {group.nodes.length} nodes, canary first.
                </p>
                <Button
                  tone="primary"
                  disabled={run.isPending}
                  onClick={() => {
                    setConfirm(false);
                    run.mutate(group);
                  }}
                >
                  Confirm rollout
                </Button>
              </div>
            </Dialog>
          </Panel>
        ) : (
          <StateMessage title="No group selected" message="Pick a group to run a rollout." />
        )}
      </div>
    </div>
  );
}
