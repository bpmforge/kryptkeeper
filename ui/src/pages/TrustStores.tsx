import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api } from "../lib/api";
import type { TrustHostOutcome, TrustHostStatus } from "../lib/api";
import type { AgentInfo } from "../lib/models";
import {
  Badge,
  Button,
  Input,
  Panel,
  StateMessage,
  Textarea,
} from "../components/ui";

const outcomeTone: Record<
  TrustHostOutcome,
  "success" | "warning" | "danger" | "neutral"
> = {
  applied: "success",
  refused_not_opted_in: "warning",
  failed: "danger",
  pending: "neutral",
};

const outcomeLabel: Record<TrustHostOutcome, string> = {
  applied: "applied",
  refused_not_opted_in: "refused: not opted in",
  failed: "failed",
  pending: "waiting for the agent",
};

const platforms = [
  { id: "linux", label: "Linux" },
  { id: "mac", label: "macOS" },
  { id: "windows", label: "Windows" },
];

// W40-03: push CA certificates to agents' OS trust stores. The hub only
// proposes; a second approver decides, and each agent applies the bundle only
// if its own configuration opts in.
export function TrustStoresPanel({ agents }: { agents: AgentInfo[] }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [action, setAction] = useState<"add" | "remove">("add");
  const [pem, setPem] = useState("");
  const [rationale, setRationale] = useState("");
  const [all, setAll] = useState(false);
  const [types, setTypes] = useState<string[]>([]);
  const [ids, setIds] = useState<string[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);

  const bundles = useQuery({
    queryKey: ["trust-bundles"],
    queryFn: () => api.trustBundles(),
  });
  const detail = useQuery({
    queryKey: ["trust-bundle", open],
    queryFn: () => api.trustBundle(open as string),
    enabled: open !== null,
  });

  const propose = useMutation({
    mutationFn: () =>
      api.proposeTrustBundle({
        name,
        action,
        cert_pem: pem,
        rationale,
        selector: { all, agent_types: types, agent_ids: ids },
      }),
    onSuccess: async (res) => {
      setWarnings(res.data.warnings ?? []);
      toast.success(
        `Proposed for ${res.data.targets} agent(s). It takes effect only after a different approver approves it.`,
      );
      setName("");
      setPem("");
      setRationale("");
      await qc.invalidateQueries({ queryKey: ["trust-bundles"] });
    },
  });

  const toggle = (list: string[], set: (v: string[]) => void, v: string) =>
    set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
  const hasTarget = all || types.length > 0 || ids.length > 0;
  const canSubmit = name.trim() !== "" && pem.trim() !== "" && hasTarget;

  return (
    <Panel
      title="Trust stores"
      subtitle="Push root and intermediate CA certificates into managed hosts' OS trust stores"
    >
      <div className="space-y-5" data-testid="trust-stores">
        <p className="text-xs text-muted-foreground">
          A bundle changes what a host trusts, so it needs a second approver in{" "}
          <Link to="/approvals" className="text-primary underline">
            Approvals
          </Link>
          . An agent applies it only if it set{" "}
          <span className="font-mono text-foreground">
            KRYPTKEEPER_TRUST_STORE_PUSH=true
          </span>{" "}
          itself; otherwise it reports "refused: not opted in".
        </p>

        {bundles.isLoading ? (
          <StateMessage title="Loading" message="Fetching trust bundles…" />
        ) : bundles.error ? (
          <StateMessage
            tone="error"
            title="Unavailable"
            message="Could not load trust bundles."
          />
        ) : (bundles.data?.data ?? []).length === 0 ? (
          <StateMessage
            title="No trust bundles"
            message="Approved bundles and their per-host results appear here."
          />
        ) : (
          <div className="space-y-2">
            {(bundles.data?.data ?? []).map((b) => (
              <div
                key={b.id}
                className="rounded-2xl border border-border bg-background/60 p-3"
              >
                <button
                  type="button"
                  className="flex w-full flex-wrap items-center justify-between gap-2 text-left"
                  aria-expanded={open === b.id}
                  onClick={() => setOpen(open === b.id ? null : b.id)}
                >
                  <span className="font-semibold text-foreground">
                    {b.name}{" "}
                    <span className="text-xs font-normal text-muted-foreground">
                      {b.action} &middot; {b.certs.length} certificate(s)
                    </span>
                  </span>
                  <span className="flex flex-wrap gap-1.5">
                    <Badge tone="success">{b.applied} applied</Badge>
                    <Badge tone="warning">
                      {b.refused_not_opted_in} not opted in
                    </Badge>
                    <Badge tone="danger">{b.failed} failed</Badge>
                    <Badge>{b.pending} waiting</Badge>
                  </span>
                </button>
                {open === b.id && (
                  <HostTable
                    hosts={detail.data?.data.hosts}
                    loading={detail.isLoading}
                  />
                )}
              </div>
            ))}
          </div>
        )}

        <form
          className="space-y-3 rounded-2xl border border-border p-4"
          onSubmit={(e) => {
            e.preventDefault();
            propose.mutate();
          }}
        >
          <div className="text-sm font-semibold text-foreground">
            Propose a bundle
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="space-y-1 text-xs text-muted-foreground">
              Name
              <Input
                value={name}
                maxLength={120}
                onChange={(e) => setName(e.target.value)}
                placeholder="Corp Root 2027 rollover"
              />
            </label>
            <fieldset className="space-y-1 text-xs text-muted-foreground">
              <legend>Action</legend>
              <div className="flex gap-4 pt-2 text-sm text-foreground">
                {(["add", "remove"] as const).map((a) => (
                  <label key={a} className="flex items-center gap-1.5">
                    <input
                      type="radio"
                      name="trust-action"
                      checked={action === a}
                      onChange={() => setAction(a)}
                    />
                    {a === "add"
                      ? "Add to trust stores"
                      : "Remove (only what Kryptkeeper added)"}
                  </label>
                ))}
              </div>
            </fieldset>
          </div>
          <label className="block space-y-1 text-xs text-muted-foreground">
            CA certificates (PEM; certificates only, never keys)
            <Textarea
              rows={6}
              value={pem}
              onChange={(e) => setPem(e.target.value)}
              className="font-mono text-xs"
              placeholder="-----BEGIN CERTIFICATE-----"
            />
          </label>
          <fieldset className="space-y-2 text-xs text-muted-foreground">
            <legend>Target agents</legend>
            <div className="flex flex-wrap gap-4 text-sm text-foreground">
              <label className="flex items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={all}
                  onChange={(e) => setAll(e.target.checked)}
                />
                All agents
              </label>
              {platforms.map((p) => (
                <label key={p.id} className="flex items-center gap-1.5">
                  <input
                    type="checkbox"
                    checked={types.includes(p.id)}
                    onChange={() => toggle(types, setTypes, p.id)}
                  />
                  Every {p.label} agent
                </label>
              ))}
            </div>
            {agents.length > 0 && (
              <div className="max-h-32 overflow-y-auto rounded-xl border border-border p-2 text-sm text-foreground">
                {agents.map((a) => (
                  <label key={a.id} className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={ids.includes(a.id)}
                      onChange={() => toggle(ids, setIds, a.id)}
                    />
                    {a.name}{" "}
                    <span className="text-xs text-muted-foreground">
                      ({a.type})
                    </span>
                  </label>
                ))}
              </div>
            )}
          </fieldset>
          <label className="block space-y-1 text-xs text-muted-foreground">
            Why (shown to the approver)
            <Input
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              placeholder="Private CA rollover: new root must land before the old one is retired"
            />
          </label>
          {warnings.length > 0 && (
            <div
              role="alert"
              className="rounded-xl border border-border bg-card p-3 text-sm text-state-attn"
              data-testid="trust-warnings"
            >
              {warnings.map((w) => (
                <div key={w}>{w}</div>
              ))}
            </div>
          )}
          <Button type="submit" disabled={!canSubmit || propose.isPending}>
            {propose.isPending ? "Proposing…" : "Propose for approval"}
          </Button>
        </form>
      </div>
    </Panel>
  );
}

export function HostTable({
  hosts,
  loading,
}: {
  hosts?: TrustHostStatus[];
  loading?: boolean;
}) {
  if (loading || !hosts) {
    return <div className="mt-2 text-xs text-muted-foreground">Loading…</div>;
  }
  return (
    <table className="mt-3 w-full text-left text-xs" data-testid="trust-hosts">
      <thead className="text-muted-foreground">
        <tr>
          <th className="py-1 pr-3 font-medium">Host</th>
          <th className="py-1 pr-3 font-medium">Result</th>
          <th className="py-1 font-medium">Detail</th>
        </tr>
      </thead>
      <tbody>
        {hosts.map((h) => (
          <tr key={h.agent_id} className="border-t border-border">
            <td className="py-1.5 pr-3 text-foreground">
              {h.agent_name || h.agent_id}
            </td>
            <td className="py-1.5 pr-3">
              <Badge tone={outcomeTone[h.outcome]}>
                {outcomeLabel[h.outcome]}
              </Badge>
            </td>
            <td className="py-1.5 text-muted-foreground">{h.detail ?? ""}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
