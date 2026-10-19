import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { useAuthz, canManageUsers } from "../lib/auth";
import {
  POLICY_ALGORITHMS,
  isPendingChange,
  policiesApi,
  type DryRunInput,
  type DryRunResult,
  type Policy,
  type PolicyRules,
  type PolicyWrite,
} from "../lib/policiesApi";
import { Badge, Button, Input, Panel, Select, StateMessage } from "../components/ui";
import { ruleChips } from "../lib/pageHelpers";
import { PageHeader } from "../components/PageHeader";
import { useCaNames } from "../lib/useResourceNames";
import { scrollableProps } from "../lib/scrollable";

type FormState = {
  name: string;
  enabled: boolean;
  ca_id: string;
  algorithms: string;
  min_rsa_bits: string;
  max_validity_days: string;
  allow_ca_certs: boolean;
};

function toForm(p?: Policy): FormState {
  return {
    name: p?.name ?? "",
    enabled: p?.enabled ?? true,
    ca_id: p?.ca_id ?? "",
    algorithms: (p?.rules.allowed_algorithms ?? []).join(", "),
    min_rsa_bits: p?.rules.min_rsa_bits ? String(p.rules.min_rsa_bits) : "",
    max_validity_days: p?.rules.max_validity_days ? String(p.rules.max_validity_days) : "",
    allow_ca_certs: p?.rules.allow_ca_certs ?? false,
  };
}

function formRules(f: FormState): PolicyRules {
  const algs = f.algorithms.split(",").map((a) => a.trim()).filter(Boolean);
  return {
    ...(algs.length ? { allowed_algorithms: algs } : {}),
    ...(f.min_rsa_bits ? { min_rsa_bits: Number(f.min_rsa_bits) } : {}),
    ...(f.max_validity_days ? { max_validity_days: Number(f.max_validity_days) } : {}),
    ...(f.allow_ca_certs ? { allow_ca_certs: true } : {}),
  };
}

// Client checks mirror the server's validation so a typo fails before the
// round trip; the server stays authoritative and its 400 text is shown as is.
function validate(f: FormState): string | null {
  if (!f.name.trim()) return "Name is required";
  for (const [label, v] of [
    ["Min RSA bits", f.min_rsa_bits],
    ["Max validity days", f.max_validity_days],
  ] as const) {
    if (v !== "" && (!Number.isFinite(Number(v)) || Number(v) < 0)) {
      return `${label} must be a non-negative number`;
    }
  }
  return null;
}

// Edit sends only what changed so a PATCH never restates (and so never
// accidentally loosens) fields the operator did not touch.
function diffPatch(orig: Policy, f: FormState): PolicyWrite {
  const patch: PolicyWrite = {};
  if (f.name.trim() !== orig.name) patch.name = f.name.trim();
  if (f.enabled !== orig.enabled) patch.enabled = f.enabled;
  if (f.ca_id.trim() !== orig.ca_id) patch.ca_id = f.ca_id.trim();
  const next = formRules(f);
  if (JSON.stringify(next) !== JSON.stringify(orig.rules ?? {})) patch.rules = next;
  return patch;
}

function PolicyForm({
  initial,
  busy,
  onSubmit,
  onCancel,
}: {
  initial?: Policy;
  busy: boolean;
  onSubmit: (f: FormState) => void;
  onCancel: () => void;
}) {
  const [f, setF] = useState<FormState>(toForm(initial));
  const [err, setErr] = useState<string | null>(null);
  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setF((p) => ({ ...p, [k]: v }));

  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        const v = validate(f);
        setErr(v);
        if (!v) onSubmit(f);
      }}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="text-xs text-muted-foreground">
          Name
          <Input value={f.name} onChange={(e) => set("name", e.target.value)} />
        </label>
        <label className="text-xs text-muted-foreground">
          CA id (blank = all CAs)
          <Input value={f.ca_id} onChange={(e) => set("ca_id", e.target.value)} />
        </label>
        <label className="text-xs text-muted-foreground sm:col-span-2">
          Allowed algorithms (comma separated; blank = any)
          <Input
            value={f.algorithms}
            onChange={(e) => set("algorithms", e.target.value)}
            placeholder={POLICY_ALGORITHMS.slice(0, 3).join(", ")}
          />
        </label>
        <label className="text-xs text-muted-foreground">
          Min RSA bits
          <Input inputMode="numeric" value={f.min_rsa_bits} onChange={(e) => set("min_rsa_bits", e.target.value)} />
        </label>
        <label className="text-xs text-muted-foreground">
          Max validity days
          <Input
            inputMode="numeric"
            value={f.max_validity_days}
            onChange={(e) => set("max_validity_days", e.target.value)}
          />
        </label>
      </div>
      <div className="flex flex-wrap gap-4 text-sm text-foreground">
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} />
          Enabled
        </label>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={f.allow_ca_certs}
            onChange={(e) => set("allow_ca_certs", e.target.checked)}
          />
          Allow CA certificates
        </label>
      </div>
      {err ? (
        <p role="alert" className="text-xs text-state-over">
          {err}
        </p>
      ) : null}
      <div className="flex gap-2">
        <Button type="submit" tone="primary" disabled={busy}>
          {initial ? "Save changes" : "Create policy"}
        </Button>
        <Button tone="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

function DryRunPanel() {
  const [algorithm, setAlgorithm] = useState("");
  const [rsaBits, setRsaBits] = useState("");
  const [validity, setValidity] = useState("365");
  const [isCA, setIsCA] = useState(false);
  const [caId, setCaId] = useState("");
  const [result, setResult] = useState<DryRunResult | null>(null);

  const run = useMutation({
    mutationFn: (input: DryRunInput) => policiesApi.dryRun(input),
    onSuccess: (res) => setResult(res.data),
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <Panel title="Dry run" subtitle="Check a request against the enabled policies without issuing anything">
      <div className="grid gap-3 sm:grid-cols-4">
        <label className="text-xs text-muted-foreground">
          Algorithm
          <Select value={algorithm} onChange={(e) => setAlgorithm(e.target.value)}>
            <option value="">Select…</option>
            {POLICY_ALGORITHMS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </Select>
        </label>
        <label className="text-xs text-muted-foreground">
          RSA bits
          <Input inputMode="numeric" value={rsaBits} onChange={(e) => setRsaBits(e.target.value)} />
        </label>
        <label className="text-xs text-muted-foreground">
          Validity days
          <Input inputMode="numeric" value={validity} onChange={(e) => setValidity(e.target.value)} />
        </label>
        <label className="text-xs text-muted-foreground">
          CA id
          <Input value={caId} onChange={(e) => setCaId(e.target.value)} />
        </label>
      </div>
      <div className="mt-3 flex items-center gap-4">
        <label className="flex items-center gap-2 text-sm text-foreground">
          <input type="checkbox" checked={isCA} onChange={(e) => setIsCA(e.target.checked)} />
          Request is a CA certificate
        </label>
        <Button
          tone="primary"
          disabled={run.isPending || !algorithm}
          onClick={() =>
            run.mutate({
              ...(caId.trim() ? { ca_id: caId.trim() } : {}),
              algorithm,
              ...(rsaBits ? { rsa_bits: Number(rsaBits) } : {}),
              validity_days: Number(validity) || 0,
              is_ca: isCA,
            })
          }
        >
          Run dry run
        </Button>
      </div>
      {result ? (
        <div className="mt-4" aria-live="polite">
          {result.allowed ? (
            <Badge tone="success">Allowed</Badge>
          ) : (
            <div className="space-y-2">
              <Badge tone="danger">Refused</Badge>
              {result.violations.map((v, i) => (
                <div key={`${v.policy_id}-${v.rule}-${i}`} className="rounded-xl border border-border p-3 text-sm">
                  <div>
                    <span className="text-muted-foreground">Policy</span> <span>{v.policy}</span> /{" "}
                    <span className="text-muted-foreground">Rule</span> <span>{v.rule}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Observed</span> <span>{v.observed}</span>
                  </div>
                  <div className="text-xs text-muted-foreground">{v.detail}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : null}
    </Panel>
  );
}

export default function Policies() {
  const authz = useAuthz();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Policy | "new" | null>(null);
  const [pending, setPending] = useState(false);
  const allowed = canManageUsers(authz.data?.role, authz.data?.scopes);
  const { names: caNames } = useCaNames();

  const list = useQuery({
    queryKey: ["policies"],
    queryFn: policiesApi.list,
    enabled: allowed,
  });

  const create = useMutation({
    mutationFn: (body: PolicyWrite) => policiesApi.create(body),
    onSuccess: () => {
      toast.success("Policy created");
      setEditing(null);
      void qc.invalidateQueries({ queryKey: ["policies"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });
  const update = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: PolicyWrite }) => policiesApi.update(id, patch),
    onSuccess: (res) => {
      if (isPendingChange(res?.data)) {
        // Do not touch the row: the change only applies once a second approver agrees.
        toast.success("Loosening needs a second approver");
        setPending(true);
      } else {
        toast.success("Policy updated");
        void qc.invalidateQueries({ queryKey: ["policies"] });
      }
      setEditing(null);
    },
    onError: (err: Error) => toast.error(err.message),
  });
  const remove = useMutation({
    mutationFn: (id: string) => policiesApi.remove(id),
    onSuccess: () => {
      toast.success("Policy deleted");
      void qc.invalidateQueries({ queryKey: ["policies"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  if (authz.isLoading) {
    return <StateMessage title="Loading" message="Checking permissions…" />;
  }
  if (!allowed) {
    return (
      <div className="p-6">
        <StateMessage tone="error" title="Not permitted" message="Managing issuance policies needs an administrator." />
      </div>
    );
  }

  const policies = list.data?.data ?? [];

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Administration"
        title="Issuance policies"
        description="Rules every issuance, including ACME and EST, is checked against. A refusal names the policy and the rule."
        actions={
          <div className="flex gap-2">
            <Button tone="secondary" onClick={() => void list.refetch()} disabled={list.isFetching}>
              <RefreshCw className={`h-4 w-4 ${list.isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <Button tone="primary" onClick={() => setEditing("new")}>
              <Plus className="h-4 w-4" />
              New policy
            </Button>
          </div>
        }
      />

      {pending ? <Badge tone="warning">Pending approval</Badge> : null}

      {editing ? (
        <Panel title={editing === "new" ? "New policy" : `Edit ${editing.name}`}>
          <PolicyForm
            key={editing === "new" ? "new" : editing.id}
            initial={editing === "new" ? undefined : editing}
            busy={create.isPending || update.isPending}
            onCancel={() => setEditing(null)}
            onSubmit={(f) => {
              if (editing === "new") {
                create.mutate({
                  name: f.name.trim(),
                  enabled: f.enabled,
                  ca_id: f.ca_id.trim(),
                  rules: formRules(f),
                });
              } else {
                const patch = diffPatch(editing, f);
                if (Object.keys(patch).length === 0) {
                  setEditing(null);
                  return;
                }
                update.mutate({ id: editing.id, patch });
              }
            }}
          />
        </Panel>
      ) : null}

      <Panel title="Policies">
        {list.isLoading ? (
          <StateMessage title="Loading" message="Fetching policies…" />
        ) : list.error ? (
          <StateMessage tone="error" title="Unavailable" message="Could not load policies." />
        ) : policies.length === 0 ? (
          <StateMessage title="No policies" message="Nothing restricts issuance yet." />
        ) : (
          <div className="overflow-x-auto" {...scrollableProps}>
            <table className="w-full min-w-[40rem] text-sm">
              <thead>
                <tr className="text-left text-xs text-muted-foreground">
                  <th className="py-2 pr-4">Name</th>
                  <th className="pr-4">Scope</th>
                  <th className="pr-4">Status</th>
                  <th className="pr-4">Rules</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => {
                  const chips = ruleChips(p.rules ?? {});
                  return (
                    <tr key={p.id} className="border-t border-border align-middle">
                      <td className="py-2 pr-4 font-medium text-foreground">{p.name}</td>
                      <td className="pr-4" title={p.ca_id || undefined}>
                        {p.ca_id ? (caNames.get(p.ca_id) ?? p.ca_id) : "All CAs"}
                      </td>
                      <td className="pr-4">
                        <Badge tone={p.enabled ? "success" : "neutral"}>{p.enabled ? "Enabled" : "Disabled"}</Badge>
                      </td>
                      <td className="pr-4 min-w-[14rem]">
                        {chips.length ? (
                          <ul className="flex flex-wrap gap-1">
                            {chips.map((c) => (
                              <li key={c} className="rounded-md border border-border px-1.5 py-0.5 text-xs text-muted-foreground">
                                {c}
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <span className="text-muted-foreground">No restrictions</span>
                        )}
                      </td>
                      <td className="py-2 text-right">
                        <div className="flex justify-end gap-2 whitespace-nowrap">
                          <Button tone="secondary" aria-label={`Edit ${p.name}`} onClick={() => setEditing(p)}>
                            Edit
                          </Button>
                          <Button
                            tone="danger"
                            aria-label={`Delete ${p.name}`}
                            disabled={remove.isPending}
                            onClick={() => {
                              if (window.confirm(`Delete policy "${p.name}"?`)) remove.mutate(p.id);
                            }}
                          >
                            Delete
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <DryRunPanel />
    </div>
  );
}
