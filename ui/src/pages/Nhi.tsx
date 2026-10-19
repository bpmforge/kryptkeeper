import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Check, Plus, Trash2, X } from "lucide-react";
import { fetchJSON } from "../lib/api";
import { useAuthz } from "../lib/auth";
import { PERMISSIONS } from "../lib/rolesApi";
import {
  Badge,
  Button,
  Dialog,
  Input,
  Panel,
  Select,
  StateMessage,
} from "../components/ops-ui";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

// The /nhi routes have no response schemas in openapi, so the wire shapes are
// defined here (see internal/bootstrap/nhi_identity.go).
type NhiStatus = "pending" | "approved" | "rejected" | "revoked";
type NhiKind = "ai_agent" | "service_account" | "workflow";

type Nhi = {
  id: string;
  name: string;
  kind: NhiKind;
  spiffe_id: string;
  scopes: string[];
  status: NhiStatus;
  created_by: string;
  decided_by?: string;
  created_at: string;
  decided_at?: string;
};

type ApproveResult = {
  id: string;
  spiffe_id: string;
  join_token: string;
  token_expires_at: string;
};

const KINDS: NhiKind[] = ["ai_agent", "service_account", "workflow"];
const NAME_RE = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;
const QUERY_KEY = ["nhi-identities"];

function statusTone(
  s: NhiStatus,
): "warning" | "success" | "danger" | "neutral" {
  switch (s) {
    case "pending":
      return "warning";
    case "approved":
      return "success";
    case "revoked":
      return "danger";
    default:
      return "neutral";
  }
}

export default function Nhi() {
  const authz = useAuthz();
  const queryClient = useQueryClient();
  const principal = authz.data?.principal;

  const list = useQuery({
    queryKey: QUERY_KEY,
    queryFn: () => fetchJSON<{ data: Nhi[] }>("/nhi/identities"),
    retry: false,
  });
  const items: Nhi[] = list.data?.data ?? [];
  const forbidden = (list.error as { status?: number } | null)?.status === 403;

  const [proposeOpen, setProposeOpen] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<NhiKind>("ai_agent");
  const [scopes, setScopes] = useState<string[]>([]);
  const [formError, setFormError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<Nhi | null>(null);
  // The join token lives ONLY here: never in the query cache, storage or URL.
  const [issued, setIssued] = useState<ApproveResult | null>(null);

  const refresh = () => queryClient.invalidateQueries({ queryKey: QUERY_KEY });
  const nameValid = NAME_RE.test(name);
  const canSubmit = nameValid && scopes.length > 0;

  const proposeMutation = useMutation({
    mutationFn: () =>
      fetchJSON<{ data: Nhi }>("/nhi/identities", {
        method: "POST",
        body: JSON.stringify({ name, kind, scopes }),
      }),
    onSuccess: () => {
      setProposeOpen(false);
      setName("");
      setScopes([]);
      setFormError(null);
    },
    onError: (e) =>
      setFormError(e instanceof Error ? e.message : "Identity not proposed."),
    onSettled: refresh,
  });
  const approveMutation = useMutation({
    mutationFn: (id: string) =>
      fetchJSON<{ data: ApproveResult }>(
        `/nhi/identities/${encodeURIComponent(id)}/approve`,
        { method: "POST" },
      ),
    onSuccess: (res) => setIssued(res.data),
    onSettled: refresh,
  });
  const rejectMutation = useMutation({
    mutationFn: (id: string) =>
      fetchJSON<void>(`/nhi/identities/${encodeURIComponent(id)}/reject`, {
        method: "POST",
      }),
    onSettled: refresh,
  });
  const revokeMutation = useMutation({
    mutationFn: (id: string) =>
      fetchJSON<void>(`/nhi/identities/${encodeURIComponent(id)}/revoke`, {
        method: "POST",
      }),
    onSuccess: () => setRevoking(null),
    onSettled: refresh,
  });

  const toggleScope = (p: string) =>
    setScopes((cur) =>
      cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p],
    );
  const actionError =
    approveMutation.error ?? rejectMutation.error ?? revokeMutation.error;

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Trust"
        title="Machine Identities"
        description="Non-human identities (AI agents, service accounts, workflows). A different person must approve each proposal before a one-time join token is issued."
        actions={
          <Button
            tone="primary"
            onClick={() => {
              setFormError(null);
              setProposeOpen(true);
            }}
          >
            <Plus size={13} aria-hidden="true" />
            Propose identity
          </Button>
        }
      />

      {actionError ? (
        <StateMessage
          tone="error"
          title="Identity action failed"
          message={
            actionError instanceof Error
              ? actionError.message
              : "The action could not be completed."
          }
        />
      ) : null}

      <Panel title="Identities">
        {list.isLoading ? (
          <StateMessage title="Loading" message="Fetching identities…" />
        ) : forbidden ? (
          <StateMessage
            tone="error"
            title="Not permitted"
            message="Machine identities need an authenticated role with access."
          />
        ) : list.error ? (
          <StateMessage
            tone="error"
            title="Unavailable"
            message="Identities could not be loaded."
          />
        ) : items.length === 0 ? (
          <EmptyState
            icon={<Bot size={20} aria-hidden="true" />}
            title="No machine identities yet"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="text-xs text-muted-foreground">
                  <th className="py-2 pr-3">Name</th>
                  <th className="py-2 pr-3">Kind</th>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Scopes</th>
                  <th className="py-2 pr-3">Proposed by</th>
                  <th className="py-2 pr-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((n) => {
                  const isProposer = !!principal && principal === n.created_by;
                  return (
                    <tr key={n.id} className="border-t border-border align-top">
                      <td className="py-2 pr-3 font-medium text-foreground">
                        {n.name}
                        <div className="text-xs font-normal text-muted-foreground">
                          {n.spiffe_id}
                        </div>
                      </td>
                      <td className="py-2 pr-3">{n.kind}</td>
                      <td className="py-2 pr-3">
                        <Badge tone={statusTone(n.status)}>{n.status}</Badge>
                      </td>
                      <td className="py-2 pr-3">
                        <div className="flex flex-wrap gap-1">
                          {n.scopes.map((s) => (
                            <Badge key={s} tone="info">
                              {s}
                            </Badge>
                          ))}
                        </div>
                      </td>
                      <td className="py-2 pr-3">{n.created_by}</td>
                      <td className="py-2 pr-3">
                        <div className="flex flex-wrap gap-2">
                          {n.status === "pending" ? (
                            <>
                              <span
                                title={
                                  isProposer
                                    ? "You proposed this identity; a different approver is required"
                                    : undefined
                                }
                              >
                                <Button
                                  tone="primary"
                                  disabled={
                                    isProposer || approveMutation.isPending
                                  }
                                  onClick={() => approveMutation.mutate(n.id)}
                                  aria-label={`Approve ${n.name}`}
                                >
                                  <Check size={13} aria-hidden="true" />
                                  Approve
                                </Button>
                              </span>
                              <Button
                                tone="secondary"
                                disabled={rejectMutation.isPending}
                                onClick={() => rejectMutation.mutate(n.id)}
                                aria-label={`Reject ${n.name}`}
                              >
                                <X size={13} aria-hidden="true" />
                                Reject
                              </Button>
                            </>
                          ) : null}
                          {n.status !== "revoked" ? (
                            <Button
                              tone="danger"
                              onClick={() => setRevoking(n)}
                              aria-label={`Revoke ${n.name}`}
                            >
                              <Trash2 size={13} aria-hidden="true" />
                              Revoke
                            </Button>
                          ) : null}
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

      <Dialog
        open={proposeOpen}
        title="Propose machine identity"
        description="Scopes come from the shared permission vocabulary and are resolved by SPIFFE ID at request time."
        onClose={() => setProposeOpen(false)}
      >
        <form
          className="space-y-3"
          noValidate
          onSubmit={(e) => {
            e.preventDefault();
            if (canSubmit) proposeMutation.mutate();
          }}
        >
          {formError ? (
            <StateMessage
              tone="error"
              title="Identity not proposed"
              message={formError}
            />
          ) : null}
          <label className="block space-y-1 text-sm text-foreground">
            <span>Name</span>
            <Input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          {name && !nameValid ? (
            <p className="text-xs text-state-over">
              Use lowercase letters, digits and hyphens (no leading or trailing
              hyphen).
            </p>
          ) : null}
          <label className="block space-y-1 text-sm text-foreground">
            <span>Kind</span>
            <Select
              value={kind}
              onChange={(e) => setKind(e.target.value as NhiKind)}
            >
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </Select>
          </label>
          <fieldset className="space-y-1">
            <legend className="text-sm text-foreground">Scopes</legend>
            <div className="grid gap-1 sm:grid-cols-2">
              {PERMISSIONS.map((p) => (
                <label
                  key={p}
                  className="flex items-center gap-2 text-xs text-foreground"
                >
                  <input
                    type="checkbox"
                    checked={scopes.includes(p)}
                    onChange={() => toggleScope(p)}
                  />
                  {p}
                </label>
              ))}
            </div>
          </fieldset>
          <div className="flex justify-end gap-2 pt-2">
            <Button tone="secondary" onClick={() => setProposeOpen(false)}>
              Cancel
            </Button>
            <Button
              tone="primary"
              type="submit"
              disabled={!canSubmit || proposeMutation.isPending}
            >
              Propose
            </Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={issued !== null}
        title="Join token"
        description="This token is shown once. Redeem it at /api/v1/spiffe/workload-svid."
        onClose={() => setIssued(null)}
        size="sm"
      >
        <div className="space-y-3">
          <code className="block break-all rounded-md bg-muted p-2 text-xs">
            {issued?.join_token}
          </code>
          <p className="text-xs text-muted-foreground">
            {issued?.spiffe_id}
            {issued?.token_expires_at
              ? ` · expires ${issued.token_expires_at}`
              : ""}
          </p>
          <div className="flex justify-end">
            <Button tone="primary" onClick={() => setIssued(null)}>
              Done
            </Button>
          </div>
        </div>
      </Dialog>

      <Dialog
        open={revoking !== null}
        title={`Revoke ${revoking?.name ?? "identity"}?`}
        description="Its SVIDs are refused within 60 s; this cannot be undone. A new proposal is required."
        onClose={() => setRevoking(null)}
        size="sm"
      >
        <div className="flex justify-end gap-2">
          <Button tone="secondary" onClick={() => setRevoking(null)}>
            Keep identity
          </Button>
          <Button
            tone="danger"
            disabled={revokeMutation.isPending}
            onClick={() => revoking && revokeMutation.mutate(revoking.id)}
          >
            Revoke
          </Button>
        </div>
      </Dialog>
    </div>
  );
}
