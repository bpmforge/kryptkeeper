import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Gavel, Plus, X } from "lucide-react";
import { api } from "../lib/api";
import { useAuthz } from "../lib/auth";
import type { Ceremony, StartCeremonyRequest } from "../lib/models";
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
import { formatDateTime } from "../components/ui";
import { humanizeEnum } from "../lib/utils";

const ALGORITHMS = [
  "ECDSA-P256",
  "ECDSA-P384",
  "RSA-2048",
  "RSA-4096",
  "Ed25519",
  "ML-DSA-65",
];

const QUORUM_ERROR =
  "Quorum must be at least 2 and no more than the number of approvers.";

function statusTone(
  s: Ceremony["status"],
): "warning" | "success" | "danger" | "neutral" {
  switch (s) {
    case "pending":
      return "warning";
    case "completed":
      return "success";
    case "expired":
      return "danger";
    default:
      return "neutral";
  }
}

function parseApprovers(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(",")
        .map((v) => v.trim())
        .filter(Boolean),
    ),
  );
}

type StartForm = {
  name: string;
  commonName: string;
  algorithm: string;
  validityDays: string;
  approvers: string;
  quorum: string;
};

const emptyForm: StartForm = {
  name: "",
  commonName: "",
  algorithm: "ECDSA-P256",
  validityDays: "3650",
  approvers: "",
  quorum: "2",
};

function QuorumProgress({ c }: { c: Ceremony }) {
  const pct = Math.min(100, (c.approvals.length / Math.max(c.quorum, 1)) * 100);
  return (
    <div className="space-y-1">
      <div className="text-xs text-foreground">
        {c.approvals.length} of {c.quorum} approvals
      </div>
      <div
        role="progressbar"
        aria-label={`Approvals for ${c.ca_name || c.id}`}
        aria-valuemin={0}
        aria-valuemax={c.quorum}
        aria-valuenow={c.approvals.length}
        className="h-1.5 w-full overflow-hidden rounded-full bg-muted"
      >
        <div className="h-full bg-primary" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export default function Ceremonies() {
  const authz = useAuthz();
  const queryClient = useQueryClient();
  const principal = authz.data?.principal;
  const isAdmin = authz.data?.role === "pki-admin";

  const list = useQuery({
    queryKey: ["ceremonies"],
    queryFn: api.ceremonies,
    refetchInterval: 15_000,
    retry: false,
  });
  const ceremonies: Ceremony[] = list.data?.data ?? [];
  const forbidden = (list.error as { status?: number } | null)?.status === 403;

  const [startOpen, setStartOpen] = useState(false);
  const [form, setForm] = useState<StartForm>(emptyForm);
  const [formError, setFormError] = useState<string | null>(null);
  const [aborting, setAborting] = useState<Ceremony | null>(null);

  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ["ceremonies"] });

  const startMutation = useMutation({
    mutationFn: (body: StartCeremonyRequest) => api.startCeremony(body),
    onSuccess: async () => {
      setStartOpen(false);
      setForm(emptyForm);
      setFormError(null);
      await refresh();
    },
    onError: (e) =>
      setFormError(e instanceof Error ? e.message : "Ceremony not started."),
  });
  const approveMutation = useMutation({
    mutationFn: (id: string) => api.approveCeremony(id),
    // A stale list is the usual cause of a refused approval; refresh either way.
    onSettled: refresh,
  });
  const abortMutation = useMutation({
    mutationFn: (id: string) => api.abortCeremony(id),
    onSuccess: () => setAborting(null),
    onSettled: refresh,
  });

  function submitStart() {
    const approvers = parseApprovers(form.approvers);
    const quorum = Number(form.quorum);
    if (!Number.isInteger(quorum) || quorum < 2 || quorum > approvers.length) {
      setFormError(QUORUM_ERROR);
      return;
    }
    setFormError(null);
    startMutation.mutate({
      name: form.name.trim(),
      common_name: form.commonName.trim(),
      algorithm: form.algorithm,
      validity_days: Number(form.validityDays),
      approvers,
      quorum,
    });
  }

  const actionError = approveMutation.error ?? abortMutation.error;

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Trust"
        title="Key Ceremonies"
        description="M-of-N activation of new root CAs: distinct designated humans must each approve before the CA can issue."
        actions={
          isAdmin ? (
            <Button
              tone="primary"
              onClick={() => {
                setFormError(null);
                setStartOpen(true);
              }}
            >
              <Plus size={13} aria-hidden="true" />
              Start ceremony
            </Button>
          ) : null
        }
      />

      {actionError ? (
        <StateMessage
          tone="error"
          title="Ceremony action failed"
          message={
            actionError instanceof Error
              ? actionError.message
              : "The action could not be completed."
          }
        />
      ) : null}

      <Panel title="Ceremonies">
        {list.isLoading ? (
          <StateMessage title="Loading" message="Fetching ceremonies…" />
        ) : forbidden ? (
          <StateMessage
            tone="error"
            title="Not permitted"
            message="Key ceremonies need an administrator role."
          />
        ) : list.error ? (
          <StateMessage
            tone="error"
            title="Unavailable"
            message="Ceremonies could not be loaded."
          />
        ) : ceremonies.length === 0 ? (
          <EmptyState
            icon={<Gavel size={20} aria-hidden="true" />}
            title="No ceremonies yet"
          />
        ) : (
          <ul className="space-y-3">
            {ceremonies.map((c) => {
              const alreadyApproved =
                !!principal && c.approvals.includes(principal);
              const eligible = !principal || c.approvers.includes(principal);
              const approveTitle = alreadyApproved
                ? "You have already approved"
                : !eligible
                  ? principal === c.initiator
                    ? "You started this ceremony and are not a designated approver"
                    : "You are not a designated approver"
                  : undefined;
              return (
                <li
                  key={c.id}
                  className="rounded-xl border border-border bg-card/40 p-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium text-foreground">
                        {c.ca_name || c.id}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {c.common_name}
                      </span>
                      <Badge tone="info">{c.algorithm}</Badge>
                      <Badge tone={statusTone(c.status)}>{humanizeEnum(c.status)}</Badge>
                    </div>
                    {c.status === "pending" ? (
                      <div className="flex items-center gap-2">
                        {approveTitle ? (
                          <span className="text-xs text-muted-foreground">
                            {approveTitle}
                          </span>
                        ) : null}
                        <span title={approveTitle}>
                          <Button
                            tone="primary"
                            onClick={() => approveMutation.mutate(c.id)}
                            disabled={
                              approveMutation.isPending ||
                              alreadyApproved ||
                              !eligible
                            }
                            aria-label={`Approve ${c.ca_name || c.id}`}
                          >
                            <Check size={13} aria-hidden="true" />
                            Approve
                          </Button>
                        </span>
                        {isAdmin ? (
                          <Button
                            tone="danger"
                            onClick={() => setAborting(c)}
                            aria-label={`Abort ${c.ca_name || c.id}`}
                          >
                            <X size={13} aria-hidden="true" />
                            Abort
                          </Button>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                  <div className="mt-2 grid gap-3 sm:grid-cols-2">
                    <QuorumProgress c={c} />
                    <ul
                      aria-label="Approvers"
                      className="flex flex-wrap content-start gap-1.5 text-xs"
                    >
                      {c.approvers.map((a) => {
                        const done = c.approvals.includes(a);
                        return (
                          <li
                            key={a}
                            className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 ${
                              done
                                ? "border-state-auto/40 text-state-auto"
                                : "border-border text-muted-foreground"
                            }`}
                          >
                            {a}
                            <span className="sr-only">
                              {done ? " (approved)" : " (pending)"}
                            </span>
                            {done ? <Check size={11} aria-hidden="true" /> : null}
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                    <span>Initiator {c.initiator}</span>
                    <span>Created {formatDateTime(c.created_at)}</span>
                    {c.expires_at ? (
                      <span>Expires {formatDateTime(c.expires_at)}</span>
                    ) : null}
                    <Link
                      className="underline font-mono"
                      to={`/cas/${c.ca_id}`}
                      title={c.ca_id}
                    >
                      {c.ca_id.slice(0, 8)}
                    </Link>
                  </div>
                  {c.status === "expired" ? (
                    <p className="mt-2 text-xs text-state-over">
                      Expired: the parked CA was never activated.
                    </p>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </Panel>

      <Dialog
        open={startOpen}
        title="Start key ceremony"
        description="Creates a root CA parked until the quorum of approvers has approved."
        onClose={() => setStartOpen(false)}
      >
        <form
          className="space-y-3"
          noValidate
          onSubmit={(e) => {
            e.preventDefault();
            submitStart();
          }}
        >
          {formError ? (
            <StateMessage
              tone="error"
              title="Ceremony not started"
              message={formError}
            />
          ) : null}
          <label className="block space-y-1 text-sm text-foreground">
            <span>Name</span>
            <Input
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Common name</span>
            <Input
              value={form.commonName}
              onChange={(e) =>
                setForm((f) => ({ ...f, commonName: e.target.value }))
              }
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Algorithm</span>
            <Select
              value={form.algorithm}
              onChange={(e) =>
                setForm((f) => ({ ...f, algorithm: e.target.value }))
              }
            >
              {ALGORITHMS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </Select>
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Validity days</span>
            <Input
              type="number"
              min={1}
              value={form.validityDays}
              onChange={(e) =>
                setForm((f) => ({ ...f, validityDays: e.target.value }))
              }
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Approvers</span>
            <Input
              value={form.approvers}
              placeholder="alice, bob, carol"
              onChange={(e) =>
                setForm((f) => ({ ...f, approvers: e.target.value }))
              }
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Quorum</span>
            <Input
              type="number"
              min={2}
              value={form.quorum}
              onChange={(e) =>
                setForm((f) => ({ ...f, quorum: e.target.value }))
              }
            />
          </label>
          <div className="flex justify-end gap-2 pt-2">
            <Button tone="secondary" onClick={() => setStartOpen(false)}>
              Cancel
            </Button>
            <Button
              tone="primary"
              type="submit"
              disabled={startMutation.isPending}
            >
              Start
            </Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={aborting !== null}
        title="Abort ceremony?"
        description={`Aborting leaves ${aborting?.ca_name || aborting?.id || "the CA"} permanently unusable.`}
        onClose={() => setAborting(null)}
        size="sm"
      >
        <div className="flex justify-end gap-2">
          <Button tone="secondary" onClick={() => setAborting(null)}>
            Keep ceremony
          </Button>
          <Button
            tone="danger"
            disabled={abortMutation.isPending}
            onClick={() => aborting && abortMutation.mutate(aborting.id)}
          >
            Confirm abort
          </Button>
        </div>
      </Dialog>
    </div>
  );
}
