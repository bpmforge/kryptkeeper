import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { useAuthz, canManageUsers } from "../lib/auth";
import { downloadAuthedFile } from "../lib/api";
import {
  accessReviewApi,
  type AccessReviewEntry,
  type Campaign,
  type Decision,
} from "../lib/accessReviewApi";
import { Badge, Button, Dialog, Input, Panel, Select, StateMessage, formatDateTime } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { scrollableProps } from "../lib/scrollable";
import { humanizeEnum } from "../lib/utils";

const DAY_MS = 86_400_000;

function daysIdle(iso?: string): string {
  if (!iso) return "never active";
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / DAY_MS);
  return `${Math.max(d, 0)} days`;
}

type Draft = { decision: Decision | ""; newRole: string };

function EntryRow({
  entry,
  campaignId,
  locked,
  onSaved,
  onError,
}: {
  entry: AccessReviewEntry;
  campaignId: string;
  locked: boolean;
  onSaved: (e: AccessReviewEntry) => void;
  onError: (msg: string) => void;
}) {
  const [draft, setDraft] = useState<Draft>({ decision: entry.decision ?? "", newRole: entry.new_role ?? "" });
  const scim = entry.source === "scim";
  const roleMissing = draft.decision === "modify" && !draft.newRole.trim();

  const save = useMutation({
    mutationFn: () =>
      accessReviewApi.decide(campaignId, {
        entry_id: entry.entry_id,
        decision: draft.decision as Decision,
        ...(draft.decision === "modify" ? { new_role: draft.newRole.trim() } : {}),
      }),
    onSuccess: (res) => onSaved(res.data),
    onError: (err: Error) => onError(err.message),
  });

  return (
    <tr className="border-t border-border align-top">
      <td className="py-2">{entry.kind === "api_key" ? "API key" : "User"}</td>
      <td className="font-medium text-foreground">
        {entry.name}
        <span className="ml-2 inline-flex gap-1">
          {entry.dormant ? <Badge tone="warning">Dormant</Badge> : null}
          {entry.approver_capable ? <Badge tone="info">Approver</Badge> : null}
        </span>
      </td>
      <td>{entry.role}</td>
      <td>{entry.tenant}</td>
      <td>{entry.source}</td>
      <td>{entry.last_activity_at ? formatDateTime(entry.last_activity_at) : "Never"}</td>
      <td className="space-y-1">
        <Select
          aria-label={`Decision for ${entry.name}`}
          value={draft.decision}
          disabled={locked}
          onChange={(e) => setDraft((d) => ({ ...d, decision: e.target.value as Decision | "" }))}
        >
          <option value="">Select…</option>
          <option value="keep">keep</option>
          <option value="revoke" disabled={scim}>
            revoke
          </option>
          <option value="modify" disabled={scim}>
            modify
          </option>
        </Select>
        {draft.decision === "modify" ? (
          <Input
            aria-label={`New role for ${entry.name}`}
            placeholder="New role"
            value={draft.newRole}
            onChange={(e) => setDraft((d) => ({ ...d, newRole: e.target.value }))}
          />
        ) : null}
        {scim ? <p className="text-xs text-muted-foreground">Managed by SCIM; change it in your IdP</p> : null}
      </td>
      <td className="space-y-1 text-right">
        <Button
          tone="secondary"
          aria-label={`Save decision for ${entry.name}`}
          disabled={locked || !draft.decision || roleMissing || save.isPending}
          onClick={() => save.mutate()}
        >
          Save decision
        </Button>
        {entry.decision_status === "pending_second" ? (
          <p className="text-xs text-state-attn">Waiting for a second reviewer</p>
        ) : entry.decision_status === "decided" ? (
          <p className="text-xs text-state-auto">Decided: {entry.decision}</p>
        ) : null}
      </td>
    </tr>
  );
}

function CampaignDetail({ id }: { id: string }) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [closed, setClosed] = useState<Campaign | null>(null);
  // Keyed by entry_id, not index: the list re-sorts after a refetch.
  const [saved, setSaved] = useState<Record<string, AccessReviewEntry>>({});

  const detail = useQuery({
    queryKey: ["access-review", "campaign", id],
    queryFn: () => accessReviewApi.campaign(id),
  });

  const close = useMutation({
    mutationFn: () => accessReviewApi.close(id, false),
    onSuccess: (res) => {
      setError(null);
      setClosed(res.data);
      void qc.invalidateQueries({ queryKey: ["access-review", "campaigns"] });
      void qc.invalidateQueries({ queryKey: ["access-review", "campaign", id] });
    },
    onError: (err: Error) => setError(err.message),
  });

  if (detail.isLoading) return <StateMessage title="Loading" message="Fetching campaign…" />;
  if (detail.error || !detail.data) {
    return <StateMessage tone="error" title="Unavailable" message="Could not load the campaign." />;
  }

  const campaign = closed ?? detail.data.data;
  const entries = (campaign.entries ?? []).map((e) => saved[e.entry_id] ?? e);
  const undecided = entries.filter((e) => e.decision_status === "undecided").length;
  const isClosed = campaign.status === "closed";

  return (
    <Panel title={campaign.name} subtitle={`Period ${formatDateTime(campaign.period_start)} to ${formatDateTime(campaign.period_end)}`}>
      {error ? <StateMessage tone="error" title="Could not save" message={error} /> : null}
      {entries.length === 0 ? (
        <StateMessage title="No entries" message="This campaign has no principals to review." />
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-muted-foreground">
              <th className="py-2">Kind</th>
              <th>Name</th>
              <th>Role</th>
              <th>Tenant</th>
              <th>Source</th>
              <th>Last activity</th>
              <th>Decision</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <EntryRow
                key={e.entry_id}
                entry={e}
                campaignId={id}
                locked={isClosed}
                onError={setError}
                onSaved={(next) => {
                  setError(null);
                  setSaved((s) => ({ ...s, [e.entry_id]: next }));
                }}
              />
            ))}
          </tbody>
        </table>
      )}
      <div className="mt-4 flex flex-wrap items-center gap-3">
        {isClosed ? (
          <>
            <Badge tone="neutral">Closed</Badge>
            <span className="text-sm">Closed. Export SHA-256: {campaign.report_sha256 ?? "unavailable"}</span>
            <Button
              tone="secondary"
              onClick={() =>
                void downloadAuthedFile(
                  `/admin/access-review/campaigns/${encodeURIComponent(id)}/export?format=csv`,
                  `access-review-${id}.csv`,
                ).catch((err: Error) => setError(err.message))
              }
            >
              Export CSV
            </Button>
          </>
        ) : (
          <>
            <Button tone="primary" disabled={undecided > 0 || close.isPending} onClick={() => close.mutate()}>
              Close campaign
            </Button>
            <span className="text-xs text-muted-foreground">{undecided} undecided</span>
          </>
        )}
      </div>
    </Panel>
  );
}

function ReportSections() {
  const report = useQuery({ queryKey: ["access-review", "report"], queryFn: () => accessReviewApi.report() });
  if (report.isLoading) return <StateMessage title="Loading" message="Fetching report…" />;
  if (report.error || !report.data) {
    return <StateMessage tone="error" title="Unavailable" message="Could not load the access review report." />;
  }
  const r = report.data.data;
  const dormant = r.principals.filter((p) => p.dormant);
  return (
    <>
      <Panel title="Role changes (period)">
        {r.role_changes.length === 0 ? (
          <StateMessage title="None" message="No role changes in this period." />
        ) : (
          <div className="overflow-x-auto" {...scrollableProps}>
          <table className="w-full min-w-[36rem] text-sm">
            <thead>
              <tr className="text-left text-xs text-muted-foreground">
                <th className="py-2">Time</th>
                <th>Action</th>
                <th>Actor</th>
                <th>Resource</th>
              </tr>
            </thead>
            <tbody>
              {r.role_changes.map((c, i) => (
                <tr key={`${c.timestamp}-${i}`} className="border-t border-border">
                  <td className="whitespace-nowrap py-2 pr-3">{formatDateTime(c.timestamp)}</td>
                  <td className="pr-3">{humanizeEnum(c.action)}</td>
                  <td>{c.actor}</td>
                  <td>
                    {c.resource_type}/{c.resource_id}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </Panel>
      <Panel title="Dormant accounts" subtitle={`Idle more than ${r.dormant_days} days`}>
        {dormant.length === 0 ? (
          <StateMessage title="None" message="No dormant accounts." />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted-foreground">
                <th className="py-2">Name</th>
                <th>Role</th>
                <th>Tenant</th>
                <th>Idle</th>
              </tr>
            </thead>
            <tbody>
              {dormant.map((p) => (
                <tr key={`${p.kind}:${p.id}`} className="border-t border-border">
                  <td className="py-2 font-medium text-foreground">{p.name}</td>
                  <td>{p.role}</td>
                  <td>{p.tenant}</td>
                  <td>{daysIdle(p.last_activity_at ?? p.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </>
  );
}

export default function AccessReview() {
  const authz = useAuthz();
  const qc = useQueryClient();
  const allowed = canManageUsers(authz.data?.role, authz.data?.scopes);
  const [selected, setSelected] = useState<string | null>(null);
  const [dialog, setDialog] = useState(false);
  const [name, setName] = useState("");
  const [openError, setOpenError] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ["access-review", "campaigns"],
    queryFn: accessReviewApi.campaigns,
    enabled: allowed,
  });

  const open = useMutation({
    mutationFn: (n: string) => accessReviewApi.open(n),
    onSuccess: (res) => {
      setDialog(false);
      setName("");
      setOpenError(null);
      setSelected(res.data.id);
      void qc.invalidateQueries({ queryKey: ["access-review", "campaigns"] });
    },
    onError: (err: Error) => setOpenError(err.message),
  });

  if (authz.isLoading) return <StateMessage title="Loading" message="Checking permissions…" />;
  if (!allowed) {
    return (
      <div className="p-6">
        <StateMessage tone="error" title="Not permitted" message="Access review is limited to administrators." />
      </div>
    );
  }

  const campaigns = list.data?.data?.items ?? [];
  // Open on the newest open campaign rather than an empty "No campaign
  // selected" panel beside a campaign that exists.
  const shown =
    selected ?? (campaigns.find((c) => c.status !== "closed") ?? campaigns[0])?.id ?? null;

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Administration"
        title="Access Review"
        description="Periodic review of who holds access. Decide each principal, then close the campaign to seal the report."
        actions={
          <Button tone="primary" onClick={() => setDialog(true)}>
            <Plus className="h-4 w-4" />
            Open campaign
          </Button>
        }
      />

      <Dialog open={dialog} title="Open campaign" onClose={() => setDialog(false)} size="sm">
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim()) open.mutate(name.trim());
          }}
        >
          <label className="text-xs text-muted-foreground">
            Campaign name
            <Input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          {openError ? <StateMessage tone="error" title="Could not open" message={openError} /> : null}
          <Button type="submit" tone="primary" disabled={!name.trim() || open.isPending}>
            Start review
          </Button>
        </form>
      </Dialog>

      <div className="grid gap-6 lg:grid-cols-[18rem_1fr]">
        <Panel title="Campaigns">
          {list.isLoading ? (
            <StateMessage title="Loading" message="Fetching campaigns…" />
          ) : list.error ? (
            <StateMessage tone="error" title="Unavailable" message="Could not load campaigns." />
          ) : campaigns.length === 0 ? (
            <StateMessage title="No campaigns" message="Open one to start a review." />
          ) : (
            <ul className="space-y-2">
              {campaigns.map((c) => (
                <li key={c.id}>
                  <button
                    type="button"
                    onClick={() => setSelected(c.id)}
                    className={`flex w-full items-center justify-between rounded-xl border px-3 py-2 text-left text-sm ${
                      shown === c.id ? "border-primary" : "border-border"
                    }`}
                  >
                    <span>{c.name}</span>
                    <Badge tone={c.status === "closed" ? "neutral" : "info"}>{c.status}</Badge>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        {shown ? (
          <CampaignDetail key={shown} id={shown} />
        ) : (
          <StateMessage title="No campaign selected" message="Pick a campaign or open a new one." />
        )}
      </div>

      <ReportSections />
    </div>
  );
}
