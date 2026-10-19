import { useState } from "react";
import { scrollableProps } from "../lib/scrollable";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import {
  api,
  type MigrationBatch,
  type MigrationDiff,
  type MigrationDiffEntry,
  type MigrationRequest,
} from "../lib/api";
import {
  Badge,
  Button,
  Dialog,
  Input,
  Panel,
  Select,
  StateMessage,
  Textarea,
  formatDateTime,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";

const MAX_BYTES = 48 * 1024;

const ACTION_TONE = {
  create: "success",
  skip: "neutral",
  conflict: "warning",
  update: "info",
} as const;

const FIELD_TONE = {
  mapped: "success",
  partial: "warning",
  unmapped: "danger",
} as const;

function capitalise(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function fieldSummary(e: MigrationDiffEntry): string {
  const n = (st: string) => e.fields.filter((f) => f.status === st).length;
  return `${n("mapped")} mapped / ${n("partial")} partial / ${n("unmapped")} unmapped`;
}

function DiffTable({ diff }: { diff: MigrationDiff }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <Badge tone="success">{diff.counts.create} create</Badge>
        <Badge>{diff.counts.skip} skip</Badge>
        <Badge tone="info">{diff.counts.update ?? 0} update</Badge>
        <Badge tone="warning">{diff.counts.conflict} conflict</Badge>
        <Badge tone="danger">{diff.unmapped} unmapped fields</Badge>
      </div>
      <div className="overflow-x-auto" {...scrollableProps}>
        <table className="w-full text-left text-sm">
          <thead className="text-xs text-muted-foreground">
            <tr>
              <th className="pb-2 pr-3">Name</th>
              <th className="pb-2 pr-3">Action</th>
              <th className="pb-2 pr-3">Reason</th>
              <th className="pb-2">Fields</th>
            </tr>
          </thead>
          <tbody>
            {diff.entries.map((e) => (
              <tr key={e.source_key} className="border-t border-border align-top">
                <td className="py-2 pr-3 font-medium text-foreground">{e.name}</td>
                <td className="py-2 pr-3">
                  <Badge tone={ACTION_TONE[e.action]}>{e.action}</Badge>
                </td>
                <td className="py-2 pr-3">
                  {e.reason ?? ""}
                  {(e.notes ?? []).map((n) => (
                    <p key={n} className="text-xs text-state-attn">
                      {n}
                    </p>
                  ))}
                </td>
                <td className="py-2">
                  <details>
                    <summary className="cursor-pointer">{fieldSummary(e)}</summary>
                    <ul className="mt-2 space-y-1 text-xs">
                      {e.fields.map((f) => (
                        <li key={f.field} className="flex flex-wrap items-center gap-2">
                          <Badge tone={FIELD_TONE[f.status]}>{f.status}</Badge>
                          <span className="font-mono">{f.field}</span>
                          {f.target ? <span>to {f.target}</span> : null}
                          {f.note ? (
                            <span className="text-muted-foreground">{f.note}</span>
                          ) : null}
                        </li>
                      ))}
                    </ul>
                  </details>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ReportList({ entries }: { entries: MigrationDiffEntry[] }) {
  return (
    <div className="space-y-3">
      {entries.map((e) => (
        <div key={e.source_key} className="rounded-xl border border-border p-3 text-sm">
          <div className="font-medium text-foreground">{e.name}</div>
          {(["mapped", "partial", "unmapped"] as const).map((st) => {
            const fs = e.fields.filter((f) => f.status === st);
            return (
              <div key={st} className="mt-2">
                <div className="text-xs text-muted-foreground">
                  {capitalise(st)} ({fs.length})
                </div>
                {fs.length === 0 ? null : (
                  <ul className="mt-1 space-y-0.5 text-xs">
                    {fs.map((f) => (
                      <li key={f.field}>
                        <span className="font-mono">{f.field}</span>
                        {f.target ? ` to ${f.target}` : ""}
                        {f.note ? ` - ${f.note}` : ""}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}

export default function Migration() {
  const queryClient = useQueryClient();
  const sourcesQuery = useQuery({
    queryKey: ["migration-sources"],
    queryFn: api.migrationSources,
  });
  const batchesQuery = useQuery({
    queryKey: ["migration-batches"],
    queryFn: api.migrationBatches,
  });
  const sources = sourcesQuery.data?.data ?? [];
  const batches = batchesQuery.data?.data ?? [];

  const [sourceChoice, setSourceChoice] = useState("");
  const source = sourceChoice || sources[0] || "";
  const [content, setContent] = useState("");
  const [fileError, setFileError] = useState<string | null>(null);
  const [credentialRef, setCredentialRef] = useState("");
  const [ldapUrl, setLdapUrl] = useState("");
  const [baseDn, setBaseDn] = useState("");
  const [bindDn, setBindDn] = useState("");
  const [dryRun, setDryRun] = useState<{ key: string; diff: MigrationDiff } | null>(null);
  const [applyMsg, setApplyMsg] = useState<
    { kind: "pending"; id?: string } | { kind: "nothing" } | null
  >(null);
  const [reportBatch, setReportBatch] = useState<string | null>(null);
  const [undoing, setUndoing] = useState<MigrationBatch | null>(null);

  const isAdcs = source === "adcs";
  const options: Record<string, string> = {};
  if (isAdcs) {
    if (ldapUrl.trim()) options.ldap_url = ldapUrl.trim();
    if (baseDn.trim()) options.base_dn = baseDn.trim();
    if (bindDn.trim()) options.bind_dn = bindDn.trim();
  }
  const body: MigrationRequest = { source };
  if (content.trim() !== "") body.content = content;
  if (isAdcs && credentialRef.trim()) body.credential_ref = credentialRef.trim();
  if (Object.keys(options).length > 0) body.options = options;
  const bodyKey = JSON.stringify(body);

  const tooLarge = new Blob([content]).size > MAX_BYTES;
  const hasInput =
    content.trim() !== "" || (isAdcs && credentialRef.trim() !== "");
  const canDryRun = source !== "" && hasInput && !tooLarge;

  // A dry run only counts while the request is unchanged since it ran.
  const diff = dryRun && dryRun.key === bodyKey ? dryRun.diff : null;
  const canApply =
    diff !== null && diff.counts.create + (diff.counts.update ?? 0) > 0;

  const dryRunMut = useMutation({
    mutationFn: (b: MigrationRequest) => api.migrationDryRun(b),
    onSuccess: (res, b) => {
      setDryRun({ key: JSON.stringify(b), diff: res.data });
      setApplyMsg(null);
      setReportBatch(null);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const applyMut = useMutation({
    mutationFn: (b: MigrationRequest) => api.migrationApply(b),
    onSuccess: (res) => {
      if (res.data.status === "pending_approval") {
        setApplyMsg({ kind: "pending", id: res.data.pending_action_id });
      } else {
        setApplyMsg({ kind: "nothing" });
      }
      return queryClient.invalidateQueries({ queryKey: ["migration-batches"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const reportQuery = useQuery({
    queryKey: ["migration-report", reportBatch],
    queryFn: () => api.migrationReport(reportBatch as string),
    enabled: reportBatch !== null,
  });

  const rollbackMut = useMutation({
    mutationFn: (id: string) => api.migrationRollback(id),
    onSuccess: (res) => {
      toast.success(
        `Disabled ${res.data.disabled} template(s); restored ${res.data.restored ?? 0}; kept ${res.data.kept} with pending approvals.`,
      );
      setUndoing(null);
      return queryClient.invalidateQueries({ queryKey: ["migration-batches"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > MAX_BYTES) {
      setFileError("Export is larger than 48 KiB; split it");
      return;
    }
    setFileError(null);
    setContent(await file.text());
  };

  const showBatchReport = reportBatch !== null;

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Estate"
        title="Migration"
        description="Bring templates from another CA product. Nothing is written until a second person approves."
      />

      <Panel title="Source">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <label className="block space-y-1 text-sm text-foreground">
            <span>Source system</span>
            <Select
              aria-label="Source system"
              value={source}
              onChange={(e) => setSourceChoice(e.target.value)}
            >
              {sources.map((s) => (
                <option key={s} value={s}>
                  {capitalise(s)}
                </option>
              ))}
            </Select>
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Export file</span>
            <input
              type="file"
              aria-label="Export file"
              className="block w-full text-sm"
              onChange={(e) => void onFile(e.target.files?.[0])}
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground md:col-span-2">
            <span>Paste export</span>
            <Textarea
              aria-label="Paste export"
              rows={6}
              className="font-mono"
              value={content}
              onChange={(e) => setContent(e.target.value)}
            />
          </label>
          {isAdcs ? (
            <>
              <label className="block space-y-1 text-sm text-foreground">
                <span>Credential reference</span>
                <Input
                  aria-label="Credential reference"
                  value={credentialRef}
                  onChange={(e) => setCredentialRef(e.target.value)}
                />
              </label>
              <label className="block space-y-1 text-sm text-foreground">
                <span>LDAP URL</span>
                <Input
                  aria-label="LDAP URL"
                  value={ldapUrl}
                  onChange={(e) => setLdapUrl(e.target.value)}
                />
              </label>
              <label className="block space-y-1 text-sm text-foreground">
                <span>Base DN</span>
                <Input
                  aria-label="Base DN"
                  value={baseDn}
                  onChange={(e) => setBaseDn(e.target.value)}
                />
              </label>
              <label className="block space-y-1 text-sm text-foreground">
                <span>Bind DN</span>
                <Input
                  aria-label="Bind DN"
                  value={bindDn}
                  onChange={(e) => setBindDn(e.target.value)}
                />
              </label>
            </>
          ) : null}
        </div>
        {fileError || tooLarge ? (
          <div className="mt-3">
            <StateMessage
              tone="error"
              title="Export too large"
              message={fileError ?? "Export is larger than 48 KiB; split it"}
            />
          </div>
        ) : null}
        <div className="mt-4 flex flex-wrap gap-2">
          <Button
            tone="primary"
            disabled={!canDryRun || dryRunMut.isPending}
            onClick={() => dryRunMut.mutate(body)}
          >
            Dry run
          </Button>
          <Button
            disabled={!canApply || applyMut.isPending}
            onClick={() => applyMut.mutate(body)}
          >
            Submit for approval
          </Button>
        </div>
        {dryRunMut.isError ? (
          <div className="mt-3">
            <StateMessage
              tone="error"
              title="Dry run failed"
              message={dryRunMut.error.message}
            />
          </div>
        ) : null}
        {applyMsg?.kind === "pending" ? (
          <div className="mt-3">
            <StateMessage
              tone="success"
              title="Submitted for approval"
              message={`Submitted for approval${applyMsg.id ? ` (id ${applyMsg.id})` : ""}. A second person must approve it in Pending Actions.`}
              action={<Link to="/pending-actions" className="underline">Open Pending Actions</Link>}
            />
          </div>
        ) : null}
        {applyMsg?.kind === "nothing" ? (
          <div className="mt-3">
            <StateMessage
              title="Nothing to apply"
              message="Nothing to apply: every object is already imported or in conflict."
            />
          </div>
        ) : null}
      </Panel>

      {diff ? (
        <Panel title="Dry-run diff">
          <DiffTable diff={diff} />
        </Panel>
      ) : null}

      {diff || showBatchReport ? (
        <Panel title="Migration report">
          {showBatchReport ? (
            reportQuery.isLoading ? (
              <StateMessage title="Loading" message="Fetching the batch report…" />
            ) : reportQuery.error ? (
              <StateMessage
                tone="error"
                title="Unavailable"
                message="Could not load the batch report."
              />
            ) : reportQuery.data ? (
              <div className="space-y-3">
                <div className="text-sm font-medium text-foreground">
                  Report for batch {reportBatch}
                </div>
                <ReportList entries={reportQuery.data.data.report.entries} />
              </div>
            ) : null
          ) : diff ? (
            <div className="space-y-3">
              <div className="text-sm font-medium text-foreground">Planned report</div>
              <ReportList entries={diff.entries} />
            </div>
          ) : null}
          <p className="mt-3 text-xs text-muted-foreground">
            Next steps: cut over per application group as described in
            docs/guides/replace-adcs.md.
          </p>
        </Panel>
      ) : null}

      <Panel title="Batches">
        {batchesQuery.isLoading ? (
          <StateMessage title="Loading" message="Fetching migration batches…" />
        ) : batchesQuery.error ? (
          <StateMessage
            tone="error"
            title="Unavailable"
            message="Could not load migration batches."
            action={<Button onClick={() => batchesQuery.refetch()}>Retry</Button>}
          />
        ) : batches.length === 0 ? (
          <StateMessage
            title="No migrations yet"
            message="Applied migrations appear here, each with a report and an undo."
          />
        ) : (
          <div className="overflow-x-auto" {...scrollableProps}>
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-muted-foreground">
                <tr>
                  <th className="pb-2 pr-3">ID</th>
                  <th className="pb-2 pr-3">Source</th>
                  <th className="pb-2 pr-3">Status</th>
                  <th className="pb-2 pr-3">Created by</th>
                  <th className="pb-2 pr-3">Created</th>
                  <th className="pb-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {batches.map((b) => (
                  <tr key={b.id} className="border-t border-border align-top">
                    <td className="py-2 pr-3 font-mono text-xs">{b.id}</td>
                    <td className="py-2 pr-3">{b.source}</td>
                    <td className="py-2 pr-3">
                      <Badge tone={b.status === "applied" ? "success" : "neutral"}>
                        {b.status}
                      </Badge>
                    </td>
                    <td className="py-2 pr-3">{b.created_by}</td>
                    <td className="py-2 pr-3">{formatDateTime(b.created_at)}</td>
                    <td className="py-2">
                      <div className="flex gap-2">
                        <Button
                          aria-label={`View report for ${b.id}`}
                          onClick={() => setReportBatch(b.id)}
                        >
                          View report
                        </Button>
                        {b.status === "applied" ? (
                          <Button
                            tone="danger"
                            aria-label={`Undo migration ${b.id}`}
                            onClick={() => setUndoing(b)}
                          >
                            Undo migration
                          </Button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Dialog
        open={undoing !== null}
        title="Undo migration"
        description={
          undoing
            ? `This disables the templates created by batch ${undoing.id} and restores the ones it updated to their state before the import. Nothing is deleted. Templates with outstanding approvals stay as they are.`
            : undefined
        }
        onClose={() => setUndoing(null)}
        size="sm"
      >
        <div className="flex justify-end gap-2">
          <Button onClick={() => setUndoing(null)}>Cancel</Button>
          <Button
            tone="danger"
            disabled={rollbackMut.isPending}
            onClick={() => undoing && rollbackMut.mutate(undoing.id)}
          >
            Undo migration
          </Button>
        </div>
      </Dialog>
    </div>
  );
}
