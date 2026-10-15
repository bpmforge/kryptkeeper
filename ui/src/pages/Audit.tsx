import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { api } from "../lib/api";
import {
  Badge,
  Button,
  Input,
  Panel,
  Select,
  StateMessage,
} from "../components/ops-ui";
import { PageHeader } from "../components/PageHeader";
import { canReadOperationalSummaries, useAuthz } from "../lib/auth";
import { AUDIT_OUTCOMES, auditOutcomeTone } from "../lib/auditOutcome";
import { isReadOnlyAction } from "../lib/auditActions";
import { shortResourceId } from "../lib/auditResource";
import type { AuditRow } from "../lib/models";

type AuditFilters = {
  action: string;
  actorType: string;
  resourceType: string;
  outcome: string;
  after: string;
  before: string;
};

const initialFilters: AuditFilters = {
  action: "",
  actorType: "",
  resourceType: "",
  outcome: "",
  after: "",
  before: "",
};

function ResourceCell({ row }: { row: AuditRow }) {
  const full = `${row.resource_type}:${row.resource_id}`;
  const name = row.resource_name?.trim();
  return (
    <span title={full}>
      <span className={name ? "text-foreground" : undefined}>
        {name || shortResourceId(row.resource_id)}
      </span>
      <span className="block text-xs text-muted-foreground">
        {row.resource_type}
        {name ? ` · ${shortResourceId(row.resource_id)}` : ""}
      </span>
    </span>
  );
}

function csvEscape(value: string) {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}

export default function Audit() {
  const navigate = useNavigate();
  const { id } = useParams();
  const authz = useAuthz();
  // Draft/applied split: the inputs edit the draft; only "Apply filters"
  // commits it into the query. Before this, every keystroke fired a request
  // — and each request emits its own audit.list event, so typing polluted
  // the very log being displayed.
  const [filters, setFilters] = useState<AuditFilters>(initialFilters);
  const [appliedFilters, setAppliedFilters] =
    useState<AuditFilters>(initialFilters);
  const [hideReadOnly, setHideReadOnly] = useState(false);
  const [cursor, setCursor] = useState<string | null | undefined>(undefined);
  const [selectedAuditId, setSelectedAuditId] = useState<string | null>(null);

  const queryParams = useMemo(
    () => ({
      limit: 50,
      cursor: cursor ?? undefined,
      action: appliedFilters.action,
      actor_type: appliedFilters.actorType,
      resource_type: appliedFilters.resourceType,
      outcome: appliedFilters.outcome,
      after: appliedFilters.after,
      before: appliedFilters.before,
      order: "desc",
    }),
    [cursor, appliedFilters],
  );

  const audit = useQuery({
    queryKey: ["audit", queryParams],
    queryFn: () => api.auditList(queryParams),
    enabled: canReadOperationalSummaries(authz.data?.role, authz.data?.scopes),
  });
  const allRows = (audit.data?.data ?? []) as AuditRow[];
  // Client-side on purpose: GET /audit only takes an exact `action` match, so
  // the server cannot express "everything except reads". Pages are therefore
  // filtered after fetch and may show fewer than 50 rows.
  // Only successful reads are hidden: a denied or failed read (e.g. an
  // authz.check that was refused) is security-relevant and stays visible.
  const rows = hideReadOnly
    ? allRows.filter(
        (row) => !(isReadOnlyAction(row.action) && row.outcome === "success"),
      )
    : allRows;
  const hiddenCount = allRows.length - rows.length;
  const meta = audit.data?.meta;
  const selectedKey = id ?? selectedAuditId ?? null;
  const pageHit = selectedKey
    ? (rows.find((row) => String(row.id) === selectedKey) ?? null)
    : null;
  // A bookmarked /audit/:id can point at a row outside the loaded page.
  // Walk the filtered cursor chain (capped) instead of showing "no row
  // selected" for a link that is perfectly valid.
  const resolvedById = useQuery({
    queryKey: ["audit-resolve", selectedKey, queryParams],
    enabled: Boolean(selectedKey) && !pageHit && !audit.isLoading,
    staleTime: 60_000,
    queryFn: async () => {
      let nextCursor: string | undefined = undefined;
      for (let page = 0; page < 20; page++) {
        const res = await api.auditList({
          ...queryParams,
          limit: 100,
          cursor: nextCursor,
        });
        const pageRows = (res.data ?? []) as AuditRow[];
        const hit = pageRows.find((row) => String(row.id) === selectedKey);
        if (hit) return hit;
        const next = (res.meta as { next_cursor?: string | null } | undefined)
          ?.next_cursor;
        if (!next) break;
        nextCursor = next;
      }
      return null;
    },
  });
  const selected =
    pageHit ?? resolvedById.data ?? (selectedKey ? null : (rows[0] ?? null));

  const [exporting, setExporting] = useState(false);

  // Export walks the cursor chain for the CURRENT filters (server caps each
  // page at 100) — exporting only the visible page under a title like
  // "Audit Evidence" quietly handed compliance 50 rows of a much larger log.
  const EXPORT_CAP = 10_000;
  const fetchAllFilteredRows = async (): Promise<AuditRow[]> => {
    const all: AuditRow[] = [];
    let nextCursor: string | undefined = undefined;
    for (;;) {
      const page = await api.auditList({
        ...queryParams,
        limit: 100,
        cursor: nextCursor,
      });
      all.push(...((page.data ?? []) as AuditRow[]));
      const next = (page.meta as { next_cursor?: string | null } | undefined)
        ?.next_cursor;
      if (!next || all.length >= EXPORT_CAP) break;
      nextCursor = next;
    }
    // The export is evidence, so it stays complete regardless of the
    // on-screen "Hide read-only events" toggle.
    return all.slice(0, EXPORT_CAP);
  };

  const exportCsv = async () => {
    setExporting(true);
    let exportRows: AuditRow[];
    try {
      exportRows = await fetchAllFilteredRows();
    } catch (err) {
      setExporting(false);
      toast.error(
        err instanceof Error ? err.message : "Audit export failed.",
      );
      return;
    }
    setExporting(false);
    const header = [
      "id",
      "timestamp",
      "action",
      "actor_type",
      "actor_id",
      "resource_type",
      "resource_id",
      "trace_id",
      "outcome",
      "resource_name",
    ];
    const csv = [
      header.join(","),
      ...exportRows.map((row: AuditRow) =>
        [
          row.id,
          row.timestamp,
          row.action,
          row.actor_type,
          row.actor_id,
          row.resource_type,
          row.resource_id,
          row.trace_id || "",
          row.outcome,
          row.resource_name || "",
        ]
          .map((value) => csvEscape(String(value ?? "")))
          .join(","),
      ),
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "audit-evidence.csv";
    link.click();
    URL.revokeObjectURL(url);
  };

  if (!canReadOperationalSummaries(authz.data?.role, authz.data?.scopes)) {
    return (
      <div className="p-6">
        <StateMessage
          tone="error"
          title="Access denied"
          message="Your role cannot view audit evidence."
        />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Evidence"
        title="Audit Evidence"
        description="Filter, review, and export audit events for compliance and incident response."
      />

      <Panel title="Filters" subtitle="Narrow the audit log before exporting">
        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
          <label className="space-y-2 text-sm text-foreground">
            <span>Action</span>
            <Input
              aria-label="Filter audit action"
              placeholder="Action"
              value={filters.action}
              onChange={(e) =>
                setFilters((curr) => ({ ...curr, action: e.target.value }))
              }
            />
          </label>
          <label className="space-y-2 text-sm text-foreground">
            <span>Actor type</span>
            <Input
              aria-label="Filter actor type"
              placeholder="Actor type"
              value={filters.actorType}
              onChange={(e) =>
                setFilters((curr) => ({ ...curr, actorType: e.target.value }))
              }
            />
          </label>
          <label className="space-y-2 text-sm text-foreground">
            <span>Resource type</span>
            <Input
              aria-label="Filter resource type"
              placeholder="Resource type"
              value={filters.resourceType}
              onChange={(e) =>
                setFilters((curr) => ({
                  ...curr,
                  resourceType: e.target.value,
                }))
              }
            />
          </label>
          <label className="space-y-2 text-sm text-foreground">
            <span>Outcome</span>
            <Select
              aria-label="Filter audit outcome"
              value={filters.outcome}
              onChange={(e) =>
                setFilters((curr) => ({ ...curr, outcome: e.target.value }))
              }
            >
              <option value="">All outcomes</option>
              {AUDIT_OUTCOMES.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </label>
          <label className="space-y-2 text-sm text-foreground">
            <span>After</span>
            <Input
              aria-label="Filter after timestamp"
              placeholder="After (RFC3339)"
              value={filters.after}
              onChange={(e) =>
                setFilters((curr) => ({ ...curr, after: e.target.value }))
              }
            />
          </label>
          <label className="space-y-2 text-sm text-foreground">
            <span>Before</span>
            <Input
              aria-label="Filter before timestamp"
              placeholder="Before (RFC3339)"
              value={filters.before}
              onChange={(e) =>
                setFilters((curr) => ({ ...curr, before: e.target.value }))
              }
            />
          </label>
        </div>
        <label className="mt-4 flex items-center gap-2 text-sm text-foreground">
          <input
            type="checkbox"
            checked={hideReadOnly}
            onChange={(e) => setHideReadOnly(e.target.checked)}
          />
          <span>Hide read-only events</span>
          <span className="text-xs text-muted-foreground">
            (successful list, get, read, view, search — denials, downloads and exports stay
            visible)
          </span>
        </label>
        <div className="mt-4 flex flex-wrap gap-2">
          <Button
            tone="primary"
            onClick={() => {
              setCursor(undefined);
              setAppliedFilters(filters);
            }}
          >
            Apply filters
          </Button>
          <Button
            onClick={() => {
              setFilters(initialFilters);
              setAppliedFilters(initialFilters);
              setCursor(undefined);
            }}
          >
            Reset
          </Button>
          <Button
            tone="primary"
            onClick={() => void exportCsv()}
            disabled={rows.length === 0 || exporting}
          >
            {exporting ? "Exporting…" : "Export CSV"}
          </Button>
        </div>
      </Panel>

      {audit.isLoading ? (
        <StateMessage
          title="Loading audit evidence"
          message="Fetching audit rows..."
        />
      ) : null}
      {audit.error ? (
        <StateMessage
          tone="error"
          title="Audit unavailable"
          message="Try again shortly."
        />
      ) : null}

      <Panel title="Audit detail" subtitle="Inspect one evidence record">
        {selected ? (
          <div className="space-y-4">
            {selectedKey ? (
              <div className="flex justify-between gap-3">
                <div />
                <Button onClick={() => navigate("/audit")}>Back to list</Button>
              </div>
            ) : null}
            <div className="grid gap-3 md:grid-cols-2 text-sm">
              <div>
                <div className="text-muted-foreground">Timestamp</div>
                <div className="text-foreground">{selected.timestamp}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Action</div>
                <div className="text-foreground">{selected.action}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Actor</div>
                <div className="text-foreground">
                  {selected.actor_type}:{selected.actor_id}
                </div>
              </div>
              <div>
                <div className="text-muted-foreground">Resource</div>
                <div className="text-foreground">
                  {selected.resource_name ? (
                    <div>{selected.resource_name}</div>
                  ) : null}
                  <div className="break-all">
                    {selected.resource_type}:{selected.resource_id}
                  </div>
                </div>
              </div>
              <div>
                <div className="text-muted-foreground">Trace</div>
                <div className="text-foreground">{selected.trace_id || "—"}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Outcome</div>
                <div className="text-foreground">{selected.outcome}</div>
              </div>
            </div>
          </div>
        ) : (
          <StateMessage
            title="No audit row selected"
            message="Choose an evidence record in the table."
          />
        )}
      </Panel>

      <Panel
        title="Audit log"
        subtitle="A compliance-ready trail of system events"
      >
        <div className="overflow-hidden rounded-xl border border-border">
          <table className="min-w-full divide-y divide-border">
            <thead className="bg-background/80">
              <tr>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Timestamp
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Action
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Actor
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Resource
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Trace
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Outcome
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border bg-background/40">
              {rows.map((row) => (
                <tr key={row.id}>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {row.timestamp}
                  </td>
                  <td className="px-4 py-3 text-sm text-foreground">
                    <button
                      type="button"
                      className="text-left font-medium hover:text-primary"
                      onClick={() => {
                        setSelectedAuditId(String(row.id));
                        navigate(`/audit/${row.id}`);
                      }}
                    >
                      {row.action}
                    </button>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {row.actor_type}:{row.actor_id}
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    <ResourceCell row={row} />
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {row.trace_id || "—"}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <Badge tone={auditOutcomeTone(row.outcome)}>
                      {row.outcome}
                    </Badge>
                  </td>
                </tr>
              ))}
              {rows.length === 0 ? (
                <tr>
                  <td
                    colSpan={6}
                    className="px-4 py-10 text-center text-sm text-muted-foreground"
                  >
                    No audit entries yet — every API action lands here as it happens. Adjust the filters if you expected results.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>

        <div className="mt-4 flex gap-2">
          <Button
            onClick={() => setCursor(meta?.prev_cursor ?? undefined)}
            disabled={!meta?.prev_cursor}
          >
            Previous
          </Button>
          <Button
            onClick={() => setCursor(meta?.next_cursor ?? undefined)}
            disabled={!meta?.next_cursor}
          >
            Next
          </Button>
          <div className="ml-auto text-sm text-muted-foreground">
            {hideReadOnly && hiddenCount > 0
              ? `${hiddenCount} read-only hidden on this page · `
              : ""}
            Total: {meta?.total ?? 0} · Principal:{" "}
            {audit.data?.principal ?? authz.data?.principal ?? "—"}
          </div>
        </div>
      </Panel>
    </div>
  );
}
