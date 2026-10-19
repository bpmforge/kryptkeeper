import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../lib/api";
import {
  Badge,
  Button,
  Panel,
  Select,
  StateMessage,
} from "../components/ops-ui";
import { PageHeader } from "../components/PageHeader";
import { formatDateTime } from "../components/ui";
import { scrollableProps } from "../lib/scrollable";
import { humanizeEnum } from "../lib/utils";
import { extractList } from "../lib/models";
import type { HistoryRecord } from "../lib/models";

// "act-expired-certs" is a slug id, not a label.
function actionLabel(id: string): string {
  return humanizeEnum(id.replace(/^act-/, ""));
}

export default function History() {
  const navigate = useNavigate();
  const { actionId } = useParams();
  const [status, setStatus] = useState("");
  const [category, setCategory] = useState("");
  const [selectedActionId, setSelectedActionId] = useState<string | null>(null);

  const [cursor, setCursor] = useState<number | undefined>(undefined);

  const queryParams = useMemo(
    () => ({ status, category, limit: 50, cursor }),
    [status, category, cursor],
  );

  const history = useQuery({
    queryKey: ["dashboard-actions-history", queryParams],
    queryFn: () => api.dashboardActionsHistory(queryParams),
  });
  const rows: HistoryRecord[] = extractList<HistoryRecord>(history.data?.data, [
    "items",
    "history",
  ]);
  const meta = history.data?.meta as
    | { next_cursor?: number | null; prev_cursor?: number | null; total?: number }
    | undefined;
  const selectedKey = actionId ?? selectedActionId ?? null;
  const pageHit = selectedKey
    ? (rows.find((row) => row.action_id === selectedKey) ?? null)
    : null;
  // Same deep-link rule as Audit: walk the cursor chain (capped) for a
  // /history/:actionId that lives beyond the loaded page.
  const resolvedById = useQuery({
    queryKey: ["history-resolve", selectedKey, status, category],
    enabled: Boolean(selectedKey) && !pageHit && !history.isLoading,
    staleTime: 60_000,
    queryFn: async () => {
      let nextCursor: number | undefined = undefined;
      for (let page = 0; page < 20; page++) {
        const res = await api.dashboardActionsHistory({
          status,
          category,
          limit: 50,
          cursor: nextCursor,
        });
        const pageRows = extractList<HistoryRecord>(res.data, [
          "items",
          "history",
        ]);
        const hit = pageRows.find((row) => row.action_id === selectedKey);
        if (hit) return hit;
        const next = (
          res.meta as { next_cursor?: number | null } | undefined
        )?.next_cursor;
        if (next == null) break;
        nextCursor = next;
      }
      return null;
    },
  });
  const selected =
    pageHit ?? resolvedById.data ?? (selectedKey ? null : (rows[0] ?? null));

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Audit"
        title="Action History"
        description="Review dashboard actions and operational outcomes."
      />

      <Panel title="Filters" subtitle="Narrow the history feed">
        <div className="grid gap-3 md:grid-cols-3">
          <label className="space-y-2 text-sm text-foreground">
            <span>Status</span>
            <Select
              aria-label="Filter history by status"
              value={status}
              onChange={(e) => {
                setStatus(e.target.value);
                setCursor(undefined);
              }}
            >
              <option value="">All statuses</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option>
              <option value="success">Success</option>
            </Select>
          </label>
          <label className="space-y-2 text-sm text-foreground">
            <span>Category</span>
            <Select
              aria-label="Filter history by category"
              value={category}
              onChange={(e) => {
                setCategory(e.target.value);
                setCursor(undefined);
              }}
            >
              <option value="">All categories</option>
              <option value="certificate">Certificate</option>
              <option value="discovery">Discovery</option>
              <option value="notification">Notification</option>
              <option value="dashboard">Dashboard</option>
            </Select>
          </label>
          <Button tone="primary" onClick={() => history.refetch()}>
            Refresh
          </Button>
        </div>
      </Panel>

      {history.isLoading ? (
        <StateMessage
          title="Loading history"
          message="Fetching the action trail..."
        />
      ) : null}
      {history.error ? (
        <StateMessage
          tone="error"
          title="History unavailable"
          message="Try again shortly."
        />
      ) : null}

      <Panel title="Action detail" subtitle="Inspect one operational event">
        {selected ? (
          <div className="space-y-4">
            {selectedKey ? (
              <div className="flex justify-between gap-3">
                <div />
                <Button onClick={() => navigate("/history")}>
                  Back to list
                </Button>
              </div>
            ) : null}
            <div className="grid gap-3 md:grid-cols-2 text-sm">
              <div>
                <div className="text-muted-foreground">Action</div>
                <div className="text-foreground" title={selected.action_id}>{actionLabel(selected.action_id)}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Status</div>
                <div className="text-foreground">{humanizeEnum(selected.status)}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Category</div>
                <div className="text-foreground">{humanizeEnum(selected.category)}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Updated by</div>
                <div className="text-foreground">{selected.updated_by}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Updated</div>
                <div className="text-foreground">
                  {selected.updated_at ? formatDateTime(selected.updated_at) : "—"}
                </div>
              </div>
              {selected.note ? (
                <div className="col-span-2">
                  <div className="text-muted-foreground">Note</div>
                  <div className="text-foreground">{selected.note}</div>
                </div>
              ) : null}
            </div>
          </div>
        ) : selectedKey && !resolvedById.isLoading && !history.isLoading ? (
          <div className="space-y-3">
            <StateMessage
              title="Action not found"
              message="This action is not in the history, or it was removed."
            />
            <Button onClick={() => navigate("/history")}>Back to list</Button>
          </div>
        ) : (
          <StateMessage
            title="No action selected"
            message="Choose an event from the history table."
          />
        )}
      </Panel>

      <Panel
        title="Action history"
        subtitle="What happened, who changed it, and when"
      >
        <div className="overflow-x-auto rounded-xl border border-border" {...scrollableProps}>
          <table className="min-w-full divide-y divide-border">
            <thead className="bg-background/80">
              <tr>
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
                  Category
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Status
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Updated By
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Updated At
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Note
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border bg-background/40">
              {rows.map((row) => (
                <tr key={`${row.action_id}-${row.updated_at}`}>
                  <td className="px-4 py-3 text-sm text-foreground">
                    <button
                      type="button"
                      className="text-left font-medium hover:text-primary"
                      onClick={() => {
                        setSelectedActionId(row.action_id);
                        navigate(`/history/${row.action_id}`);
                      }}
                    >
                      <span title={row.action_id}>{actionLabel(row.action_id)}</span>
                    </button>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {humanizeEnum(row.category)}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <Badge
                      tone={
                        row.status === "resolved" || row.status === "success"
                          ? "success"
                          : row.status === "acknowledged"
                            ? "info"
                            : "warning"
                      }
                    >
                      {humanizeEnum(row.status)}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {row.updated_by}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-sm text-muted-foreground">
                    {row.updated_at ? formatDateTime(row.updated_at) : "—"}
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {row.note || "—"}
                  </td>
                </tr>
              ))}
              {rows.length === 0 ? (
                <tr>
                  <td
                    colSpan={6}
                    className="px-4 py-10 text-center text-sm text-muted-foreground"
                  >
                    No action history yet — dashboard actions you acknowledge or resolve are recorded here. Adjust the filters if you expected results.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        {(meta?.next_cursor ?? null) !== null ||
        (meta?.prev_cursor ?? null) !== null ? (
          <div className="mt-3 flex items-center justify-between text-sm text-muted-foreground">
            <span>{meta?.total != null ? `${meta.total} total` : ""}</span>
            <div className="flex gap-2">
              <Button
                disabled={(meta?.prev_cursor ?? null) === null}
                onClick={() => setCursor(meta?.prev_cursor ?? undefined)}
              >
                Previous
              </Button>
              <Button
                disabled={(meta?.next_cursor ?? null) === null}
                onClick={() => setCursor(meta?.next_cursor ?? undefined)}
              >
                Next
              </Button>
            </div>
          </div>
        ) : null}
      </Panel>
    </div>
  );
}
