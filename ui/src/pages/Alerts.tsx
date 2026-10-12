import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { api } from "../lib/api";
import {
  Badge,
  Button,
  Dialog,
  Input,
  Panel,
  Select,
  StateMessage,
} from "../components/ops-ui";
import { PageHeader } from "../components/PageHeader";
import { canManageNotifications, useAuthz } from "../lib/auth";
import { extractList } from "../lib/models";
import type {
  NotificationDeliveryRecord,
  NotificationRule,
  NotificationSummary,
} from "../lib/models";

export default function Alerts() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { id } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const authz = useAuthz();
  const [tab, setTab] = useState<"deliveries" | "rules">("deliveries");
  const [ruleDialog, setRuleDialog] = useState<"create" | "edit" | null>(null);
  const [activeRule, setActiveRule] = useState<NotificationRule | null>(null);
  const [ruleForm, setRuleForm] = useState({
    name: "",
    threshold_days: 30,
    channel: "email",
    target: "",
    enabled: true,
  });
  const [statusFilter, setStatusFilter] = useState(
    searchParams.get("status") ?? "",
  );
  const [deliveryChannelFilter, setDeliveryChannelFilter] = useState(
    searchParams.get("channel") ?? "",
  );
  const [cursor, setCursor] = useState<string | null>(
    searchParams.get("cursor") ?? null,
  );

  useEffect(() => {
    const next = new URLSearchParams();
    if (statusFilter) next.set("status", statusFilter);
    if (deliveryChannelFilter) next.set("channel", deliveryChannelFilter);
    if (cursor) next.set("cursor", cursor);
    setSearchParams(next, { replace: true });
  }, [statusFilter, deliveryChannelFilter, cursor]); // eslint-disable-line react-hooks/exhaustive-deps
  const [channel, setChannel] = useState("email");
  const [target, setTarget] = useState("");
  const [message, setMessage] = useState("Test delivery from Kryptkeeper");
  const [selectedDeliveryId, setSelectedDeliveryId] = useState<string | null>(
    null,
  );
  const [activeRow, setActiveRow] = useState<NotificationDeliveryRecord | null>(
    null,
  );
  const [action, setAction] = useState<"retry" | "ack" | null>(null);
  const [actionNote, setActionNote] = useState("");
  const [statusMessage, setStatusMessage] = useState<{
    tone: "success" | "error";
    title: string;
    message: string;
  } | null>(null);

  const rulesQuery = useQuery({
    queryKey: ["notification-rules"],
    queryFn: api.notificationRules,
    enabled: tab === "rules",
  });
  const rules = extractList<NotificationRule>(rulesQuery.data?.data, ["items"]);

  const createRuleMutation = useMutation({
    mutationFn: () =>
      api.createNotificationRule({
        name: ruleForm.name,
        threshold_days: ruleForm.threshold_days,
        channel: ruleForm.channel,
        target: ruleForm.target,
      }),
    onSuccess: async () => {
      setRuleDialog(null);
      await queryClient.invalidateQueries({ queryKey: ["notification-rules"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const updateRuleMutation = useMutation({
    mutationFn: () => {
      if (!activeRule) throw new Error("No rule selected");
      return api.updateNotificationRule(activeRule.id, {
        enabled: ruleForm.enabled,
        target: ruleForm.target,
      });
    },
    onSuccess: async () => {
      setRuleDialog(null);
      await queryClient.invalidateQueries({ queryKey: ["notification-rules"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const deleteRuleMutation = useMutation({
    mutationFn: (id: string) => api.deleteNotificationRule(id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["notification-rules"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const openCreateRule = () => {
    setRuleForm({
      name: "",
      threshold_days: 30,
      channel: "email",
      target: "",
      enabled: true,
    });
    setActiveRule(null);
    setRuleDialog("create");
  };

  const openEditRule = (rule: NotificationRule) => {
    setActiveRule(rule);
    setRuleForm({
      name: rule.name,
      threshold_days: rule.threshold_days,
      channel: rule.channel,
      target: rule.target,
      enabled: rule.enabled,
    });
    setRuleDialog("edit");
  };

  const summary = useQuery({
    queryKey: ["notifications-summary"],
    queryFn: api.notificationsSummary,
  });
  const deliveries = useQuery({
    queryKey: [
      "notification-deliveries",
      statusFilter,
      deliveryChannelFilter,
      cursor,
    ],
    queryFn: () =>
      api.notificationDeliveries({
        status: statusFilter,
        channel: deliveryChannelFilter,
        limit: 50,
        ...(cursor ? { cursor } : {}),
      }),
  });
  const deliveriesMeta = deliveries.data?.meta;

  const refresh = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["notifications-summary"] }),
      queryClient.invalidateQueries({ queryKey: ["notification-deliveries"] }),
    ]);
  };

  const testDeliveryMutation = useMutation({
    mutationFn: async () =>
      api.testNotificationDelivery({ channel, target, message }),
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Test delivery queued",
        message: "The channel test was accepted.",
      });
      await refresh();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Test delivery failed",
        message:
          e instanceof Error
            ? e.message
            : "Check the channel inputs and try again.",
      });
    },
  });

  const retryMutation = useMutation({
    mutationFn: async () => {
      if (!activeRow) throw new Error("No delivery selected");
      return api.retryNotificationDelivery({
        delivery_id: activeRow.id,
        reason: actionNote,
      });
    },
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Retry queued",
        message: "The delivery will be retried.",
      });
      setAction(null);
      await refresh();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Retry failed",
        message: e instanceof Error ? e.message : "Try again in a moment.",
      });
    },
  });

  const ackMutation = useMutation({
    mutationFn: async () => {
      if (!activeRow) throw new Error("No delivery selected");
      return api.acknowledgeNotificationDelivery({
        delivery_id: activeRow.id,
        note: actionNote,
      });
    },
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Delivery acknowledged",
        message: "The queue item was marked done.",
      });
      setAction(null);
      await refresh();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Acknowledge failed",
        message: e instanceof Error ? e.message : "Try again in a moment.",
      });
    },
  });

  const summaryData = summary.data?.data as NotificationSummary | undefined;
  const deliveriesData: NotificationDeliveryRecord[] =
    extractList<NotificationDeliveryRecord>(deliveries.data?.data, [
      "items",
      "deliveries",
    ]);
  const selectedKey = id ?? selectedDeliveryId ?? null;
  const deliveryPageHit = selectedKey
    ? (deliveriesData.find((row) => row.id === selectedKey) ?? null)
    : null;
  // A bookmarked /alerts/deliveries/:id can point past the loaded page —
  // walk the unfiltered cursor chain (capped) before giving up.
  const resolvedDelivery = useQuery({
    queryKey: ["alerts-delivery-resolve", selectedKey],
    enabled: Boolean(selectedKey) && !deliveryPageHit && !deliveries.isLoading,
    staleTime: 60_000,
    queryFn: async () => {
      let nextCursor: number | string | undefined = undefined;
      for (let page = 0; page < 20; page++) {
        const res = await api.notificationDeliveries({
          limit: 50,
          cursor: nextCursor,
        });
        const pageRows = extractList<NotificationDeliveryRecord>(res.data, [
          "items",
          "deliveries",
        ]);
        const hit = pageRows.find((row) => row.id === selectedKey);
        if (hit) return hit;
        const next = (
          res.meta as { next_cursor?: number | string | null } | undefined
        )?.next_cursor;
        if (next == null) break;
        nextCursor = next;
      }
      return null;
    },
  });
  const selectedDelivery =
    deliveryPageHit ??
    resolvedDelivery.data ??
    (selectedKey ? null : (deliveriesData[0] ?? null));
  const canManage = canManageNotifications(
    authz.data?.role,
    authz.data?.scopes,
  );

  const openAction = (
    nextAction: "retry" | "ack",
    row: NotificationDeliveryRecord,
  ) => {
    setActiveRow(row);
    setAction(nextAction);
    setActionNote("");
    setStatusMessage(null);
  };

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Automation"
        title="Alerts & Notifications"
        description="See delivery health and act on failures without leaving the product."
        actions={
          tab === "rules" && canManage ? (
            <Button tone="primary" onClick={openCreateRule}>
              New rule
            </Button>
          ) : undefined
        }
      />

      <div className="flex gap-1 rounded-xl border border-border bg-background/60 p-1 w-fit">
        {(["deliveries", "rules"] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`rounded-lg px-4 py-1.5 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-ring ${tab === t ? "bg-primary text-primary-foreground" : "text-foreground hover:text-foreground"}`}
          >
            {t === "deliveries" ? "Delivery queue" : "Alert rules"}
          </button>
        ))}
      </div>

      {tab === "rules" ? (
        <Panel
          title="Alert rules"
          subtitle="Configure when and how Kryptkeeper fires notifications"
        >
          {rulesQuery.isLoading ? (
            <StateMessage
              title="Loading rules"
              message="Fetching alert rules…"
            />
          ) : rulesQuery.error ? (
            <StateMessage
              tone="error"
              title="Rules unavailable"
              message="Try again shortly."
            />
          ) : (
            <div className="overflow-hidden rounded-xl border border-border">
              <table className="min-w-full divide-y divide-border">
                <thead className="bg-background/80">
                  <tr>
                    {[
                      "Name",
                      "Threshold",
                      "Channel",
                      "Target",
                      "Status",
                      "Actions",
                    ].map((h) => (
                      <th
                        key={h}
                        scope="col"
                        className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-border bg-background/40">
                  {rules.map((rule) => (
                    <tr key={rule.id}>
                      <td className="px-4 py-3 text-sm font-medium text-foreground">
                        {rule.name}
                      </td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">
                        {rule.threshold_days}d
                      </td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">
                        {rule.channel}
                      </td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">
                        {rule.target}
                      </td>
                      <td className="px-4 py-3 text-sm">
                        <Badge tone={rule.enabled ? "success" : "neutral"}>
                          {rule.enabled ? "enabled" : "disabled"}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-sm">
                        {canManage ? (
                          <div className="flex gap-2">
                            <Button onClick={() => openEditRule(rule)}>
                              Edit
                            </Button>
                            <Button
                              tone="danger"
                              onClick={() =>
                                void deleteRuleMutation.mutateAsync(rule.id).catch(() => {})
                              }
                              disabled={deleteRuleMutation.isPending}
                            >
                              Delete
                            </Button>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            Read only
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {rules.length === 0 ? (
                    <tr>
                      <td
                        colSpan={6}
                        className="px-4 py-10 text-center text-sm text-muted-foreground"
                      >
                        No alert rules configured. Click &ldquo;New rule&rdquo;
                        to create one.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      ) : null}

      {tab === "deliveries" ? (
        <>
          <div className="grid gap-4 md:grid-cols-3">
            <Panel>
              <div className="text-sm text-muted-foreground">Pending</div>
              <div className="mt-2 text-3xl font-semibold text-foreground">
                {summaryData?.pending_notifications ?? 0}
              </div>
            </Panel>
            <Panel>
              <div className="text-sm text-muted-foreground">Escalations</div>
              <div className="mt-2 text-3xl font-semibold text-state-attn">
                {summaryData?.ownership_escalations ?? 0}
              </div>
            </Panel>
            <Panel>
              <div className="text-sm text-muted-foreground">Failures (24h)</div>
              <div className="mt-2 text-3xl font-semibold text-state-over">
                {summaryData?.delivery_failures_24h ?? 0}
              </div>
            </Panel>
          </div>

          <div className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
            <Panel
              title="Test delivery"
              subtitle="Send a synthetic message to validate the channel"
            >
              <div className="space-y-3">
                <label className="block space-y-2 text-sm text-foreground">
                  <span>Channel</span>
                  <Select
                    aria-label="Notification test channel"
                    value={channel}
                    onChange={(e) => setChannel(e.target.value)}
                  >
                    <option value="email">Email</option>
                    <option value="slack">Slack</option>
                    <option value="pagerduty">PagerDuty</option>
                    <option value="webhook">Webhook</option>
                  </Select>
                </label>
                <label className="block space-y-2 text-sm text-foreground">
                  <span>Target</span>
                  <Input
                    aria-label="Notification test target"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder={
                      channel === "email"
                        ? "user@example.com"
                        : channel === "slack"
                          ? "#channel or @user"
                          : channel === "pagerduty"
                            ? "routing-key"
                            : channel === "webhook"
                              ? "https://hooks.example.com/…"
                              : "Target"
                    }
                  />
                </label>
                <label className="block space-y-2 text-sm text-foreground">
                  <span>Message</span>
                  <Input
                    aria-label="Notification test message"
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    placeholder="Message"
                  />
                </label>
                {canManage ? (
                  <Button
                    tone="primary"
                    onClick={() => void testDeliveryMutation.mutateAsync().catch(() => {})}
                    disabled={testDeliveryMutation.isPending}
                  >
                    Send test delivery
                  </Button>
                ) : (
                  <StateMessage
                    title="Read-only access"
                    message="Your role can inspect delivery health, but not trigger or retry deliveries."
                  />
                )}
              </div>
            </Panel>

            <Panel title="Delivery filters" subtitle="Narrow the queue">
              <div className="grid gap-3 md:grid-cols-2">
                <label className="space-y-2 text-sm text-foreground">
                  <span>Status</span>
                  <Select
                    aria-label="Filter deliveries by status"
                    value={statusFilter}
                    onChange={(e) => {
                      setCursor(null);
                      setStatusFilter(e.target.value);
                    }}
                  >
                    <option value="">All statuses</option>
                    <option value="queued">Queued</option>
                    <option value="sending">Sending</option>
                    <option value="sent">Sent</option>
                    <option value="failed">Failed</option>
                    <option value="acknowledged">Acknowledged</option>
                    <option value="retrying">Retrying</option>
                  </Select>
                </label>
                <label className="space-y-2 text-sm text-foreground">
                  <span>Channel</span>
                  <Select
                    aria-label="Filter deliveries by channel"
                    value={deliveryChannelFilter}
                    onChange={(e) => {
                      setCursor(null);
                      setDeliveryChannelFilter(e.target.value);
                    }}
                  >
                    <option value="">All channels</option>
                    <option value="email">Email</option>
                    <option value="slack">Slack</option>
                    <option value="pagerduty">PagerDuty</option>
                    <option value="webhook">Webhook</option>
                  </Select>
                </label>
              </div>
            </Panel>
          </div>

          <Panel
            title="Delivery detail"
            subtitle="Inspect a single notification delivery"
          >
            {selectedDelivery ? (
              <div className="space-y-4">
                {selectedKey ? (
                  <div className="flex justify-between gap-3">
                    <div />
                    <Button onClick={() => navigate("/alerts")}>
                      Back to list
                    </Button>
                  </div>
                ) : null}
                <div className="grid gap-3 md:grid-cols-2 text-sm">
                  <div>
                    <div className="text-muted-foreground">Channel</div>
                    <div className="text-foreground">
                      {selectedDelivery.channel}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Target</div>
                    <div className="text-foreground">
                      {selectedDelivery.target}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Status</div>
                    <div className="text-foreground">
                      {selectedDelivery.status}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Queued</div>
                    <div className="text-foreground">
                      {selectedDelivery.queued_at ||
                        selectedDelivery.delivered_at ||
                        "—"}
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <StateMessage
                title="No delivery selected"
                message="Choose a row in the delivery queue."
              />
            )}
          </Panel>

          <Panel
            title="Delivery queue"
            subtitle="Ack, retry, and verify notification health"
          >
            {summary.isLoading || deliveries.isLoading ? (
              <StateMessage
                title="Loading notifications"
                message="Fetching delivery state..."
              />
            ) : null}
            {summary.error || deliveries.error ? (
              <StateMessage
                tone="error"
                title="Notifications unavailable"
                message="Try again shortly."
              />
            ) : null}
            {statusMessage ? (
              <StateMessage
                tone={statusMessage.tone}
                title={statusMessage.title}
                message={statusMessage.message}
              />
            ) : null}

            <div className="overflow-hidden rounded-xl border border-border">
              <table className="min-w-full divide-y divide-border">
                <thead className="bg-background/80">
                  <tr>
                    <th
                      scope="col"
                      className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                    >
                      Channel
                    </th>
                    <th
                      scope="col"
                      className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                    >
                      Target
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
                      Queued
                    </th>
                    <th
                      scope="col"
                      className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                    >
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border bg-background/40">
                  {deliveriesData.map((row) => (
                    <tr key={row.id}>
                      <td className="px-4 py-3 text-sm text-foreground">
                        <button
                          type="button"
                          className="text-left font-medium hover:text-primary"
                          onClick={() => {
                            setSelectedDeliveryId(row.id);
                            navigate(`/alerts/deliveries/${row.id}`);
                          }}
                        >
                          {row.channel}
                        </button>
                      </td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">
                        <button
                          type="button"
                          className="text-left hover:text-primary"
                          onClick={() => {
                            setSelectedDeliveryId(row.id);
                            navigate(`/alerts/deliveries/${row.id}`);
                          }}
                        >
                          {row.target}
                        </button>
                      </td>
                      <td className="px-4 py-3 text-sm">
                        <Badge
                          tone={
                            row.status === "failed"
                              ? "danger"
                              : row.status === "queued"
                                ? "warning"
                                : row.status === "acknowledged"
                                  ? "success"
                                  : "info"
                          }
                        >
                          {row.status}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">
                        {row.queued_at || row.delivered_at || "—"}
                      </td>
                      <td className="px-4 py-3 text-sm">
                        {canManage ? (
                          <div className="flex flex-wrap gap-2">
                            <Button
                              onClick={() => openAction("retry", row)}
                              disabled={
                                row.status === "acknowledged" ||
                                row.status === "sent"
                              }
                            >
                              Retry
                            </Button>
                            <Button
                              tone="primary"
                              onClick={() => openAction("ack", row)}
                              disabled={row.status === "acknowledged"}
                            >
                              Ack
                            </Button>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            Read only
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {deliveriesData.length === 0 ? (
                    <tr>
                      <td
                        colSpan={5}
                        className="px-4 py-10 text-center text-sm text-muted-foreground"
                      >
                        No deliveries yet. Send a test delivery above, or wait for a rule to fire.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
            <div className="mt-4 flex items-center justify-between text-sm text-muted-foreground">
              <span>
                {deliveriesMeta?.total != null
                  ? `${deliveriesMeta.total} total · page size ${deliveriesMeta.limit ?? 50}`
                  : ""}
              </span>
              <div className="flex gap-2">
                <Button
                  disabled={!deliveriesMeta?.prev_cursor}
                  onClick={() => setCursor(deliveriesMeta?.prev_cursor ?? null)}
                >
                  ← Previous
                </Button>
                <Button
                  disabled={!deliveriesMeta?.next_cursor}
                  onClick={() => setCursor(deliveriesMeta?.next_cursor ?? null)}
                >
                  Next →
                </Button>
              </div>
            </div>
          </Panel>

          <Dialog
            open={action !== null}
            title={
              action === "retry" ? "Retry delivery" : "Acknowledge delivery"
            }
            description={
              activeRow
                ? `${activeRow.channel} · ${activeRow.target}`
                : undefined
            }
            onClose={() => setAction(null)}
          >
            <form
              className="space-y-4"
              onSubmit={(e) => {
                e.preventDefault();
                void (action === "retry"
                  ? retryMutation.mutateAsync()
                  : ackMutation.mutateAsync());
              }}
            >
              <label className="block space-y-2 text-sm text-foreground">
                <span>{action === "retry" ? "Reason" : "Note"}</span>
                <Input
                  value={actionNote}
                  onChange={(e) => setActionNote(e.target.value)}
                  placeholder="Optional context"
                />
              </label>
              <div className="flex gap-2">
                <Button
                  tone="primary"
                  type="submit"
                  disabled={retryMutation.isPending || ackMutation.isPending}
                >
                  Confirm
                </Button>
                <Button onClick={() => setAction(null)}>Cancel</Button>
              </div>
            </form>
          </Dialog>
        </>
      ) : null}

      {/* Rule dialogs — rendered outside the tab conditional so they stay mounted */}
      <Dialog
        open={ruleDialog === "create"}
        title="New alert rule"
        description="Fire a notification when a certificate is within the threshold."
        onClose={() => setRuleDialog(null)}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void createRuleMutation.mutateAsync().catch(() => {});
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Name</span>
            <Input
              value={ruleForm.name}
              onChange={(e) =>
                setRuleForm((f) => ({ ...f, name: e.target.value }))
              }
              placeholder="30-day expiry alert"
              required
            />
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>Threshold (days before expiry)</span>
            <Select
              value={String(ruleForm.threshold_days)}
              onChange={(e) =>
                setRuleForm((f) => ({
                  ...f,
                  threshold_days: Number(e.target.value),
                }))
              }
            >
              {[90, 60, 30, 14, 7].map((d) => (
                <option key={d} value={d}>
                  {d} days
                </option>
              ))}
            </Select>
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>Channel</span>
            <Select
              value={ruleForm.channel}
              onChange={(e) =>
                setRuleForm((f) => ({ ...f, channel: e.target.value }))
              }
            >
              <option value="email">Email</option>
              <option value="slack">Slack</option>
              <option value="pagerduty">PagerDuty</option>
              <option value="webhook">Webhook</option>
            </Select>
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>Target</span>
            <Input
              value={ruleForm.target}
              onChange={(e) =>
                setRuleForm((f) => ({ ...f, target: e.target.value }))
              }
              placeholder={
                ruleForm.channel === "email"
                  ? "pki-team@example.com"
                  : ruleForm.channel === "slack"
                    ? "#pki-alerts"
                    : ruleForm.channel === "pagerduty"
                      ? "routing-key"
                      : "https://hooks.example.com/…"
              }
              required
            />
          </label>
          <div className="flex gap-2">
            <Button
              tone="primary"
              type="submit"
              disabled={createRuleMutation.isPending}
            >
              Create rule
            </Button>
            <Button onClick={() => setRuleDialog(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={ruleDialog === "edit"}
        title="Edit alert rule"
        description={activeRule?.name}
        onClose={() => setRuleDialog(null)}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void updateRuleMutation.mutateAsync().catch(() => {});
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Target</span>
            <Input
              value={ruleForm.target}
              onChange={(e) =>
                setRuleForm((f) => ({ ...f, target: e.target.value }))
              }
              placeholder="Destination"
            />
          </label>
          <label className="flex items-center gap-3 text-sm text-foreground">
            <input
              type="checkbox"
              checked={ruleForm.enabled}
              onChange={(e) =>
                setRuleForm((f) => ({ ...f, enabled: e.target.checked }))
              }
              className="h-4 w-4 rounded border-border bg-background text-primary focus:ring-ring"
            />
            <span>Enabled</span>
          </label>
          <div className="flex gap-2">
            <Button
              tone="primary"
              type="submit"
              disabled={updateRuleMutation.isPending}
            >
              Save
            </Button>
            <Button onClick={() => setRuleDialog(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>
    </div>
  );
}
