import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, RefreshCw, XCircle } from "lucide-react";
import { toast } from "sonner";
import {
  approvalInboxApi,
  quorumProgress,
  type InboxItem,
  type InboxItemType,
  type InboxQuery,
} from "../lib/approvalInboxApi";
import { canDecidePendingActions, useAuthz } from "../lib/auth";
import { Badge, Button, Input, Panel, Select, StateMessage } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { useCaNames, useTemplateNames } from "../lib/useResourceNames";
import { formatAge, humanizeInboxSummary } from "../lib/inboxFormat";

const typeLabel: Record<InboxItemType, string> = {
  certificate_approval: "Certificate approval",
  pending_action: "Pending action",
};

function InboxRow({
  item,
  busy,
  currentPrincipal,
  role,
  progress,
  focused,
  caNames,
  templateNames,
  onApprove,
  onReject,
}: {
  item: InboxItem;
  busy: boolean;
  currentPrincipal?: string;
  role?: string;
  progress?: string;
  focused?: boolean;
  caNames: Map<string, string>;
  templateNames: Map<string, string>;
  onApprove: () => void;
  onReject: (reason: string) => void;
}) {
  const [rejecting, setRejecting] = useState(false);
  const [reason, setReason] = useState("");
  const isOwn = Boolean(currentPrincipal) && item.requester === currentPrincipal;
  const roleBlocked = item.type === "pending_action" && !canDecidePendingActions(role);
  const roleBlockedReason = `Your role (${role}) cannot approve or reject pending actions; that needs pki-admin or pki-operator.`;
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focused) ref.current?.scrollIntoView?.({ block: "center" });
  }, [focused]);

  return (
    <div
      ref={ref}
      data-focused={focused ? "true" : undefined}
      className={`rounded-2xl border border-border bg-background/60 p-4 ${focused ? "ring-2 ring-primary" : ""}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Badge tone="neutral">
              {typeLabel[item.type]}
            </Badge>
            {progress ? <Badge tone="warning">{progress}</Badge> : null}
          </div>
          <div className="mt-1 font-semibold text-foreground">{humanizeInboxSummary(item.summary, caNames, templateNames)}</div>
          <div className="mt-0.5 text-xs text-muted-foreground">
            Requested by {item.requester}
            {item.tenant ? <> &middot; tenant {item.tenant}</> : null} &middot;{" "}
            <span>{formatAge(item.age_seconds)}</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span
            title={roleBlocked ? roleBlockedReason : isOwn ? "You cannot approve your own request" : undefined}
          >
            <Button tone="primary" disabled={busy || isOwn || roleBlocked} onClick={onApprove}>
              <CheckCircle2 className="h-4 w-4" />
              Approve
            </Button>
          </span>
          <span title={roleBlocked ? roleBlockedReason : undefined}>
            <Button tone="secondary" disabled={busy || roleBlocked} onClick={() => setRejecting((r) => !r)}>
              <XCircle className="h-4 w-4" />
              Reject
            </Button>
          </span>
        </div>
      </div>
      {rejecting ? (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Rejection reason (required)"
            className="min-w-[260px] flex-1"
          />
          <Button
            tone="danger"
            disabled={busy || reason.trim() === ""}
            onClick={() => {
              onReject(reason.trim());
              setRejecting(false);
              setReason("");
            }}
          >
            Confirm rejection
          </Button>
        </div>
      ) : null}
    </div>
  );
}

export default function ApprovalInbox() {
  const [type, setType] = useState<"" | InboxItemType>("");
  const [minAge, setMinAge] = useState("");
  const [tenant, setTenant] = useState("");
  // Quorum progress per item key, kept client-side: the inbox list does not
  // carry approvals_count, so the 202 body is the only source until refetch.
  const [progress, setProgress] = useState<Record<string, string>>({});
  const queryClient = useQueryClient();
  const { names: caNames } = useCaNames();
  const { names: templateNames } = useTemplateNames();
  const authz = useAuthz();
  // Deep link from other pages: ?focus=<type>:<id> highlights one row.
  const [searchParams] = useSearchParams();
  const focusKey = searchParams.get("focus");

  const query: InboxQuery = {
    ...(type ? { type } : {}),
    ...(minAge ? { min_age: minAge } : {}),
    ...(tenant.trim() ? { tenant: tenant.trim() } : {}),
  };

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["approval-inbox", query],
    queryFn: () => approvalInboxApi.list(query),
    refetchInterval: 30_000,
  });
  const items = data?.data ?? [];

  // The tenant filter only matters when the caller can see more than one
  // tenant (the server ignores it for tenant principals); keep it visible
  // while a value is typed so it cannot vanish under the user.
  const distinctTenants = new Set(items.map((i) => i.tenant).filter(Boolean));
  const showTenant = distinctTenants.size > 1 || tenant !== "";

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["approval-inbox"] });
    void queryClient.invalidateQueries({ queryKey: ["certificates"] });
    void queryClient.invalidateQueries({ queryKey: ["approvals"] });
    void queryClient.invalidateQueries({ queryKey: ["pending-actions"] });
  };

  const approve = useMutation({
    mutationFn: (item: InboxItem) => approvalInboxApi.approve(item.type, item.id),
    onSuccess: (res, item) => {
      const p = quorumProgress(res);
      if (p && p.approvals < p.required) {
        setProgress((prev) => ({
          ...prev,
          [`${item.type}:${item.id}`]: `${p.approvals} of ${p.required} approvals`,
        }));
        toast.success(`Approval recorded: ${p.approvals} of ${p.required} needed`);
      } else {
        toast.success("Approved");
      }
      invalidate();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const reject = useMutation({
    mutationFn: ({ item, reason }: { item: InboxItem; reason: string }) =>
      approvalInboxApi.reject(item.type, item.id, reason),
    onSuccess: () => {
      toast.success("Rejected");
      invalidate();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const busy = approve.isPending || reject.isPending;

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Operations"
        title="Approvals inbox"
        description="Certificate requests and proposed actions waiting for a second person, oldest first."
        actions={
          <Button tone="secondary" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`h-4 w-4 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        }
      />

      <div className="flex flex-wrap items-end gap-3">
        <label className="text-xs text-muted-foreground">
          Type
          <Select
            aria-label="Type"
            value={type}
            onChange={(e) => setType(e.target.value as "" | InboxItemType)}
          >
            <option value="">All</option>
            <option value="certificate_approval">Certificate approvals</option>
            <option value="pending_action">Pending actions</option>
          </Select>
        </label>
        <label className="text-xs text-muted-foreground">
          Age
          <Select aria-label="Age" value={minAge} onChange={(e) => setMinAge(e.target.value)}>
            <option value="">Any</option>
            <option value="1h">&gt; 1h</option>
            <option value="24h">&gt; 24h</option>
            <option value="72h">&gt; 72h</option>
          </Select>
        </label>
        {showTenant ? (
          <label className="text-xs text-muted-foreground">
            Tenant
            <Input
              aria-label="Tenant"
              value={tenant}
              onChange={(e) => setTenant(e.target.value)}
              placeholder="Tenant id"
            />
          </label>
        ) : null}
      </div>

      {authz.data?.role && authz.data.role !== "pki-admin" ? (
        <p role="note" className="rounded-xl border border-border bg-background/60 px-4 py-3 text-sm text-muted-foreground">
          Signed in as {authz.data.role}.{" "}
          {authz.data.role === "approver"
            ? "You see the certificate requests you raised and those on templates that name your role as an approver, and you can approve or reject the ones you did not raise. Key and CA actions are decided only by pki-admin or pki-operator."
            : "You see the certificate requests you raised and those on templates that name your role as an approver. Pending actions can be decided only by pki-admin or pki-operator."}
        </p>
      ) : null}

      <Panel title="Waiting for approval" subtitle="Every decision is audit-logged">
        {isLoading ? (
          <StateMessage title="Loading" message="Fetching the approvals inbox…" />
        ) : error ? (
          <StateMessage tone="error" title="Unavailable" message="Could not load the approvals inbox." />
        ) : items.length === 0 ? (
          <StateMessage title="Inbox empty" message="Nothing is waiting for approval." />
        ) : (
          <div className="space-y-3">
            {items.map((item) => (
              <InboxRow
                key={`${item.type}:${item.id}`}
                item={item}
                busy={busy}
                caNames={caNames}
                templateNames={templateNames}
                currentPrincipal={authz.data?.principal}
                role={authz.data?.role}
                progress={progress[`${item.type}:${item.id}`]}
                focused={focusKey === `${item.type}:${item.id}`}
                onApprove={() => approve.mutate(item)}
                onReject={(reason) => reject.mutate({ item, reason })}
              />
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
