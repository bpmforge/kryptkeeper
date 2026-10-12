import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, RefreshCw, Stamp, XCircle } from "lucide-react";
import { toast } from "sonner";
import { api } from "../lib/api";
import { extractList } from "../lib/models";
import type { ApprovalRequest, ApprovalStatus } from "../lib/models";
import { Badge, Button, Panel, StateMessage } from "../components/ui";
import { useAuthz } from "../lib/auth";
import { PageHeader } from "../components/PageHeader";

type StatusTone = "success" | "warning" | "danger" | "neutral";

const statusTone: Record<ApprovalStatus, StatusTone> = {
  pending: "warning",
  approved: "success",
  rejected: "danger",
};

const statusFilters: { value: string; label: string }[] = [
  { value: "pending", label: "Pending" },
  { value: "approved", label: "Approved" },
  { value: "rejected", label: "Rejected" },
  { value: "", label: "All" },
];

function ApprovalRow({
  request,
  onApprove,
  onReject,
  busy,
  currentPrincipal,
}: {
  request: ApprovalRequest;
  onApprove: (id: string) => void;
  onReject: (id: string, reason: string) => void;
  busy: boolean;
  currentPrincipal?: string;
}) {
  const [rejecting, setRejecting] = useState(false);
  const [reason, setReason] = useState("");
  const isOwnRequest =
    Boolean(currentPrincipal) && request.requester === currentPrincipal;

  return (
    <div className="rounded-2xl border border-border bg-background/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <Stamp className="h-5 w-5 text-muted-foreground shrink-0" />
          <div>
            <div className="font-semibold text-foreground">
              Template {request.template_id}
            </div>
            <div className="mt-0.5 text-xs text-muted-foreground">
              Requested by {request.requester} &middot;{" "}
              {new Date(request.requested_at).toLocaleString()}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge tone={statusTone[request.status]}>{request.status}</Badge>
          {request.status === "pending" && (
            <>
              <span
                title={
                  isOwnRequest
                    ? "You raised this request — a second person must approve it."
                    : undefined
                }
              >
                <Button
                  tone="primary"
                  disabled={busy || isOwnRequest}
                  onClick={() => onApprove(request.id)}
                >
                  <CheckCircle2 className="h-4 w-4" />
                  Approve
                </Button>
              </span>
              <Button
                tone="secondary"
                disabled={busy}
                onClick={() => setRejecting((r) => !r)}
              >
                <XCircle className="h-4 w-4" />
                Reject
              </Button>
            </>
          )}
        </div>
      </div>

      <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-xs text-muted-foreground sm:grid-cols-4">
        <span>
          <span className="text-muted-foreground">CA</span>{" "}
          <span className="font-mono text-foreground">{request.ca_id}</span>
        </span>
        {request.team_id && (
          <span>
            <span className="text-muted-foreground">Team</span>{" "}
            <span className="text-foreground">{request.team_id}</span>
          </span>
        )}
        {request.decided_by && (
          <span>
            <span className="text-muted-foreground">Decided by</span>{" "}
            <span className="text-foreground">{request.decided_by}</span>
          </span>
        )}
        {request.issued_fingerprint && (
          <span className="col-span-2">
            <span className="text-muted-foreground">Issued cert</span>{" "}
            <Link
              to={`/certificates/${request.issued_fingerprint}`}
              className="font-mono text-primary hover:underline"
            >
              {request.issued_fingerprint.slice(0, 16)}…
            </Link>
          </span>
        )}
        {request.reject_reason && (
          <span className="col-span-2">
            <span className="text-muted-foreground">Reason</span>{" "}
            <span className="text-foreground">{request.reject_reason}</span>
          </span>
        )}
      </div>

      {rejecting && request.status === "pending" && (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Rejection reason (required)"
            className="min-w-[260px] flex-1 rounded-xl border border-border bg-card px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
          />
          <Button
            tone="danger"
            disabled={busy || reason.trim() === ""}
            onClick={() => {
              onReject(request.id, reason.trim());
              setRejecting(false);
              setReason("");
            }}
          >
            Confirm rejection
          </Button>
        </div>
      )}
    </div>
  );
}

export default function Approvals() {
  const [status, setStatus] = useState("pending");
  const queryClient = useQueryClient();
  const authz = useAuthz();

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["approvals", status],
    queryFn: () => api.approvals(status ? { status } : undefined),
    refetchInterval: 30_000,
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["approvals"] });
    void queryClient.invalidateQueries({ queryKey: ["certificates"] });
  };

  const approveMutation = useMutation({
    mutationFn: (id: string) => api.approveRequest(id),
    onSuccess: () => {
      toast.success("Request approved — certificate issued");
      invalidate();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const rejectMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.rejectRequest(id, reason),
    onSuccess: () => {
      toast.success("Request rejected");
      invalidate();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const requests = extractList<ApprovalRequest>(data?.data);
  const busy = approveMutation.isPending || rejectMutation.isPending;

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Operations"
        title="Approvals"
        description="Certificate requests for templates that require manual approval. Approving issues the certificate immediately."
        actions={
          <Button
            tone="secondary"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw
              className={`h-4 w-4 ${isFetching ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
        }
      />

      <div className="flex gap-2">
        {statusFilters.map((f) => (
          <button
            key={f.value}
            type="button"
            onClick={() => setStatus(f.value)}
            className={`rounded-xl px-3 py-1.5 text-sm transition ${
              status === f.value
                ? "bg-primary/15 text-primary border border-primary/40"
                : "border border-border text-muted-foreground hover:text-foreground"
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      <Panel
        title="Approval Queue"
        subtitle="Requests are issued on approval and audit-logged either way"
      >
        {isLoading ? (
          <StateMessage title="Loading" message="Fetching approval queue…" />
        ) : error ? (
          <StateMessage
            tone="error"
            title="Unavailable"
            message="Could not load approval requests."
          />
        ) : requests.length === 0 ? (
          <StateMessage
            title="No requests"
            message={
              status === "pending"
                ? "Nothing waiting for approval. Templates with require_approval route new requests here."
                : "No approval requests match this filter."
            }
          />
        ) : (
          <div className="space-y-3">
            {requests.map((request) => (
              <ApprovalRow
                key={request.id}
                request={request}
                busy={busy}
                onApprove={(id) => approveMutation.mutate(id)}
                onReject={(id, reason) => rejectMutation.mutate({ id, reason })}
                currentPrincipal={authz.data?.principal}
              />
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
