import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { api, type CTFinding } from "../lib/api";
import {
  Badge,
  Button,
  Panel,
  Select,
  StateMessage,
  formatDateTime,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";

const STATUS_TONE = {
  open: "warning",
  acknowledged: "neutral",
  known_issuer: "info",
} as const;

function FindingRow({ finding }: { finding: CTFinding }) {
  const queryClient = useQueryClient();
  const onSuccess = (message: string) => () => {
    toast.success(message);
    return queryClient.invalidateQueries({ queryKey: ["ct-findings"] });
  };
  const onError = (err: Error) => toast.error(err.message);
  const acknowledge = useMutation({
    mutationFn: () => api.acknowledgeCTFinding(finding.id),
    onSuccess: onSuccess("Finding acknowledged"),
    onError,
  });
  const knownIssuer = useMutation({
    mutationFn: () => api.markCTFindingKnownIssuer(finding.id),
    onSuccess: onSuccess("Marked as known issuer"),
    onError,
  });
  const pending = acknowledge.isPending || knownIssuer.isPending;

  return (
    <div className="rounded-2xl border border-border bg-background/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="font-semibold text-foreground">{finding.domain}</div>
          {finding.common_name ? (
            <div className="mt-0.5 text-xs text-muted-foreground">
              {finding.common_name}
            </div>
          ) : null}
        </div>
        <Badge tone={STATUS_TONE[finding.status]}>{finding.status}</Badge>
      </div>

      <dl className="mt-3 grid grid-cols-1 gap-x-6 gap-y-1 text-xs sm:grid-cols-2">
        <div>
          <dt className="inline text-muted-foreground">CA </dt>
          <dd className="inline text-foreground">{finding.ca}</dd>
        </div>
        <div>
          <dt className="inline text-muted-foreground">Serial </dt>
          <dd className="inline break-all font-mono text-foreground">
            {finding.serial}
          </dd>
        </div>
        <div>
          <dt className="inline text-muted-foreground">Not before </dt>
          <dd className="inline text-foreground">
            {finding.not_before ? formatDateTime(finding.not_before) : "—"}
          </dd>
        </div>
        <div>
          <dt className="inline text-muted-foreground">Log id </dt>
          <dd className="inline text-foreground">{finding.log_id}</dd>
        </div>
      </dl>

      {finding.ours ? (
        <p className="mt-2 text-xs text-foreground">
          Issued by one of your CAs
        </p>
      ) : null}

      {finding.status === "open" ? (
        <div className="mt-3 flex flex-wrap gap-2">
          <Button disabled={pending} onClick={() => acknowledge.mutate()}>
            Acknowledge
          </Button>
          <Button disabled={pending} onClick={() => knownIssuer.mutate()}>
            Known issuer
          </Button>
        </div>
      ) : (
        <p className="mt-3 text-xs text-muted-foreground">
          Resolved{finding.resolved_by ? ` by ${finding.resolved_by}` : ""}
          {finding.resolved_at
            ? ` on ${formatDateTime(finding.resolved_at)}`
            : ""}
        </p>
      )}

      {finding.ours && finding.revoke_url ? (
        <div className="mt-3 space-y-1">
          <Link to={finding.revoke_url} className="text-sm underline">
            Find in inventory to revoke
          </Link>
          <p className="text-xs text-muted-foreground">
            Not in inventory yet? Import the certificate first, then revoke it
            from Certificates.
          </p>
        </div>
      ) : null}
    </div>
  );
}

export default function CTFindings() {
  const [status, setStatus] = useState("open");
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["ct-findings", status],
    queryFn: () => api.ctFindings(status === "all" ? undefined : status),
    refetchInterval: 60_000,
  });
  const findings = data?.data?.findings ?? [];

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Today"
        title="CT Findings"
        description="Certificates logged in Certificate Transparency for your domains that are not in inventory."
        actions={
          <div className="flex items-center gap-2">
            <Select
              aria-label="Status filter"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="known_issuer">Known issuer</option>
              <option value="all">All</option>
            </Select>
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
          </div>
        }
      />

      <Panel title="Findings">
        {isLoading ? (
          <StateMessage title="Loading" message="Fetching CT findings…" />
        ) : error ? (
          <StateMessage
            tone="error"
            title="Unavailable"
            message="Could not load CT findings."
            action={<Button onClick={() => refetch()}>Retry</Button>}
          />
        ) : findings.length === 0 ? (
          <StateMessage
            title={`No ${status === "all" ? "" : status.replace("_", " ") + " "}findings`.replace("  ", " ")}
            message="CT monitoring only runs for domains listed under Settings or KRYPTKEEPER_CT_DOMAINS."
          />
        ) : (
          <div className="space-y-3">
            {findings.map((f) => (
              <FindingRow key={f.id} finding={f} />
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
