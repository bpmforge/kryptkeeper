import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { useState } from "react";
import { api, type TeamQuota } from "../lib/api";
import { useAuthz } from "../lib/auth";
import { extractList } from "../lib/models";
import {
  mergeRequests,
  type RequestRow,
  type RequestState,
} from "../lib/myRequests";
import type { ApprovalRequest, CertificateRecord } from "../lib/models";
import { scrollableProps } from "../lib/scrollable";
import { savePemFile } from "../lib/utils";
import { Badge, Button, Panel, StateMessage } from "../components/ui";
import { PageHeader } from "../components/PageHeader";

const stateLabel: Record<RequestState, string> = {
  pending: "Pending",
  approved: "Approved",
  issued: "Issued",
  denied: "Denied",
};

const stateTone: Record<
  RequestState,
  "warning" | "info" | "success" | "danger"
> = {
  pending: "warning",
  approved: "info",
  issued: "success",
  denied: "danger",
};

function QuotaCard({ quota }: { quota: TeamQuota }) {
  const unlimited = quota.limit === 0;
  const resets = quota.resets_at ? quota.resets_at.slice(0, 10) : "";
  const reached = !unlimited && quota.remaining === 0;
  return (
    <Panel>
      <div className="space-y-3">
        <div className="text-sm font-semibold text-foreground">
          Monthly quota
        </div>
        {unlimited ? (
          <p className="text-sm text-foreground">
            Unlimited. No monthly limit applies to your team.
          </p>
        ) : (
          <p className="text-sm text-foreground">
            {quota.used} of {quota.limit} used this month
            {resets ? <> (resets {resets} UTC)</> : null}
          </p>
        )}
        {reached ? (
          <StateMessage
            tone="error"
            title="Quota reached"
            message="Further requests are refused until the quota resets."
          />
        ) : quota.warn ? (
          <StateMessage
            title="You have used 80% or more of your monthly quota"
            message="Plan remaining requests, or ask an administrator to raise the quota."
          />
        ) : null}
      </div>
    </Panel>
  );
}

export default function MyRequests() {
  const authz = useAuthz();
  const principal = authz.data?.principal ?? "";
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const approvals = useQuery({
    queryKey: ["my-requests", "approvals"],
    queryFn: () => api.approvals({ limit: 100 }),
  });
  const certs = useQuery({
    queryKey: ["my-requests", "certificates", principal],
    queryFn: () => api.certificates({ team_id: principal, limit: 100 }),
    enabled: principal !== "",
  });
  const quota = useQuery({
    queryKey: ["team-quota", principal],
    queryFn: () => api.teamQuota(principal),
    enabled: principal !== "",
    retry: false,
  });

  const certList = extractList<CertificateRecord>(certs.data?.data, ["items"]);
  const rows = mergeRequests(
    extractList<ApprovalRequest>(approvals.data?.data, ["items"]),
    certList,
  );
  const hasDetails = rows.some(
    (r) => r.state === "denied" || r.state === "approved",
  );
  const certByFp = new Map(certList.map((c) => [c.fingerprint_sha256, c]));

  const download = async (row: RequestRow) => {
    if (!row.fingerprint) return;
    setDownloadError(null);
    try {
      const pem = await api.downloadCertificatePem(row.fingerprint);
      savePemFile(
        `${certByFp.get(row.fingerprint)?.common_name || row.fingerprint}.pem`,
        pem,
      );
    } catch (e) {
      setDownloadError(
        e instanceof Error ? e.message : "Certificate download failed.",
      );
    }
  };

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Requests"
        title="My requests"
        description="Track your certificate requests and how much of your team's monthly quota is left."
      />
      {quota.data ? <QuotaCard quota={quota.data.data} /> : null}
      {downloadError ? (
        <StateMessage
          tone="error"
          title="Download failed"
          message={downloadError}
        />
      ) : null}
      {approvals.isLoading ? (
        <StateMessage title="Loading your requests" />
      ) : approvals.isError ? (
        <StateMessage
          tone="error"
          title="Could not load your requests"
          message={
            approvals.error instanceof Error
              ? approvals.error.message
              : undefined
          }
        />
      ) : rows.length === 0 ? (
        <StateMessage
          title="No requests yet"
          message="Use Issue certificate to ask for one."
        />
      ) : (
        <Panel>
          <div className="overflow-x-auto" {...scrollableProps}>
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Your certificate requests</caption>
            <thead className="text-muted-foreground">
              <tr>
                <th scope="col" className="pb-2 pr-3">
                  Status
                </th>
                <th scope="col" className="pb-2 pr-3">
                  Certificate or template
                </th>
                <th scope="col" className="pb-2 pr-3">
                  Requested
                </th>
                {hasDetails ? (
                  <th scope="col" className="pb-2 pr-3">
                    Details
                  </th>
                ) : null}
                <th scope="col" className="pb-2">
                  Download
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.key} className="border-t border-border">
                  <td className="py-2 pr-3">
                    <Badge tone={stateTone[row.state]}>
                      {stateLabel[row.state]}
                    </Badge>
                  </td>
                  <td className="py-2 pr-3 text-foreground">{row.name}</td>
                  <td className="py-2 pr-3 whitespace-nowrap text-muted-foreground">
                    {row.requestedAt ? row.requestedAt.slice(0, 10) : ""}
                  </td>
                  {hasDetails ? (
                    <td className="py-2 pr-3 text-muted-foreground">
                      {row.state === "denied"
                        ? (row.reason ?? "No reason given")
                        : ""}
                      {row.state === "approved" ? "Being issued" : ""}
                    </td>
                  ) : null}
                  <td className="py-2">
                    {row.state === "issued" && row.fingerprint ? (
                      <Button
                        tone="secondary"
                        aria-label={`Download certificate ${row.name}`}
                        onClick={() => void download(row)}
                      >
                        <Download className="h-4 w-4" />
                        Download
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </Panel>
      )}
    </div>
  );
}
