import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Layers, RefreshCw, Send } from "lucide-react";
import { api } from "../lib/api";
import {
  NOTIFY_CHANNELS,
  isNotifyChannel,
  notifyOwnerTeam,
  openPqcWave,
  renewalPath,
  type NotifyChannel,
} from "../lib/actions";
import {
  Badge,
  Button,
  Dialog,
  formatDateTime,
  Input,
  Panel,
  Select,
  StateMessage,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { extractList } from "../lib/models";
import type {
  CaRecord,
  ExpiryTimelineReport as ExpiryData,
} from "../lib/models";
import { ReportSkeleton } from "../components/Skeletons";

const BUCKET_COLORS = [
  "bg-state-over",
  "bg-state-over",
  "bg-state-attn",
  "bg-state-attn",
  "bg-state-attn",
  "bg-state-auto",
  "bg-state-auto",
  "bg-state-idle",
];

// S-46: resolve CA ids to display names; the raw id renders only when no
// name exists, marked as such. `ready` gates the fall-through so an
// in-flight lookup can't flash a false "no name exists".
const ET_CA_SENTINELS = ["unknown"];

function resolveCaLabel(
  caId: string,
  names: Map<string, string>,
  ready: boolean,
): { label: string; isIdentifier: boolean } {
  if (ET_CA_SENTINELS.includes(caId))
    return { label: caId, isIdentifier: false };
  const name = names.get(caId);
  if (name) return { label: name, isIdentifier: false };
  if (!ready) return { label: caId, isIdentifier: false };
  return { label: caId, isIdentifier: true };
}

export default function ExpiryTimeline() {
  const navigate = useNavigate();
  const q = useQuery({
    queryKey: ["report-expiry-timeline"],
    queryFn: api.expiryTimeline,
  });
  const report = q.data?.data as ExpiryData | undefined;

  const casQuery = useQuery({
    queryKey: ["cas", { limit: 200 }],
    queryFn: () => api.cas({ limit: 200 }),
  });
  const cas = extractList<CaRecord>(casQuery.data?.data, ["items"]);
  const caNames = new Map(
    cas
      .filter((c) => c.display_name || c.name)
      .map((c) => [c.id, (c.display_name || c.name) as string]),
  );
  const caNamesReady = !casQuery.isLoading;

  const maxBucket = Math.max(1, ...(report?.buckets.map((b) => b.count) ?? []));

  const [banner, setBanner] = useState<string | null>(null);

  const [notifyTeam, setNotifyTeam] = useState<string | null>(null);
  const [notifyChannel, setNotifyChannel] = useState<NotifyChannel>("email");
  const [notifyTarget, setNotifyTarget] = useState("");
  const [notifyError, setNotifyError] = useState<string | null>(null);

  const notifyMutation = useMutation({
    mutationFn: () =>
      notifyOwnerTeam(notifyTeam ?? "", notifyChannel, notifyTarget),
    onSuccess: (outcome) => {
      if (outcome.ok) {
        setNotifyTeam(null);
        setNotifyTarget("");
        setNotifyError(null);
        setBanner(outcome.message);
      } else {
        setNotifyError(outcome.message);
      }
    },
  });

  const [waveConfirmOpen, setWaveConfirmOpen] = useState(false);
  const [waveError, setWaveError] = useState<string | null>(null);

  const waveMutation = useMutation({
    mutationFn: openPqcWave,
    onSuccess: (outcome) => {
      if (outcome.ok) {
        setWaveConfirmOpen(false);
        setWaveError(null);
        setBanner(outcome.message);
        navigate("/reports/pqc-migration");
      } else {
        setWaveError(outcome.message);
      }
    },
  });

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto fade-in-up">
      <PageHeader
        eyebrow="Reports"
        title="Expiry Timeline"
        description="Certificate expiry distribution across time windows."
        actions={
          <Button
            tone="secondary"
            onClick={() => {
              setWaveError(null);
              setWaveConfirmOpen(true);
            }}
          >
            <Layers size={13} aria-hidden="true" />
            Open PQC wave
          </Button>
        }
      />

      {banner && (
        <StateMessage tone="success" title="Action complete" message={banner} />
      )}

      {q.isLoading && <ReportSkeleton tiles={4} />}
      {q.error && (
        <StateMessage
          tone="error"
          title="Report unavailable"
          message={(q.error as Error).message}
        />
      )}

      {report && (
        <>
          {/* Bar chart */}
          <Panel
            title="Expiry Distribution"
            subtitle={`${report.total_certs} certificates · ${formatDateTime(report.generated_at)}`}
          >
            <div
              role="img"
              aria-label={`Bar chart: expiry distribution of ${report.total_certs} certificates across ${report.buckets.length} time buckets. A table with the same data follows.`}
              className="space-y-3"
            >
              {report.buckets.map((bucket, i) => (
                <div
                  key={bucket.label}
                  aria-hidden="true"
                  className="flex items-center gap-3"
                >
                  <div className="w-36 text-xs text-muted-foreground shrink-0 text-right">
                    {bucket.label}
                  </div>
                  <div className="flex-1 h-7 bg-muted/60 rounded-lg overflow-hidden">
                    {bucket.count > 0 && (
                      <div
                        className={`h-full ${BUCKET_COLORS[i] ?? "bg-state-idle"} rounded-lg transition-all duration-700 flex items-center px-2`}
                        style={{ width: `${(bucket.count / maxBucket) * 100}%` }}
                      >
                        <span className="text-xs font-bold text-primary-foreground whitespace-nowrap">
                          {bucket.count}
                        </span>
                      </div>
                    )}
                  </div>
                  <div className="w-12 text-right text-xs font-semibold text-foreground shrink-0">
                    {bucket.count}
                  </div>
                </div>
              ))}
            </div>
            <div className="sr-only">
              <table>
                <caption>
                  Expiry distribution: {report.total_certs} certificates by time until
                  expiry.
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Expires in</th>
                    <th scope="col">Certificates</th>
                  </tr>
                </thead>
                <tbody>
                  {report.buckets.map((bucket) => (
                    <tr key={bucket.label}>
                      <td>{bucket.label}</td>
                      <td>{bucket.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* By CA */}
            <Panel title="By Certificate Authority">
              {Object.keys(report.by_ca).length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {report.total_certs === 0
                    ? "No certificates in inventory yet. Issue a certificate to populate the CA breakdown."
                    : "No certificates have a usable expiry date to group by CA. Set a valid expiry on a certificate to include it."}
                </p>
              ) : (
                Object.entries(report.by_ca)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 10)
                  .map(([ca, count]) => {
                    const { label, isIdentifier } = resolveCaLabel(
                      ca,
                      caNames,
                      caNamesReady,
                    );
                    return (
                      <div
                        key={ca}
                        className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
                      >
                        <span className="flex items-center gap-1.5 min-w-0">
                          {isIdentifier && <Badge tone="neutral">ID</Badge>}
                          <span
                            className={
                              isIdentifier
                                ? "font-mono text-xs text-muted-foreground truncate"
                                : "text-sm text-foreground truncate"
                            }
                            title={
                              isIdentifier
                                ? "No display name on record — showing the raw identifier"
                                : undefined
                            }
                          >
                            {label === "unknown" ? "Unknown CA" : label}
                          </span>
                        </span>
                        <div className="flex items-center gap-3 shrink-0 ml-4">
                          <span className="text-sm font-semibold text-primary">
                            {count}
                          </span>
                          {/* "unknown" isn't a real CA id — the report falls
                            back to it when a cert has none, so there is
                            nothing for ca_id= to filter on. Only link real
                            CAs. */}
                          <span
                            title={
                              ca === "unknown"
                                ? "These certificates have no CA on record, so there is nothing to renew by CA."
                                : undefined
                            }
                          >
                            <Button
                              tone="secondary"
                              disabled={ca === "unknown"}
                              onClick={() => navigate(renewalPath(ca))}
                            >
                              <RefreshCw size={12} aria-hidden="true" />
                              Renew
                            </Button>
                          </span>
                        </div>
                      </div>
                    );
                  })
              )}
            </Panel>

            {/* By team */}
            <Panel title="By Owner Team">
              {Object.keys(report.by_owner_team).length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {report.total_certs === 0
                    ? "No certificates in inventory yet. Issue a certificate to populate the owner-team breakdown."
                    : "No certificates have a usable expiry date to group by owner team. Set a valid expiry on a certificate to include it."}
                </p>
              ) : (
                Object.entries(report.by_owner_team)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 10)
                  .map(([team, count]) => (
                    <div
                      key={team}
                      className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
                    >
                      <span className="text-sm text-foreground truncate">
                        {team}
                      </span>
                      <div className="flex items-center gap-3 shrink-0 ml-4">
                        <span className="text-sm font-semibold text-primary">
                          {count}
                        </span>
                        <span
                          title={
                            team === "unassigned"
                              ? "These certificates have no owner team, so there is nobody to notify."
                              : undefined
                          }
                        >
                          <Button
                            tone="secondary"
                            disabled={team === "unassigned"}
                            onClick={() => {
                              setNotifyTeam(team);
                              setNotifyChannel("email");
                              setNotifyTarget("");
                              setNotifyError(null);
                            }}
                          >
                            <Send size={12} aria-hidden="true" />
                            Notify owner
                          </Button>
                        </span>
                      </div>
                    </div>
                  ))
              )}
            </Panel>
          </div>
        </>
      )}

      <Dialog
        open={notifyTeam !== null}
        title="Notify owner"
        description={
          notifyTeam
            ? `Send a real delivery to the "${notifyTeam}" owner team about their expiring certificates.`
            : undefined
        }
        onClose={() => setNotifyTeam(null)}
        size="sm"
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            notifyMutation.mutate();
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Channel</span>
            <Select
              value={notifyChannel}
              onChange={(e) => {
                const v = e.target.value;
                if (isNotifyChannel(v)) setNotifyChannel(v);
              }}
            >
              {NOTIFY_CHANNELS.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </Select>
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>Delivery target</span>
            <Input
              value={notifyTarget}
              onChange={(e) => setNotifyTarget(e.target.value)}
              placeholder="owner@example.com"
              aria-label="Delivery target"
            />
          </label>
          {notifyError && (
            <p role="alert" className="text-xs text-state-over">
              {notifyError}
            </p>
          )}
          <div className="flex gap-2">
            <Button
              tone="primary"
              type="submit"
              disabled={notifyMutation.isPending}
            >
              {notifyMutation.isPending ? "Sending…" : "Confirm send"}
            </Button>
            <Button onClick={() => setNotifyTeam(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={waveConfirmOpen}
        title="Open PQC wave"
        description="This re-derives post-quantum migration waves from the current certificate inventory. Continue?"
        onClose={() => setWaveConfirmOpen(false)}
        size="sm"
      >
        <div className="space-y-4">
          {waveError && (
            <p role="alert" className="text-xs text-state-over">
              {waveError}
            </p>
          )}
          <div className="flex gap-2">
            <Button
              tone="primary"
              onClick={() => waveMutation.mutate()}
              disabled={waveMutation.isPending}
            >
              {waveMutation.isPending ? "Opening…" : "Confirm"}
            </Button>
            <Button onClick={() => setWaveConfirmOpen(false)}>Cancel</Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
