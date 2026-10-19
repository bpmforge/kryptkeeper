import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import { api, type DiscoverySchedule, type ManagedTarget } from "../lib/api";
import {
  Badge,
  Button,
  Dialog,
  Input,
  Panel,
  SectionLabel,
  Select,
  StateMessage,
} from "../components/ops-ui";
import { PageHeader } from "../components/PageHeader";
import { BulkTakeoverDialog } from "./Certificates";
import { canManageCertificates, canManageDiscovery, useAuthz } from "../lib/auth";
import { AcceptRiskDialog, type AcceptRiskTarget } from "../components/AcceptRiskDialog";
import { FindingFunnelPanel } from "../components/FindingFunnel";
import { extractList } from "../lib/models";
import { useOperationEvents } from "../hooks/useOperationEvents";
import {
  observedProtocol,
  primaryTrustClass,
  topFindingChips,
  findingLabel,
} from "../lib/discoveryDisplay";
import { formatDateTime } from "../components/ui";
import { scrollableProps } from "../lib/scrollable";
import { humanizeEnum } from "../lib/utils";
import {
  applyAuthorizedIssuer,
  INVENTORY_CLASSES,
  INVENTORY_CLASS_LABEL,
  inventoryClassLabel,
} from "../lib/inventoryClass";
import {
  TRUST_CLASSES,
  TRUST_CLASS_LABEL,
  trustClassLabel,
} from "../lib/trustClass";
import type {
  CertificateRecord,
  DiscoveryEndpointRecord,
  DiscoveryScanJobRecord,
  DiscoverySummary,
  SearchResult,
} from "../lib/models";
import type { components } from "../generated/api-types";
import {
  runBulkAction,
  useBulkSelection,
  type BulkProgress,
} from "../lib/bulk";

// W18-17: winrm's target is a managed target id (a Windows machine cert
// store), not a host/CIDR — see internal/bootstrap/handlers_discovery.go's
// scanTypeWinRM case and the /discovery/scans enum in docs/openapi.yaml.
const scanTypeWinRM = "winrm";
// W24-10: ssh scans a Linux/Unix managed target (install_mode ssh) by id too.
const scanTypeSSH = "ssh";

// ui/src/lib/models.ts is a hand-written mirror of the OpenAPI spec and is
// out of write_scope for this ticket (W3-02); DiscoverySummary there
// predates the `findings` field W2-11 added to the spec. Read it straight
// from the generated types instead of widening scope to models.ts.
type FindingFunnelSummary = components["schemas"]["FindingFunnelSummary"];
type DiscoverySummaryWithFindings = DiscoverySummary & {
  findings?: FindingFunnelSummary;
};

// Tone for a scan job's status badge. completed_with_errors is a finished
// scan that found hosts it could not read, so it is a warning, not success.
function scanJobTone(status: string): "danger" | "warning" | "success" | "info" {
  switch (status) {
    case "failed":
      return "danger";
    case "running":
    case "completed_with_errors":
      return "warning";
    case "completed":
      return "success";
    default:
      return "info";
  }
}

function isRiskyEndpoint(ep: {
  risky?: boolean;
  risk_score?: number;
}): boolean {
  // Older hubs do not send `risky`; the score is the best they can say.
  return ep.risky ?? (ep.risk_score ?? 0) >= 70;
}

// Compact trust-class badge plus the top findings for a row of the endpoint
// list, so the list answers "whose cert, and what is wrong" without opening
// every endpoint.
function EndpointPosture({ ep }: { ep: DiscoveryEndpointRecord }) {
  const trust = primaryTrustClass(ep);
  const inventory = ep.inventory_class;
  const chips = topFindingChips(ep);
  if (!trust && !inventory && chips.shown.length === 0) {
    return <span className="text-muted-foreground">—</span>;
  }
  return (
    <div className="flex flex-wrap items-center gap-1">
      {inventory ? (
        <Badge tone={inventory === "unknown_issuer" ? "warning" : "neutral"}>
          {inventoryClassLabel(inventory)}
        </Badge>
      ) : trust ? (
        <Badge tone="neutral">{trustClassLabel(trust)}</Badge>
      ) : null}
      {chips.shown.map((c) => (
        <span
          key={c.code}
          title={c.code}
          className={
            c.high
              ? "rounded bg-state-over/10 px-1.5 py-0.5 text-[10px] font-medium text-state-over"
              : "rounded bg-state-attn/10 px-1.5 py-0.5 text-[10px] font-medium text-state-attn"
          }
        >
          {c.label}
        </span>
      ))}
      {chips.more > 0 ? (
        <span className="text-[10px] font-medium text-muted-foreground">
          +{chips.more}
        </span>
      ) : null}
    </div>
  );
}

type DiscoveryFilters = {
  protocol: string;
  riskyOnly: boolean;
  trustClass: string;
  inventoryClass: string;
  scanStatus: string;
};

const thClass =
  "px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground";

function fmtTime(iso: string | null): string {
  return iso ? formatDateTime(iso) : "—";
}

// W24-05: per-target scan cadence. Minutes in the UI, seconds on the wire.
// The UI never computes next run; it prints what the API says (which does
// not advance while a job is running).
function SchedulesPanel({
  canManage,
  onError,
}: {
  canManage: boolean;
  onError: (e: unknown) => void;
}) {
  const queryClient = useQueryClient();
  const schedules = useQuery({
    queryKey: ["discovery-schedules"],
    queryFn: api.discoverySchedules,
    refetchInterval: 15000,
  });
  const [intervalDraft, setIntervalDraft] = useState<Record<string, string>>(
    {},
  );
  const mutation = useMutation({
    mutationFn: (body: { key: string; interval_seconds: number | null }) =>
      api.updateDiscoverySchedule(body),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["discovery-schedules"] }),
    onError,
  });
  const rows: DiscoverySchedule[] = schedules.data?.data ?? [];

  return (
    <Panel
      title="Scan schedules"
      subtitle="Per-target scan interval, last run and next run"
    >
      {schedules.isLoading ? (
        <StateMessage
          title="Loading schedules"
          message="Fetching scan schedules..."
        />
      ) : rows.length === 0 ? (
        <StateMessage
          title="No scheduled targets"
          message="No scheduled targets. Set KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL and a target list, or add a WinRM managed target."
        />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-border" {...scrollableProps}>
          <table className="min-w-full divide-y divide-border">
            <thead className="bg-background/80">
              <tr>
                <th scope="col" className={thClass}>Target</th>
                <th scope="col" className={thClass}>Interval</th>
                <th scope="col" className={thClass}>Last run</th>
                <th scope="col" className={thClass}>Next run</th>
                <th scope="col" className={thClass}>State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.map((s) => {
                const current =
                  s.interval_seconds != null ? String(s.interval_seconds / 60) : "";
                const draft = intervalDraft[s.key] ?? current;
                const minutes = Number(draft);
                const valid =
                  draft.trim() !== "" && Number.isInteger(minutes) && minutes >= 1;
                return (
                  <tr key={s.key}>
                    <td className="px-4 py-3 text-sm text-foreground">
                      {s.name ?? s.target}{" "}
                      <Badge>{s.scan_type}</Badge>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <div className="flex items-center gap-2">
                        <Input
                          type="number"
                          min={1}
                          aria-label={`Interval (minutes) for ${s.key}`}
                          placeholder={
                            s.effective_interval_seconds != null
                              ? `${s.effective_interval_seconds / 60} (global)`
                              : "global"
                          }
                          value={draft}
                          disabled={!canManage}
                          onChange={(e) =>
                            setIntervalDraft((d) => ({
                              ...d,
                              [s.key]: e.target.value,
                            }))
                          }
                          className="w-36"
                        />
                        {canManage ? (
                          <>
                            <Button
                              aria-label={`Save interval for ${s.key}`}
                              disabled={!valid || mutation.isPending}
                              onClick={() =>
                                mutation.mutate({
                                  key: s.key,
                                  interval_seconds: Math.round(minutes * 60),
                                })
                              }
                            >
                              Save
                            </Button>
                            <Button
                              aria-label={`Clear interval for ${s.key}`}
                              disabled={mutation.isPending}
                              onClick={() => {
                                setIntervalDraft((d) => {
                                  const next = { ...d };
                                  delete next[s.key];
                                  return next;
                                });
                                mutation.mutate({
                                  key: s.key,
                                  interval_seconds: null,
                                });
                              }}
                            >
                              Clear
                            </Button>
                          </>
                        ) : null}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {fmtTime(s.last_run)}
                    </td>
                    <td
                      className="px-4 py-3 text-sm text-muted-foreground"
                      title={
                        s.running
                          ? "not advanced while a job is running"
                          : undefined
                      }
                    >
                      {fmtTime(s.next_run)}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {s.running ? <Badge>running</Badge> : "idle"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

export default function Discovery() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { id } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const authz = useAuthz();
  const [filters, setFilters] = useState<DiscoveryFilters>(() => ({
    protocol: searchParams.get("protocol") ?? "",
    riskyOnly: searchParams.get("risky") === "true",
    trustClass: searchParams.get("trust_class") ?? "",
    inventoryClass: searchParams.get("inventory_class") ?? "",
    scanStatus: searchParams.get("scan_status") ?? "",
  }));
  const [endpointCursor, setEndpointCursor] = useState<number | null>(null);
  const updateFilter = (patch: Partial<DiscoveryFilters>) => {
    setEndpointCursor(null);
    setFilters((curr) => ({ ...curr, ...patch }));
  };

  useEffect(() => {
    const next = new URLSearchParams();
    if (filters.protocol) next.set("protocol", filters.protocol);
    if (filters.riskyOnly) next.set("risky", "true");
    if (filters.trustClass) next.set("trust_class", filters.trustClass);
    if (filters.inventoryClass) next.set("inventory_class", filters.inventoryClass);
    if (filters.scanStatus) next.set("scan_status", filters.scanStatus);
    setSearchParams(next, { replace: true });
  }, [filters]); // eslint-disable-line react-hooks/exhaustive-deps
  const [selectedEndpoint, setSelectedEndpoint] = useState<string | null>(null);
  const [scanDialogOpen, setScanDialogOpen] = useState(false);
  const [scanType, setScanType] = useState("full");
  const [scanTarget, setScanTarget] = useState("");
  const [scanPorts, setScanPorts] = useState("");
  // W18-17: winrm's target is a managed target id, not a host/CIDR, so it
  // gets its own field rather than overloading scanTarget — switching scan
  // types must not clobber whatever the operator already typed for the
  // other kind of target.
  const [winrmTargetId, setWinrmTargetId] = useState("");
  const [sshTargetId, setSshTargetId] = useState("");
  // W34-17: one-off sudo password for this ssh scan; sent once, never kept.
  const [jitSudoPassword, setJitSudoPassword] = useState("");
  const [selectedJob, setSelectedJob] = useState<DiscoveryScanJobRecord | null>(
    null,
  );
  const [jobAction, setJobAction] = useState<
    "cancel" | "requeue" | "bulk-cancel" | "bulk-requeue" | null
  >(null);
  const [jobReason, setJobReason] = useState("");
  const [statusMessage, setStatusMessage] = useState<{
    tone: "success" | "error";
    title: string;
    message: string;
  } | null>(null);
  const scanJobSelection = useBulkSelection<string>();
  const discoveredSelection = useBulkSelection<string>();
  const [bulkTakeoverOpen, setBulkTakeoverOpen] = useState(false);
  const [bulkProgress, setBulkProgress] = useState<BulkProgress | null>(null);

  const endpointQuery = useMemo(
    () => ({
      protocol: filters.protocol,
      risky_only: filters.riskyOnly,
      trust_class: filters.trustClass,
      inventory_class: filters.inventoryClass,
      limit: 50,
      ...(endpointCursor != null ? { cursor: endpointCursor } : {}),
    }),
    [
      filters.protocol,
      filters.riskyOnly,
      filters.trustClass,
      filters.inventoryClass,
      endpointCursor,
    ],
  );

  const summary = useQuery({
    queryKey: ["discovery-summary"],
    queryFn: api.discoverySummary,
  });
  // W18-17: same query key RenewalPolicy uses for its "Discover now"
  // button, so the two views share one cache entry for managed targets.
  const managedTargets = useQuery({
    queryKey: ["managed-targets"],
    queryFn: api.targets,
  });
  const winrmTargets: ManagedTarget[] = (
    managedTargets.data?.data ?? []
  ).filter((t) => t.discovery_mode === "winrm");
  // Same predicate as the backend's isSSHDiscoveryTarget (W24-08).
  const sshTargets: ManagedTarget[] = (managedTargets.data?.data ?? []).filter(
    (t) => t.install_mode === "ssh" && t.discovery_mode !== "none",
  );
  const summaryData = summary.data?.data as
    DiscoverySummaryWithFindings | undefined;
  const endpoints = useQuery({
    queryKey: ["discovery-endpoints", endpointQuery],
    queryFn: () => api.discoveryEndpoints(endpointQuery),
  });
  const endpointsMeta = endpoints.data?.meta;
  const { live: streamLive } = useOperationEvents({
    kinds: ["scan"],
    onEvent: (e) => {
      void queryClient.invalidateQueries({ queryKey: ["discovery-scan-jobs"] });
      if (e.status === "completed") {
        void queryClient.invalidateQueries({ queryKey: ["discovery-summary"] });
      }
    },
    onResync: () => {
      void queryClient.invalidateQueries({ queryKey: ["discovery-scan-jobs"] });
      void queryClient.invalidateQueries({ queryKey: ["discovery-summary"] });
    },
  });
  const scanJobs = useQuery({
    queryKey: ["discovery-scan-jobs", filters.scanStatus],
    queryFn: () =>
      api.discoveryScanJobs({ status: filters.scanStatus, limit: 25 }),
    // A queued/running scan finishes server-side within seconds; without
    // polling the table freezes at its load-time snapshot and "watch the
    // scan complete" never happens.
    // While the SSE stream is live, events invalidate this query instead.
    refetchInterval: (query) => {
      if (streamLive) return false;
      const jobs = extractList<DiscoveryScanJobRecord>(query.state.data?.data, [
        "items",
        "scan_jobs",
      ]);
      const active = jobs.some(
        (j) => j.status === "queued" || j.status === "running",
      );
      return active ? 4_000 : false;
    },
  });

  const endpointsData: DiscoveryEndpointRecord[] =
    extractList<DiscoveryEndpointRecord>(endpoints.data?.data, [
      "items",
      "endpoints",
    ]);
  const scanJobsData: DiscoveryScanJobRecord[] =
    extractList<DiscoveryScanJobRecord>(scanJobs.data?.data, [
      "items",
      "scan_jobs",
    ]);
  const selectedKey = id ?? selectedEndpoint ?? null;
  const selected = selectedKey
    ? (endpointsData.find((ep) => ep.id === selectedKey) ?? null)
    : (endpointsData[0] ?? null);
  const selectedHostname = selected?.hostname ?? selected?.ip_address ?? "";
  const certMappings = useQuery({
    queryKey: ["discovery-cert-mappings", selectedHostname],
    queryFn: () => api.search(selectedHostname),
    enabled: !!selectedHostname,
    staleTime: 60_000,
  });
  const certMappingsData: SearchResult[] = Array.isArray(
    certMappings.data?.data,
  )
    ? (certMappings.data!.data as SearchResult[]).filter(
        (r) => r.kind === "certificate",
      )
    : [];
  const endpointScanHistory = scanJobsData.filter(
    (j) =>
      j.target === selectedHostname ||
      (selectedHostname && j.target?.includes(selectedHostname)),
  );
  const canManage = canManageDiscovery(authz.data?.role, authz.data?.scopes);
  const canAcceptRisk = canManageCertificates(authz.data?.role, authz.data?.scopes);
  const discoveredCerts = useQuery({
    queryKey: ["discovered-certs"],
    queryFn: () =>
      api.certificates({
        origin: "discovered",
        management_state: "unmanaged",
        limit: 200,
      }),
    enabled: canAcceptRisk,
  });
  const discoveredItems = extractList<CertificateRecord>(
    discoveredCerts.data?.data,
    ["items"],
  );
  const selectedDiscovered = discoveredItems.filter((c) =>
    discoveredSelection.selected.includes(c.fingerprint_sha256),
  );
  const [acceptRisk, setAcceptRisk] = useState<{ target: AcceptRiskTarget | null; code: string } | null>(null);
  const allScanJobsSelected =
    scanJobsData.length > 0 &&
    scanJobsData.every((job) => scanJobSelection.selected.includes(job.id));
  const selectedScanJobCount = scanJobSelection.selected.length;

  const refreshAll = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["discovery-summary"] }),
      queryClient.invalidateQueries({ queryKey: ["discovery-endpoints"] }),
      queryClient.invalidateQueries({ queryKey: ["discovery-scan-jobs"] }),
    ]);
  };

  const createScanMutation = useMutation({
    mutationFn: async () =>
      // W18-17: a winrm scan's target is a managed target id and the
      // backend rejects a ports list on it, so it gets its own shape
      // rather than reusing the host/CIDR + ports request built below.
      scanType === scanTypeWinRM
        ? api.createDiscoveryScan({
            scan_type: scanTypeWinRM,
            target: winrmTargetId,
          })
        : scanType === scanTypeSSH
          ? api.createDiscoveryScan({
              scan_type: scanTypeSSH,
              target: sshTargetId,
              ...(jitSudoPassword ? { jit_sudo_password: jitSudoPassword } : {}),
            })
          : api.createDiscoveryScan({
            scan_type: scanType,
            target: scanTarget,
            // Optional org-standardized custom ports, merged with the scan
            // type's catalogue. Bad tokens are dropped client-side.
            ports: scanPorts
              .split(",")
              .map((p) => parseInt(p.trim(), 10))
              .filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535),
          }),
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Scan queued",
        message: "Discovery scan accepted.",
      });
      setScanDialogOpen(false);
      setJitSudoPassword("");
      await refreshAll();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Scan failed",
        message:
          e instanceof Error ? e.message : "Check the target and try again.",
      });
    },
  });

  const cancelScanMutation = useMutation({
    mutationFn: async () => {
      if (!selectedJob) throw new Error("No scan job selected");
      return api.cancelDiscoveryScanJob({
        scan_job_id: selectedJob.id,
        reason: jobReason,
      });
    },
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Scan cancelled",
        message: "The queued scan has been stopped.",
      });
      setJobAction(null);
      await refreshAll();
    },
    onError: (e) =>
      setStatusMessage({
        tone: "error",
        title: "Cancel failed",
        message: e instanceof Error ? e.message : "Try again in a moment.",
      }),
  });

  const requeueScanMutation = useMutation({
    mutationFn: async () => {
      if (!selectedJob) throw new Error("No scan job selected");
      return api.requeueDiscoveryScanJob({
        scan_job_id: selectedJob.id,
        reason: jobReason,
      });
    },
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Scan requeued",
        message: "A replacement scan job was created.",
      });
      setJobAction(null);
      await refreshAll();
    },
    onError: (e) =>
      setStatusMessage({
        tone: "error",
        title: "Requeue failed",
        message: e instanceof Error ? e.message : "Try again in a moment.",
      }),
  });

  const bulkCancelMutation = useMutation({
    mutationFn: async () => {
      const ids = [...scanJobSelection.selected];
      return {
        total: ids.length,
        errors: await runBulkAction(
          ids,
          (jobId) =>
            api.cancelDiscoveryScanJob({
              scan_job_id: jobId,
              reason: jobReason,
            }),
          setBulkProgress,
        ),
      };
    },
    onSuccess: async ({ total, errors }) => {
      setStatusMessage({
        tone: errors.length > 0 ? "error" : "success",
        title:
          errors.length > 0
            ? `${errors.length} cancellations failed`
            : "Bulk cancel complete",
        message:
          errors.length > 0
            ? `${total - errors.length} of ${total} cancelled successfully.`
            : `${total} scan jobs cancelled.`,
      });
      setJobAction(null);
      setBulkProgress(null);
      scanJobSelection.clear();
      await refreshAll();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Bulk cancel failed",
        message: e instanceof Error ? e.message : "Try again.",
      });
      setBulkProgress(null);
    },
  });

  const bulkRequeueMutation = useMutation({
    mutationFn: async () => {
      const ids = [...scanJobSelection.selected];
      return {
        total: ids.length,
        errors: await runBulkAction(
          ids,
          (jobId) =>
            api.requeueDiscoveryScanJob({
              scan_job_id: jobId,
              reason: jobReason,
            }),
          setBulkProgress,
        ),
      };
    },
    onSuccess: async ({ total, errors }) => {
      setStatusMessage({
        tone: errors.length > 0 ? "error" : "success",
        title:
          errors.length > 0
            ? `${errors.length} requeues failed`
            : "Bulk requeue complete",
        message:
          errors.length > 0
            ? `${total - errors.length} of ${total} requeued successfully.`
            : `${total} scan jobs requeued.`,
      });
      setJobAction(null);
      setBulkProgress(null);
      scanJobSelection.clear();
      await refreshAll();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Bulk requeue failed",
        message: e instanceof Error ? e.message : "Try again.",
      });
      setBulkProgress(null);
    },
  });

  // W34-06: declare the issuer of an unknown-issuer certificate as a CA group
  // we accept. The hub re-judges stored certificates at once; the cached pages
  // are updated here so the row changes class without waiting for the refetch.
  const authorizeIssuer = useMutation({
    mutationFn: (issuerDN: string) =>
      api.createAuthorizedIssuer({
        name: issuerDN.split(",")[0]?.replace(/^CN=/i, "") || issuerDN,
        kind: "issuer_dn",
        value: issuerDN,
      }),
    onSuccess: (_res, issuerDN) => {
      queryClient.setQueriesData<{ data?: unknown }>(
        { queryKey: ["discovery-endpoints"] },
        (old) => {
          const data = old?.data as
            | { endpoints?: DiscoveryEndpointRecord[]; items?: DiscoveryEndpointRecord[] }
            | undefined;
          if (!old || !data) return old;
          const key = data.endpoints ? "endpoints" : data.items ? "items" : null;
          if (!key) return old;
          return {
            ...old,
            data: { ...data, [key]: applyAuthorizedIssuer(data[key] ?? [], issuerDN) },
          };
        },
      );
      void queryClient.invalidateQueries({ queryKey: ["discovery-summary"] });
      void queryClient.invalidateQueries({ queryKey: ["discovery-endpoints"] });
      setStatusMessage({
        tone: "success",
        title: "Issuer authorized",
        message: "Certificates from this issuer are now authorized external.",
      });
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Could not authorize the issuer",
        message: e instanceof Error ? e.message : "Try again.",
      });
    },
  });

  const openJobAction = (
    nextAction: "cancel" | "requeue",
    job: DiscoveryScanJobRecord,
  ) => {
    setSelectedJob(job);
    setJobAction(nextAction);
    setJobReason("");
    setStatusMessage(null);
  };

  const openBulkJobAction = (nextAction: "bulk-cancel" | "bulk-requeue") => {
    setJobAction(nextAction);
    setJobReason("");
    setStatusMessage(null);
    setBulkProgress(null);
  };

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Discovery"
        title="Discovery"
        description="Spot exposed infrastructure, inspect risk, and queue scans."
        actions={
          canManage ? (
            <Button
              tone="primary"
              onClick={() => {
                // Page-level entry: the only other "Queue scan" button lives
                // in the endpoint DETAIL panel, which needs an existing
                // endpoint — so a fresh install could never start its
                // FIRST scan. Scans produce endpoints; the door cannot be
                // behind one.
                setScanTarget("");
                setScanDialogOpen(true);
                setStatusMessage(null);
              }}
            >
              New scan
            </Button>
          ) : undefined
        }
      />

      {summary.isLoading ? (
        <StateMessage
          title="Loading discovery summary"
          message="Checking inventory and scan health..."
        />
      ) : null}
      {summary.error ? (
        <StateMessage
          tone="error"
          title="Discovery summary unavailable"
          message="Try again shortly."
        />
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Panel>
          <div className="text-sm text-muted-foreground">Discovered</div>
          <div className="mt-2 text-3xl font-semibold text-foreground">
            {summaryData?.discovered_endpoints ?? 0}
          </div>
        </Panel>
        <Panel>
          <div className="text-sm text-muted-foreground">Mapped Certs</div>
          <div className="mt-2 text-3xl font-semibold text-foreground">
            {summaryData?.mapped_certificates ?? 0}
          </div>
        </Panel>
        <Panel>
          <div className="text-sm text-muted-foreground">Risky</div>
          <div className="mt-2 text-3xl font-semibold text-state-over">
            {summaryData?.risky_endpoints ?? 0}
          </div>
        </Panel>
        <Panel>
          <div className="text-sm text-muted-foreground">Active Scans</div>
          <div className="mt-2 text-3xl font-semibold text-primary">
            {summaryData?.active_scan_jobs ?? 0}
          </div>
        </Panel>
      </div>

      {summaryData?.inventory_classes ? (
        <Panel title="Certificates by issuer class">
          <ul className="flex flex-wrap gap-3 text-sm" aria-label="Certificates by issuer class">
            {INVENTORY_CLASSES.map((cls) => (
              <li key={cls} className="rounded-lg border border-border bg-background/60 px-3 py-2">
                <span className="text-muted-foreground">{INVENTORY_CLASS_LABEL[cls]}</span>{" "}
                <span className="font-semibold text-foreground">
                  {summaryData.inventory_classes?.[cls] ?? 0}
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}

      <FindingFunnelPanel
        title="Findings"
        subtitle="Certificate flags (expired, self-signed, weak key...) and endpoint TLS issues"
        findings={summaryData?.findings}
      />
      <AcceptRiskDialog
        open={acceptRisk !== null}
        target={acceptRisk?.target ?? null}
        findingCode={acceptRisk?.code}
        onClose={() => setAcceptRisk(null)}
        onProposed={() => {
          void queryClient.invalidateQueries({ queryKey: ["exceptions"] });
          void queryClient.invalidateQueries({ queryKey: ["discovery-summary"] });
        }}
      />

      <div className="grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
        <Panel
          className="self-start"
          title="Scan filters"
          subtitle="Narrow the endpoint and scan queue"
        >
          <div className="grid gap-3 md:grid-cols-2">
            <label className="space-y-2 text-sm text-foreground">
              <span>Protocol</span>
              <Select
                aria-label="Filter by protocol"
                value={filters.protocol}
                onChange={(e) => updateFilter({ protocol: e.target.value })}
              >
                <option value="">All protocols</option>
                <option value="tls">TLS</option>
                <option value="http">HTTP</option>
                <option value="ldap">LDAP</option>
                <option value="smtp">SMTP</option>
                <option value="ssh">SSH</option>
              </Select>
            </label>
            <label className="space-y-2 text-sm text-foreground">
              <span>Risky only</span>
              <Select
                aria-label="Show risky endpoints only"
                value={String(filters.riskyOnly)}
                onChange={(e) =>
                  updateFilter({ riskyOnly: e.target.value === "true" })
                }
              >
                <option value="false">All endpoints</option>
                <option value="true">
                  Risky only (expired, self-signed, weak, deprecated TLS...)
                </option>
              </Select>
            </label>
            <label className="space-y-2 text-sm text-foreground">
              <span>Issuer</span>
              <Select
                aria-label="Filter by trust class"
                value={filters.trustClass}
                onChange={(e) => updateFilter({ trustClass: e.target.value })}
              >
                <option value="">Any issuer</option>
                {TRUST_CLASSES.map((cls) => (
                  <option key={cls} value={cls}>
                    {TRUST_CLASS_LABEL[cls]}
                  </option>
                ))}
              </Select>
            </label>
            <label className="space-y-2 text-sm text-foreground">
              <span>Inventory class</span>
              <Select
                aria-label="Filter by inventory class"
                value={filters.inventoryClass}
                onChange={(e) => updateFilter({ inventoryClass: e.target.value })}
              >
                <option value="">Any class</option>
                {INVENTORY_CLASSES.map((cls) => (
                  <option key={cls} value={cls}>
                    {INVENTORY_CLASS_LABEL[cls]}
                  </option>
                ))}
              </Select>
            </label>
            <label className="space-y-2 text-sm text-foreground">
              <span>Scan status</span>
              <Select
                aria-label="Filter scan jobs by status"
                value={filters.scanStatus}
                onChange={(e) =>
                  setFilters((curr) => ({
                    ...curr,
                    scanStatus: e.target.value,
                  }))
                }
              >
                <option value="">All scan jobs</option>
                <option value="queued">Queued</option>
                <option value="running">Running</option>
                <option value="completed">Complete</option>
                <option value="completed_with_errors">
                  Complete with errors
                </option>
                <option value="failed">Failed</option>
                <option value="cancelled">Cancelled</option>
              </Select>
            </label>
            <Button
              tone="primary"
              onClick={() => {
                void endpoints.refetch();
                void scanJobs.refetch();
                void summary.refetch();
              }}
            >
              Refresh
            </Button>
          </div>
        </Panel>

        <Panel
          title="Endpoint detail"
          subtitle="Cert mappings and scan history"
        >
          {selected ? (
            <div className="space-y-5">
              {/* Header */}
              <div>
                <h2 className="text-lg font-semibold text-foreground">
                  {selected.hostname || selected.ip_address}
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  {selected.ip_address &&
                  selected.ip_address !== selected.hostname
                    ? `${selected.ip_address}:`
                    : ""}
                  {selected.port ? `${selected.port}` : ""} ·{" "}
                  {observedProtocol(selected)}
                </p>
              </div>
              {selectedKey ? (
                <Button onClick={() => navigate("/discovery")}>
                  ← Back to list
                </Button>
              ) : null}

              {/* Risk + last seen */}
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <div className="text-muted-foreground">Risk score</div>
                  <div
                    className={
                      isRiskyEndpoint(selected)
                        ? "font-semibold text-state-over"
                        : (selected.risk_score ?? 0) >= 40
                          ? "font-semibold text-state-attn"
                          : "text-state-auto"
                    }
                  >
                    {selected.risk_score ?? 0}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Last seen</div>
                  <div className="text-foreground">
                    {selected.last_seen_at ? formatDateTime(selected.last_seen_at) : "—"}
                  </div>
                </div>
                {selected.server_tech ? (
                  <div>
                    <div className="text-muted-foreground">Server</div>
                    <div className="text-foreground capitalize">
                      {selected.server_tech}
                    </div>
                  </div>
                ) : null}
                {selected.recommended_install_mode ? (
                  <div>
                    <div className="text-muted-foreground">
                      Suggested automation
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-foreground uppercase">
                        {selected.recommended_install_mode}
                      </span>
                      {canManage ? (
                        <button
                          className="text-xs text-primary hover:underline"
                          onClick={() =>
                            navigate(
                              `/targets/setup?host=${encodeURIComponent(selected.hostname ?? selected.ip_address ?? "")}&install_mode=${selected.recommended_install_mode}`,
                            )
                          }
                        >
                          Set up →
                        </button>
                      ) : null}
                    </div>
                  </div>
                ) : null}
              </div>

              {selected.ssh_banner ||
              (selected.ssh_host_key_algorithms?.length ?? 0) > 0 ? (
                <div className="rounded-lg border border-border bg-background/60 p-3">
                  <div className="text-xs font-medium text-muted-foreground">
                    SSH host keys
                  </div>
                  {selected.ssh_banner ? (
                    <div className="mt-1 font-mono text-xs text-foreground">
                      {selected.ssh_banner}
                    </div>
                  ) : null}
                  {(selected.ssh_host_key_algorithms?.length ?? 0) > 0 ? (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {selected.ssh_host_key_algorithms!.map((a) => {
                        // ssh-rsa (SHA-1) and ssh-dss are deprecated/weak.
                        const weak = a === "ssh-rsa" || a === "ssh-dss";
                        return (
                          <span
                            key={a}
                            className={
                              weak
                                ? "rounded bg-state-over/10 px-1.5 py-0.5 text-[10px] font-medium text-state-over"
                                : "rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground"
                            }
                            title={
                              weak
                                ? "Deprecated/weak host-key algorithm"
                                : undefined
                            }
                          >
                            {a}
                            {weak ? " ⚠" : ""}
                          </span>
                        );
                      })}
                    </div>
                  ) : null}
                </div>
              ) : null}

              {selected.install_posture ? (
                <div className="rounded-lg border border-border bg-background/60 p-3" data-testid="install-posture">
                  <div className="flex items-center gap-2">
                    <div className="text-xs font-medium text-muted-foreground">Install posture</div>
                    <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                      {humanizeEnum(selected.install_posture.posture)}
                    </span>
                  </div>
                  <div className="mt-1 font-mono text-xs text-foreground" title={selected.install_posture.host}>
                    {selected.install_posture.path}
                    {selected.install_posture.owner ? ` · ${selected.install_posture.owner}` : ""}
                    {selected.install_posture.mode ? ` · ${selected.install_posture.mode}` : ""}
                  </div>
                  <ul className="mt-2 space-y-1">
                    {(selected.install_posture.findings ?? []).map((finding) => {
                      const code = finding.split(":")[0].trim();
                      const accepted = selected.install_posture!.accepted_findings?.includes(code);
                      const fileId = selected.install_posture!.file_id;
                      return (
                        <li
                          key={finding}
                          className={`flex items-center justify-between gap-2 rounded px-2 py-1 text-xs ${
                            accepted ? "bg-muted text-muted-foreground" : "bg-state-over/10 text-state-over"
                          }`}
                        >
                          <span title={finding}>{finding}</span>
                          {accepted ? (
                            <span className="shrink-0 text-[10px] font-medium">Risk accepted</span>
                          ) : canAcceptRisk && fileId ? (
                            <button
                              className="shrink-0 text-primary underline"
                              onClick={() => setAcceptRisk({ target: { type: "target_file", id: fileId }, code })}
                            >
                              Accept risk
                            </button>
                          ) : null}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ) : null}

              {selected.crypto_posture ? (
                <div className="rounded-lg border border-border bg-background/60 p-3">
                  <div className="flex items-center gap-2">
                    <div className="text-xs font-medium text-muted-foreground">
                      Crypto posture
                    </div>
                    {selected.crypto_posture.pqc?.hybrid_negotiated ? (
                      <span className="rounded bg-state-auto/10 px-1.5 py-0.5 text-[10px] font-medium text-state-auto">
                        ML-KEM negotiated
                      </span>
                    ) : selected.crypto_posture.pqc?.hybrid_offered ? (
                      <span className="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                        ML-KEM offered
                      </span>
                    ) : null}
                  </div>
                  <div className="mt-1 text-xs text-foreground">
                    {selected.crypto_posture.negotiated_version}
                    {selected.crypto_posture.negotiated_group
                      ? ` · ${selected.crypto_posture.negotiated_group}`
                      : ""}
                  </div>
                  {(selected.crypto_posture.offered_versions?.length ?? 0) >
                  0 ? (
                    <div className="mt-1 text-[11px] text-muted-foreground">
                      offers:{" "}
                      {selected.crypto_posture.offered_versions!.join(", ")}
                    </div>
                  ) : null}
                  {(selected.crypto_posture.weak_findings?.length ?? 0) > 0 ? (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {selected.crypto_posture.weak_findings!.map((w) => (
                        <span
                          key={w}
                          className="rounded bg-state-over/10 px-1.5 py-0.5 text-[10px] font-medium text-state-over"
                        >
                          {humanizeEnum(w)}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </div>
              ) : null}

              {(selected.issues?.length ?? 0) > 0 ? (
                <div>
                  <SectionLabel>Endpoint findings</SectionLabel>
                  <ul className="mt-2 space-y-1" data-testid="endpoint-findings">
                    {selected.issues!.map((issue) => (
                      <li
                        key={issue}
                        className="flex items-center justify-between gap-2 rounded bg-state-over/10 px-2 py-1 text-xs text-state-over"
                      >
                        <span title={issue}>{findingLabel(issue)}</span>
                        {canAcceptRisk ? (
                          <button
                            className="shrink-0 text-primary underline disabled:cursor-not-allowed disabled:opacity-50"
                            disabled={!selected.mapped_certs?.[0]}
                            title={selected.mapped_certs?.[0] ? undefined : "No certificate mapped"}
                            onClick={() =>
                              setAcceptRisk({
                                target: { type: "certificate", id: selected.mapped_certs![0].fingerprint },
                                code: issue,
                              })
                            }
                          >
                            Accept risk
                          </button>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}

              {/* Cert-to-endpoint mappings — the scan's real
                  certificate_endpoints join; the text search below is only
                  a fallback for endpoints with no recorded mapping. */}
              <div>
                <SectionLabel>Mapped certificates</SectionLabel>
                {(selected.mapped_certs?.length ?? 0) > 0 ? (
                  <ul className="mt-2 space-y-1">
                    {(selected.mapped_certs ?? []).map((mc) => (
                      <li
                        key={mc.fingerprint}
                        className="flex items-center justify-between rounded-lg border border-border bg-background/60 px-3 py-2 text-sm"
                      >
                        <div>
                          <div className="font-medium text-foreground">
                            {mc.common_name ||
                              `${mc.fingerprint.slice(0, 16)}…`}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {mc.valid_until
                              ? `${new Date(mc.valid_until) < new Date() ? "expired" : "expires"} ${new Date(mc.valid_until).toLocaleDateString()}`
                              : ""}
                            {mc.risk_score >= 40
                              ? ` · risk ${mc.risk_score}`
                              : ""}
                            {mc.chain_ca
                              ? " · CA in served chain"
                              : mc.inventory_class
                                ? ` · ${inventoryClassLabel(mc.inventory_class)}`
                                : mc.trust_class
                                  ? ` · ${trustClassLabel(mc.trust_class)}`
                                  : ""}
                            {mc.chain_complete === false
                              ? " · intermediate not served"
                              : ""}
                          </div>
                          {canManage &&
                          !mc.chain_ca &&
                          mc.inventory_class === "unknown_issuer" &&
                          mc.issuer_dn ? (
                            <button
                              className="mt-1 text-xs text-primary hover:underline"
                              aria-label={`Authorize this issuer for ${mc.common_name || mc.fingerprint.slice(0, 16)}`}
                              disabled={authorizeIssuer.isPending}
                              onClick={() => authorizeIssuer.mutate(mc.issuer_dn!)}
                            >
                              Authorize this issuer
                            </button>
                          ) : null}
                          {mc.risk_flags && mc.risk_flags.length > 0 ? (
                            <div className="mt-1 flex flex-wrap gap-1">
                              {mc.risk_flags.map((f) => (
                                <span
                                  key={f}
                                  className="rounded bg-state-attn/10 px-1.5 py-0.5 text-[10px] font-medium text-state-attn"
                                >
                                  {humanizeEnum(f)}
                                  {canAcceptRisk ? (
                                    <button
                                      className="ml-1 text-primary underline"
                                      aria-label={`Accept risk for ${f}`}
                                      onClick={() =>
                                        setAcceptRisk({
                                          target: { type: "certificate", id: mc.fingerprint },
                                          code: f,
                                        })
                                      }
                                    >
                                      Accept risk
                                    </button>
                                  ) : null}
                                </span>
                              ))}
                            </div>
                          ) : null}
                        </div>
                        <button
                          className="ml-2 shrink-0 text-xs text-primary hover:text-primary"
                          onClick={() =>
                            navigate(`/certificates/${mc.fingerprint}`)
                          }
                        >
                          View →
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : certMappings.isLoading ? (
                  <p className="mt-2 text-xs text-muted-foreground">
                    Searching certificates…
                  </p>
                ) : certMappingsData.length === 0 ? (
                  <p className="mt-2 text-xs text-muted-foreground">
                    No certificates found for this hostname.{" "}
                    <button
                      className="text-primary underline hover:text-primary"
                      onClick={() =>
                        navigate(
                          `/search?q=${encodeURIComponent(selectedHostname)}`,
                        )
                      }
                    >
                      Open full search
                    </button>
                  </p>
                ) : (
                  <ul className="mt-2 space-y-1">
                    {certMappingsData.slice(0, 5).map((cert) => (
                      <li
                        key={cert.id}
                        className="flex items-center justify-between rounded-lg border border-border bg-background/60 px-3 py-2 text-sm"
                      >
                        <div>
                          <div className="font-medium text-foreground">
                            {cert.label}
                          </div>
                          {cert.description ? (
                            <div className="text-xs text-muted-foreground">
                              {cert.description}
                            </div>
                          ) : null}
                        </div>
                        <div className="ml-2 flex shrink-0 gap-2">
                          <button
                            className="text-xs text-primary hover:text-primary"
                            onClick={() => navigate(cert.url)}
                          >
                            View →
                          </button>
                          <button
                            className="text-xs text-state-attn hover:text-state-attn"
                            onClick={() => navigate(`${cert.url}?takeover=1`)}
                          >
                            Take over →
                          </button>
                        </div>
                      </li>
                    ))}
                    {certMappingsData.length > 5 ? (
                      <li className="text-xs text-muted-foreground">
                        +{certMappingsData.length - 5} more —{" "}
                        <button
                          className="text-primary underline"
                          onClick={() =>
                            navigate(
                              `/search?q=${encodeURIComponent(selectedHostname)}`,
                            )
                          }
                        >
                          see all
                        </button>
                      </li>
                    ) : null}
                  </ul>
                )}
              </div>

              {/* Scan history timeline */}
              <div>
                <SectionLabel>Scan history</SectionLabel>
                {endpointScanHistory.length === 0 ? (
                  <p className="mt-2 text-xs text-muted-foreground">
                    No scans recorded for this endpoint.
                  </p>
                ) : (
                  <ol className="mt-2 space-y-2 border-l border-border pl-4">
                    {endpointScanHistory.slice(0, 6).map((job) => (
                      <li key={job.id} className="relative text-sm">
                        <span className="absolute -left-[18px] top-1.5 h-2 w-2 rounded-full bg-muted" />
                        <div className="flex items-center gap-2">
                          <Badge tone={scanJobTone(job.status)}>
                            {job.status}
                          </Badge>
                          <span className="text-foreground">
                            {job.scan_type}
                          </span>
                        </div>
                        <div className="mt-0.5 text-xs text-muted-foreground">
                          {job.queued_at
                            ? formatDateTime(job.queued_at)
                            : "—"}
                        </div>
                        {job.error ? (
                          <div className="mt-0.5 text-xs text-state-attn">
                            {job.error}
                          </div>
                        ) : null}
                      </li>
                    ))}
                  </ol>
                )}
              </div>

              {/* Actions */}
              <div className="flex flex-wrap gap-2 pt-1">
                {canManage ? (
                  <Button
                    tone="primary"
                    onClick={() => {
                      setScanTarget(
                        selected.hostname || selected.ip_address || "",
                      );
                      setScanDialogOpen(true);
                      setStatusMessage(null);
                    }}
                  >
                    Queue scan
                  </Button>
                ) : null}
                <Button
                  onClick={() =>
                    navigate(
                      `/search?q=${encodeURIComponent(selectedHostname)}`,
                    )
                  }
                >
                  Search certs
                </Button>
              </div>
            </div>
          ) : (
            <StateMessage
              title="No endpoint selected"
              message="Choose a row in the endpoint table."
            />
          )}
        </Panel>
      </div>

      <Panel title="Endpoints" subtitle="Filtered inventory with risk scoring">
        {endpoints.isLoading ? (
          <StateMessage
            title="Loading endpoints"
            message="Fetching discovered infrastructure..."
          />
        ) : null}
        {endpoints.error ? (
          <StateMessage
            tone="error"
            title="Endpoints unavailable"
            message="Try again shortly."
          />
        ) : null}
        <div className="overflow-x-auto rounded-xl border border-border" {...scrollableProps}>
          <table className="min-w-full divide-y divide-border">
            <thead className="bg-background/80">
              <tr>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Hostname
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Port
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Protocol
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Risk Score
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Posture
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border bg-background/40">
              {endpointsData.map((ep) => (
                <tr
                  key={ep.id}
                  className={selected?.id === ep.id ? "bg-card/80" : ""}
                >
                  <td className="px-4 py-3 text-sm text-foreground">
                    <button
                      type="button"
                      className="text-left font-medium hover:text-primary"
                      onClick={() => {
                        setSelectedEndpoint(ep.id);
                        navigate(`/discovery/endpoints/${ep.id}`);
                      }}
                    >
                      {ep.hostname || ep.ip_address}
                    </button>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {ep.port === 0 ? "secret" : ep.port}
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {observedProtocol(ep)}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <div className="flex items-center gap-2">
                      <Badge
                        tone={
                          isRiskyEndpoint(ep)
                            ? "danger"
                            : (ep.risk_score ?? 0) >= 40
                              ? "warning"
                              : "success"
                        }
                      >
                        {ep.risk_score ?? 0}
                      </Badge>
                      {isRiskyEndpoint(ep) ? (
                        <span className="text-xs font-semibold uppercase tracking-wide text-state-over">
                          risky
                        </span>
                      ) : null}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <EndpointPosture ep={ep} />
                  </td>
                </tr>
              ))}
              {endpointsData.length === 0 ? (
                <tr>
                  <td
                    colSpan={5}
                    className="px-4 py-10 text-center text-sm text-muted-foreground"
                  >
                    Nothing discovered yet. Queue a scan (New scan, top right)
                    to sweep a host or CIDR — or adjust the filters if you
                    expected results.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        <div className="mt-4 flex items-center justify-between text-sm text-muted-foreground">
          <span>
            {endpointsMeta?.total != null
              ? `${endpointsMeta.total} total · page size ${endpointsMeta.limit ?? 50}`
              : ""}
          </span>
          <div className="flex gap-2">
            <Button
              disabled={!endpointsMeta?.prev_cursor}
              onClick={() =>
                setEndpointCursor(
                  typeof endpointsMeta?.prev_cursor === "number"
                    ? endpointsMeta.prev_cursor
                    : null,
                )
              }
            >
              ← Previous
            </Button>
            <Button
              disabled={!endpointsMeta?.next_cursor}
              onClick={() =>
                setEndpointCursor(
                  typeof endpointsMeta?.next_cursor === "number"
                    ? endpointsMeta.next_cursor
                    : null,
                )
              }
            >
              Next →
            </Button>
          </div>
        </div>
      </Panel>

      {canAcceptRisk ? (
        <Panel
          title="Discovered certificates"
          subtitle="Unmanaged certificates found by scans"
        >
          {discoveredCerts.isLoading ? (
            <StateMessage
              title="Loading certificates"
              message="Fetching discovered certificates..."
            />
          ) : discoveredItems.length === 0 ? (
            <StateMessage
              title="No unmanaged discovered certificates"
              message="Certificates found by scans that are not yet managed appear here."
            />
          ) : (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-2 text-sm text-foreground">
                <Button
                  onClick={() =>
                    discoveredSelection.toggleAll(
                      discoveredItems.map((c) => c.fingerprint_sha256),
                    )
                  }
                >
                  Select all visible
                </Button>
                <Button
                  tone="primary"
                  onClick={() => setBulkTakeoverOpen(true)}
                  disabled={selectedDiscovered.length === 0}
                >
                  Take over selected
                </Button>
                <span className="text-muted-foreground">
                  {selectedDiscovered.length} selected
                </span>
              </div>
              <div className="overflow-x-auto rounded-xl border border-border" {...scrollableProps}>
                <table className="min-w-full divide-y divide-border">
                  <thead className="bg-background/80">
                    <tr>
                      {["Select", "Common name", "Issuer", "Valid until"].map(
                        (h) => (
                          <th
                            key={h}
                            scope="col"
                            className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                          >
                            {h}
                          </th>
                        ),
                      )}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border bg-background/40">
                    {discoveredItems.map((c) => {
                      const name = c.common_name || c.fingerprint_sha256;
                      return (
                        <tr key={c.fingerprint_sha256}>
                          <td className="px-4 py-3 text-sm text-foreground">
                            <input
                              type="checkbox"
                              aria-label={`Select ${name}`}
                              checked={discoveredSelection.selected.includes(
                                c.fingerprint_sha256,
                              )}
                              onChange={() =>
                                discoveredSelection.toggle(c.fingerprint_sha256)
                              }
                              className="h-4 w-4 rounded border-border bg-background text-primary focus:ring-ring"
                            />
                          </td>
                          <td className="px-4 py-3 text-sm text-foreground">
                            {name}
                          </td>
                          <td className="px-4 py-3 text-sm text-muted-foreground">
                            {c.issuer_cn || "—"}
                          </td>
                          <td
                            className={`whitespace-nowrap px-4 py-3 text-sm ${c.valid_until && new Date(c.valid_until) < new Date() ? "text-state-over" : "text-muted-foreground"}`}
                          >
                            {c.valid_until
                              ? new Date(c.valid_until).toLocaleDateString()
                              : "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
          <BulkTakeoverDialog
            open={bulkTakeoverOpen}
            certs={selectedDiscovered}
            onClose={() => setBulkTakeoverOpen(false)}
            onDone={() => {
              discoveredSelection.clear();
              void discoveredCerts.refetch();
            }}
          />
        </Panel>
      ) : null}

      <Panel title="Scan jobs" subtitle="Queue health and progress">
        {scanJobs.isLoading ? (
          <StateMessage
            title="Loading scan jobs"
            message="Fetching scan queue..."
          />
        ) : null}
        {statusMessage ? (
          <StateMessage
            tone={statusMessage.tone}
            title={statusMessage.title}
            message={statusMessage.message}
          />
        ) : null}
        {canManage ? (
          <div className="mb-3 flex flex-wrap items-center gap-2 text-sm text-foreground">
            <Button
              onClick={() =>
                scanJobSelection.toggleAll(scanJobsData.map((j) => j.id))
              }
            >
              {allScanJobsSelected ? "Clear selection" : "Select all visible"}
            </Button>
            <Button
              onClick={() => openBulkJobAction("bulk-requeue")}
              disabled={selectedScanJobCount === 0}
            >
              Bulk requeue
            </Button>
            <Button
              tone="danger"
              onClick={() => openBulkJobAction("bulk-cancel")}
              disabled={selectedScanJobCount === 0}
            >
              Bulk cancel
            </Button>
            <span className="text-muted-foreground">
              {selectedScanJobCount} selected
            </span>
          </div>
        ) : null}
        <div className="overflow-x-auto rounded-xl border border-border" {...scrollableProps}>
          <table className="min-w-full divide-y divide-border">
            <thead className="bg-background/80">
              <tr>
                {canManage ? (
                  <th
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                  >
                    Select
                  </th>
                ) : null}
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                >
                  Scan type
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
              {scanJobsData.map((job) => (
                <tr key={job.id}>
                  {canManage ? (
                    <td className="px-4 py-3 text-sm text-foreground">
                      <input
                        type="checkbox"
                        aria-label={`Select scan job ${job.target || job.id}`}
                        checked={scanJobSelection.selected.includes(job.id)}
                        onChange={() => scanJobSelection.toggle(job.id)}
                        className="h-4 w-4 rounded border-border bg-background text-primary focus:ring-ring"
                      />
                    </td>
                  ) : null}
                  <td className="px-4 py-3 text-sm text-foreground">
                    {job.scan_type || "—"}
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {job.target || "—"}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <Badge tone={scanJobTone(job.status)}>{job.status}</Badge>
                    {job.error ? (
                      <div
                        className="mt-1 max-w-md text-xs text-muted-foreground"
                        data-testid="scan-job-error"
                      >
                        {job.error}
                      </div>
                    ) : null}
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {job.queued_at
                      ? formatDateTime(job.queued_at)
                      : "—"}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {canManage ? (
                      <div className="flex flex-wrap gap-2">
                        <Button onClick={() => openJobAction("requeue", job)}>
                          Requeue
                        </Button>
                        <Button
                          tone="danger"
                          onClick={() => openJobAction("cancel", job)}
                          disabled={
                            job.status === "cancelled" ||
                            job.status === "completed" ||
                            job.status === "completed_with_errors"
                          }
                        >
                          Cancel
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
              {scanJobsData.length === 0 ? (
                <tr>
                  <td
                    colSpan={canManage ? 6 : 5}
                    className="px-4 py-10 text-center text-sm text-muted-foreground"
                  >
                    No scan jobs yet.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </Panel>

      <SchedulesPanel
        canManage={canManage}
        onError={(e) =>
          setStatusMessage({
            tone: "error",
            title: "Schedule update failed",
            message: e instanceof Error ? e.message : "Try again.",
          })
        }
      />

      <Dialog
        open={scanDialogOpen}
        title="Queue discovery scan"
        description="Create a new discovery scan job for the selected endpoint."
        onClose={() => setScanDialogOpen(false)}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void createScanMutation.mutateAsync();
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Scan type</span>
            <Select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
            >
              <option value="fast">Fast — HTTPS/SSH + key protocols</option>
              <option value="targeted">Targeted — common cert ports</option>
              <option value="full">Full — the whole cert/key catalogue</option>
              <option value="deep">
                Deep — full port sweep (slow, finds certs anywhere)
              </option>
              <option value={scanTypeWinRM}>
                WinRM — Windows machine certificate stores (managed target)
              </option>
              <option value={scanTypeSSH}>
                SSH — Linux/Unix cert files and host keys (managed target)
              </option>
            </Select>
          </label>
          {scanType === "deep" ? (
            <p className="text-xs text-muted-foreground">
              Deep scan connect-sweeps every port on the host, then captures
              certs and keys on whatever it finds — slow, but it catches a cert
              on a non-standard port. Custom ports below become the sweep range
              (lo, hi).
            </p>
          ) : null}
          {scanType === scanTypeWinRM || scanType === scanTypeSSH ? (
            <>
            <label className="block space-y-2 text-sm text-foreground">
              <span>Managed target</span>
              <Select
                aria-label="Managed target"
                value={scanType === scanTypeSSH ? sshTargetId : winrmTargetId}
                onChange={(e) =>
                  scanType === scanTypeSSH
                    ? setSshTargetId(e.target.value)
                    : setWinrmTargetId(e.target.value)
                }
              >
                <option value="">Select a managed target…</option>
                {(scanType === scanTypeSSH ? sshTargets : winrmTargets).map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.host})
                  </option>
                ))}
              </Select>
              {(scanType === scanTypeSSH ? sshTargets : winrmTargets).length ===
              0 ? (
                <p className="text-xs text-muted-foreground">
                  {scanType === scanTypeSSH
                    ? "No SSH managed targets yet."
                    : "No WinRM managed targets yet."}{" "}
                  <Link to="/targets/setup" className="underline">
                    Set one up
                  </Link>
                  .
                </p>
              ) : null}
            </label>
              {scanType === scanTypeSSH ? (
                <label className="block space-y-1 pt-2 text-sm text-foreground">
                  <span>Run with sudo password (optional)</span>
                  <Input
                    type="password"
                    autoComplete="off"
                    value={jitSudoPassword}
                    onChange={(e) => setJitSudoPassword(e.target.value)}
                    placeholder="Used for this scan only"
                  />
                  <span className="block text-xs text-muted-foreground">
                    Needed when the target's credential has no sudo and root-owned
                    certificates are unreadable (a scheduled scan reports "needs a
                    password"). Held in memory for this scan, then wiped; never
                    stored or logged.
                  </span>
                </label>
              ) : null}
            </>
          ) : (
            <>
              <label className="block space-y-2 text-sm text-foreground">
                <span>Target</span>
                <Input
                  value={scanTarget}
                  onChange={(e) => setScanTarget(e.target.value)}
                  placeholder="10.0.0.0/24 or host"
                />
              </label>
              <label className="block space-y-2 text-sm text-foreground">
                <span>
                  Custom ports{" "}
                  <span className="text-muted-foreground">
                    (optional, comma-separated — added to the scan type's ports)
                  </span>
                </span>
                <Input
                  value={scanPorts}
                  onChange={(e) => setScanPorts(e.target.value)}
                  placeholder="e.g. 9443, 8888"
                />
              </label>
            </>
          )}
          <div className="flex gap-2">
            <Button
              tone="primary"
              type="submit"
              disabled={
                createScanMutation.isPending ||
                (scanType === scanTypeWinRM && !winrmTargetId) ||
                (scanType === scanTypeSSH && !sshTargetId)
              }
            >
              Queue scan
            </Button>
            <Button onClick={() => setScanDialogOpen(false)}>Cancel</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={jobAction === "cancel" || jobAction === "requeue"}
        title={jobAction === "cancel" ? "Cancel scan job" : "Requeue scan job"}
        description={
          selectedJob
            ? `${selectedJob.scan_type} · ${selectedJob.target}`
            : undefined
        }
        onClose={() => setJobAction(null)}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void (jobAction === "cancel"
              ? cancelScanMutation.mutateAsync()
              : requeueScanMutation.mutateAsync());
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Reason</span>
            <Input
              value={jobReason}
              onChange={(e) => setJobReason(e.target.value)}
              placeholder="Optional context"
            />
          </label>
          <div className="flex gap-2">
            <Button
              tone="primary"
              type="submit"
              disabled={
                cancelScanMutation.isPending || requeueScanMutation.isPending
              }
            >
              Confirm
            </Button>
            <Button onClick={() => setJobAction(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={jobAction === "bulk-cancel"}
        title={`Bulk cancel ${selectedScanJobCount} scan job${selectedScanJobCount !== 1 ? "s" : ""}`}
        description="Each selected scan job will be cancelled individually; a failure on one does not stop the rest."
        onClose={() => {
          setJobAction(null);
          setBulkProgress(null);
        }}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void bulkCancelMutation.mutateAsync();
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Reason</span>
            <Input
              value={jobReason}
              onChange={(e) => setJobReason(e.target.value)}
              placeholder="Optional context"
            />
          </label>
          {bulkProgress ? (
            <div className="rounded-xl border border-border bg-background/60 p-3 text-sm text-foreground">
              <div className="mb-1 font-medium">
                Progress: {bulkProgress.done} / {bulkProgress.total}
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-2 rounded-full bg-state-over transition-all"
                  style={{
                    width: `${Math.round((bulkProgress.done / bulkProgress.total) * 100)}%`,
                  }}
                />
              </div>
              {bulkProgress.errors.length > 0 ? (
                <div className="mt-2 text-state-over">
                  {bulkProgress.errors.length} failed so far
                </div>
              ) : null}
            </div>
          ) : null}
          <div className="flex gap-2">
            <Button
              tone="danger"
              type="submit"
              disabled={bulkCancelMutation.isPending}
            >
              {bulkCancelMutation.isPending
                ? "Cancelling…"
                : `Cancel ${selectedScanJobCount}`}
            </Button>
            <Button
              onClick={() => {
                setJobAction(null);
                setBulkProgress(null);
              }}
            >
              Close
            </Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={jobAction === "bulk-requeue"}
        title={`Bulk requeue ${selectedScanJobCount} scan job${selectedScanJobCount !== 1 ? "s" : ""}`}
        description="Each selected scan job will be requeued individually; a failure on one does not stop the rest."
        onClose={() => {
          setJobAction(null);
          setBulkProgress(null);
        }}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void bulkRequeueMutation.mutateAsync();
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Reason</span>
            <Input
              value={jobReason}
              onChange={(e) => setJobReason(e.target.value)}
              placeholder="Optional context"
            />
          </label>
          {bulkProgress ? (
            <div className="rounded-xl border border-border bg-background/60 p-3 text-sm text-foreground">
              <div className="mb-1 font-medium">
                Progress: {bulkProgress.done} / {bulkProgress.total}
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-2 rounded-full bg-primary transition-all"
                  style={{
                    width: `${Math.round((bulkProgress.done / bulkProgress.total) * 100)}%`,
                  }}
                />
              </div>
              {bulkProgress.errors.length > 0 ? (
                <div className="mt-2 text-state-over">
                  {bulkProgress.errors.length} failed so far
                </div>
              ) : null}
            </div>
          ) : null}
          <div className="flex gap-2">
            <Button
              tone="primary"
              type="submit"
              disabled={bulkRequeueMutation.isPending}
            >
              {bulkRequeueMutation.isPending
                ? "Requeuing…"
                : `Requeue ${selectedScanJobCount}`}
            </Button>
            <Button
              onClick={() => {
                setJobAction(null);
                setBulkProgress(null);
              }}
            >
              Close
            </Button>
          </div>
        </form>
      </Dialog>
    </div>
  );
}
