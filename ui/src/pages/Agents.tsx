import { useQuery } from "@tanstack/react-query";
import { scrollableProps } from "../lib/scrollable";
import { Monitor, RefreshCw } from "lucide-react";
import { api } from "../lib/api";
import type { AgentInfo, AgentStatus } from "../lib/models";
import { Badge, Button, Panel, StateMessage } from "../components/ui";
import { PageHeader } from "../components/PageHeader";

type StatusTone = "success" | "warning" | "danger" | "neutral";

const statusTone: Record<AgentStatus, StatusTone> = {
  active: "success",
  stale: "warning",
  offline: "danger",
};

const typeLabelMap: Record<string, string> = {
  linux: "Linux",
  mac: "macOS",
  windows: "Windows",
};

function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "never";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function AgentRow({ agent }: { agent: AgentInfo }) {
  return (
    <div className="rounded-2xl border border-border bg-background/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <Monitor className="h-5 w-5 text-muted-foreground shrink-0" />
          <div>
            <div className="font-semibold text-foreground">{agent.name}</div>
            <div className="mt-0.5 text-xs text-muted-foreground">
              {typeLabelMap[agent.type] ?? agent.type} &middot; ID: {agent.id}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge tone={statusTone[agent.status]}>{agent.status}</Badge>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-xs text-muted-foreground sm:grid-cols-4">
        <span>
          <span className="text-muted-foreground">Last seen</span>{" "}
          <span className="text-foreground">
            {formatRelative(agent.last_seen)}
          </span>
        </span>
        <span>
          <span className="text-muted-foreground">Certs managed</span>{" "}
          <span className="text-foreground">{agent.inventory_count}</span>
        </span>
        <span>
          <span className="text-muted-foreground">Registered</span>{" "}
          <span className="text-foreground">
            {new Date(agent.registered_at).toLocaleDateString()}
          </span>
        </span>
      </div>

      <AgentHostReportView report={agent.host_report} />
    </div>
  );
}

// W34-09: what the agent could and could not read on its own host.
export function AgentHostReportView({ report }: { report?: AgentInfo["host_report"] }) {
  if (!report) return null;
  if (!report.posture_known) {
    return (
      <p className="mt-3 text-xs text-muted-foreground" data-testid="agent-host-report">
        Install posture unknown: this agent predates privilege reporting. Upgrade it to see
        unreadable paths and file ownership.
      </p>
    );
  }
  const n = report.unreadable_count;
  const mode = report.privilege_mode ?? "none";
  const counts = report.posture_counts ?? {};
  const nonStandard = (counts.privileged ?? 0) + (counts.root_service ?? 0);
  return (
    <div className="mt-3 space-y-1 text-xs" data-testid="agent-host-report">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={mode === "none" ? "neutral" : "info"}>
          {mode === "none" ? "Unprivileged" : `Privilege: ${mode}`}
        </Badge>
        {n > 0 ? (
          <Badge tone="warning">
            Insufficient privilege: {n} path{n === 1 ? "" : "s"} unreadable
          </Badge>
        ) : (
          <Badge tone="success">Every path readable</Badge>
        )}
        {nonStandard > 0 ? (
          <Badge tone="warning">{nonStandard} file{nonStandard === 1 ? "" : "s"} need root to replace or run as root</Badge>
        ) : null}
        <span className="text-muted-foreground">
          {report.listener_count} listener{report.listener_count === 1 ? "" : "s"}
          {report.listeners_hidden > 0 ? ` (${report.listeners_hidden} hidden)` : ""}
        </span>
      </div>
      {n > 0 ? (
        <details>
          <summary className="cursor-pointer text-muted-foreground">Unreadable paths and fix</summary>
          <ul className="mt-1 list-disc pl-5 text-muted-foreground">
            {(report.unreadable_paths ?? []).map((p) => (
              <li key={p.path}>{p.path}</li>
            ))}
          </ul>
          <p className="mt-1 text-muted-foreground">
            {(report.findings ?? []).find((f) => f.startsWith("INSUFFICIENT_PRIVILEGE"))?.split("; fix=")[1]}
          </p>
        </details>
      ) : null}
    </div>
  );
}

export default function Agents() {
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.agents(),
    refetchInterval: 30_000,
  });

  const agents: AgentInfo[] = data?.agents ?? [];
  const active = agents.filter((a) => a.status === "active").length;
  const stale = agents.filter((a) => a.status === "stale").length;
  const offline = agents.filter((a) => a.status === "offline").length;

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Infrastructure"
        title="Satellite Agents"
        description="Lightweight agents running on remote hosts that discover and auto-renew certificates without inbound network access."
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

      {/* Summary row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Total" value={agents.length} />
        <StatCard label="Active" value={active} tone="success" />
        <StatCard label="Stale" value={stale} tone="warning" />
        <StatCard label="Offline" value={offline} tone="danger" />
      </div>

      {/* Agent list */}
      <Panel
        title="Registered Agents"
        subtitle="Agents that have registered with this Hub"
      >
        {isLoading ? (
          <StateMessage title="Loading" message="Fetching agent registry…" />
        ) : error ? (
          <StateMessage
            tone="error"
            title="Unavailable"
            message="Could not load agent registry."
          />
        ) : agents.length === 0 ? (
          <StateMessage
            title="No agents registered"
            message="Install kryptkeeper-agent on a host to start discovering certificates automatically."
          />
        ) : (
          <div className="space-y-3">
            {agents.map((agent) => (
              <AgentRow key={agent.id} agent={agent} />
            ))}
          </div>
        )}
      </Panel>

      {/* Setup instructions */}
      <Panel
        title="Install an Agent"
        subtitle="Quick-start for Linux and macOS hosts"
      >
        <div className="space-y-3 text-sm text-foreground">
          <p>
            Download the{" "}
            <span className="font-mono text-primary">kryptkeeper-agent</span>{" "}
            binary and run with your Hub URL:
          </p>
          <pre className="overflow-x-auto rounded-xl bg-card p-4 text-xs text-foreground" {...scrollableProps}>
            {`# Linux (amd64)
curl -sL https://github.com/bpmforge/kryptkeeper/releases/latest/download/kryptkeeper-agent-linux-amd64 \\
  -o /usr/local/bin/kryptkeeper-agent
chmod +x /usr/local/bin/kryptkeeper-agent

KRYPTKEEPER_HUB_URL=https://your-hub.example.com \\
KRYPTKEEPER_AGENT_NAME=$(hostname) \\
  kryptkeeper-agent`}
          </pre>
          <p className="text-muted-foreground">
            On first run the agent registers itself and prints its{" "}
            <span className="font-mono text-foreground">AGENT_ID</span> and{" "}
            <span className="font-mono text-foreground">AGENT_TOKEN</span>. Set
            these as environment variables or in a systemd unit file to persist
            credentials across restarts.
          </p>
        </div>
      </Panel>
    </div>
  );
}

function StatCard({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: "success" | "warning" | "danger";
}) {
  const color =
    tone === "success"
      ? "text-state-auto"
      : tone === "warning"
        ? "text-state-attn"
        : tone === "danger"
          ? "text-state-over"
          : "text-foreground";

  return (
    <div className="rounded-2xl border border-border bg-background/60 p-4">
      <div className={`text-3xl font-bold ${color}`}>{value}</div>
      <div className="mt-1 text-xs text-muted-foreground">{label}</div>
    </div>
  );
}
