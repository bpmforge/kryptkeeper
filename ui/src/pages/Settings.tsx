import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, Send, Trash2, Plus } from "lucide-react";
import { toast } from "sonner";
import { api, type CredentialMeta, type EffectiveSetting } from "../lib/api";
import {
  Badge,
  Button,
  Input,
  Panel,
  Select,
  StateMessage,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { ReportDeliveryPanel } from "./ReportDeliveryPanel";
import type { EvidenceSchedule, SIEMTestResult } from "../lib/models";

function testResultLine(label: string, ok: boolean, error?: string) {
  return (
    <div className="flex items-center gap-2 text-sm">
      <Badge tone={ok ? "success" : "danger"}>{ok ? "OK" : "Failed"}</Badge>
      <span className="text-foreground">{label}</span>
      {error ? <span className="text-state-over">— {error}</span> : null}
    </div>
  );
}

function SiemPanel() {
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["siem-status"],
    queryFn: api.siemStatus,
    staleTime: 30_000,
  });
  const status = data?.data;

  const testMutation = useMutation({
    mutationFn: api.siemTest,
  });
  const testResult: SIEMTestResult | undefined = testMutation.data?.data;

  return (
    <Panel
      title="SIEM Integration"
      subtitle="Security event forwarding (configured via environment)"
    >
      {isLoading ? (
        <StateMessage title="Loading" message="Fetching SIEM status…" />
      ) : error || !status ? (
        <StateMessage
          tone="error"
          title="Status unavailable"
          message="The SIEM integration status could not be loaded."
        />
      ) : (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">State</span>
            <Badge tone={status.enabled ? "success" : "neutral"}>
              {status.enabled ? "Enabled" : "Not configured"}
            </Badge>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="rounded-xl border border-border bg-card/40 p-3 text-sm">
              <div className="flex items-center gap-2">
                <span className="font-medium text-foreground">Webhook</span>
                <Badge tone={status.webhook_enabled ? "success" : "neutral"}>
                  {status.webhook_enabled ? "On" : "Off"}
                </Badge>
              </div>
              <div className="mt-2 text-muted-foreground">
                Target:{" "}
                <span className="font-mono text-foreground">
                  {status.webhook_target || "—"}
                </span>
              </div>
              <div className="mt-1 text-muted-foreground">
                Auth token: {status.webhook_has_token ? "configured" : "none"}
              </div>
            </div>

            <div className="rounded-xl border border-border bg-card/40 p-3 text-sm">
              <div className="flex items-center gap-2">
                <span className="font-medium text-foreground">Syslog</span>
                <Badge tone={status.syslog_enabled ? "success" : "neutral"}>
                  {status.syslog_enabled ? "On" : "Off"}
                </Badge>
              </div>
              <div className="mt-2 text-muted-foreground">
                Address:{" "}
                <span className="font-mono text-foreground">
                  {status.syslog_addr || "—"}
                </span>
              </div>
              <div className="mt-1 text-muted-foreground">
                Protocol: {status.syslog_proto?.toUpperCase() || "—"}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button
              tone="secondary"
              onClick={() => refetch()}
              disabled={isFetching}
            >
              <RefreshCw size={13} aria-hidden="true" />
              Refresh
            </Button>
            <Button
              tone="primary"
              onClick={() => testMutation.mutate()}
              disabled={!status.enabled || testMutation.isPending}
            >
              <Send size={13} aria-hidden="true" />
              {testMutation.isPending ? "Sending…" : "Send test event"}
            </Button>
          </div>

          {testMutation.isError ? (
            <p className="text-sm text-state-over">
              {testMutation.error instanceof Error
                ? testMutation.error.message
                : "Test failed."}
            </p>
          ) : null}

          {testResult ? (
            <div className="space-y-1.5 rounded-xl border border-border bg-card/40 p-3">
              <div className="text-xs uppercase tracking-wide text-muted-foreground">
                Test result
              </div>
              {testResult.webhook_tested
                ? testResultLine(
                    "Webhook",
                    testResult.webhook_ok,
                    testResult.webhook_error,
                  )
                : null}
              {testResult.syslog_tested
                ? testResultLine(
                    "Syslog",
                    testResult.syslog_ok,
                    testResult.syslog_error,
                  )
                : null}
            </div>
          ) : null}

          {!status.enabled ? (
            <p className="text-sm text-muted-foreground">
              No SIEM target is configured. Set <code>SIEM_WEBHOOK_URL</code> or{" "}
              <code>SIEM_SYSLOG_ADDR</code> in the server environment to forward
              security events.
            </p>
          ) : null}
        </div>
      )}
    </Panel>
  );
}

const FRAMEWORK_OPTIONS: Record<string, string> = {
  all: "All frameworks",
  pci: "PCI DSS 4.0.1",
  soc2: "SOC 2",
  nist: "NIST SP 800-57",
};

function EvidenceDeliveryPanel() {
  const queryClient = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ["evidence-schedules"],
    queryFn: api.evidenceSchedules,
    staleTime: 30_000,
  });
  const schedules: EvidenceSchedule[] = data?.data ?? [];

  const [framework, setFramework] = useState("all");
  const [cadence, setCadence] = useState("monthly");
  const [recipients, setRecipients] = useState("");

  const parseRecipients = () =>
    recipients
      .split(",")
      .map((r) => r.trim())
      .filter(Boolean);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["evidence-schedules"] });

  const createMutation = useMutation({
    mutationFn: () =>
      api.createEvidenceSchedule({
        framework,
        cadence,
        recipients: parseRecipients(),
        enabled: true,
      }),
    onSuccess: async () => {
      setRecipients("");
      await invalidate();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteEvidenceSchedule(id),
    onSuccess: invalidate,
    onError: (err: Error) => toast.error(err.message),
  });

  const sendNowMutation = useMutation({
    mutationFn: () =>
      api.sendEvidenceNow({ framework, recipients: parseRecipients() }),
  });

  return (
    <Panel
      title="Evidence Delivery"
      subtitle="Scheduled compliance evidence packs by email (requires SMTP)"
    >
      <div className="space-y-4">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            createMutation.mutate();
          }}
        >
          <div>
            <label htmlFor="report-framework" className="text-xs text-muted-foreground">Framework</label>
            <Select id="report-framework"
              value={framework}
              onChange={(e) => setFramework(e.target.value)}
            >
              {Object.entries(FRAMEWORK_OPTIONS).map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <label htmlFor="report-cadence" className="text-xs text-muted-foreground">Cadence</label>
            <Select id="report-cadence"
              value={cadence}
              onChange={(e) => setCadence(e.target.value)}
            >
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </Select>
          </div>
          <div className="grow">
            <label htmlFor="report-recipients" className="text-xs text-muted-foreground">
              Recipients (comma-separated)
            </label>
            <Input id="report-recipients"
              value={recipients}
              onChange={(e) => setRecipients(e.target.value)}
              placeholder="auditor@example.com, ciso@example.com"
            />
          </div>
          <Button
            type="submit"
            tone="primary"
            disabled={
              createMutation.isPending || parseRecipients().length === 0
            }
          >
            <Plus size={13} aria-hidden="true" />
            Add schedule
          </Button>
          <Button
            type="button"
            tone="secondary"
            onClick={() => sendNowMutation.mutate()}
            disabled={
              sendNowMutation.isPending || parseRecipients().length === 0
            }
          >
            <Send size={13} aria-hidden="true" />
            Send now
          </Button>
        </form>

        {sendNowMutation.isSuccess ? (
          <p className="text-xs text-state-auto">Evidence pack sent.</p>
        ) : null}
        {sendNowMutation.isError ? (
          <p className="text-xs text-state-over">
            {sendNowMutation.error instanceof Error
              ? sendNowMutation.error.message
              : "Send failed."}
          </p>
        ) : null}
        {createMutation.isError ? (
          <p className="text-xs text-state-over">
            {createMutation.error instanceof Error
              ? createMutation.error.message
              : "Could not create schedule."}
          </p>
        ) : null}

        {isLoading ? (
          <StateMessage title="Loading" message="Fetching schedules…" />
        ) : error ? (
          <StateMessage
            tone="error"
            title="Unavailable"
            message="Evidence schedules could not be loaded."
          />
        ) : schedules.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No scheduled deliveries. Add one above to email evidence packs on a
            cadence.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                <th className="py-2 pr-4">Framework</th>
                <th className="py-2 pr-4">Cadence</th>
                <th className="py-2 pr-4">Recipients</th>
                <th className="py-2 pr-4">Last sent</th>
                <th className="py-2 pr-4" />
              </tr>
            </thead>
            <tbody>
              {schedules.map((s) => (
                <tr key={s.id} className="border-b border-border">
                  <td className="py-2 pr-4 text-foreground">
                    {FRAMEWORK_OPTIONS[s.framework] ?? s.framework}
                  </td>
                  <td className="py-2 pr-4 text-foreground">{s.cadence}</td>
                  <td className="py-2 pr-4 text-foreground">
                    {s.recipients.join(", ")}
                  </td>
                  <td className="py-2 pr-4 text-muted-foreground">
                    {s.last_sent_at
                      ? new Date(s.last_sent_at).toLocaleDateString()
                      : "—"}
                  </td>
                  <td className="py-2 pr-4">
                    <Button
                      tone="danger"
                      onClick={() => deleteMutation.mutate(s.id)}
                      disabled={deleteMutation.isPending}
                    >
                      <Trash2 size={13} aria-hidden="true" />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// W24-25: discovery sources (cloud scopes, SaaS endpoints, kube clusters, CT
// domains) edited through the config-store API. Key names and value shapes
// mirror the backend parsers (internal/bootstrap/kube_clusters.go,
// cloud_discovery.go parseCloudScopes, mesh_discovery_wiring.go
// parseSaaSEndpoints, ctmonitor.ParseDomainList).
// ---------------------------------------------------------------------------

type SourceRow = Record<string, string>;

type SourceField = {
  name: string;
  label: string; // also the aria-label
  kind: "text" | "credential" | "provider";
  placeholder?: string;
};

type SourcePanelDef = {
  key: string;
  title: string;
  env: string;
  addLabel: string;
  fields: SourceField[];
  // Fields shown for a row (cloud scopes vary by provider).
  visible?: (row: SourceRow) => string[];
  blank: SourceRow;
  parse: (raw: string) => SourceRow[] | null;
  serialize: (rows: SourceRow[]) => string;
  validate: (row: SourceRow, rows: SourceRow[]) => string | null;
  rowName: (row: SourceRow, index: number) => string;
};

const CLOUD_PROVIDERS = ["aws-acm", "azure-keyvault", "gcp-certmanager"];
const KUBE_NAME_RE = /^[a-z0-9-]{1,40}$/;
const SAAS_RE = /^[A-Za-z0-9.-]+:\d{1,5}$/;
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function parseJSONArray(raw: string): unknown[] | null {
  if (raw.trim() === "") return [];
  try {
    const v: unknown = JSON.parse(raw);
    return Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

function parseObjectRows(raw: string, names: string[]): SourceRow[] | null {
  const arr = parseJSONArray(raw);
  if (!arr) return null;
  const out: SourceRow[] = [];
  for (const e of arr) {
    if (typeof e !== "object" || e === null) return null;
    const o = e as Record<string, unknown>;
    const row: SourceRow = {};
    for (const n of names) row[n] = typeof o[n] === "string" ? (o[n] as string) : "";
    out.push(row);
  }
  return out;
}

function parseStringRows(raw: string, name: string): SourceRow[] | null {
  const arr = parseJSONArray(raw);
  if (!arr) return null;
  if (!arr.every((e) => typeof e === "string")) return null;
  return (arr as string[]).map((e) => ({ [name]: e }));
}

const cloudVisible = (row: SourceRow): string[] =>
  row.provider === "aws-acm"
    ? ["provider", "region", "profile"]
    : row.provider === "azure-keyvault"
      ? ["provider", "vault_url"]
      : row.provider === "gcp-certmanager"
        ? ["provider", "project_id", "region"]
        : ["provider"];

const SOURCE_PANELS: SourcePanelDef[] = [
  {
    key: "discovery.kube_clusters",
    title: "Kubernetes clusters",
    env: "KRYPTKEEPER_K8S_CLUSTERS",
    addLabel: "Add cluster",
    fields: [
      { name: "name", label: "Cluster name", kind: "text", placeholder: "prod" },
      { name: "credential_ref", label: "Cluster credential", kind: "credential" },
      { name: "namespace", label: "Cluster namespace", kind: "text", placeholder: "(all)" },
    ],
    blank: { name: "", credential_ref: "", namespace: "" },
    parse: (raw) => parseObjectRows(raw, ["name", "credential_ref", "namespace"]),
    serialize: (rows) =>
      JSON.stringify(
        rows.map((r) => ({
          name: r.name.trim(),
          credential_ref: r.credential_ref,
          namespace: r.namespace.trim(),
        })),
      ),
    validate: (r, rows) => {
      const name = r.name.trim();
      if (!KUBE_NAME_RE.test(name)) return "Name must be 1-40 characters of a-z, 0-9 or -.";
      if (rows.filter((x) => x.name.trim() === name).length > 1) return "Cluster names must be unique.";
      if (!r.credential_ref) return "Pick a credential.";
      return null;
    },
    rowName: (r, i) => r.name || `cluster ${i + 1}`,
  },
  {
    key: "discovery.saas_endpoints",
    title: "SaaS / API endpoints",
    env: "KRYPTKEEPER_SAAS_ENDPOINTS",
    addLabel: "Add endpoint",
    fields: [{ name: "host_port", label: "SaaS endpoint", kind: "text", placeholder: "api.example.com:443" }],
    blank: { host_port: "" },
    parse: (raw) => parseStringRows(raw, "host_port"),
    serialize: (rows) => JSON.stringify(rows.map((r) => r.host_port.trim())),
    validate: (r) => {
      const hp = r.host_port.trim();
      if (!SAAS_RE.test(hp)) return "Use host:port, e.g. api.example.com:443.";
      const port = Number(hp.slice(hp.lastIndexOf(":") + 1));
      return port >= 1 && port <= 65535 ? null : "Port must be 1-65535.";
    },
    rowName: (r, i) => r.host_port || `endpoint ${i + 1}`,
  },
  {
    key: "ct.domains",
    title: "CT monitor domains",
    env: "KRYPTKEEPER_CT_DOMAINS",
    addLabel: "Add domain",
    fields: [{ name: "domain", label: "CT domain", kind: "text", placeholder: "example.com" }],
    blank: { domain: "" },
    // The CT monitor reads a comma-separated list (ctmonitor.ParseDomainList);
    // a JSON array is accepted on read for leniency but never written.
    parse: (raw) => {
      const t = raw.trim();
      if (t.startsWith("[")) return parseStringRows(t, "domain");
      return t === ""
        ? []
        : t
            .split(",")
            .map((d) => d.trim())
            .filter(Boolean)
            .map((d) => ({ domain: d }));
    },
    serialize: (rows) => rows.map((r) => r.domain.trim().toLowerCase()).join(","),
    validate: (r) =>
      DOMAIN_RE.test(r.domain.trim()) ? null : "Enter a hostname without scheme or path.",
    rowName: (r, i) => r.domain || `domain ${i + 1}`,
  },
  {
    key: "discovery.cloud_scopes",
    title: "Cloud sources",
    env: "KRYPTKEEPER_CLOUD_SCOPES",
    addLabel: "Add cloud source",
    fields: [
      { name: "provider", label: "Cloud provider", kind: "provider" },
      { name: "region", label: "Cloud region", kind: "text", placeholder: "us-east-1" },
      { name: "profile", label: "AWS profile", kind: "text", placeholder: "(default)" },
      { name: "vault_url", label: "Azure vault URL", kind: "text", placeholder: "https://myvault.vault.azure.net" },
      { name: "project_id", label: "GCP project id", kind: "text" },
    ],
    visible: cloudVisible,
    blank: { provider: "aws-acm", region: "", profile: "", vault_url: "", project_id: "" },
    parse: (raw) => parseObjectRows(raw, ["provider", "region", "profile", "vault_url", "project_id"]),
    serialize: (rows) =>
      JSON.stringify(
        rows.map((r) => {
          const keep = cloudVisible(r);
          const o: Record<string, string> = {};
          for (const k of keep) if (r[k].trim()) o[k] = r[k].trim();
          return o;
        }),
      ),
    validate: (r) => {
      if (!CLOUD_PROVIDERS.includes(r.provider)) return "Pick a provider.";
      if (r.provider === "aws-acm" && !r.region.trim()) return "AWS needs a region.";
      if (r.provider === "azure-keyvault" && !/^https:\/\/[^/\s]+/.test(r.vault_url.trim())) {
        return "Azure needs an https vault URL.";
      }
      if (r.provider === "gcp-certmanager" && !r.project_id.trim()) return "GCP needs a project id.";
      return null;
    },
    rowName: (r, i) =>
      r.region || r.vault_url || r.project_id || r.provider || `source ${i + 1}`,
  },
];

function SourceListEditor({
  def,
  setting,
  credentials,
}: {
  def: SourcePanelDef;
  setting: EffectiveSetting | undefined;
  credentials: CredentialMeta[];
}) {
  const queryClient = useQueryClient();
  // Secret values are never rendered or parsed; the list starts empty.
  const hidden = setting?.secret === true;
  const raw = hidden ? "" : (setting?.value ?? "");
  const parsed = def.parse(raw);
  const [rows, setRows] = useState<SourceRow[]>(parsed ?? []);

  const save = useMutation({
    mutationFn: () =>
      rows.length === 0
        ? api.resetRuntimeConfig(def.key)
        : api.setRuntimeConfig(def.key, def.serialize(rows)),
    onSuccess: () => {
      toast.success(`${def.title} saved`);
      return queryClient.invalidateQueries({ queryKey: ["runtime-config"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const errors = rows.map((r) => def.validate(r, rows));
  const invalid = errors.some((e) => e !== null);
  const update = (i: number, name: string, value: string) =>
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, [name]: value } : r)));

  return (
    <Panel
      title={def.title}
      subtitle={`Overrides ${def.env}. Empty list falls back to the environment.`}
    >
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <Badge tone={setting?.source === "database" ? "success" : "neutral"}>
            {setting?.source ?? "unset"}
          </Badge>
          <span>{def.env}</span>
        </div>
        {hidden && setting?.configured ? (
          <p className="text-sm text-muted-foreground">Configured (write-only)</p>
        ) : null}
        {parsed === null ? (
          <StateMessage
            tone="error"
            title="Stored value could not be parsed"
            message="The stored value could not be parsed; saving replaces it."
          />
        ) : null}
        {rows.map((row, i) => {
          const shown = def.visible ? def.visible(row) : def.fields.map((f) => f.name);
          return (
            <div key={i} className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                {def.fields
                  .filter((f) => shown.includes(f.name))
                  .map((f) =>
                    f.kind === "credential" ? (
                      <Select
                        key={f.name}
                        aria-label={f.label}
                        value={row[f.name]}
                        onChange={(e) => update(i, f.name, e.target.value)}
                      >
                        <option value="">Select a credential…</option>
                        {credentials.map((c) => (
                          <option key={c.id} value={c.id}>
                            {c.name}
                          </option>
                        ))}
                      </Select>
                    ) : f.kind === "provider" ? (
                      <Select
                        key={f.name}
                        aria-label={f.label}
                        value={row[f.name]}
                        onChange={(e) => update(i, f.name, e.target.value)}
                      >
                        {CLOUD_PROVIDERS.map((p) => (
                          <option key={p} value={p}>
                            {p}
                          </option>
                        ))}
                      </Select>
                    ) : (
                      <Input
                        key={f.name}
                        aria-label={f.label}
                        placeholder={f.placeholder}
                        value={row[f.name]}
                        onChange={(e) => update(i, f.name, e.target.value)}
                      />
                    ),
                  )}
                <Button
                  aria-label={`Remove ${def.rowName(row, i)}`}
                  onClick={() => setRows((rs) => rs.filter((_, j) => j !== i))}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
              {errors[i] ? (
                <p className="text-xs text-state-over">{errors[i]}</p>
              ) : null}
            </div>
          );
        })}
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => setRows((rs) => [...rs, { ...def.blank }])}>
            <Plus className="h-4 w-4" />
            {def.addLabel}
          </Button>
          <Button
            tone="primary"
            aria-label={`Save ${def.title}`}
            disabled={invalid || save.isPending}
            onClick={() => save.mutate()}
          >
            Save
          </Button>
        </div>
      </div>
    </Panel>
  );
}

function DiscoverySourcesPanel() {
  const config = useQuery({
    queryKey: ["runtime-config"],
    queryFn: api.runtimeConfig,
  });
  const creds = useQuery({ queryKey: ["credentials"], queryFn: api.credentials });
  const credentials = (creds.data?.data?.items ?? []).filter(
    (c) => c.credential_type === "api_token" || c.credential_type === "cloud_iam",
  );

  if (config.isLoading) {
    return (
      <Panel title="Discovery sources">
        <StateMessage title="Loading" message="Fetching discovery configuration…" />
      </Panel>
    );
  }
  if (config.error) {
    return (
      <Panel title="Discovery sources">
        <StateMessage
          tone="error"
          title="Unavailable"
          message="Could not load discovery configuration."
        />
      </Panel>
    );
  }
  const settings = config.data?.data ?? [];
  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">
        Discovery sources. Credentials are chosen by reference; create them via
        the API/CLI first. Secrets are never shown.
      </p>
      {SOURCE_PANELS.map((def) => {
        const setting = settings.find((s) => s.key === def.key);
        return (
          <SourceListEditor
            key={`${def.key}:${setting?.updated_at ?? ""}:${setting?.value ?? ""}`}
            def={def}
            setting={setting}
            credentials={credentials}
          />
        );
      })}
    </div>
  );
}

// W34-11: which outbound credentials are high-impact on the hosts they reach.
// The sudo preflight sets the flag on its own; this is the manual half.
function PrivilegedCredentialsPanel() {
  const queryClient = useQueryClient();
  const creds = useQuery({ queryKey: ["credentials"], queryFn: api.credentials });
  const toggle = useMutation({
    mutationFn: (c: CredentialMeta) =>
      api.setCredentialPrivileged(
        c.id,
        !c.privileged,
        c.privileged ? undefined : "marked privileged in Settings",
      ),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["credentials"] }),
  });
  const items = (creds.data?.data?.items ?? []).filter((c) => c.credential_type === "ssh_key");
  return (
    <Panel title="Privileged credentials">
      <p className="mb-3 text-sm text-muted-foreground">
        Mark an SSH account that is high-impact on the hosts it reaches (root, or sudo that
        can run anything). The sudo preflight marks accounts automatically. The flag gates
        nothing: it is shown on every target that uses the account and in the access-review
        report, and each change is audited.
      </p>
      {items.length === 0 ? (
        <StateMessage title="No SSH credentials" message="Create one from Target Setup." />
      ) : (
        <ul className="space-y-2">
          {items.map((c) => (
            <li key={c.id} className="flex items-center gap-3 text-sm">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={c.privileged === true}
                  disabled={toggle.isPending}
                  onChange={() => toggle.mutate(c)}
                  aria-label={`Privileged: ${c.name}`}
                />
                <span>{c.name}</span>
              </label>
              {c.privileged ? (
                <span className="rounded bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-900">
                  Privileged
                  {c.privileged_set_by?.startsWith("auto:") ? " (auto)" : ""}
                </span>
              ) : null}
              {c.privileged && c.privileged_reason ? (
                <span className="text-xs text-muted-foreground">{c.privileged_reason}</span>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export default function Settings() {
  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="System"
        title="Settings"
        description="Automation status and integration configuration."
      />

      <SiemPanel />
      <EvidenceDeliveryPanel />
      <ReportDeliveryPanel />
      <DiscoverySourcesPanel />
      <PrivilegedCredentialsPanel />
    </div>
  );
}
