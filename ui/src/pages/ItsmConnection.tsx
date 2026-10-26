import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fetchJSON } from "../lib/api";
import { Badge, Button, Input, Panel, Select, StateMessage } from "../components/ui";
import type { DeliveryPlugin, DeliveryPluginVersion } from "../lib/plugins";

// Wire contract constants (handlers_itsm.go, W32-10). Change only these if the
// backend moves.
const CONNECTIONS_PATH = "/itsm/connections";
const testPath = (id: string) => `${CONNECTIONS_PATH}/${encodeURIComponent(id)}/test`;

const PLUGINS_PATH = "/delivery-plugins";
const EVENT_CLASSES = ["renewal_failed", "approval_pending", "expiry_no_owner"] as const;
// A plugin connection cannot carry approval_pending: approval sync is
// native-only in 1.1 (D-326), and the API refuses it.
const classesFor = (kind: Kind) =>
  kind === "plugin" ? EVENT_CLASSES.filter((c) => c !== "approval_pending") : EVENT_CLASSES;
// "default" for a plugin means "open a ticket of the plugin's default type";
// the wire value is the empty string.
const TICKET_TYPES: Record<Kind, string[]> = {
  servicenow: ["incident", "change_request"],
  jira: ["Task", "Bug", "Story"],
  plugin: ["default"],
};
const DEFAULT_TICKET_TYPE: Record<Kind, string> = { servicenow: "incident", jira: "Task", plugin: "default" };

type Kind = "servicenow" | "jira" | "plugin";

// The enabled ticket plugins an operator can pick, with the credential fields
// each one asks for (its credential_schema).
function ticketPlugins(plugins: DeliveryPlugin[]): { id: string; version: DeliveryPluginVersion }[] {
  const out: { id: string; version: DeliveryPluginVersion }[] = [];
  for (const p of plugins) {
    const v = p.versions.find((x) => x.version === p.enabled_version);
    if (v && v.kind === "ticket") out.push({ id: p.id, version: v });
  }
  return out;
}

interface ItsmConn {
  id: string;
  kind: string;
  name: string;
  base_url: string;
  credential_ref: string;
  plugin_id?: string;
  enabled: boolean;
}

interface TestResult {
  ok: boolean;
  detail: string;
}

function buildEventClasses(kind: Kind, rows: Record<string, string>) {
  return classesFor(kind)
    .filter((c) => rows[c])
    .map((c) => ({ class: c, ticket_type: kind === "plugin" && rows[c] === "default" ? "" : rows[c] }));
}

function defaultRows(kind: Kind): Record<string, string> {
  return Object.fromEntries(classesFor(kind).map((c) => [c, DEFAULT_TICKET_TYPE[kind]]));
}

function isHttpsUrl(v: string): boolean {
  try {
    return new URL(v).protocol === "https:";
  } catch {
    return false;
  }
}

export default function ItsmConnection({ canWrite }: { canWrite: boolean }) {
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<Kind>("servicenow");
  const [name, setName] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [projectKey, setProjectKey] = useState("");
  const [issueType, setIssueType] = useState("Task");
  const [approvedStatus, setApprovedStatus] = useState("");
  const [rejectedStatus, setRejectedStatus] = useState("");
  const [doneStatus, setDoneStatus] = useState("");
  const [pluginId, setPluginId] = useState("");
  const [pluginFields, setPluginFields] = useState<Record<string, string>>({});
  const [rows, setRows] = useState<Record<string, string>>(defaultRows("servicenow"));
  const [formError, setFormError] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, TestResult>>({});
  const [testingId, setTestingId] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ["itsm-connections"],
    queryFn: () => fetchJSON<{ data: { items: ItsmConn[] } }>(CONNECTIONS_PATH),
  });
  const items = list.data?.data?.items ?? [];

  // Read only while the plugin kind is chosen, so the native kinds never
  // depend on the plugin API being on.
  const pluginList = useQuery({
    queryKey: ["itsm-ticket-plugins"],
    queryFn: () => fetchJSON<{ data: DeliveryPlugin[] }>(PLUGINS_PATH),
    enabled: kind === "plugin",
  });
  const rawPlugins = pluginList.data?.data;
  const plugins = ticketPlugins(Array.isArray(rawPlugins) ? rawPlugins : []);
  const chosenPlugin = plugins.find((p) => p.id === pluginId);
  const schema = Object.entries(chosenPlugin?.version.manifest.credential_schema ?? {});

  function changeKind(k: Kind) {
    setKind(k);
    setPluginId("");
    setPluginFields({});
    setRows(defaultRows(k));
  }

  function resetForm() {
    setName("");
    setBaseUrl("");
    setUsername("");
    setSecret("");
    setProjectKey("");
    setIssueType("Task");
    setApprovedStatus("");
    setRejectedStatus("");
    setDoneStatus("");
    setPluginId("");
    setPluginFields({});
    setRows(defaultRows(kind));
  }

  const addMutation = useMutation({
    mutationFn: async () => {
      const payload: Record<string, unknown> =
        kind === "plugin"
          ? Object.fromEntries(Object.entries(pluginFields).filter(([, v]) => v.trim() !== ""))
          : kind === "jira"
          ? {
              email: username.trim(),
              api_token: secret,
              project_key: projectKey.trim(),
              issue_type: issueType.trim() || "Task",
              approved_status: approvedStatus.trim(),
              rejected_status: rejectedStatus.trim(),
              done_status: doneStatus.trim(),
            }
          : { username: username.trim(), password: secret };
      const cred = await api.createCredential({
        name: `${name.trim()} ITSM`,
        credential_type: "api_token",
        payload,
      });
      return fetchJSON(CONNECTIONS_PATH, {
        method: "POST",
        body: JSON.stringify({
          kind,
          name: name.trim(),
          ...(kind === "plugin" ? { plugin_id: pluginId } : { base_url: baseUrl.trim() }),
          credential_ref: cred.data.id,
          event_classes: buildEventClasses(kind, rows),
        }),
      });
    },
    onSuccess: async () => {
      setFormError(null);
      resetForm();
      await queryClient.invalidateQueries({ queryKey: ["itsm-connections"] });
    },
    onError: (e) => {
      setSecret("");
      setFormError(e instanceof Error ? e.message : "Could not save the connection.");
    },
  });

  function submit() {
    if (!name.trim()) return setFormError("Name is required.");
    if (kind === "plugin") {
      if (!chosenPlugin) return setFormError("Choose an enabled ticket plugin.");
      for (const [field, f] of schema) {
        const v = (pluginFields[field] ?? "").trim();
        if (f.required && !v && !f.default) return setFormError(`${field} is required.`);
        if (f.type === "url" && v && !isHttpsUrl(v)) return setFormError(`${field} must start with https://`);
      }
      setFormError(null);
      addMutation.mutate();
      return;
    }
    if (!isHttpsUrl(baseUrl.trim())) return setFormError("URL must start with https://");
    if (!secret) return setFormError("Credential is required.");
    if (kind === "jira" && !projectKey.trim()) return setFormError("Jira project key is required.");
    setFormError(null);
    addMutation.mutate();
  }

  async function runTest(id: string) {
    setTestingId(id);
    try {
      const res = await fetchJSON<{ data: TestResult }>(testPath(id), { method: "POST" });
      setResults((r) => ({ ...r, [id]: res.data }));
    } catch (e) {
      setResults((r) => ({
        ...r,
        [id]: { ok: false, detail: e instanceof Error ? e.message : "Test failed." },
      }));
    } finally {
      setTestingId(null);
    }
  }

  const isJira = kind === "jira";
  const disabled = !canWrite;

  return (
    <Panel
      title="ITSM connections"
      subtitle="ServiceNow, Jira and ticket plugins; credentials are write-only"
    >
      <div className="space-y-4">
        {!canWrite ? (
          <p className="text-xs text-muted-foreground">
            Admin role required to change these settings.
          </p>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block space-y-1 text-sm text-foreground">
            <span>Kind</span>
            <Select
              aria-label="ITSM kind"
              value={kind}
              disabled={disabled}
              onChange={(e) => changeKind(e.target.value as Kind)}
            >
              <option value="servicenow">ServiceNow</option>
              <option value="jira">Jira</option>
              <option value="plugin">Ticket plugin</option>
            </Select>
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Name</span>
            <Input aria-label="ITSM name" value={name} disabled={disabled} onChange={(e) => setName(e.target.value)} />
          </label>
          {kind === "plugin" ? (
            <>
              <label className="block space-y-1 text-sm text-foreground sm:col-span-2">
                <span>Plugin</span>
                <Select
                  aria-label="Ticket plugin"
                  value={pluginId}
                  disabled={disabled}
                  onChange={(e) => {
                    setPluginId(e.target.value);
                    setPluginFields({});
                  }}
                >
                  <option value="">Choose an enabled ticket plugin</option>
                  {plugins.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.version.manifest.name} ({p.id})
                    </option>
                  ))}
                </Select>
                {pluginList.isSuccess && plugins.length === 0 ? (
                  <span className="block text-xs text-muted-foreground">
                    No ticket plugin is enabled. Install one under Delivery plugins; enabling needs a second approver.
                  </span>
                ) : null}
              </label>
              {schema.map(([field, f]) => (
                <label key={field} className="block space-y-1 text-sm text-foreground">
                  <span>{field}</span>
                  <Input
                    type={f.secret ? "password" : "text"}
                    aria-label={`Plugin credential ${field}`}
                    value={pluginFields[field] ?? ""}
                    disabled={disabled}
                    autoComplete={f.secret ? "new-password" : "off"}
                    placeholder={f.secret ? "Write-only" : f.default ?? ""}
                    onChange={(e) => setPluginFields((p) => ({ ...p, [field]: e.target.value }))}
                  />
                </label>
              ))}
            </>
          ) : null}
          {kind !== "plugin" ? (
            <>
          <label className="block space-y-1 text-sm text-foreground sm:col-span-2">
            <span>URL</span>
            <Input
              aria-label="ITSM URL"
              value={baseUrl}
              disabled={disabled}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://example.service-now.com"
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>{isJira ? "Account email" : "Username"}</span>
            <Input
              aria-label={isJira ? "Jira account email" : "ServiceNow username"}
              value={username}
              disabled={disabled}
              autoComplete="off"
              onChange={(e) => setUsername(e.target.value)}
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>{isJira ? "API token" : "Password"}</span>
            <Input
              type="password"
              aria-label="ITSM credential"
              value={secret}
              disabled={disabled}
              autoComplete="new-password"
              onChange={(e) => setSecret(e.target.value)}
              placeholder="Write-only"
            />
          </label>
            </>
          ) : null}
          {isJira ? (
            <>
              <label className="block space-y-1 text-sm text-foreground">
                <span>Project key</span>
                <Input aria-label="Jira project key" value={projectKey} disabled={disabled} onChange={(e) => setProjectKey(e.target.value)} />
              </label>
              <label className="block space-y-1 text-sm text-foreground">
                <span>Issue type</span>
                <Input aria-label="Jira issue type" value={issueType} disabled={disabled} onChange={(e) => setIssueType(e.target.value)} />
              </label>
              <label className="block space-y-1 text-sm text-foreground">
                <span>Approved status</span>
                <Input aria-label="Jira approved status" value={approvedStatus} disabled={disabled} onChange={(e) => setApprovedStatus(e.target.value)} />
              </label>
              <label className="block space-y-1 text-sm text-foreground">
                <span>Rejected status</span>
                <Input aria-label="Jira rejected status" value={rejectedStatus} disabled={disabled} onChange={(e) => setRejectedStatus(e.target.value)} />
              </label>
              <label className="block space-y-1 text-sm text-foreground">
                <span>Done status</span>
                <Input aria-label="Jira done status" value={doneStatus} disabled={disabled} onChange={(e) => setDoneStatus(e.target.value)} />
              </label>
            </>
          ) : null}
        </div>

        <fieldset className="space-y-2">
          <legend className="text-sm font-medium text-foreground">Event class to ticket type</legend>
          {classesFor(kind).map((c) => (
            <div key={c} className="flex flex-wrap items-center gap-2 text-sm">
              <code className="w-40 font-mono text-xs">{c}</code>
              <Select
                aria-label={`Ticket type for ${c}`}
                value={rows[c] ?? ""}
                disabled={disabled}
                onChange={(e) => setRows((r) => ({ ...r, [c]: e.target.value }))}
              >
                <option value="">No ticket</option>
                {TICKET_TYPES[kind].map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </Select>
            </div>
          ))}
        </fieldset>

        {formError ? (
          <p role="alert" className="text-sm text-state-over">
            {formError}
          </p>
        ) : null}
        <Button tone="primary" disabled={disabled || addMutation.isPending} onClick={submit}>
          {addMutation.isPending ? "Saving…" : "Add connection"}
        </Button>

        {list.isLoading ? (
          <StateMessage title="Loading" message="Reading ITSM connections…" />
        ) : list.error ? (
          <StateMessage tone="error" title="Unavailable" message="ITSM connections could not be loaded." />
        ) : items.length === 0 ? (
          <p className="text-sm text-muted-foreground">No ITSM connections yet.</p>
        ) : (
          <ul className="space-y-2" aria-label="ITSM connections">
            {items.map((c) => (
              <li key={c.id} className="space-y-1 rounded-xl border border-border bg-card/40 p-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-foreground">{c.name}</span>
                  <Badge tone="info">{c.kind}</Badge>
                  <span className="text-muted-foreground">{c.kind === "plugin" ? c.plugin_id : c.base_url}</span>
                </div>
                <div className="text-xs text-muted-foreground">Credential: Stored (write-only)</div>
                <Button
                  tone="secondary"
                  aria-label={`Test connection ${c.name}`}
                  disabled={disabled || testingId === c.id}
                  onClick={() => runTest(c.id)}
                >
                  {testingId === c.id ? "Testing…" : "Test connection"}
                </Button>
                <div aria-live="polite" className="text-sm">
                  {results[c.id] ? (
                    <span className={results[c.id].ok ? "text-state-auto" : "text-state-over"}>
                      {results[c.id].ok ? "OK" : "Failed"}: {results[c.id].detail}
                    </span>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Panel>
  );
}
