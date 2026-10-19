import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fetchJSON } from "../lib/api";
import { Badge, Button, Input, Panel, Select, StateMessage } from "../components/ui";

// Wire contract constants (handlers_itsm.go, W32-10). Change only these if the
// backend moves.
const CONNECTIONS_PATH = "/itsm/connections";
const testPath = (id: string) => `${CONNECTIONS_PATH}/${encodeURIComponent(id)}/test`;

const EVENT_CLASSES = ["renewal_failed", "approval_pending", "expiry_no_owner"] as const;
const TICKET_TYPES: Record<Kind, string[]> = {
  servicenow: ["incident", "change_request"],
  jira: ["Task", "Bug", "Story"],
};
const DEFAULT_TICKET_TYPE: Record<Kind, string> = { servicenow: "incident", jira: "Task" };

type Kind = "servicenow" | "jira";

interface ItsmConn {
  id: string;
  kind: string;
  name: string;
  base_url: string;
  credential_ref: string;
  enabled: boolean;
}

interface TestResult {
  ok: boolean;
  detail: string;
}

function buildEventClasses(rows: Record<string, string>) {
  return EVENT_CLASSES.filter((c) => rows[c]).map((c) => ({ class: c, ticket_type: rows[c] }));
}

function defaultRows(kind: Kind): Record<string, string> {
  return Object.fromEntries(EVENT_CLASSES.map((c) => [c, DEFAULT_TICKET_TYPE[kind]]));
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
  const [rows, setRows] = useState<Record<string, string>>(defaultRows("servicenow"));
  const [formError, setFormError] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, TestResult>>({});
  const [testingId, setTestingId] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ["itsm-connections"],
    queryFn: () => fetchJSON<{ data: { items: ItsmConn[] } }>(CONNECTIONS_PATH),
  });
  const items = list.data?.data?.items ?? [];

  function changeKind(k: Kind) {
    setKind(k);
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
    setRows(defaultRows(kind));
  }

  const addMutation = useMutation({
    mutationFn: async () => {
      const payload: Record<string, unknown> =
        kind === "jira"
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
          base_url: baseUrl.trim(),
          credential_ref: cred.data.id,
          event_classes: buildEventClasses(rows),
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
      subtitle="ServiceNow and Jira ticket creation; credentials are write-only"
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
            </Select>
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Name</span>
            <Input aria-label="ITSM name" value={name} disabled={disabled} onChange={(e) => setName(e.target.value)} />
          </label>
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
          {EVENT_CLASSES.map((c) => (
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
                  <span className="text-muted-foreground">{c.base_url}</span>
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
