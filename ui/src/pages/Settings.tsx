import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, Send, Trash2, Plus } from "lucide-react";
import { toast } from "sonner";
import { api } from "../lib/api";
import {
  Badge,
  Button,
  Input,
  Panel,
  Select,
  StateMessage,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";
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
            <label className="text-xs text-muted-foreground">Framework</label>
            <Select
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
            <label className="text-xs text-muted-foreground">Cadence</label>
            <Select
              value={cadence}
              onChange={(e) => setCadence(e.target.value)}
            >
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </Select>
          </div>
          <div className="grow">
            <label className="text-xs text-muted-foreground">
              Recipients (comma-separated)
            </label>
            <Input
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
    </div>
  );
}
