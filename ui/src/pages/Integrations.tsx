import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, RotateCcw, Send } from "lucide-react";
import { api } from "../lib/api";
import type { EffectiveSetting } from "../lib/api";
import {
  Badge,
  Button,
  Input,
  Panel,
  Select,
  StateMessage,
  formatDateTime,
} from "../components/ui";
import ItsmConnection from "./ItsmConnection";
import { PageHeader } from "../components/PageHeader";
import { rolesApi, type RolePreview } from "../lib/rolesApi";
import { canManageNotifications, canManageUsers, useAuthz } from "../lib/auth";

// Human labels for the registered runtime-config keys (W8-03,
// internal/bootstrap/config_store.go's configRegistry) -- not invented,
// mirrors the real key names so the label always matches what gets PUT.
const CONFIG_LABELS: Record<string, string> = {
  "notifications.slack_webhook_url": "Slack webhook URL",
  "notifications.smtp_host": "SMTP host",
  "notifications.smtp_port": "SMTP port",
  "notifications.smtp_username": "SMTP username",
  "notifications.smtp_password": "SMTP password",
  "notifications.smtp_from": "SMTP from address",
  "notifications.pagerduty_routing_key": "PagerDuty routing key",
  "notifications.webhook_url": "Webhook URL",
  "notifications.escalation_channel": "Escalation channel",
  "notifications.escalation_target": "Escalation target",
  "notifications.webhook_secret": "Webhook signing secret",
  "notifications.webhook_secret_previous":
    "Previous webhook signing secret (rotation, kept 24 h)",
  "sso.oidc_issuer": "OIDC issuer",
  "sso.oidc_audience": "OIDC audience",
  "sso.oidc_discovery_url": "OIDC discovery URL",
  "sso.oidc_jwks_json": "OIDC JWKS (static, JSON)",
  "saml.sp_entity_id": "SAML SP entity ID",
  "saml.idp_sso_url": "SAML IdP SSO URL",
  "saml.idp_issuer": "SAML IdP issuer",
  "saml.idp_certificate": "SAML IdP certificate (PEM)",
  "scim.enabled": "SCIM enabled (true/false)",
  "scim.token": "SCIM bearer token",
  "key_backend.kind": "Key backend kind",
  "key_backend.pkcs11_module": "PKCS#11 module path",
  "notifications.slack_bot_token": "Slack bot token",
  "notifications.slack_team_channels": "Slack team channels (JSON: team to channel id)",
  "notifications.teams_app_id": "Teams app ID",
  "notifications.teams_app_password": "Teams app password",
  "notifications.teams_team_channels": "Teams team channels (JSON: team to conversation)",
  "renewal_policy.threshold_days": "Renewal threshold (days before expiry)",
  "renewal_policy.poll_hours": "Renewal scan interval (hours)",
  "renewal_policy.alert_cooldown_hours": "Renewal alert cooldown (hours)",
  "renewal_policy.retry_base_minutes": "Renewal retry base delay (minutes)",
  "renewal_policy.retry_cap_hours": "Renewal retry cap (hours)",
  "discovery.provider": "Discovery provider",
  "ct.domains": "Certificate Transparency watch domains",
  "discovery.kube_clusters": "Kubernetes clusters to scan",
  "discovery.mesh_leaf_retention_days": "Service-mesh leaf retention (days)",
  "discovery.saas_endpoints": "SaaS endpoints to scan",
  "discovery.cloud_scopes": "Cloud scopes to scan",
  "slo.renewal_success_objective": "Renewal success objective",
  "slo.issuance_success_objective": "Issuance success objective",
  "slo.issuance_latency_p95_seconds": "Issuance latency p95 objective (seconds)",
  "metrics.bearer_token": "Metrics bearer token",
  "agentless.default_privilege_mode":
    "Default sudo mode for SSH credentials",
};

function sourceBadge(setting: EffectiveSetting) {
  if (!setting.configured) return <Badge tone="neutral">Not set</Badge>;
  if (setting.effective_source === "override")
    return <Badge tone="success">Override</Badge>;
  return <Badge tone="info">Env</Badge>;
}

// Deterministic, local checks only -- no network call. A secret's saved
// value never reaches the browser (GET /config is write-only for secrets),
// so this can only validate what's currently typed into the field, not
// what's already stored.
function validateForKey(
  key: string,
  value: string,
): { ok: boolean; message: string } | null {
  if (!value.trim()) return null;
  if (key === "sso.oidc_jwks_json") {
    try {
      const parsed = JSON.parse(value);
      if (!Array.isArray(parsed?.keys)) {
        return {
          ok: false,
          message: 'Valid JSON, but missing a "keys" array.',
        };
      }
      return {
        ok: true,
        message: `Valid JWKS — ${parsed.keys.length} key(s).`,
      };
    } catch {
      return { ok: false, message: "Not valid JSON." };
    }
  }
  if (key === "sso.oidc_issuer" || key === "sso.oidc_discovery_url") {
    try {
      new URL(value);
      return { ok: true, message: "Looks like a valid URL." };
    } catch {
      return { ok: false, message: "Not a valid absolute URL." };
    }
  }
  if (key === "saml.idp_sso_url" && !value.trim().startsWith("https://")) {
    return { ok: false, message: "IdP SSO URL must be an https:// URL" };
  }
  if (key === "scim.enabled" && value.trim() !== "true" && value.trim() !== "false") {
    return { ok: false, message: "Must be true or false." };
  }
  return null;
}

function ConfigField({
  setting,
  canWrite,
  savePending,
  resetPending,
  onSave,
  onReset,
}: {
  setting: EffectiveSetting;
  canWrite: boolean;
  savePending: boolean;
  resetPending: boolean;
  onSave: (value: string) => void;
  onReset: () => void;
}) {
  const [draft, setDraft] = useState(
    setting.secret ? "" : (setting.value ?? ""),
  );
  const label = CONFIG_LABELS[setting.key] ?? setting.key;
  const canReset = setting.effective_source === "override";
  const saveDisabled =
    !canWrite || savePending || (setting.secret && draft.trim() === "");
  const check = validateForKey(setting.key, draft);

  return (
    <div className="space-y-2 rounded-xl border border-border bg-card/40 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-sm font-medium text-foreground">{label}</div>
          <div className="text-xs text-muted-foreground">
            env default: <code className="font-mono">{setting.env_var}</code>
          </div>
        </div>
        {sourceBadge(setting)}
      </div>

      {setting.restart_required ? (
        <p className="text-xs text-muted-foreground">
          Takes effect after the hub restarts.
        </p>
      ) : null}

      {setting.secret ? (
        <p className="text-xs text-muted-foreground">
          {setting.configured
            ? `Configured (${setting.effective_source === "override" ? "override" : "environment"}) — the value is write-only and never displayed here.`
            : "Not configured."}
        </p>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <Input
          type={setting.secret ? "password" : "text"}
          aria-label={label}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={setting.secret ? "New value" : setting.env_var}
          disabled={!canWrite}
          className="max-w-sm"
        />
        <Button
          tone="primary"
          disabled={saveDisabled}
          onClick={() => onSave(draft)}
        >
          {savePending ? "Saving…" : "Save"}
        </Button>
        <Button
          tone="secondary"
          disabled={!canWrite || !canReset || resetPending}
          onClick={onReset}
        >
          <RotateCcw size={13} aria-hidden="true" />
          {resetPending ? "Resetting…" : "Reset to env default"}
        </Button>
      </div>

      {check ? (
        <p
          className={`text-xs ${check.ok ? "text-state-auto" : "text-state-over"}`}
        >
          {check.message}
        </p>
      ) : null}
    </div>
  );
}

function ConfigCategoryPanel({
  title,
  subtitle,
  settings,
  canWrite,
}: {
  title: string;
  subtitle: string;
  settings: EffectiveSetting[];
  canWrite: boolean;
}) {
  const queryClient = useQueryClient();
  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["runtime-config"] });

  const saveMutation = useMutation({
    mutationFn: ({ key, value }: { key: string; value: string }) =>
      api.setRuntimeConfig(key, value),
    onMutate: ({ key }) => setPendingKey(key),
    onSuccess: async () => {
      setErrorMsg(null);
      await invalidate();
    },
    onError: (e) =>
      setErrorMsg(e instanceof Error ? e.message : "Save failed."),
    onSettled: () => setPendingKey(null),
  });

  const resetMutation = useMutation({
    mutationFn: (key: string) => api.resetRuntimeConfig(key),
    onMutate: (key) => setPendingKey(key),
    onSuccess: async () => {
      setErrorMsg(null);
      await invalidate();
    },
    onError: (e) =>
      setErrorMsg(e instanceof Error ? e.message : "Reset failed."),
    onSettled: () => setPendingKey(null),
  });

  return (
    <Panel title={title} subtitle={subtitle}>
      <div className="space-y-3">
        {!canWrite ? (
          <p className="text-xs text-muted-foreground">
            Admin role required to change these settings.
          </p>
        ) : null}
        {errorMsg ? <p className="text-sm text-state-over">{errorMsg}</p> : null}
        {settings.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No settings in this category.
          </p>
        ) : (
          settings.map((s) => (
            <ConfigField
              key={`${s.key}:${s.source}:${s.updated_at ?? ""}`}
              setting={s}
              canWrite={canWrite}
              savePending={saveMutation.isPending && pendingKey === s.key}
              resetPending={resetMutation.isPending && pendingKey === s.key}
              onSave={(value) => saveMutation.mutate({ key: s.key, value })}
              onReset={() => resetMutation.mutate(s.key)}
            />
          ))
        )}
      </div>
    </Panel>
  );
}

const CHANNEL_PLACEHOLDER: Record<string, string> = {
  email: "user@example.com",
  slack: "#channel or Slack webhook URL",
  pagerduty: "routing-key",
  webhook: "https://hooks.example.com/…",
};

function ChannelTestPanel({ canTest }: { canTest: boolean }) {
  const [channel, setChannel] = useState("email");
  const [target, setTarget] = useState("");
  const [message, setMessage] = useState(
    "Test message from Kryptkeeper Integrations",
  );

  const testMutation = useMutation({
    mutationFn: () =>
      api.testNotificationDelivery({ channel, target, message }),
  });
  const result = testMutation.data?.data?.delivery;

  return (
    <Panel
      title="Test a notification channel"
      subtitle="Sends a synthetic message to the target you supply"
    >
      <div className="space-y-3">
        <div className="flex flex-wrap items-end gap-2">
          <label className="block space-y-1 text-sm text-foreground">
            <span>Channel</span>
            <Select
              aria-label="Notification test channel"
              value={channel}
              onChange={(e) => setChannel(e.target.value)}
            >
              <option value="email">Email (SMTP)</option>
              <option value="slack">Slack</option>
              <option value="pagerduty">PagerDuty</option>
              <option value="webhook">Webhook</option>
            </Select>
          </label>
          <label className="block grow space-y-1 text-sm text-foreground">
            <span>Target</span>
            <Input
              aria-label="Notification test target"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={CHANNEL_PLACEHOLDER[channel]}
            />
          </label>
          <Button
            tone="primary"
            disabled={!canTest || !target.trim() || testMutation.isPending}
            onClick={() => testMutation.mutate()}
          >
            <Send size={13} aria-hidden="true" />
            {testMutation.isPending ? "Sending…" : "Send test"}
          </Button>
        </div>
        <label className="block space-y-1 text-sm text-foreground">
          <span>Message</span>
          <Input
            aria-label="Notification test message"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
        </label>

        {testMutation.isError ? (
          <p className="text-sm text-state-over">
            {testMutation.error instanceof Error
              ? testMutation.error.message
              : "Test failed."}
          </p>
        ) : null}
        {result ? (
          <p className="text-sm text-state-auto">
            Queued: {result.channel} → {result.target} ({result.status})
          </p>
        ) : null}

        <p className="text-xs text-muted-foreground">
          This tests delivery to the target you enter above. Changes to SMTP,
          Slack, PagerDuty and webhook settings apply on the next send; no
          restart is needed. Webhook URL and signing secret are saved in the
          Notifications panel above.
        </p>
      </div>
    </Panel>
  );
}

function DcvValidationsPanel() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["dcv-validations"],
    queryFn: api.dcvValidations,
    staleTime: 30_000,
  });
  const rows = [...(data?.data ?? [])].sort((a, b) => a.days_remaining - b.days_remaining);

  return (
    <Panel
      title="Domain validation (DCV)"
      subtitle="How long each domain's validation can still be reused, from the CA/Browser Forum schedule"
    >
      {isLoading ? (
        <StateMessage title="Loading" message="Reading domain validations…" />
      ) : error || !data ? (
        <StateMessage
          tone="error"
          title="Unavailable"
          message="Domain validations could not be loaded."
        />
      ) : rows.length === 0 ? (
        <StateMessage
          title="No validations yet"
          message="Domains appear here after an ACME order succeeds."
        />
      ) : (
        <div className="space-y-6">
          <table className="w-full text-sm" aria-label="Domain validations">
            <caption className="sr-only">Domain validations and days remaining</caption>
            <thead>
              <tr className="text-left text-xs text-muted-foreground">
                <th scope="col" className="py-2">Domain</th>
                <th scope="col">Connector</th>
                <th scope="col">Validated</th>
                <th scope="col">Expires</th>
                <th scope="col">Days remaining</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr
                  key={`${r.connector_id}:${r.domain}`}
                  className="border-t border-border"
                  data-warn={r.warn ? "true" : undefined}
                >
                  <td className="py-2 font-medium text-foreground">{r.domain}</td>
                  <td>{r.connector_id}</td>
                  <td>{formatDateTime(r.validated_at)}</td>
                  <td>{formatDateTime(r.expires_at)}</td>
                  <td>{r.days_remaining}</td>
                  <td>
                    {r.warn ? (
                      <Badge tone="warning">Under 20% left</Badge>
                    ) : (
                      <Badge tone="success">OK</Badge>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <table className="w-full text-sm" aria-label="Reuse period schedule">
            <caption className="sr-only">CA/Browser Forum validation reuse schedule</caption>
            <thead>
              <tr className="text-left text-xs text-muted-foreground">
                <th scope="col" className="py-2">Effective from</th>
                <th scope="col">Reuse period (days)</th>
              </tr>
            </thead>
            <tbody>
              {data.schedule.map((s) => (
                <tr key={s.effective} className="border-t border-border">
                  <td className="py-2">{s.effective}</td>
                  <td>
                    {s.days}{" "}
                    {s.days === data.current_reuse_days ? <Badge tone="info">Current</Badge> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function SsoServerStatusPanel() {
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["protected-config"],
    queryFn: api.protectedConfig,
    staleTime: 10_000,
  });

  return (
    <Panel
      title="SSO status on the running server"
      subtitle="What the server is actually enforcing right now, independent of any override saved above"
    >
      {isLoading ? (
        <StateMessage title="Loading" message="Checking server auth mode…" />
      ) : error || !data ? (
        <StateMessage
          tone="error"
          title="Unavailable"
          message="Could not read the server's auth mode."
        />
      ) : (
        <div className="space-y-3 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">Auth mode</span>
            <Badge tone={data.config.oidc_enabled ? "success" : "neutral"}>
              {data.auth_mode}
            </Badge>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">OIDC enabled</span>
            <Badge tone={data.config.oidc_enabled ? "success" : "neutral"}>
              {data.config.oidc_enabled ? "Yes" : "No"}
            </Badge>
          </div>
          <Button
            tone="secondary"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw size={13} aria-hidden="true" />
            Refresh
          </Button>
          <p className="text-xs text-muted-foreground">
            Saving an SSO override above stores it immediately, but the running
            server only reads OIDC settings from environment variables at
            startup — this status will not change until the server restarts with
            SSO consumers rewired to the config store.
          </p>
        </div>
      )}
    </Panel>
  );
}

function RoleMapPreviewPanel() {
  const [groups, setGroups] = useState("");
  const [result, setResult] = useState<RolePreview | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const preview = useMutation({
    mutationFn: (list: string[]) => rolesApi.preview(list),
    onSuccess: (res) => {
      setMessage(null);
      setResult(res.data);
    },
    onError: (err: Error & { status?: number }) => {
      setResult(null);
      setMessage(
        err.status === 403
          ? "Role mapping preview needs an administrator."
          : "Could not preview the role mapping.",
      );
    },
  });

  return (
    <Panel
      title="Role mapping preview"
      subtitle="Which Kryptkeeper role an SSO login with these IdP groups would receive"
    >
      <div className="flex flex-wrap items-end gap-3">
        <label className="min-w-[260px] flex-1 text-xs text-muted-foreground">
          IdP groups (comma separated)
          <Input value={groups} onChange={(e) => setGroups(e.target.value)} placeholder="kk-ops, kk-admins" />
        </label>
        <Button
          tone="secondary"
          disabled={preview.isPending}
          onClick={() =>
            preview.mutate(
              groups
                .split(",")
                .map((g) => g.trim())
                .filter(Boolean),
            )
          }
        >
          Preview
        </Button>
      </div>
      {message ? (
        <p role="status" className="mt-3 text-sm text-muted-foreground">
          {message}
        </p>
      ) : null}
      {result ? (
        <div className="mt-3 space-y-1 text-sm" aria-live="polite">
          <div>
            <span className="text-muted-foreground">Effective role</span>{" "}
            <span className="font-medium text-foreground">{result.effective_role || "none"}</span>
          </div>
          <div>
            {result.would_login ? (
              <Badge tone="success">Login allowed</Badge>
            ) : (
              <Badge tone="danger">Would be denied (403)</Badge>
            )}
          </div>
          <div className="text-muted-foreground">
            {result.mapped
              ? `Matched claim value: ${result.matched_claim_value}`
              : "No mapping matches"}
          </div>
        </div>
      ) : null}
    </Panel>
  );
}

export default function Integrations() {
  const authz = useAuthz();
  const role = authz.data?.role;
  const scopes = authz.data?.scopes;
  // Config writes are pki-admin only on the server
  // (internal/bootstrap/handlers_config.go's isAdminRole gate);
  // canManageUsers is the same "role === pki-admin" check (Users.tsx:29).
  const canWrite = canManageUsers(role, scopes);
  const canTest = canManageNotifications(role, scopes);

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["runtime-config"],
    queryFn: api.runtimeConfig,
  });
  const settings = data?.data ?? [];
  const notificationSettings = settings.filter(
    (s) => s.category === "notifications",
  );
  const ssoSettings = settings.filter((s) => s.category === "sso");
  const samlSettings = settings.filter((s) => s.category === "saml");
  const scimSettings = settings.filter((s) => s.category === "scim");
  const keyBackendSettings = settings.filter(
    (s) => s.category === "key_backend",
  );
  const agentlessSettings = settings.filter((s) => s.category === "agentless");

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="System"
        title="Integrations"
        description="Notification channels and SSO/OIDC, backed by the runtime config store — env remains the default, a database override applies immediately at the store/API layer."
        actions={
          <Button
            tone="secondary"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw size={13} aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      {isLoading ? (
        <StateMessage title="Loading" message="Fetching runtime settings…" />
      ) : error ? (
        <StateMessage
          tone="error"
          title="Unavailable"
          message="Runtime settings could not be loaded."
        />
      ) : (
        <>
          <ConfigCategoryPanel
            title="Notifications"
            subtitle="Slack, PagerDuty and SMTP (email) delivery settings"
            settings={notificationSettings}
            canWrite={canWrite}
          />
          <ChannelTestPanel canTest={canTest} />
          <ItsmConnection canWrite={canWrite} />
          <ConfigCategoryPanel
            title="SSO / OIDC"
            subtitle="Issuer, audience, discovery URL and static JWKS for OIDC login"
            settings={ssoSettings}
            canWrite={canWrite}
          />
          <ConfigCategoryPanel
            title="SAML"
            subtitle="Service-provider entity ID and IdP details for SAML login"
            settings={samlSettings}
            canWrite={canWrite}
          />
          <ConfigCategoryPanel
            title="SCIM"
            subtitle="Provisioning token (write-only) and enable switch"
            settings={scimSettings}
            canWrite={canWrite}
          />
          <ConfigCategoryPanel
            title="Key backend"
            subtitle="Key store kind and PKCS#11 module"
            settings={keyBackendSettings}
            canWrite={canWrite}
          />
          <ConfigCategoryPanel
            title="Agentless privilege"
            subtitle="The sudo mode preselected when creating an SSH credential; any mode stays selectable per credential"
            settings={agentlessSettings}
            canWrite={canWrite}
          />
          <SsoServerStatusPanel />
          <DcvValidationsPanel />
          {canWrite ? <RoleMapPreviewPanel /> : null}
        </>
      )}
    </div>
  );
}
