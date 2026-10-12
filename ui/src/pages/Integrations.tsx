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
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";
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
  "sso.oidc_issuer": "OIDC issuer",
  "sso.oidc_audience": "OIDC audience",
  "sso.oidc_discovery_url": "OIDC discovery URL",
  "sso.oidc_jwks_json": "OIDC JWKS (static, JSON)",
};

function sourceBadge(setting: EffectiveSetting) {
  if (setting.source === "database")
    return <Badge tone="success">Database override</Badge>;
  if (setting.source === "env_default")
    return <Badge tone="info">Environment default</Badge>;
  return <Badge tone="neutral">Not set</Badge>;
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
  const canReset = setting.source === "database";
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

      {setting.secret ? (
        <p className="text-xs text-muted-foreground">
          {setting.configured
            ? `Configured (${setting.source === "database" ? "database override" : "environment default"}) — the value is write-only and never displayed here.`
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
          This tests delivery to the target you enter above; it exercises the
          channel itself, not necessarily the saved config below — the running
          server still binds SMTP/Slack/PagerDuty credentials from startup
          environment variables until those consumers are rewired to read the
          config store (W8-13). Webhook has no saved config at all: the
          runtime-config store has no generic webhook key, so a webhook target
          can only be tested here, never persisted.
        </p>
      </div>
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
            SSO consumers rewired to the config store (W8-13).
          </p>
        </div>
      )}
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
          <ConfigCategoryPanel
            title="SSO / OIDC"
            subtitle="Issuer, audience, discovery URL and static JWKS for OIDC login"
            settings={ssoSettings}
            canWrite={canWrite}
          />
          <SsoServerStatusPanel />
        </>
      )}
    </div>
  );
}
