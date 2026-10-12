import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Check } from "lucide-react";
import {
  api,
  type CredentialMeta,
  type CredentialPreflight,
  type ManagedTarget,
} from "../lib/api";
import type { AgentType } from "../lib/models";
import {
  Badge,
  Button,
  Input,
  Panel,
  Select,
  StateMessage,
  Textarea,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { Wizard, type WizardStepDef } from "../components/Wizard";
import { CapabilityList } from "../components/PluginCapabilities";
import { capabilityTier, tierLabel, tierTone, type PluginManifest } from "../lib/plugins";

type Mode = "agent" | "agentless";

const AGENT_TYPE_OPTIONS: { value: AgentType; label: string }[] = [
  { value: "linux", label: "Linux" },
  { value: "mac", label: "macOS" },
  { value: "windows", label: "Windows" },
];

// Restricted to the agentless-relevant subset of the full W5-09 enum
// ("agent" discovery/install belongs to the agent-mode branch of this page,
// not the agentless form) -- see docs/board/specs/W8-06.md's shape.
// The host's operating system decides how a certificate gets ONTO it.
// Linux takes files over SSH and reloads a service; Windows has no such
// paths -- certificates live in the machine store and bindings are set
// with netsh, reached over WinRM. Presenting one shape for both is what
// made this wizard look like it supported Windows when it did not.
//
// macOS keeps machine identities in the System keychain, reached over SSH
// with Apple's `security` tool (W18-05); the issuing root is trusted too.
type TargetOS = "linux" | "windows" | "mac";

const TARGET_OS_OPTIONS: { value: TargetOS; label: string; hint: string }[] = [
  { value: "linux", label: "Linux / Unix", hint: "Files over SSH, reloaded with systemctl or the server binary." },
  { value: "windows", label: "Windows", hint: "Machine certificate store and an HTTP.sys binding, over WinRM." },
  { value: "mac", label: "macOS", hint: "System keychain over SSH; the issuing root CA is trusted too." },
];

// Appliances and protocols are not the host, so they are offered for
// either OS. Only the host-based modes are OS-specific.
const OS_NEUTRAL_INSTALL_MODES = [
  { value: "f5", label: "F5 BIG-IP" },
  { value: "citrix", label: "Citrix ADC" },
  { value: "k8s", label: "Kubernetes secret" },
  { value: "cloud", label: "Cloud API" },
  { value: "acme", label: "ACME (target polls)" },
  { value: "plugin", label: "Delivery plugin" },
];

function discoveryOptionsFor(os: TargetOS) {
  const shared = [
    { value: "network", label: "Network scan" },
    { value: "cloud", label: "Cloud provider" },
    { value: "none", label: "None (manual only)" },
  ];
  return os === "windows"
    ? [{ value: "winrm", label: "WinRM (agentless)" }, ...shared]
    : shared;
}

function installOptionsFor(os: TargetOS) {
  const hostMode =
    os === "windows"
      ? { value: "iis", label: "IIS / HTTP.sys binding" }
      : os === "mac"
        ? { value: "keychain", label: "System keychain (SSH)" }
        : { value: "ssh", label: "SSH push" };
  return [hostMode, ...OS_NEUTRAL_INSTALL_MODES];
}

// iis, keychain and k8s need a credential for the same reason ssh and the
// appliances do: something has to authenticate to the target.
const CREDENTIAL_REQUIRED_MODES = new Set(["ssh", "keychain", "iis", "f5", "citrix", "k8s", "plugin"]);

// Modes the hub's renewal sweep can execute (renewal_scheduler.go). ssh also
// needs server type and paths; keychain installs into the macOS keychain.
const AUTO_RENEW_MODES = new Set(["ssh", "keychain", "plugin"]);

// pluginCredentialShape builds the credential form from the plugin's
// credential_schema (W20-21). tls_ca_pem is the hub's own field: the
// device's internal CA, trusted for this target's HTTPS only.
function pluginCredentialShape(manifest?: PluginManifest): { type: string; fields: CredField[] } | undefined {
  if (!manifest) return undefined;
  const fields: CredField[] = Object.entries(manifest.credential_schema ?? {}).map(([key, f]) => ({
    key,
    label: `${key}${f.required ? "" : " (optional)"}`,
    secret: f.secret,
    multiline: f.type === "pem",
    placeholder: f.default,
  }));
  if (!manifest.credential_schema?.tls_ca_pem) {
    fields.push({ key: "tls_ca_pem", label: "Device CA (PEM, optional)", multiline: true, placeholder: "-----BEGIN CERTIFICATE-----" });
  }
  return { type: "api_token", fields };
}


// What a credential FOR THIS INSTALL MODE is made of. The old step was a
// free-text "reference" to a credential "already configured for this hub"
// — but nothing in the product could configure one, so a first-time user
// hit a hard dead end. Now the step lists what exists and can create one
// in place, with fields shaped by the mode instead of a raw JSON blob.
type CredField = { key: string; label: string; secret?: boolean; multiline?: boolean; placeholder?: string };

// The renewal executor refuses an SSH credential without the host's public
// key: it pins it rather than trusting whatever answers (renewal_executor.go).
const SSH_CREDENTIAL_SHAPE: { type: string; fields: CredField[] } = {
  type: "ssh_key",
  fields: [
    { key: "user", label: "SSH user", placeholder: "root" },
    { key: "private_key_pem", label: "Private key (PEM)", secret: true, multiline: true, placeholder: "-----BEGIN OPENSSH PRIVATE KEY-----" }, // secret-scan:allow input placeholder
    { key: "host_public_key", label: "Host public key (pinned)", placeholder: "ecdsa-sha2-nistp256 AAAA… (ssh-keyscan -t ecdsa host)" },
  ],
};

const CREDENTIAL_SHAPES: Record<string, { type: string; fields: CredField[] }> = {
  ssh: SSH_CREDENTIAL_SHAPE,
  keychain: SSH_CREDENTIAL_SHAPE,
  iis: {
    type: "windows_password",
    fields: [
      { key: "base_url", label: "WinRM endpoint", placeholder: "https://host.corp.example.com:5986/wsman" },
      { key: "username", label: "Username", placeholder: "CORP\\svc-pki" },
      { key: "password", label: "Password", secret: true },
      { key: "ipport", label: "HTTPS binding (ip:port)", placeholder: "0.0.0.0:443" },
    ],
  },
  f5: {
    type: "api_token",
    fields: [
      { key: "base_url", label: "iControl URL", placeholder: "https://bigip.corp.example.com" },
      { key: "username", label: "Username" },
      { key: "password", label: "Password", secret: true },
      { key: "client_ssl_profile", label: "Client-SSL profile" },
    ],
  },
  citrix: {
    type: "api_token",
    fields: [
      { key: "base_url", label: "NITRO URL", placeholder: "https://adc.corp.example.com" },
      { key: "username", label: "Username" },
      { key: "password", label: "Password", secret: true },
      { key: "certkey_name", label: "Cert-key pair name" },
    ],
  },
  k8s: {
    type: "api_token",
    fields: [
      { key: "base_url", label: "API server", placeholder: "https://k8s.corp.example.com:6443" },
      { key: "bearer_token", label: "Bearer token", secret: true },
      { key: "namespace", label: "Namespace", placeholder: "edge" },
      { key: "secret_name", label: "TLS secret name", placeholder: "gateway-tls" },
    ],
  },
};

function CredentialPicker({
  installMode,
  value,
  onChange,
  shapeOverride,
}: {
  installMode: string;
  value: string;
  onChange: (ref: string, name?: string) => void;
  shapeOverride?: { type: string; fields: CredField[] };
}) {
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  const listQ = useQuery({ queryKey: ["credentials"], queryFn: api.credentials });
  const items: CredentialMeta[] = listQ.data?.data?.items ?? [];
  const shape = shapeOverride ?? CREDENTIAL_SHAPES[installMode];

  // W18-11: a Windows credential can be tested the moment it is picked.
  // Discovery and install need different privilege, and learning that at
  // install time (after a renewal was issued) is the failure this exists
  // to prevent. The probe only reads; the secret never comes back.
  const selected = items.find((c) => c.id === value);
  const canPreflight = selected?.credential_type === "windows_password";
  const preflightM = useMutation({
    mutationFn: () => api.preflightCredential(value),
  });
  const verdict: CredentialPreflight | undefined = preflightM.data?.data;

  const createM = useMutation({
    mutationFn: () =>
      api.createCredential({
        name: name.trim(),
        credential_type: shape.type,
        payload: fields,
      }),
    onSuccess: (res) => {
      setCreating(false);
      setName("");
      setFields({});
      setError(null);
      void qc.invalidateQueries({ queryKey: ["credentials"] });
      if (res?.data?.id) onChange(res.data.id, res.data.name);
    },
    onError: (e) => setError(e instanceof Error ? e.message : "Create failed"),
  });

  if (!shape) {
    // Modes with no credential (cloud IAM from env, ACME) keep the plain
    // reference field for the optional case.
    return (
      <label className="block space-y-1 text-sm text-foreground">
        <span>Credential reference (optional)</span>
        <Input value={value} onChange={(e) => onChange(e.target.value)} />
      </label>
    );
  }

  return (
    <div className="space-y-3">
      <label className="block space-y-1 text-sm text-foreground">
        <span>Credential</span>
        <Select
          value={creating ? "__new__" : value}
          onChange={(e) => {
            if (e.target.value === "__new__") {
              setCreating(true);
            } else {
              setCreating(false);
              const picked = items.find((c) => c.id === e.target.value);
              onChange(e.target.value, picked?.name);
            }
          }}
        >
          <option value="">Select a credential…</option>
          {items.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name} · {c.credential_type}
            </option>
          ))}
          <option value="__new__">+ Create a new credential</option>
        </Select>
      </label>

      {canPreflight && !creating && (
        <div className="space-y-2">
          <Button
            tone="secondary"
            disabled={preflightM.isPending}
            onClick={() => preflightM.mutate()}
          >
            {preflightM.isPending ? "Testing…" : "Test credential"}
          </Button>
          {preflightM.isError && (
            <p className="text-sm text-state-over" role="alert">
              {preflightM.error instanceof Error
                ? preflightM.error.message
                : "Preflight failed"}
            </p>
          )}
          {verdict && (
            <div
              className="space-y-1 rounded-lg border border-border bg-muted/30 p-3 text-sm"
              data-testid="credential-preflight"
            >
              <div className="flex flex-wrap items-center gap-2">
                <Badge
                  tone={
                    verdict.can_install
                      ? "success"
                      : verdict.can_discover
                        ? "warning"
                        : "danger"
                  }
                >
                  {verdict.can_install
                    ? "Can discover and install"
                    : verdict.can_discover
                      ? "Discover only"
                      : verdict.level === "unauthenticated"
                        ? "Not accepted"
                        : verdict.level === "no_shell"
                          ? "No remote shell"
                          : "Unreachable"}
                </Badge>
                <span className="text-xs text-muted-foreground">
                  {installMode === "iis" && !verdict.can_install
                    ? "This target's install mode needs a local Administrator."
                    : null}
                </span>
              </div>
              <p className="text-xs text-muted-foreground">{verdict.detail}</p>
            </div>
          )}
        </div>
      )}

      {creating && (
        <div className="space-y-3 rounded-lg border border-border bg-muted/30 p-3">
          <label className="block space-y-1 text-sm text-foreground">
            <span>Name</span>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={`${installMode} credential`}
            />
          </label>
          {shape.fields.map((f) => (
            <label key={f.key} className="block space-y-1 text-sm text-foreground">
              <span>{f.label}</span>
              {f.multiline ? (
                <Textarea
                  rows={5}
                  value={fields[f.key] ?? ""}
                  onChange={(e) => setFields((m) => ({ ...m, [f.key]: e.target.value }))}
                  placeholder={f.placeholder}
                  // A multiline secret (an SSH private key) must not sit
                  // readable on screen; text-security masks it like a
                  // password field. Paste still works.
                  style={
                    f.secret
                      ? ({ WebkitTextSecurity: "disc" } as React.CSSProperties)
                      : undefined
                  }
                  spellCheck={false}
                  autoComplete="off"
                />
              ) : (
                <Input
                  type={f.secret && !f.multiline ? "password" : "text"}
                  value={fields[f.key] ?? ""}
                  onChange={(e) => setFields((m) => ({ ...m, [f.key]: e.target.value }))}
                  placeholder={f.placeholder}
                />
              )}
            </label>
          ))}
          <p className="text-xs text-muted-foreground">
            Stored encrypted. It can be used and deleted, never read back.
          </p>
          {error && <p className="text-sm text-state-over">{error}</p>}
          <Button
            tone="primary"
            disabled={createM.isPending || !name.trim()}
            onClick={() => createM.mutate()}
          >
            {createM.isPending ? "Creating…" : "Create & use"}
          </Button>
        </div>
      )}
    </div>
  );
}

function hubURL(): string {
  return window.location.origin;
}

function AgentSetupPanel() {
  const [name, setName] = useState("");
  const [type, setType] = useState<AgentType>("linux");
  const [copied, setCopied] = useState(false);

  const registerMutation = useMutation({
    mutationFn: () => api.registerAgent({ name: name.trim(), type }),
  });
  const registration = registerMutation.data;

  const pairingQuery = useQuery({
    queryKey: ["target-setup-agent-pairing", registration?.agent_id],
    queryFn: () => api.agents(),
    enabled: !!registration,
    refetchInterval: (query) => {
      const agent = query.state.data?.agents.find(
        (a) => a.id === registration?.agent_id,
      );
      return agent?.last_seen ? false : 3000;
    },
  });

  const pairedAgent = registration
    ? pairingQuery.data?.agents.find((a) => a.id === registration.agent_id)
    : undefined;
  const isPaired = !!pairedAgent?.last_seen;

  const installCommand = registration
    ? `KRYPTKEEPER_HUB_URL=${hubURL()} \\
KRYPTKEEPER_AGENT_ID=${registration.agent_id} \\
KRYPTKEEPER_AGENT_TOKEN=${registration.token} \\
  kryptkeeper-agent`
    : "";

  const copyCommand = async () => {
    await navigator.clipboard.writeText(installCommand);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-4">
      <Panel
        title="1. Generate an enrollment token"
        subtitle="Each agent gets a unique ID and token minted on registration -- never reused across hosts."
      >
        <div className="space-y-3">
          <label className="block space-y-1 text-sm text-foreground">
            <span>Agent name</span>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="web-01.prod"
              disabled={!!registration}
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Host type</span>
            <Select
              value={type}
              onChange={(e) => setType(e.target.value as AgentType)}
              disabled={!!registration}
            >
              {AGENT_TYPE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </label>
          <Button
            tone="primary"
            onClick={() => registerMutation.mutate()}
            disabled={
              registerMutation.isPending || !!registration || !name.trim()
            }
          >
            {registration ? "Token generated" : "Generate token"}
          </Button>
          {registerMutation.isError && (
            <p role="alert" className="text-xs text-state-over">
              {registerMutation.error instanceof Error
                ? registerMutation.error.message
                : "Failed to generate a token."}
            </p>
          )}
        </div>
      </Panel>

      {registration && (
        <>
          <Panel
            title="2. Install the agent"
            subtitle="Run this on the target host. The token is single-use for enrollment; the agent persists it for future heartbeats."
          >
            <div className="space-y-3">
              <pre className="overflow-x-auto rounded-xl bg-card p-4 text-xs text-foreground">
                {installCommand}
              </pre>
              <Button onClick={() => void copyCommand()}>
                {copied ? (
                  <>
                    <Check className="h-4 w-4" /> Copied
                  </>
                ) : (
                  <>
                    <Copy className="h-4 w-4" /> Copy command
                  </>
                )}
              </Button>
            </div>
          </Panel>

          <Panel
            title="3. Live pairing status"
            subtitle="This updates automatically once the agent checks in -- no page refresh needed."
          >
            {isPaired && pairedAgent ? (
              <StateMessage
                tone="success"
                title={`Paired ✓ ${pairedAgent.name}`}
                message={`Last seen ${new Date(pairedAgent.last_seen!).toLocaleString()}`}
                action={<Badge tone="success">{pairedAgent.status}</Badge>}
              />
            ) : (
              <StateMessage
                title="Waiting for agent..."
                message="Run the install command above on the target host. This page polls automatically."
                action={
                  <Button onClick={() => void pairingQuery.refetch()}>
                    Check now
                  </Button>
                }
              />
            )}
          </Panel>
        </>
      )}
    </div>
  );
}

type AgentlessForm = {
  name: string;
  host: string;
  targetOS: TargetOS;
  credentialName: string;
  discoveryMode: string;
  installMode: string;
  credentialRef: string;
  schedule: string;
  renewalMethod: string;
  autoRenew: boolean;
  installServerType: string;
  installCertPath: string;
  installKeyPath: string;
  pluginId: string;
  pluginSettings: Record<string, string>;
};

function AgentlessSetupWizard() {
  // Switching OS must not leave behind a mode that OS cannot perform --
  // "Windows + SSH push" would submit and then fail at install time.
  function selectOS(next: TargetOS) {
    setForm((f) => {
      const installs = installOptionsFor(next).map((o) => o.value);
      const discoveries = discoveryOptionsFor(next).map((o) => o.value);
      return {
        ...f,
        targetOS: next,
        installMode: installs.includes(f.installMode) ? f.installMode : installs[0],
        discoveryMode: discoveries.includes(f.discoveryMode) ? f.discoveryMode : discoveries[0],
      };
    });
  }

  const prefill =
    typeof window !== "undefined"
      ? new URLSearchParams(window.location.search)
      : new URLSearchParams();
  const prefillHost = prefill.get("host") ?? "";
  const prefillMode = prefill.get("install_mode") ?? "";
  const [form, setForm] = useState<AgentlessForm>({
    name: prefillHost ? `${prefillHost}` : "",
    host: prefillHost,
    targetOS: prefillMode === "iis" ? "windows" : prefillMode === "keychain" ? "mac" : "linux",
    credentialName: "",
    discoveryMode: prefillMode === "iis" ? "winrm" : "network",
    installMode: prefillMode || "ssh",
    credentialRef: "",
    schedule: "",
    renewalMethod: "manual",
    autoRenew: false,
    installServerType: "nginx",
    installCertPath: "",
    installKeyPath: "",
    pluginId: "",
    pluginSettings: {},
  });
  // W20-21: only enabled plugins can drive a target.
  const pluginsQ = useQuery({
    queryKey: ["delivery-plugins"],
    queryFn: api.deliveryPlugins,
    retry: false,
    enabled: form.installMode === "plugin",
  });
  const enabledPlugins = (pluginsQ.data?.data ?? []).filter((p) => p.enabled_version);
  const chosenPlugin = enabledPlugins.find((p) => p.id === form.pluginId);
  const chosenManifest = chosenPlugin?.versions.find((v) => v.version === chosenPlugin.enabled_version)?.manifest;
  const [created, setCreated] = useState<ManagedTarget | null>(null);

  const createMutation = useMutation({
    mutationFn: () =>
      api.createTarget({
        name: form.name.trim(),
        host: form.host.trim(),
        discovery_mode: form.discoveryMode,
        install_mode: form.installMode,
        credential_ref: form.credentialRef.trim() || undefined,
        schedule: form.schedule.trim() || undefined,
        // The renewal sweep executes only targets carrying ALL of
        // auto_renew + server type + cert/key paths (renewal_scheduler.go)
        // — omitting them made every wizard-created target silently
        // non-renewing, while the handler defaulted renewal_method to
        // "acme" regardless of what was chosen.
        renewal_method: form.renewalMethod,
        auto_renew: AUTO_RENEW_MODES.has(form.installMode) ? form.autoRenew : false,
        install_server_type:
          form.installMode === "ssh" && form.autoRenew
            ? form.installServerType
            : undefined,
        install_cert_path:
          form.installMode === "ssh" && form.autoRenew
            ? form.installCertPath.trim() || undefined
            : undefined,
        install_key_path:
          form.installMode === "ssh" && form.autoRenew
            ? form.installKeyPath.trim() || undefined
            : undefined,
        plugin_id: form.installMode === "plugin" ? form.pluginId : undefined,
        plugin_settings: form.installMode === "plugin" ? form.pluginSettings : undefined,
      }),
    onSuccess: (res) => setCreated(res.data),
  });

  const set = <K extends keyof AgentlessForm>(
    key: K,
    value: AgentlessForm[K],
  ) => setForm((f) => ({ ...f, [key]: value }));

  const steps: WizardStepDef[] = [
    {
      id: "host",
      title: "Host",
      validate: () =>
        form.name.trim() && form.host.trim()
          ? null
          : "Name and host are required.",
      render: () => (
        <div className="space-y-3">
          <label className="block space-y-1 text-sm text-foreground">
            <span>Target name</span>
            <Input
              value={form.name}
              onChange={(e) => set("name", e.target.value)}
              placeholder="db-01.internal"
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Host</span>
            <Input
              value={form.host}
              onChange={(e) => set("host", e.target.value)}
              placeholder="db-01.internal.example.com"
            />
          </label>
          <fieldset className="space-y-2">
            <legend className="text-sm text-foreground">Operating system</legend>
            <p className="text-xs text-muted-foreground">
              Decides how a renewed certificate is delivered and how the host is reached.
            </p>
            {TARGET_OS_OPTIONS.map((o) => (
              <label
                key={o.value}
                className="flex cursor-pointer items-start gap-2 rounded-lg border border-border p-2.5"
              >
                <input
                  type="radio"
                  name="target-os"
                  className="mt-0.5"
                  value={o.value}
                  checked={form.targetOS === o.value}
                  onChange={() => selectOS(o.value)}
                />
                <span className="space-y-0.5">
                  <span className="block text-sm text-foreground">{o.label}</span>
                  <span className="block text-xs text-muted-foreground">{o.hint}</span>
                </span>
              </label>
            ))}
          </fieldset>
        </div>
      ),
    },
    {
      id: "discovery_mode",
      title: "Discovery",
      validate: () => null,
      render: () => (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            How should Kryptkeeper find the certificates already on this host?
          </p>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Discovery mode</span>
            <Select
              value={form.discoveryMode}
              onChange={(e) => set("discoveryMode", e.target.value)}
            >
              {discoveryOptionsFor(form.targetOS).map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </label>
        </div>
      ),
    },
    {
      id: "install_mode",
      title: "Install",
      validate: () => {
        if (form.installMode !== "plugin") return null;
        if (!form.pluginId) return "Choose an enabled delivery plugin.";
        const missing = Object.entries(chosenManifest?.target_schema ?? {})
          .filter(([k, f]) => f.required && !(form.pluginSettings[k] ?? "").trim())
          .map(([k]) => k);
        return missing.length ? `Fill in: ${missing.join(", ")}.` : null;
      },
      render: () => (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            How should a renewed certificate be delivered to this host?
          </p>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Install mode</span>
            <Select
              value={form.installMode}
              onChange={(e) => set("installMode", e.target.value)}
            >
              {installOptionsFor(form.targetOS).map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </label>
          {form.installMode === "plugin" ? (
            <div className="space-y-3 rounded-xl border border-border p-3">
              {enabledPlugins.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No delivery plugin is enabled. Install and enable one under Delivery Plugins first.
                </p>
              ) : (
                <label className="block space-y-1 text-sm text-foreground">
                  <span>Plugin</span>
                  <Select
                    value={form.pluginId}
                    onChange={(e) => setForm((f) => ({ ...f, pluginId: e.target.value, pluginSettings: {}, credentialRef: "" }))}
                  >
                    <option value="">Choose a plugin…</option>
                    {enabledPlugins.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.id} ({p.enabled_version})
                      </option>
                    ))}
                  </Select>
                </label>
              )}
              {chosenManifest ? (
                <>
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-muted-foreground">What it can do on this target</span>
                    <Badge tone={tierTone(capabilityTier(chosenManifest.capabilities ?? {}))}>
                      {tierLabel(capabilityTier(chosenManifest.capabilities ?? {}))}
                    </Badge>
                  </div>
                  <CapabilityList manifest={chosenManifest} />
                  {Object.entries(chosenManifest.target_schema ?? {}).map(([key, f]) => (
                    <label key={key} className="block space-y-1 text-sm text-foreground">
                      <span>
                        {key}
                        {f.required ? "" : " (optional)"}
                      </span>
                      <Input
                        value={form.pluginSettings[key] ?? ""}
                        placeholder={f.default}
                        onChange={(e) =>
                          setForm((prev) => ({
                            ...prev,
                            pluginSettings: { ...prev.pluginSettings, [key]: e.target.value },
                          }))
                        }
                      />
                    </label>
                  ))}
                </>
              ) : null}
            </div>
          ) : null}
        </div>
      ),
    },
    {
      id: "credential",
      title: "Credential",
      validate: () => {
        if (
          CREDENTIAL_REQUIRED_MODES.has(form.installMode) &&
          !form.credentialRef.trim()
        ) {
          return `A credential reference is required for ${form.installMode} install mode.`;
        }
        if (
          form.installMode === "ssh" &&
          form.autoRenew &&
          (!form.installCertPath.trim() || !form.installKeyPath.trim())
        ) {
          return "Auto-renew needs the certificate and key paths on the host — the sweep skips targets without them.";
        }
        if (form.installMode === "ssh" && form.autoRenew && !form.credentialRef.trim()) {
          return "Auto-renew over SSH needs a credential.";
        }
        return null;
      },
      render: () => (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            How Kryptkeeper authenticates to this target.
            {CREDENTIAL_REQUIRED_MODES.has(form.installMode)
              ? " Required for this install mode."
              : " Optional for this install mode."}
          </p>
          <CredentialPicker
            installMode={form.installMode}
            shapeOverride={form.installMode === "plugin" ? pluginCredentialShape(chosenManifest) : undefined}
            value={form.credentialRef}
            onChange={(ref, name) => {
              set("credentialRef", ref);
              set("credentialName", name ?? "");
            }}
          />
          <label className="block space-y-1 text-sm text-foreground">
            <span>Renewal schedule (optional)</span>
            <Input
              value={form.schedule}
              onChange={(e) => set("schedule", e.target.value)}
              placeholder="0 3 * * *"
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Renewal method</span>
            <Select
              value={form.renewalMethod}
              onChange={(e) => set("renewalMethod", e.target.value)}
            >
              <option value="manual">Manual</option>
              <option value="acme">ACME</option>
              <option value="est">EST</option>
              <option value="scep">SCEP</option>
            </Select>
          </label>
          {AUTO_RENEW_MODES.has(form.installMode) ? (
            <div className="space-y-3 rounded-xl border border-border p-3">
              <label className="flex items-center gap-2 text-sm text-foreground">
                <input
                  type="checkbox"
                  checked={form.autoRenew}
                  onChange={(e) => set("autoRenew", e.target.checked)}
                />
                <span>
                  {form.installMode === "keychain"
                    ? "Auto-renew — the daily sweep renews the certificate and installs it in this Mac's System keychain over SSH"
                    : form.installMode === "plugin"
                      ? "Auto-renew — the daily sweep renews the certificate and delivers it through the plugin; the hub verifies what the device serves"
                      : "Auto-renew — the daily sweep renews and pushes the certificate to this host over SSH"}
                </span>
              </label>
              {form.autoRenew && form.installMode === "ssh" ? (
                <>
                  <label className="block space-y-1 text-sm text-foreground">
                    <span>Web server</span>
                    <Select
                      value={form.installServerType}
                      onChange={(e) => set("installServerType", e.target.value)}
                    >
                      <option value="nginx">nginx</option>
                      <option value="apache">Apache</option>
                      <option value="haproxy">HAProxy</option>
                    </Select>
                  </label>
                  <label className="block space-y-1 text-sm text-foreground">
                    <span>Certificate path on the host</span>
                    <Input
                      value={form.installCertPath}
                      onChange={(e) => set("installCertPath", e.target.value)}
                      placeholder="/etc/ssl/certs/site.crt"
                    />
                  </label>
                  <label className="block space-y-1 text-sm text-foreground">
                    <span>Private key path on the host</span>
                    <Input
                      value={form.installKeyPath}
                      onChange={(e) => set("installKeyPath", e.target.value)}
                      placeholder="/etc/ssl/private/site.key"
                    />
                  </label>
                </>
              ) : null}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">
              The automatic renewal sweep executes SSH-push and macOS keychain
              targets only; this target renews via its connector or manually.
            </p>
          )}
        </div>
      ),
    },
  ];

  if (created) {
    return (
      <Panel title="Target created">
        <div className="space-y-3">
          <StateMessage
            tone="success"
            title={`${created.name} declared`}
            message={`${created.host} — discovery: ${created.discovery_mode}, install: ${created.install_mode}`}
          />
          <Button
            tone="primary"
            onClick={() => {
              setCreated(null);
              setForm({
                name: "",
                host: "",
                targetOS: "linux",
                credentialName: "",
                discoveryMode: "network",
                installMode: "ssh",
                credentialRef: "",
                schedule: "",
                renewalMethod: "manual",
                autoRenew: false,
                installServerType: "nginx",
                installCertPath: "",
                installKeyPath: "",
                pluginId: "",
                pluginSettings: {},
              });
            }}
          >
            Add another target
          </Button>
        </div>
      </Panel>
    );
  }

  return (
    <Panel>
      <Wizard
        steps={steps}
        onComplete={() => createMutation.mutateAsync().then(() => undefined)}
        summary={() => (
          <div className="space-y-2 text-sm text-foreground">
            <p>
              <span className="text-muted-foreground">Name:</span> {form.name}
            </p>
            <p>
              <span className="text-muted-foreground">Host:</span> {form.host}
            </p>
            <p>
              <span className="text-muted-foreground">Discovery:</span>{" "}
              {form.discoveryMode}
            </p>
            <p>
              <span className="text-muted-foreground">Install:</span>{" "}
              {form.installMode}
            </p>
            <p>
              <span className="text-muted-foreground">Credential:</span>{" "}
              {form.credentialName || form.credentialRef || "(none)"}
            </p>
            {createMutation.isError && (
              <p role="alert" className="text-xs text-state-over">
                {createMutation.error instanceof Error
                  ? createMutation.error.message
                  : "Failed to create the target."}
              </p>
            )}
          </div>
        )}
      />
    </Panel>
  );
}

export default function TargetSetup() {
  const [mode, setMode] = useState<Mode>("agent");

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Infrastructure"
        title="Target Setup"
        description="Bring a host under management -- deploy a lightweight agent, or go agentless and declare how the host should be discovered, renewed, and installed."
      />

      <div
        role="radiogroup"
        aria-label="Setup mode"
        className="grid gap-3 sm:grid-cols-2"
      >
        <button
          type="button"
          role="radio"
          aria-checked={mode === "agent"}
          onClick={() => setMode("agent")}
          className={`rounded-2xl border p-4 text-left transition ${
            mode === "agent"
              ? "border-primary/50 bg-primary/10"
              : "border-border bg-foreground/[0.02] hover:border-primary/40"
          }`}
        >
          <div className="font-semibold text-foreground">Agent</div>
          <p className="mt-1 text-xs text-muted-foreground">
            A lightweight agent runs on the host, discovering and auto-renewing
            certificates with no inbound access required.
          </p>
        </button>
        <button
          type="button"
          role="radio"
          aria-checked={mode === "agentless"}
          onClick={() => setMode("agentless")}
          className={`rounded-2xl border p-4 text-left transition ${
            mode === "agentless"
              ? "border-primary/50 bg-primary/10"
              : "border-border bg-foreground/[0.02] hover:border-primary/40"
          }`}
        >
          <div className="font-semibold text-foreground">Agentless</div>
          <p className="mt-1 text-xs text-muted-foreground">
            Declare a target's host and how it should be discovered, renewed,
            and installed -- no software runs on the target.
          </p>
        </button>
      </div>

      {mode === "agent" ? <AgentSetupPanel /> : <AgentlessSetupWizard />}
    </div>
  );
}
