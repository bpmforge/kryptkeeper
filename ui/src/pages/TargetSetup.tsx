import { useState } from "react";
import { scrollableProps } from "../lib/scrollable";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Check } from "lucide-react";
import {
  api,
  type CredentialMeta,
  type CertTargetBinding,
  type CredentialPreflight,
  type EffectiveSetting,
  type HostKeyProbe,
  type PrivilegeBundle,
  type ManagedTarget,
} from "../lib/api";
import { extractList, type AgentType, type CertificateRecord } from "../lib/models";
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
import { TargetPreflightPanel } from "../components/TargetPreflightPanel";
import { Wizard, type WizardStepDef } from "../components/Wizard";
import { CapabilityList } from "../components/PluginCapabilities";
import { ExternalCredentialFields, type ExternalCredentialValue } from "../components/ExternalCredentialFields";
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
  const hostModes =
    os === "windows"
      ? [
          { value: "iis", label: "IIS / HTTP.sys binding" },
          { value: "sqlserver", label: "Microsoft SQL Server (WinRM)" },
          { value: "rdp", label: "Remote Desktop listener (WinRM)" },
          { value: "exchange", label: "Microsoft Exchange (WinRM)" },
        ]
      : os === "mac"
        ? [{ value: "keychain", label: "System keychain (SSH)" }]
        : [{ value: "ssh", label: "SSH push" }];
  return [...hostModes, ...OS_NEUTRAL_INSTALL_MODES];
}

// iis, keychain and k8s need a credential for the same reason ssh and the
// appliances do: something has to authenticate to the target.
const CREDENTIAL_REQUIRED_MODES = new Set(["ssh", "keychain", "iis", "sqlserver", "rdp", "exchange", "f5", "citrix", "k8s", "plugin"]);

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
      { key: "base_url", label: "WinRM endpoint (https :5986 = local admin; http :5985 = NTLM, domain account allowed)", placeholder: "https://host.corp.example.com:5986/wsman" },
      { key: "username", label: "Username", placeholder: "CORP\\svc-pki" },
      { key: "password", label: "Password", secret: true },
      { key: "ipport", label: "HTTPS binding (ip:port)", placeholder: "0.0.0.0:443" },
    ],
  },
  sqlserver: {
    type: "windows_password",
    fields: [
      { key: "base_url", label: "WinRM endpoint (https :5986 = local admin; http :5985 = NTLM, domain account allowed)", placeholder: "https://host.corp.example.com:5986/wsman" },
      { key: "username", label: "Username (local administrator)", placeholder: "CORP\\svc-pki" },
      { key: "password", label: "Password", secret: true },
      { key: "sql_instance", label: "Instance name (blank = MSSQLSERVER)", placeholder: "MSSQLSERVER" },
      { key: "sql_port", label: "Instance TCP port (blank = 1433)", placeholder: "1433" },
    ],
  },
  rdp: {
    type: "windows_password",
    fields: [
      { key: "base_url", label: "WinRM endpoint (https :5986 = local admin; http :5985 = NTLM, domain account allowed)", placeholder: "https://host.corp.example.com:5986/wsman" },
      { key: "username", label: "Username (local administrator)", placeholder: "CORP\\svc-pki" },
      { key: "password", label: "Password", secret: true },
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

// W34-14 (D-209): how the SSH account is elevated on a Linux target. One-line
// consequences follow docs/board/specs/W34-00-DESIGN.md section 3.3.
type PrivilegeMode = "none" | "nopasswd" | "password" | "helper";

const PRIVILEGE_MODES: { value: PrivilegeMode; label: string; consequence: string }[] = [
  {
    value: "helper",
    label: "Helper (recommended)",
    consequence:
      "One sudoers line grants a hash-pinned helper; the key can do only the helper's verbs (list, stat, read-cert, install, reload).",
  },
  {
    value: "nopasswd",
    label: "Raw sudo allowlist",
    consequence:
      "The sudoers drop-in lists find, stat, cat, ss, install and reload commands; with path globs that is effectively root read/write for anyone holding the key.",
  },
  {
    value: "password",
    label: "Sudo password",
    consequence:
      "The password is stored encrypted and never returned; the account is root while it is valid, and rotating it breaks scans until updated.",
  },
  {
    value: "none",
    label: "None",
    consequence:
      "Read-only scan of world-readable certificates; privileged paths are reported as INSUFFICIENT_PRIVILEGE and cannot be renewed.",
  },
];

function isPrivilegeMode(v: string | undefined): v is PrivilegeMode {
  return v === "none" || v === "nopasswd" || v === "password" || v === "helper";
}

// The preselected mode is an operator setting (agentless.default_privilege_mode);
// helper when it is unset or unreadable. Any mode stays selectable per credential.
function defaultPrivilegeMode(settings: EffectiveSetting[] | undefined): PrivilegeMode {
  const v = settings?.find((s) => s.key === "agentless.default_privilege_mode")?.value?.trim();
  return isPrivilegeMode(v) ? v : "helper";
}

function downloadText(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// Sudoers drop-in, helper (with the hash to verify) and the checklist for the
// host owner (W34-16). Served by the hub, so the hash always matches the helper.
function PrivilegeBundlePanel({ bundle }: { bundle: PrivilegeBundle }) {
  return (
    <div className="space-y-2 rounded-lg border border-border p-3" data-testid="privilege-bundle">
      <div className="flex flex-wrap gap-2">
        <Button tone="secondary" onClick={() => downloadText(`kryptkeeper-${bundle.user}.sudoers`, bundle.sudoers)}>
          Download sudoers
        </Button>
        {bundle.helper ? (
          <Button tone="secondary" onClick={() => downloadText("kryptkeeper-helper", bundle.helper ?? "")}>
            Download helper
          </Button>
        ) : null}
      </div>
      {bundle.helper_sha256 ? (
        <p className="text-xs text-muted-foreground">
          Helper sha256 (verify on the host): <code className="font-mono break-all">{bundle.helper_sha256}</code>
        </p>
      ) : null}
      {bundle.warnings.map((w) => (
        <p key={w} className="text-xs text-state-over" role="note">
          {w}
        </p>
      ))}
      <ol className="list-decimal space-y-1 pl-5 text-xs text-muted-foreground">
        {bundle.checklist.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ol>
    </div>
  );
}

function PrivilegeModeFields({
  mode,
  onMode,
  password,
  onPassword,
  sha,
  onSha,
  bundle,
  external,
}: {
  bundle?: PrivilegeBundle;
  // W38-07: with an external credential the sudo password is fetched with the
  // rest of the secret, so there is nothing to type here.
  external?: boolean;
  mode: PrivilegeMode;
  onMode: (m: PrivilegeMode) => void;
  password: string;
  onPassword: (v: string) => void;
  sha: string;
  onSha: (v: string) => void;
}) {
  return (
    <fieldset className="space-y-2 text-sm text-foreground">
      <legend className="font-medium">Privilege on the target</legend>
      {PRIVILEGE_MODES.map((m) => (
        <label key={m.value} className="flex items-start gap-2">
          <input
            type="radio"
            name="sudo_mode"
            value={m.value}
            checked={mode === m.value}
            onChange={() => onMode(m.value)}
            className="mt-1"
          />
          <span>
            <span className="block">{m.label}</span>
            <span className="block text-xs text-muted-foreground">{m.consequence}</span>
          </span>
        </label>
      ))}
      {mode === "password" && external && (
        <p className="text-xs text-muted-foreground">
          The secret in the manager must also hold the sudo password as a field named sudo_password.
        </p>
      )}
      {mode === "password" && !external && (
        <label className="block space-y-1">
          <span>Sudo password</span>
          <Input
            type="password"
            value={password}
            onChange={(e) => onPassword(e.target.value)}
            autoComplete="off"
          />
        </label>
      )}
      {mode === "helper" && (
        <label className="block space-y-1">
          <span>Helper SHA-256</span>
          <Input
            value={sha}
            onChange={(e) => onSha(e.target.value)}
            placeholder="64 hex characters from the privilege bundle"
            spellCheck={false}
          />
        </label>
      )}
      {mode !== "none" && bundle && <PrivilegeBundlePanel bundle={bundle} />}
    </fieldset>
  );
}

function CredentialPicker({
  installMode,
  value,
  onChange,
  shapeOverride,
  bundleHints,
}: {
  bundleHints?: { serverType?: string; certPath?: string; keyPath?: string };
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
  // W38-07: "local" stores the secret here, encrypted; "external" stores only
  // a reference to a secret manager and fetches the secret at each use.
  const [home, setHome] = useState<"local" | "external">("local");
  const [ext, setExt] = useState<ExternalCredentialValue>({ sourceId: "", reference: {}, fixed: {}, valid: false });

  const listQ = useQuery({ queryKey: ["credentials"], queryFn: api.credentials });
  const allItems: CredentialMeta[] = listQ.data?.data?.items ?? [];
  const shape = shapeOverride ?? CREDENTIAL_SHAPES[installMode];
  // Only credentials of the kind this install mode consumes: offering e.g. a
  // Jira api_token for SSH blocks Next on a credential the executor refuses.
  const items = shape ? allItems.filter((c) => c.credential_type === shape.type) : allItems;

  // Only Linux (ssh) targets elevate with sudo; the macOS keychain path does not.
  const hasPrivilege = shape?.type === "ssh_key" && installMode === "ssh";
  const configQ = useQuery({ queryKey: ["runtime-config"], queryFn: api.runtimeConfig, enabled: hasPrivilege });
  const [pickedMode, setPickedMode] = useState<PrivilegeMode | null>(null);
  const [sudoPassword, setSudoPassword] = useState("");
  const [helperSha, setHelperSha] = useState("");
  const privilegeMode = pickedMode ?? defaultPrivilegeMode(configQ.data?.data);
  const bundleQ = useQuery({
    queryKey: ["privilege-bundle", privilegeMode, bundleHints?.serverType, bundleHints?.certPath, bundleHints?.keyPath],
    queryFn: () =>
      api.privilegeBundle({
        mode: privilegeMode,
        serverType: bundleHints?.serverType,
        certPath: bundleHints?.certPath,
        keyPath: bundleHints?.keyPath,
      }),
    enabled: hasPrivilege && creating && privilegeMode !== "none",
  });
  const bundle = privilegeMode === "none" ? undefined : bundleQ.data?.data;
  // Prefilled from the hub's own helper so the pin cannot be mistyped; the
  // operator may still overwrite it (for example with a site-built helper).
  const effectiveHelperSha = helperSha || (privilegeMode === "helper" ? (bundle?.helper_sha256 ?? "") : "");
  const privilegeInvalid =
    hasPrivilege &&
    ((privilegeMode === "password" && sudoPassword === "" && home === "local") ||
      (privilegeMode === "helper" && !/^[0-9a-fA-F]{64}$/.test(effectiveHelperSha.trim())));

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
      home === "external"
        ? api.createCredential({
            name: name.trim(),
            credential_type: shape.type,
            source: "external",
            source_id: ext.sourceId,
            reference: ext.reference,
            static: {
              ...ext.fixed,
              ...(hasPrivilege ? { sudo_mode: privilegeMode } : {}),
              ...(hasPrivilege && privilegeMode === "helper" ? { helper_sha256: effectiveHelperSha.trim() } : {}),
            },
          })
        : api.createCredential({
        name: name.trim(),
        credential_type: shape.type,
        payload: hasPrivilege
          ? {
              ...fields,
              sudo_mode: privilegeMode,
              ...(privilegeMode === "password" ? { sudo_password: sudoPassword } : {}),
              ...(privilegeMode === "helper" ? { helper_sha256: effectiveHelperSha.trim() } : {}),
            }
          : fields,
      }),
    onSuccess: (res) => {
      setCreating(false);
      setHome("local");
      setName("");
      setFields({});
      setPickedMode(null);
      setSudoPassword("");
      setHelperSha("");
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
                  {(installMode === "iis" || installMode === "exchange") && !verdict.can_install
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
          <fieldset className="space-y-1 text-sm text-foreground">
            <legend className="font-medium">Where does the secret live?</legend>
            <label className="flex items-start gap-2">
              <input type="radio" name="secret_home" checked={home === "local"} onChange={() => setHome("local")} className="mt-1" />
              <span>Store it here (encrypted, never read back)</span>
            </label>
            <label className="flex items-start gap-2">
              <input type="radio" name="secret_home" checked={home === "external"} onChange={() => setHome("external")} className="mt-1" />
              <span>Fetch it from a secret manager (Vault, OpenBao, CyberArk, Delinea) at each use</span>
            </label>
          </fieldset>
          {home === "external" && (
            <ExternalCredentialFields
              credentialType={shape.type}
              fields={shape.fields.map((f) => ({ key: f.key, label: f.label, secret: f.secret }))}
              onChange={setExt}
            />
          )}
          {home === "local" && shape.fields.map((f) => (
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
          {hasPrivilege && (
            <PrivilegeModeFields
              mode={privilegeMode}
              onMode={setPickedMode}
              password={sudoPassword}
              onPassword={setSudoPassword}
              sha={effectiveHelperSha}
              onSha={setHelperSha}
              bundle={bundle}
              external={home === "external"}
            />
          )}
          <p className="text-xs text-muted-foreground">
            {home === "external"
              ? "No secret is stored in Kryptkeeper: only the source and this reference. The secret is fetched, used and dropped each time."
              : "Stored encrypted. It can be used and deleted, never read back."}
          </p>
          {error && <p className="text-sm text-state-over">{error}</p>}
          <Button
            tone="primary"
            disabled={createM.isPending || !name.trim() || privilegeInvalid || (home === "external" && !ext.valid)}
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

// Pairing window: an agent registered up to this long before the mint click
// (clock skew between browser and hub) still counts as the one we minted for.
const MINT_SKEW_MS = 2000;

function AgentSetupPanel() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [type, setType] = useState<AgentType>("linux");
  const [copied, setCopied] = useState(false);
  // The minted token lives in component state only: it is shown once and is
  // never written to storage, the URL or the query cache.
  const [minted, setMinted] = useState<{
    id: string;
    token: string;
    expires_at: string;
    name: string;
    type: AgentType;
    at: number;
  } | null>(null);

  const mintMutation = useMutation({
    mutationFn: () => api.mintAgentEnrollmentToken({ label: name.trim() }),
    onSuccess: (res) => {
      setMinted({
        ...res.data,
        name: name.trim(),
        type,
        at: Date.now(),
      });
      void queryClient.invalidateQueries({ queryKey: ["agent-enrollment-tokens"] });
    },
  });

  const isPairedAgent = (a: {
    name: string;
    registered_at: string;
    last_seen?: string | null;
  }) =>
    !!minted &&
    a.name === minted.name &&
    Date.parse(a.registered_at) >= minted.at - MINT_SKEW_MS &&
    !!a.last_seen;

  const pairingQuery = useQuery({
    queryKey: ["target-setup-agent-pairing", minted?.id],
    queryFn: () => api.agents(),
    enabled: !!minted,
    refetchInterval: (query) =>
      query.state.data?.agents.some(isPairedAgent) ? false : 3000,
  });

  const pairedAgent = minted
    ? pairingQuery.data?.agents.find(isPairedAgent)
    : undefined;
  const isPaired = !!pairedAgent;

  const tokensQuery = useQuery({
    queryKey: ["agent-enrollment-tokens"],
    // Expiry is judged when the list is fetched (not during render).
    queryFn: async () => {
      const res = await api.agentEnrollmentTokens();
      const now = Date.now();
      return (res.data ?? []).filter(
        (t) =>
          !t.redeemed_at && !t.revoked_at && Date.parse(t.expires_at) > now,
      );
    },
    retry: false,
  });
  const revokeMutation = useMutation({
    mutationFn: (id: string) => api.revokeAgentEnrollmentToken(id),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["agent-enrollment-tokens"] }),
  });
  const activeTokens = tokensQuery.data ?? [];

  const installCommand = minted
    ? `KRYPTKEEPER_HUB_URL=${hubURL()} \\
KRYPTKEEPER_AGENT_NAME=${minted.name} \\
KRYPTKEEPER_AGENT_TYPE=${minted.type} \\
KRYPTKEEPER_ENROLL_TOKEN=${minted.token} \\
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
        subtitle="A single-use token lets one agent register itself. It expires in 24 hours and is never reusable across hosts."
      >
        <div className="space-y-3">
          <label className="block space-y-1 text-sm text-foreground">
            <span>Agent name</span>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="web-01.prod"
              disabled={!!minted}
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Host type</span>
            <Select
              value={type}
              onChange={(e) => setType(e.target.value as AgentType)}
              disabled={!!minted}
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
            onClick={() => mintMutation.mutate()}
            disabled={mintMutation.isPending || !!minted || !name.trim()}
          >
            {minted ? "Token generated" : "Generate token"}
          </Button>
          {mintMutation.isError && (
            <p role="alert" className="text-xs text-state-over">
              {mintMutation.error instanceof Error
                ? mintMutation.error.message
                : "Failed to generate a token."}
            </p>
          )}
        </div>
      </Panel>

      {minted && (
        <>
          <Panel
            title="2. Install the agent"
            subtitle="Run this on the target host. The agent exchanges the token for its own credential on first start."
          >
            <div className="space-y-3">
              <p role="status" className="text-sm font-medium text-state-attn">
                Copy this now: you will not see this token again.
              </p>
              {isPaired ? (
                <p className="text-sm text-muted-foreground">
                  The token has been used and is no longer shown.
                </p>
              ) : (
                <>
                  <pre className="overflow-x-auto rounded-xl bg-card p-4 text-xs text-foreground" {...scrollableProps}>
                    {installCommand}
                  </pre>
                  <p className="text-xs text-muted-foreground">
                    Token expires {new Date(minted.expires_at).toLocaleString()}{" "}
                    and works once.
                  </p>
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
                </>
              )}
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

      {activeTokens.length > 0 && (
        <Panel
          title="Unused enrollment tokens"
          subtitle="Revoke a token you no longer need; a revoked token can never register an agent."
        >
          <ul className="space-y-2">
            {activeTokens.map((t) => (
              <li
                key={t.id}
                className="flex items-center justify-between gap-3 text-sm"
              >
                <span>
                  {t.label || "unnamed"}
                  {t.expires_at && (
                    <span className="text-muted-foreground">
                      {" "}
                      - expires {new Date(t.expires_at).toLocaleString()}
                    </span>
                  )}
                </span>
                <Button
                  onClick={() => revokeMutation.mutate(t.id)}
                  disabled={revokeMutation.isPending}
                  aria-label={`Revoke token ${t.label || t.id}`}
                >
                  Revoke
                </Button>
              </li>
            ))}
          </ul>
          {revokeMutation.isError && (
            <p role="alert" className="text-xs text-state-over">
              {revokeMutation.error instanceof Error
                ? revokeMutation.error.message
                : "Failed to revoke the token."}
            </p>
          )}
        </Panel>
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
  // W24-09/W24-10: the pinned SSH host key and the operator's explicit
  // confirmation of its fingerprint. A changed host invalidates both.
  sshHostKey: string;
  hostKeyConfirmed: boolean;
};

// BindCertificatesPanel (W27-05): after a target exists, authorize which
// certificates the renewal scheduler may renew onto it. Bind failures are
// shown per certificate; they never undo the target.
function BindCertificatesPanel({
  target,
  initialError,
}: {
  target: ManagedTarget;
  initialError: string | null;
}) {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<string[]>([]);
  const [errors, setErrors] = useState<{ fp: string; message: string }[]>(
    initialError ? [{ fp: "handed-off certificate", message: initialError }] : [],
  );

  const bindingsQ = useQuery({
    queryKey: ["target-bindings", target.id],
    queryFn: () => api.certTargetBindings(target.id),
    retry: false,
  });
  const certsQ = useQuery({
    queryKey: ["certificates", "bindable"],
    queryFn: () => api.certificates({ limit: 200 }),
    retry: false,
  });
  const bindings: CertTargetBinding[] = bindingsQ.data?.data ?? [];
  const certs = extractList<CertificateRecord>(certsQ.data?.data, ["items"]);
  const nameByFp = new Map(certs.map((c) => [c.fingerprint_sha256, c.common_name]));
  const boundFps = new Set(bindings.map((b) => b.cert_fingerprint));
  const candidates = certs.filter((c) => !boundFps.has(c.fingerprint_sha256));

  const bindMutation = useMutation({
    mutationFn: async (fps: string[]) => {
      const failed: { fp: string; message: string }[] = [];
      for (const fp of fps) {
        try {
          await api.bindCertToTarget(target.id, fp);
        } catch (e) {
          failed.push({
            fp: nameByFp.get(fp) || fp,
            message: e instanceof Error ? e.message : "Binding failed.",
          });
        }
      }
      return failed;
    },
    onSuccess: (failed) => {
      setErrors(failed);
      setSelected([]);
      void queryClient.invalidateQueries({ queryKey: ["target-bindings", target.id] });
    },
  });

  const unbindMutation = useMutation({
    mutationFn: (fp: string) => api.unbindCertFromTarget(target.id, fp),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["target-bindings", target.id] }),
    onError: (e) =>
      setErrors([{ fp: "unbind", message: e instanceof Error ? e.message : "Unbind failed." }]),
  });

  return (
    <section aria-label="Bind certificates" className="space-y-3 rounded-xl border border-border p-3">
      <h3 className="text-sm font-medium text-foreground">Bind certificates</h3>
      <p className="text-xs text-muted-foreground">
        Only bound certificates are auto-renewed onto this target. A wildcard
        certificate can be bound to several targets.
      </p>
      {candidates.length > 0 ? (
        <fieldset className="space-y-1">
          <legend className="text-sm text-foreground">Certificates to bind</legend>
          {candidates.map((c) => (
            <label key={c.fingerprint_sha256} className="flex items-center gap-2 text-sm text-foreground">
              <input
                type="checkbox"
                checked={selected.includes(c.fingerprint_sha256)}
                onChange={() =>
                  setSelected((cur) =>
                    cur.includes(c.fingerprint_sha256)
                      ? cur.filter((x) => x !== c.fingerprint_sha256)
                      : [...cur, c.fingerprint_sha256],
                  )
                }
              />
              <span>{c.common_name || c.fingerprint_sha256}</span>
            </label>
          ))}
        </fieldset>
      ) : (
        <p className="text-xs text-muted-foreground">No further certificates available to bind.</p>
      )}
      <Button
        tone="primary"
        disabled={selected.length === 0 || bindMutation.isPending}
        onClick={() => bindMutation.mutate(selected)}
      >
        {bindMutation.isPending ? "Binding…" : "Bind selected"}
      </Button>
      {errors.length > 0 ? (
        <ul className="space-y-1 text-xs text-state-over" role="alert">
          {errors.map((e) => (
            <li key={e.fp + e.message}>
              {e.fp}: {e.message}
            </li>
          ))}
        </ul>
      ) : null}
      <div>
        <h4 className="text-sm text-foreground">Bound certificates</h4>
        {bindings.length === 0 ? (
          <p className="text-xs text-muted-foreground">None bound yet.</p>
        ) : (
          <ul aria-label="Bound certificates" className="space-y-1">
            {bindings.map((b) => {
              const name = nameByFp.get(b.cert_fingerprint) || b.cert_fingerprint;
              return (
                <li key={b.cert_fingerprint} className="flex items-center gap-2 text-sm text-foreground">
                  <span>{name}</span>
                  <code className="text-xs text-muted-foreground">{b.cert_fingerprint.slice(0, 16)}</code>
                  <Button
                    tone="secondary"
                    aria-label={`Unbind ${name}`}
                    disabled={unbindMutation.isPending}
                    onClick={() => unbindMutation.mutate(b.cert_fingerprint)}
                  >
                    Unbind
                  </Button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </section>
  );
}

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
        sshHostKey: "",
        hostKeyConfirmed: false,
      };
    });
    setProbe(null);
  }

  const prefill =
    typeof window !== "undefined"
      ? new URLSearchParams(window.location.search)
      : new URLSearchParams();
  const prefillHost = prefill.get("host") ?? "";
  const prefillMode = prefill.get("install_mode") ?? "";
  // Fingerprint of the certificate a takeover handed off (W27-13); shown
  // read-only here.
  const prefillCertificate = prefill.get("certificate") ?? "";
  const [form, setForm] = useState<AgentlessForm>({
    name: prefillHost ? `${prefillHost}` : "",
    host: prefillHost,
    targetOS: prefillMode === "iis" || prefillMode === "exchange" ? "windows" : prefillMode === "keychain" ? "mac" : "linux",
    credentialName: "",
    discoveryMode: prefillMode === "iis" || prefillMode === "exchange" ? "winrm" : "network",
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
    sshHostKey: "",
    hostKeyConfirmed: false,
  });
  const [probe, setProbe] = useState<HostKeyProbe | null>(null);
  const needsHostKey = form.installMode === "ssh" || form.installMode === "keychain";
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
  // A failed bind of the handed-off certificate must not fail the create:
  // the target exists, so the error is surfaced in the bind panel instead.
  const [handoffBindError, setHandoffBindError] = useState<string | null>(null);

  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await api.createTarget({
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
        ssh_host_key: needsHostKey ? form.sshHostKey : undefined,
      });
      let bindError: string | null = null;
      if (prefillCertificate) {
        try {
          await api.bindCertToTarget(res.data.id, prefillCertificate);
        } catch (e) {
          bindError = e instanceof Error ? e.message : "Binding failed.";
        }
      }
      return { target: res.data, bindError };
    },
    onSuccess: ({ target, bindError }) => {
      setHandoffBindError(bindError);
      setCreated(target);
    },
  });

  const probeM = useMutation({
    mutationFn: () => api.probeTargetHostKey({ host: form.host.trim() }),
    onSuccess: (r) => {
      setProbe(r.data);
      setForm((f) => ({
        ...f,
        sshHostKey: r.data.ssh_host_key,
        hostKeyConfirmed: false,
      }));
    },
  });

  const set = <K extends keyof AgentlessForm>(
    key: K,
    value: AgentlessForm[K],
  ) => {
    if (key === "host" || key === "installMode") {
      // A changed host (or mode) invalidates any fetched key and its confirmation.
      setProbe(null);
      probeM.reset();
      setForm((f) => ({
        ...f,
        [key]: value,
        sshHostKey: "",
        hostKeyConfirmed: false,
      }));
      return;
    }
    setForm((f) => ({ ...f, [key]: value }));
  };

  const allSteps: WizardStepDef[] = [
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
          {prefillCertificate ? (
            <label className="block space-y-1 text-sm text-foreground">
              <span>Certificate</span>
              <Input
                aria-label="Certificate"
                value={prefillCertificate}
                readOnly
                className="font-mono"
              />
            </label>
          ) : null}
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
            bundleHints={{
              serverType: form.autoRenew ? form.installServerType : undefined,
              certPath: form.autoRenew ? form.installCertPath.trim() : undefined,
              keyPath: form.autoRenew ? form.installKeyPath.trim() : undefined,
            }}
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
    {
      id: "hostkey",
      title: "Host key",
      validate: () => {
        if (!form.sshHostKey) return "Fetch the host key first.";
        if (!form.hostKeyConfirmed) {
          return "Confirm the fingerprint before saving.";
        }
        return null;
      },
      render: () => (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Pin this host's SSH key so later connections to {form.host.trim() || "the host"} are
            refused if it changes. Fetch the key, then verify the fingerprint out of band.
          </p>
          <Button
            onClick={() => probeM.mutate()}
            disabled={!form.host.trim() || probeM.isPending}
          >
            {probeM.isPending ? "Fetching..." : "Fetch host key"}
          </Button>
          {probeM.isError ? (
            <StateMessage
              tone="error"
              title="Host key fetch failed"
              message={
                probeM.error instanceof Error
                  ? probeM.error.message
                  : "Could not reach the host."
              }
            />
          ) : null}
          {probe ? (
            <div className="space-y-2 rounded-xl border border-border p-3 text-sm text-foreground">
              <p>
                <span className="text-muted-foreground">Algorithm:</span>{" "}
                {probe.algorithm}
              </p>
              <p>
                <span className="text-muted-foreground">SHA-256 fingerprint:</span>{" "}
                <code aria-label="Host key fingerprint">{probe.fingerprint_sha256}</code>
              </p>
              <p className="text-xs text-muted-foreground">
                Compare with{" "}
                <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code> on the host.
              </p>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={form.hostKeyConfirmed}
                  onChange={(e) => set("hostKeyConfirmed", e.target.checked)}
                />
                <span>I have verified this fingerprint</span>
              </label>
            </div>
          ) : null}
        </div>
      ),
    },
  ];
  const steps = allSteps.filter((st) => st.id !== "hostkey" || needsHostKey);

  if (created) {
    return (
      <Panel title="Target created">
        <div className="space-y-3">
          <StateMessage
            tone="success"
            title={`${created.name} declared`}
            message={`${created.host} — discovery: ${created.discovery_mode}, install: ${created.install_mode}`}
          />
          {created.ssh_host_key_fingerprint ? (
            <p className="text-sm text-foreground">
              <span className="text-muted-foreground">Pinned host key:</span>{" "}
              <code>{created.ssh_host_key_fingerprint}</code>
            </p>
          ) : null}
          {created.install_mode === "ssh" && created.credential_ref ? (
            <TargetPreflightPanel targetId={created.id} />
          ) : null}
          <BindCertificatesPanel
            target={created}
            initialError={handoffBindError}
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
                sshHostKey: "",
                hostKeyConfirmed: false,
              });
              setProbe(null);
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
          aria-labelledby="setup-mode-agent-title"
          aria-describedby="setup-mode-agent-desc"
          onClick={() => setMode("agent")}
          className={`rounded-2xl border p-4 text-left transition ${
            mode === "agent"
              ? "border-primary/50 bg-primary/10"
              : "border-border bg-foreground/[0.02] hover:border-primary/40"
          }`}
        >
          <div id="setup-mode-agent-title" className="font-semibold text-foreground">Agent</div>
          <p id="setup-mode-agent-desc" className="mt-1 text-xs text-muted-foreground">
            A lightweight agent runs on the host, discovering and auto-renewing
            certificates with no inbound access required.
          </p>
        </button>
        <button
          type="button"
          role="radio"
          aria-checked={mode === "agentless"}
          aria-labelledby="setup-mode-agentless-title"
          aria-describedby="setup-mode-agentless-desc"
          onClick={() => setMode("agentless")}
          className={`rounded-2xl border p-4 text-left transition ${
            mode === "agentless"
              ? "border-primary/50 bg-primary/10"
              : "border-border bg-foreground/[0.02] hover:border-primary/40"
          }`}
        >
          <div id="setup-mode-agentless-title" className="font-semibold text-foreground">Agentless</div>
          <p id="setup-mode-agentless-desc" className="mt-1 text-xs text-muted-foreground">
            Declare a target's host and how it should be discovered, renewed,
            and installed -- no software runs on the target.
          </p>
        </button>
      </div>

      {mode === "agent" ? <AgentSetupPanel /> : <AgentlessSetupWizard />}
    </div>
  );
}
