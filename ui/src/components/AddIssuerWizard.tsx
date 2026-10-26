import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import { ACME_PRESETS } from "../lib/acmePresets";
import {
  ISSUER_TYPES,
  buildConfig,
  configDefaults,
  fieldVisible,
  missingRequired,
  type IssuerField,
  type IssuerType,
} from "../lib/issuerTypes";
import { enabledDNS01Plugins } from "../lib/plugins";
import { Badge, Dialog, Input, Select, Textarea } from "./ui";
import { Wizard } from "./Wizard";

type Values = Record<string, string>;

function FieldInput({
  field,
  value,
  onChange,
  secret = false,
  choices,
}: {
  field: IssuerField;
  value: string;
  onChange: (v: string) => void;
  secret?: boolean;
  // Options for a select that takes them from the hub (field.optionsFrom).
  choices?: { value: string; label: string }[];
}) {
  const label = field.required ? field.label : `${field.label} (optional)`;
  return (
    <label className="block space-y-1 text-xs text-muted-foreground">
      <span>{label}</span>
      {field.kind === "textarea" ? (
        <Textarea
          rows={4}
          className="font-mono"
          value={value}
          placeholder={field.placeholder}
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => onChange(e.target.value)}
        />
      ) : field.kind === "select" ? (
        <Select value={value} onChange={(e) => onChange(e.target.value)}>
          {field.optionsFrom ? (
            <>
              <option value="">Choose one</option>
              {(choices ?? []).map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </>
          ) : (
            (field.options ?? []).map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))
          )}
        </Select>
      ) : (
        <Input
          type={
            secret ? "password" : field.kind === "number" ? "number" : "text"
          }
          value={value}
          placeholder={field.placeholder}
          autoComplete={secret ? "new-password" : "off"}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
      {field.help && <span className="block text-[11px]">{field.help}</span>}
    </label>
  );
}

export function AddIssuerWizard({
  open,
  onClose,
  onDone,
}: {
  open: boolean;
  onClose: () => void;
  // Called once the connector exists, even if the wizard is closed early.
  onDone: () => void;
}) {
  const [typeId, setTypeId] = useState<string>("");
  const [name, setName] = useState("");
  const [config, setConfig] = useState<Values>({});
  const [modeId, setModeId] = useState("");
  const [secrets, setSecrets] = useState<Values>({});
  const [credentialRef, setCredentialRef] = useState<string | undefined>();
  const [connectorId, setConnectorId] = useState<string | undefined>();
  const [probe, setProbe] = useState<{
    status: string;
    detail?: string;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [stepError, setStepError] = useState<string | null>(null);
  const [caName, setCaName] = useState("");
  const [trustPem, setTrustPem] = useState("");
  // Enabled DNS-01 plugins and the api_token credentials a plugin can read,
  // loaded only when the ACME DNS provider is "plugin".
  const [hubChoices, setHubChoices] = useState<
    Record<"dns01-plugins" | "plugin-credentials", { value: string; label: string }[]>
  >({ "dns01-plugins": [], "plugin-credentials": [] });

  const type: IssuerType | undefined = ISSUER_TYPES.find(
    (t) => t.id === typeId,
  );
  const modes = useMemo(
    () => (type ? type.secrets(config) : []),
    [type, config],
  );
  const mode = modes.find((m) => m.id === modeId) ?? modes[0];
  const visibleSecretFields = mode?.fields ?? [];

  const wantsPlugins =
    typeId === "acme" &&
    config.challenge === "dns-01" &&
    config.dns_provider === "plugin";
  useEffect(() => {
    if (!wantsPlugins) return;
    let cancelled = false;
    void Promise.all([api.deliveryPlugins(), api.credentials()])
      .then(([plugins, creds]) => {
        if (cancelled) return;
        setHubChoices({
          "dns01-plugins": enabledDNS01Plugins(plugins.data).map((id) => ({ value: id, label: id })),
          "plugin-credentials": creds.data.items
            .filter((c) => c.credential_type === "api_token")
            .map((c) => ({ value: c.id, label: `${c.name} (${c.id})` })),
        });
      })
      .catch(() => {
        if (!cancelled) setStepError("Could not load the plugins and credentials.");
      });
    return () => {
      cancelled = true;
    };
  }, [wantsPlugins]);

  const pickType = (t: IssuerType) => {
    setTypeId(t.id);
    setConfig(configDefaults(t));
    setModeId("");
    setSecrets({});
  };

  const setCfg = (k: string, v: string) => setConfig((c) => ({ ...c, [k]: v }));

  const hasSecret = visibleSecretFields.some(
    (f) => (secrets[f.key] ?? "").trim() !== "",
  );

  const runTest = async () => {
    if (!type) return;
    setBusy(true);
    setStepError(null);
    try {
      let ref = credentialRef;
      if (!ref && hasSecret) {
        const payload: Record<string, unknown> = {};
        for (const f of visibleSecretFields) {
          const v = (secrets[f.key] ?? "").trim();
          if (!v) continue;
          if (f.nestUnder) {
            const group = (payload[f.nestUnder] ??= {}) as Record<string, unknown>;
            // The delegated provider's accounts map is JSON, not a string.
            group[f.key] = f.key === "accounts" ? JSON.parse(v) : v;
          } else {
            payload[f.key] = v;
          }
        }
        const cred = await api.createCredential({
          name: `${name.trim()} credential`,
          credential_type: type.credentialType,
          payload,
        });
        ref = cred.data.id;
        setCredentialRef(ref);
        // Write-only: the secret leaves the browser's state as soon as it is stored.
        setSecrets({});
      }
      let id = connectorId;
      if (!id) {
        const created = await api.createConnector({
          name: name.trim(),
          type: type.id,
          config_json: JSON.stringify(buildConfig(type, config)),
          credential_ref: ref,
        });
        id = created.data.id;
        setConnectorId(id);
        onDone();
      }
      setProbe(await api.testConnector(id));
    } catch (e) {
      setStepError(
        e instanceof Error ? e.message : "Could not test the connection.",
      );
    } finally {
      setBusy(false);
    }
  };

  const complete = async () => {
    if (connectorId && caName.trim() && trustPem.trim()) {
      try {
        await api.createExternalCa({
          name: caName.trim(),
          connector_id: connectorId,
          trust_pem: trustPem.trim(),
        });
        onDone();
      } catch (e) {
        setStepError(
          e instanceof Error ? e.message : "Could not create the CA.",
        );
        return;
      }
    }
    onClose();
  };

  const steps = [
    {
      id: "type",
      title: "Pick type",
      validate: () => (type ? null : "Pick an issuer type."),
      render: () => (
        <fieldset className="space-y-2">
          <legend className="sr-only">Issuer type</legend>
          <div className="grid gap-2 sm:grid-cols-2">
            {ISSUER_TYPES.map((t) => (
              <label
                key={t.id}
                className={`flex cursor-pointer gap-2 rounded-xl border p-3 text-sm focus-within:ring-2 focus-within:ring-ring/60 ${
                  typeId === t.id
                    ? "border-primary/60 bg-primary/10"
                    : "border-border"
                }`}
              >
                <input
                  type="radio"
                  name="issuer-type"
                  className="mt-1"
                  checked={typeId === t.id}
                  disabled={!!connectorId}
                  onChange={() => pickType(t)}
                />
                <span>
                  <span className="block font-medium text-foreground">
                    {t.label}
                  </span>
                  <span className="block text-xs text-muted-foreground">
                    {t.description}
                  </span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
      ),
    },
    {
      id: "settings",
      title: "Settings",
      validate: () => {
        if (!name.trim()) return "Issuer name is required.";
        return type ? missingRequired(type.config, config) : null;
      },
      render: () => (
        <div className="space-y-3">
          {connectorId && (
            <p className="text-xs text-muted-foreground">
              The issuer is already saved. Delete it from the list to change
              these settings.
            </p>
          )}
          <fieldset disabled={!!connectorId} className="space-y-3">
            <label className="block space-y-1 text-xs text-muted-foreground">
              <span>Issuer name</span>
              <Input value={name} onChange={(e) => setName(e.target.value)} />
            </label>
            {type?.id === "acme" && (
              <label className="block space-y-1 text-xs text-muted-foreground">
                <span>Preset (optional)</span>
                <Select
                  value={
                    ACME_PRESETS.find(
                      (p) => p.directoryUrl === config.directory_url,
                    )?.id ?? ""
                  }
                  onChange={(e) => {
                    const p = ACME_PRESETS.find((x) => x.id === e.target.value);
                    if (p) setCfg("directory_url", p.directoryUrl);
                  }}
                >
                  <option value="">Custom directory</option>
                  {ACME_PRESETS.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.label}
                    </option>
                  ))}
                </Select>
                {(() => {
                  const p = ACME_PRESETS.find(
                    (x) => x.directoryUrl === config.directory_url,
                  );
                  return p ? (
                    <span className="block text-[11px]">
                      {p.eabRequired
                        ? "Needs EAB credentials. "
                        : "No EAB needed. "}
                      {p.note}
                    </span>
                  ) : null;
                })()}
              </label>
            )}
            {type?.config
              .filter((f) => fieldVisible(f, config))
              .map((f) => (
                <FieldInput
                  key={f.key}
                  field={f}
                  value={config[f.key] ?? ""}
                  onChange={(v) => setCfg(f.key, v)}
                  choices={f.optionsFrom ? hubChoices[f.optionsFrom] : undefined}
                />
              ))}
          </fieldset>
        </div>
      ),
    },
    {
      id: "credentials",
      title: "Credentials",
      validate: () => {
        if (credentialRef || !type) return null;
        // Optional-only groups (ACME over http-01 without EAB) may stay empty.
        const mustFill =
          visibleSecretFields.some((f) => f.required) || hasSecret;
        return mustFill ? missingRequired(visibleSecretFields, secrets) : null;
      },
      render: () =>
        modes.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            These settings use the hub's own identity, so there is nothing to
            store.
          </p>
        ) : credentialRef ? (
          <p className="text-sm text-muted-foreground">
            Credentials are stored. They are write-only and cannot be shown
            again.
          </p>
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground">
              Secrets are encrypted in the credential store and never shown
              again.
            </p>
            {modes.length > 1 && (
              <label className="block space-y-1 text-xs text-muted-foreground">
                <span>Sign-in method</span>
                <Select
                  value={mode?.id ?? ""}
                  onChange={(e) => {
                    setModeId(e.target.value);
                    setSecrets({});
                  }}
                >
                  {modes.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.label}
                    </option>
                  ))}
                </Select>
              </label>
            )}
            {visibleSecretFields.map((f) => (
              <FieldInput
                key={`${mode?.id}-${f.key}`}
                field={f}
                secret
                value={secrets[f.key] ?? ""}
                onChange={(v) => setSecrets((s) => ({ ...s, [f.key]: v }))}
              />
            ))}
          </div>
        ),
    },
    {
      id: "test",
      title: "Test connection",
      validate: () => (probe ? null : "Run the connection test first."),
      render: () => (
        <div className="space-y-3">
          <p className="text-xs text-muted-foreground">
            This saves the issuer and checks that Kryptkeeper can reach it.
          </p>
          <button
            type="button"
            onClick={() => void runTest()}
            disabled={busy}
            className="rounded-xl border border-border bg-muted px-3.5 py-2 text-sm font-medium hover:bg-accent focus:outline-none focus:ring-2 focus:ring-ring/60 disabled:opacity-40"
          >
            {busy ? "Testing…" : probe ? "Test again" : "Save and test"}
          </button>
          {probe && (
            <div role="status" className="space-y-1 text-sm">
              <Badge tone={probe.status === "healthy" ? "success" : "warning"}>
                {probe.status}
              </Badge>
              {probe.detail && (
                <p className="text-xs text-muted-foreground">{probe.detail}</p>
              )}
              {probe.status !== "healthy" && (
                <p className="text-xs text-state-attn">
                  The test did not pass cleanly. You can continue, but issuing
                  through this issuer may fail until it is fixed.
                </p>
              )}
            </div>
          )}
          {stepError && (
            <p role="alert" className="text-xs text-state-over">
              {stepError}
            </p>
          )}
        </div>
      ),
    },
    {
      id: "ca",
      title: "Create external CA",
      validate: () =>
        !!caName.trim() !== !!trustPem.trim()
          ? "Give both a CA name and its trust PEM, or leave both empty."
          : null,
      render: () => (
        <div className="space-y-3">
          <p className="text-xs text-muted-foreground">
            Optional. An external CA lets templates and protocols issue through
            this issuer. You can add it later.
          </p>
          <label className="block space-y-1 text-xs text-muted-foreground">
            <span>CA name (optional)</span>
            <Input value={caName} onChange={(e) => setCaName(e.target.value)} />
          </label>
          <label className="block space-y-1 text-xs text-muted-foreground">
            <span>Trust PEM (optional)</span>
            <Textarea
              rows={6}
              className="font-mono"
              value={trustPem}
              placeholder="-----BEGIN CERTIFICATE-----"
              spellCheck={false}
              onChange={(e) => setTrustPem(e.target.value)}
            />
            <span className="block text-[11px]">
              Paste the CA certificates that issued certificates must chain to.
            </span>
          </label>
          {stepError && (
            <p role="alert" className="text-xs text-state-over">
              {stepError}
            </p>
          )}
        </div>
      ),
    },
  ];

  return (
    <Dialog open={open} title="Add issuer" size="lg" onClose={onClose}>
      <Wizard steps={steps} onComplete={complete} onCancel={onClose} />
    </Dialog>
  );
}
