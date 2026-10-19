import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, ShieldCheck, Upload } from "lucide-react";
import { toast } from "sonner";
import { api } from "../lib/api";
import { useAuthz } from "../lib/auth";
import {
  capabilityTier,
  sha256Hex,
  tierLabel,
  tierTone,
  toBase64,
  type DeliveryPlugin,
  type DeliveryPluginVersion,
  type PluginManifest,
} from "../lib/plugins";
import {
  Badge,
  Button,
  Dialog,
  Panel,
  StateMessage,
  formatDateTime,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { CapabilityList } from "../components/PluginCapabilities";

function statusTone(
  s: DeliveryPluginVersion["status"],
): "success" | "warning" | "neutral" | "danger" {
  switch (s) {
    case "enabled":
      return "success";
    case "pending_approval":
      return "warning";
    case "disabled":
      return "danger";
    default:
      return "neutral";
  }
}

function FieldList({
  title,
  fields,
}: {
  title: string;
  fields?: PluginManifest["credential_schema"];
}) {
  const entries = Object.entries(fields ?? {});
  if (entries.length === 0) return null;
  return (
    <div className="space-y-1 text-sm">
      <div className="text-muted-foreground">{title}</div>
      <ul className="flex flex-wrap gap-1.5">
        {entries.map(([name, f]) => (
          <li key={name}>
            <Badge tone="neutral">
              {name}
              {f.required ? " *" : ""}
              {f.secret ? " (secret)" : ""}
            </Badge>
          </li>
        ))}
      </ul>
    </div>
  );
}

function InstallDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [manifest, setManifest] = useState<PluginManifest | null>(null);
  // The exact file bytes: a signature covers them, not a re-encoding.
  const [manifestBytes, setManifestBytes] = useState<ArrayBuffer | null>(null);
  const [signature, setSignature] = useState("");
  const [manifestError, setManifestError] = useState<string | null>(null);
  const [wasm, setWasm] = useState<ArrayBuffer | null>(null);
  const [wasmHash, setWasmHash] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);

  const reset = () => {
    setManifest(null);
    setManifestBytes(null);
    setSignature("");
    setManifestError(null);
    setWasm(null);
    setWasmHash("");
    setAcknowledged(false);
  };

  const install = useMutation({
    mutationFn: () =>
      api.installDeliveryPlugin(
        toBase64(manifestBytes as ArrayBuffer),
        toBase64(wasm as ArrayBuffer),
        signature,
      ),
    onSuccess: async (res) => {
      toast.success(
        `Installed ${res.data.plugin_id} ${res.data.version}. It is disabled until you enable it.`,
      );
      await qc.invalidateQueries({ queryKey: ["delivery-plugins"] });
      reset();
      onClose();
    },
  });

  const hashMatches =
    manifest !== null &&
    wasmHash !== "" &&
    wasmHash === manifest.artifact?.sha256;
  const tier = manifest
    ? capabilityTier(manifest.capabilities ?? {})
    : "standard";
  const needsAck = tier !== "standard";

  return (
    <Dialog
      open={open}
      title="Install a delivery plugin"
      description="Review what the plugin can do before it is stored. Installing does not run it."
      onClose={() => {
        reset();
        onClose();
      }}
      size="lg"
    >
      <div className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block space-y-1 text-sm text-foreground">
            <span>manifest.json</span>
            <input
              type="file"
              accept="application/json,.json"
              aria-label="manifest.json"
              className="block w-full text-sm"
              onChange={async (e) => {
                const f = e.target.files?.[0];
                setManifest(null);
                setManifestBytes(null);
                setManifestError(null);
                if (!f) return;
                try {
                  const bytes = await f.arrayBuffer();
                  setManifest(
                    JSON.parse(
                      new TextDecoder().decode(bytes),
                    ) as PluginManifest,
                  );
                  setManifestBytes(bytes);
                } catch {
                  setManifestError("That file is not valid JSON.");
                }
              }}
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Plugin module (.wasm)</span>
            <input
              type="file"
              accept=".wasm,application/wasm"
              aria-label="Plugin module"
              className="block w-full text-sm"
              onChange={async (e) => {
                const f = e.target.files?.[0];
                setWasm(null);
                setWasmHash("");
                if (!f) return;
                const buf = await f.arrayBuffer();
                setWasm(buf);
                setWasmHash(await sha256Hex(buf));
              }}
            />
          </label>
        </div>

        <label className="block space-y-1 text-sm text-foreground">
          <span>Signature (optional)</span>
          <input
            type="file"
            accept=".sig,.bundle,.json"
            aria-label="Signature"
            className="block w-full text-sm"
            onChange={async (e) => {
              const f = e.target.files?.[0];
              setSignature(f ? (await f.text()).trim() : "");
            }}
          />
          <span className="block text-xs text-muted-foreground">
            The .bundle or .sig from cosign sign-blob over manifest.json. The
            hub checks it on install and refuses a signature it cannot verify.
          </span>
        </label>

        {manifestError ? (
          <StateMessage tone="error" title="Manifest" message={manifestError} />
        ) : null}

        {manifest ? (
          <div className="space-y-3 rounded-xl border border-border bg-card/40 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-base font-semibold text-foreground">
                {manifest.name}
              </span>
              <Badge tone="info">{manifest.version}</Badge>
              <Badge tone={tierTone(tier)}>
                {tierLabel(tier)} capabilities
              </Badge>
              <Badge tone="neutral">
                {signature
                  ? "Trust: signed (checked by the hub on install)"
                  : "Trust: community (unsigned upload)"}
              </Badge>
            </div>
            <dl className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[auto_1fr]">
              <dt className="text-muted-foreground">ID</dt>
              <dd className="text-foreground">{manifest.id}</dd>
              <dt className="text-muted-foreground">Publisher</dt>
              <dd className="text-foreground">{manifest.publisher}</dd>
              {manifest.source ? (
                <>
                  <dt className="text-muted-foreground">Source</dt>
                  <dd className="break-all text-foreground">
                    {manifest.source}
                  </dd>
                </>
              ) : null}
              <dt className="text-muted-foreground">SHA-256</dt>
              <dd className="break-all font-mono text-xs text-foreground">
                {manifest.artifact?.sha256}
              </dd>
            </dl>
            {wasm ? (
              hashMatches ? (
                <p className="flex items-center gap-1.5 text-sm text-state-auto">
                  <ShieldCheck size={14} aria-hidden="true" /> The module
                  matches the manifest's SHA-256.
                </p>
              ) : (
                <p
                  className="flex items-center gap-1.5 text-sm text-state-over"
                  role="alert"
                >
                  <ShieldAlert size={14} aria-hidden="true" /> The module does
                  not match the manifest's SHA-256 ({wasmHash.slice(0, 16)}…).
                  The hub will refuse it.
                </p>
              )
            ) : null}
            <div className="space-y-2">
              <div className="text-sm font-medium text-foreground">
                What this plugin can do
              </div>
              <CapabilityList manifest={manifest} />
            </div>
            <FieldList
              title="Credential fields"
              fields={manifest.credential_schema}
            />
            <FieldList
              title="Target settings"
              fields={manifest.target_schema}
            />
            {needsAck ? (
              <label className="flex items-start gap-2 text-sm text-foreground">
                <input
                  type="checkbox"
                  checked={acknowledged}
                  onChange={(e) => setAcknowledged(e.target.checked)}
                />
                <span>
                  I have read what this plugin can do. Enabling it will also
                  need a second pki-admin's approval.
                </span>
              </label>
            ) : null}
          </div>
        ) : null}

        {install.isError ? (
          <StateMessage
            tone="error"
            title="Install failed"
            message={
              install.error instanceof Error
                ? install.error.message
                : "The hub refused the plugin."
            }
          />
        ) : null}

        <div className="flex gap-2">
          <Button
            tone="primary"
            onClick={() => install.mutate()}
            disabled={
              !manifest ||
              !wasm ||
              !hashMatches ||
              (needsAck && !acknowledged) ||
              install.isPending
            }
          >
            <Upload size={13} aria-hidden="true" />
            Install
          </Button>
          <Button
            onClick={() => {
              reset();
              onClose();
            }}
          >
            Cancel
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

function PluginCard({
  plugin,
  isAdmin,
}: {
  plugin: DeliveryPlugin;
  isAdmin: boolean;
}) {
  const qc = useQueryClient();
  const refresh = () =>
    qc.invalidateQueries({ queryKey: ["delivery-plugins"] });
  const shown =
    plugin.versions.find((v) => v.version === plugin.enabled_version) ??
    plugin.versions[0];

  const enable = useMutation({
    mutationFn: (version: string) =>
      api.enableDeliveryPlugin(plugin.id, version),
    onSuccess: async (res) => {
      if (res.data.status === "pending_approval") {
        toast.message(
          "Waiting for a second pki-admin: approve it in Pending Actions.",
        );
      } else {
        toast.success(`Enabled ${plugin.id} ${res.data.version ?? ""}`);
      }
      await refresh();
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const disable = useMutation({
    mutationFn: () => api.disableDeliveryPlugin(plugin.id),
    onSuccess: refresh,
    onError: (e: Error) => toast.error(e.message),
  });
  const remove = useMutation({
    mutationFn: () => api.removeDeliveryPlugin(plugin.id),
    onSuccess: refresh,
    onError: (e: Error) => toast.error(e.message),
  });

  if (!shown) return null;
  return (
    <Panel title={shown.manifest.name || plugin.id} subtitle={plugin.id}>
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          {plugin.enabled_version ? (
            <Badge tone="success">Enabled: {plugin.enabled_version}</Badge>
          ) : (
            <Badge tone="neutral">Not running</Badge>
          )}
          <Badge tone={tierTone(shown.capability_tier)}>
            {tierLabel(shown.capability_tier)} capabilities
          </Badge>
          <Badge tone="info">Trust: {shown.trust_tier}</Badge>
          {shown.signer_key_id ? (
            <span
              className="font-mono text-xs text-muted-foreground"
              title={`Signing key sha256:${shown.signer_key_id}`}
            >
              key {shown.signer_key_id.slice(0, 12)}…
            </span>
          ) : null}
          <span className="text-xs text-muted-foreground">
            by {shown.manifest.publisher}
          </span>
        </div>
        <CapabilityList manifest={shown.manifest} />

        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-muted-foreground">
              <th className="py-1 font-medium">Version</th>
              <th className="py-1 font-medium">Status</th>
              <th className="py-1 font-medium">SHA-256</th>
              <th className="py-1 font-medium">Installed</th>
              <th className="py-1 font-medium">Approved</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {plugin.versions.map((v) => (
              <tr key={v.version} className="border-t border-border">
                <td className="py-1.5 text-foreground">{v.version}</td>
                <td className="py-1.5">
                  <Badge tone={statusTone(v.status)}>
                    {v.status.replace("_", " ")}
                  </Badge>
                </td>
                <td
                  className="py-1.5 font-mono text-xs text-muted-foreground"
                  title={v.sha256}
                >
                  {v.sha256.slice(0, 12)}…
                </td>
                <td className="py-1.5 text-xs text-muted-foreground">
                  {v.installed_by}, {formatDateTime(v.installed_at)}
                </td>
                <td className="py-1.5 text-xs text-muted-foreground">
                  {v.approved_by
                    ? `${v.approved_by}, ${formatDateTime(v.approved_at ?? "")}`
                    : "—"}
                </td>
                <td className="py-1.5 text-right">
                  {v.status === "pending_approval" ? (
                    <Link
                      className="text-xs text-primary underline"
                      to="/inbox"
                    >
                      Awaiting approval
                    </Link>
                  ) : isAdmin && v.status !== "enabled" ? (
                    <Button
                      onClick={() => enable.mutate(v.version)}
                      disabled={enable.isPending}
                    >
                      Enable
                    </Button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {isAdmin ? (
          <div className="flex gap-2">
            {plugin.enabled_version ? (
              <Button
                tone="danger"
                onClick={() => disable.mutate()}
                disabled={disable.isPending}
              >
                Disable
              </Button>
            ) : (
              <Button
                tone="danger"
                onClick={() => remove.mutate()}
                disabled={remove.isPending}
              >
                Remove
              </Button>
            )}
          </div>
        ) : null}
      </div>
    </Panel>
  );
}

export default function DeliveryPlugins() {
  const authz = useAuthz();
  const isAdmin = authz.data?.role === "pki-admin";
  const [installing, setInstalling] = useState(false);
  const { data, isLoading, error } = useQuery({
    queryKey: ["delivery-plugins"],
    queryFn: api.deliveryPlugins,
    retry: false,
  });
  const plugins = data?.data ?? [];
  const off = error instanceof Error && /turned off/i.test(error.message);

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Automation"
        title="Delivery Plugins"
        description="Deliver renewed certificates to devices Kryptkeeper does not support natively. Plugins run sandboxed, and what each one can do is shown before it runs."
        actions={
          isAdmin && !off ? (
            <Button tone="primary" onClick={() => setInstalling(true)}>
              <Upload size={13} aria-hidden="true" />
              Install plugin
            </Button>
          ) : null
        }
      />

      {isLoading ? (
        <StateMessage title="Loading" message="Fetching delivery plugins…" />
      ) : off ? (
        <StateMessage
          title="Delivery plugins are turned off"
          message="This hub runs with KRYPTKEEPER_DELIVERY_PLUGINS=off, so no plugin loads and plugin targets do not renew."
        />
      ) : error ? (
        <StateMessage
          tone="error"
          title="Unavailable"
          message="Delivery plugins could not be loaded."
        />
      ) : plugins.length === 0 ? (
        <Panel title="No plugins installed">
          <p className="text-sm text-muted-foreground">
            A plugin is a WebAssembly module with a manifest. See
            docs/plugins/README.md to write one, or install a published plugin.
          </p>
        </Panel>
      ) : (
        <div className="space-y-4">
          {plugins.map((p) => (
            <PluginCard key={p.id} plugin={p} isAdmin={isAdmin} />
          ))}
        </div>
      )}

      <InstallDialog open={installing} onClose={() => setInstalling(false)} />
    </div>
  );
}
