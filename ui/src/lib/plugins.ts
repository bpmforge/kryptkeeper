// Delivery plugins (W20-19..W20-21). The capability wording is fixed here,
// never taken from a plugin's manifest: a plugin cannot describe its own
// powers more gently than this (docs/design/DELIVERY_PLUGINS.md).

export type PluginNetwork = {
  hosts_from_credential?: string;
  hosts?: string[];
  ports?: number[];
};

// Plugin kinds (D-321). A manifest without one is a delivery plugin.
export type PluginKind =
  "delivery" | "notify" | "ticket" | "dns01" | "inventory" | "credentials";

export const KIND_LABELS: Record<PluginKind, string> = {
  delivery: "Delivery",
  notify: "Notification",
  ticket: "Ticket",
  dns01: "DNS-01",
  inventory: "Inventory",
  credentials: "Credentials",
};

export function kindLabel(kind: string | undefined): string {
  return KIND_LABELS[(kind || "delivery") as PluginKind] ?? kind ?? "Delivery";
}

export type PluginCapabilities = {
  provide_credentials?: boolean;
  receive_private_key?: boolean;
  trust_store?: boolean;
  elevated_exec?: boolean;
  remote_exec?: boolean;
  network?: PluginNetwork;
  file_write?: string[];
  tls_verify?: boolean;
};

export type PluginField = {
  type: string;
  required?: boolean;
  secret?: boolean;
  default?: string;
};

export type PluginManifest = {
  api_version: string;
  kind?: PluginKind;
  id: string;
  name: string;
  version: string;
  publisher: string;
  license?: string;
  source?: string;
  artifact: { file: string; sha256: string };
  capabilities: PluginCapabilities;
  credential_schema?: Record<string, PluginField>;
  target_schema?: Record<string, PluginField>;
};

/** One row of the signed catalogue (W38-11) with this hub's install status. */
export type PluginCatalogueEntry = {
  id: string;
  kind: string;
  name: string;
  publisher: string;
  version: string;
  description: string;
  sha256: string;
  capabilities: string[];
  min_hub_version?: string;
  status: "available" | "installed" | "upgradable";
  installed_version?: string;
  compatible: boolean;
};

export type DeliveryPluginVersion = {
  plugin_id: string;
  kind: PluginKind;
  version: string;
  sha256: string;
  trust_tier: "first-party" | "verified" | "community";
  capability_tier: CapabilityTier;
  status:
    "installed" | "pending_approval" | "enabled" | "superseded" | "disabled";
  manifest: PluginManifest;
  installed_by: string;
  installed_at: string;
  approved_by?: string;
  approved_at?: string;
  pending_action_id?: string;
  signer_key_id?: string;
};

export type DeliveryPlugin = {
  id: string;
  enabled_version?: string;
  versions: DeliveryPluginVersion[];
};

export type CapabilityTier = "critical" | "high" | "standard";

export type CapabilityLine = {
  key: string;
  tier: CapabilityTier;
  text: string;
  // Every capability is enforced by the WebAssembly sandbox (D-113): the
  // plugin can only reach the world through host calls the hub checks.
  enforced: boolean;
};

const TIER_ORDER: Record<CapabilityTier, number> = {
  critical: 0,
  high: 1,
  standard: 2,
};

// capabilityLines turns a manifest's capabilities into the fixed sentences
// the operator approves, most dangerous first.
export function capabilityLines(c: PluginCapabilities): CapabilityLine[] {
  const out: CapabilityLine[] = [];
  const add = (key: string, tier: CapabilityTier, text: string) =>
    out.push({ key, tier, text, enforced: true });
  if (c.provide_credentials)
    add(
      "provide_credentials",
      "critical",
      "This plugin returns credentials the hub uses to log in to your systems.",
    );
  if (c.receive_private_key)
    add(
      "receive_private_key",
      "critical",
      "This plugin receives the private key of every certificate it delivers.",
    );
  if (c.trust_store)
    add(
      "trust_store",
      "critical",
      "This plugin can add certificate authorities to the trust store of the hosts it delivers to.",
    );
  if (c.elevated_exec)
    add(
      "elevated_exec",
      "high",
      "This plugin runs commands as an administrator (root/sudo or Windows administrator) on target hosts.",
    );
  if (c.remote_exec)
    add(
      "remote_exec",
      "high",
      "This plugin runs commands on target hosts over SSH or WinRM.",
    );
  if (c.network) {
    const hosts = c.network.hosts ?? [];
    if (hosts.length > 0)
      add(
        "network_hosts",
        "high",
        `This plugin connects to hosts other than the device you configure: ${hosts.join(", ")}.`,
      );
    if (c.network.hosts_from_credential)
      add(
        "network",
        "high",
        "This plugin connects to the device address you configure, so it has network access.",
      );
    const ports = c.network.ports ?? [];
    if (ports.length > 0 && !(ports.length === 1 && ports[0] === 443))
      add(
        "network_ports",
        "standard",
        `It may use these ports: ${ports.join(", ")}.`,
      );
  }
  if (c.file_write && c.file_write.length > 0)
    add(
      "file_write",
      "standard",
      `This plugin writes files on target hosts under: ${c.file_write.join(", ")}.`,
    );
  if (c.tls_verify)
    add(
      "tls_verify",
      "standard",
      "This plugin checks which certificate the service presents.",
    );
  return out.sort((a, b) => TIER_ORDER[a.tier] - TIER_ORDER[b.tier]);
}

// capabilityTier is the highest tier among the capabilities, matching the
// hub's abi.Capabilities.Tier.
export function capabilityTier(c: PluginCapabilities): CapabilityTier {
  const lines = capabilityLines(c);
  return lines.length > 0 ? lines[0].tier : "standard";
}

export function tierTone(t: CapabilityTier): "danger" | "warning" | "neutral" {
  return t === "critical" ? "danger" : t === "high" ? "warning" : "neutral";
}

export function tierLabel(t: CapabilityTier): string {
  return t === "critical" ? "Critical" : t === "high" ? "High" : "Standard";
}

// sha256Hex hashes a module in the browser so the operator sees, before
// uploading, whether it matches the manifest's pin.
export async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function toBase64(bytes: ArrayBuffer): string {
  const u8 = new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) {
    s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

// enabledDNS01Plugins lists the ids of plugins whose enabled version is a
// dns01 plugin: the ones an ACME connector can use as its DNS provider.
export function enabledDNS01Plugins(plugins: DeliveryPlugin[]): string[] {
  return plugins
    .filter((p) =>
      p.versions.some(
        (v) => v.version === p.enabled_version && v.kind === "dns01",
      ),
    )
    .map((p) => p.id)
    .sort();
}
