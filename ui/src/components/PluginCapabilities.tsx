import { useQuery } from "@tanstack/react-query";
import { Badge } from "./ui";
import { api } from "../lib/api";
import { capabilityLines, tierLabel, tierTone, type PluginManifest } from "../lib/plugins";

// CapabilityList is the review every operator sees before a plugin runs:
// the fixed sentence for each capability, grouped by tier, and whether the
// sandbox enforces it.
export function CapabilityList({ manifest }: { manifest: PluginManifest }) {
  const lines = capabilityLines(manifest.capabilities ?? {});
  if (lines.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        This plugin declares no capabilities beyond computing.
      </p>
    );
  }
  return (
    <ul className="space-y-2" aria-label="Capabilities">
      {lines.map((l) => (
        <li key={l.key} className="flex items-start gap-2 text-sm">
          <Badge tone={tierTone(l.tier)}>{tierLabel(l.tier)}</Badge>
          <span className="flex-1 text-foreground">{l.text}</span>
          <span className="text-xs text-muted-foreground">
            {l.enforced ? "Enforced by the sandbox" : "Declared only"}
          </span>
        </li>
      ))}
    </ul>
  );
}

// PluginBadge marks a target delivered through a plugin, with the plugin's
// highest capability tier, wherever targets are listed (W20-21).
export function PluginBadge({ pluginId }: { pluginId: string }) {
  const q = useQuery({ queryKey: ["delivery-plugins"], queryFn: api.deliveryPlugins, retry: false });
  const plugin = q.data?.data?.find((p) => p.id === pluginId);
  const version = plugin?.versions.find((v) => v.version === plugin.enabled_version);
  if (!version) {
    return <Badge tone="danger">Plugin {pluginId}: not enabled</Badge>;
  }
  return (
    <Badge tone={tierTone(version.capability_tier)}>
      Plugin {pluginId} · {tierLabel(version.capability_tier)}
    </Badge>
  );
}
