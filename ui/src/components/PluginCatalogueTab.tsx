import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api } from "../lib/api";
import type { PluginCatalogueEntry } from "../lib/plugins";
import { Badge, Button, Panel, StateMessage } from "../components/ui";

const STATUS_LABEL: Record<PluginCatalogueEntry["status"], string> = {
  available: "Not installed",
  installed: "Installed",
  upgradable: "Upgrade available",
};

// The catalogue is fetched by the hub only when this tab is open (D-328); an
// install lands the version disabled, exactly like an upload, and enabling it
// from the Installed tab still follows the approval rules.
export function PluginCatalogueTab() {
  const qc = useQueryClient();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["plugin-catalogue"],
    queryFn: api.pluginCatalogue,
    retry: false,
    refetchOnWindowFocus: false,
  });
  const install = useMutation({
    mutationFn: (e: PluginCatalogueEntry) =>
      api.installFromPluginCatalogue(e.id, e.version),
    onSuccess: (_r, e) => {
      toast.success(
        `${e.name} ${e.version} installed, disabled. Enable it from the Installed tab.`,
      );
      void qc.invalidateQueries({ queryKey: ["plugin-catalogue"] });
      void qc.invalidateQueries({ queryKey: ["delivery-plugins"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  if (isLoading) {
    return (
      <StateMessage title="Loading" message="Fetching the plugin catalogue…" />
    );
  }
  if (error) {
    const disabled = /turned off|disabled/i.test(error.message);
    return (
      <StateMessage
        tone={disabled ? "neutral" : "error"}
        title={
          disabled ? "The catalogue is turned off" : "Catalogue unavailable"
        }
        message={
          disabled
            ? "KRYPTKEEPER_PLUGIN_CATALOGUE_URL is empty on this hub. Install plugins by upload, or import catalogue files offline (docs/ops/PLUGIN_CATALOGUE.md)."
            : error.message
        }
      />
    );
  }
  const entries = data?.data.entries ?? [];
  return (
    <Panel title="Signed catalogue">
      <div className="mb-3 flex justify-end">
        <Button onClick={() => void refetch()} aria-label="Refresh catalogue">
          Refresh
        </Button>
      </div>
      {entries.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          The catalogue lists no plugins.
        </p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-muted-foreground">
              <th className="py-1">Plugin</th>
              <th>Version</th>
              <th>Can do</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={`${e.id}@${e.version}`} className="border-t">
                <td className="py-2">
                  <div className="font-medium">{e.name}</div>
                  <div className="text-xs text-muted-foreground">
                    {e.id} · {e.kind} · {e.publisher}
                  </div>
                </td>
                <td>{e.version}</td>
                <td className="text-xs">
                  {e.capabilities.join(", ") || "none"}
                </td>
                <td>
                  <Badge
                    tone={e.status === "installed" ? "success" : "neutral"}
                  >
                    {STATUS_LABEL[e.status]}
                  </Badge>
                  {e.installed_version && e.status === "upgradable" && (
                    <div className="text-xs text-muted-foreground">
                      installed {e.installed_version}
                    </div>
                  )}
                </td>
                <td className="text-right">
                  {e.status === "installed" ? null : !e.compatible ? (
                    <span className="text-xs text-muted-foreground">
                      needs hub {e.min_hub_version}
                    </span>
                  ) : (
                    <Button
                      tone="primary"
                      disabled={install.isPending}
                      onClick={() => install.mutate(e)}
                    >
                      {e.status === "upgradable" ? "Upgrade" : "Install"}
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
