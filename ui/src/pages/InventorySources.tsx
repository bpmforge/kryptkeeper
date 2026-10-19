import { useState } from "react";
import { scrollableProps } from "../lib/scrollable";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { api, type InventorySourceRecord } from "../lib/api";
import {
  Badge,
  Button,
  Dialog,
  Input,
  Panel,
  Select,
  StateMessage,
  Textarea,
  formatDateTime,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";

const TYPES = [
  "adcs_export",
  "adcs_live",
  "digicert",
  "sectigo",
  "entrust",
  "aws_pca",
  "gcp_cas",
] as const;

const TYPE_LABELS: Record<string, string> = {
  adcs_export: "AD CS export",
  adcs_live: "AD CS live",
  digicert: "DigiCert",
  sectigo: "Sectigo",
  entrust: "Entrust",
  aws_pca: "AWS Private CA",
  gcp_cas: "GCP CA Service",
};
const typeLabel = (t: string) => TYPE_LABELS[t] ?? t;

const CONFIG_TEMPLATES: Record<string, string> = {
  adcs_export: '{"export_path":""}',
  adcs_live: '{"ldap_url":"","bind_dn":"","search_base":""}',
  digicert: '{"base_url":"https://www.digicert.com"}',
  sectigo: '{"base_url":"","customer_uri":""}',
  entrust: '{"base_url":""}',
  aws_pca: '{"region":""}',
  gcp_cas: '{"project":"","location":"","ca_pool":""}',
};

type SyncOutcome =
  | { kind: "none" }
  | { kind: "error"; message: string }
  | { kind: "ok"; synced: number; skipped: number; failed: number }
  | { kind: "unparseable" };

// last_sync_result is server-stored JSON; never trust its shape.
function parseResult(raw?: string): SyncOutcome {
  if (!raw) return { kind: "none" };
  try {
    const v = JSON.parse(raw) as Record<string, unknown> | null;
    if (!v || typeof v !== "object") return { kind: "unparseable" };
    if (typeof v.error === "string" && v.error) {
      return { kind: "error", message: v.error };
    }
    return {
      kind: "ok",
      synced: Number(v.synced) || 0,
      skipped: Number(v.skipped) || 0,
      failed: Array.isArray(v.failed) ? v.failed.length : 0,
    };
  } catch {
    return { kind: "unparseable" };
  }
}

function ResultCell({ raw }: { raw?: string }) {
  const r = parseResult(raw);
  switch (r.kind) {
    case "none":
      return <span className="text-muted-foreground">Not synced yet</span>;
    case "unparseable":
      return <span className="text-muted-foreground">Unreadable result</span>;
    case "error":
      return (
        <div className="space-y-1">
          <Badge tone="danger">Failed</Badge>
          <div className="text-xs text-foreground">{r.message}</div>
        </div>
      );
    case "ok":
      return (
        <span>
          {r.synced} new, {r.skipped} existing
          {r.failed > 0 ? `, ${r.failed} failed` : ""}
        </span>
      );
  }
}

function scheduleLabel(minutes: number): string {
  return minutes === 0 ? "Manual" : `every ${minutes} min`;
}

function CreateForm() {
  const queryClient = useQueryClient();
  const creds = useQuery({ queryKey: ["credentials"], queryFn: api.credentials });
  const credentials = creds.data?.data?.items ?? [];

  const [name, setName] = useState("");
  const [type, setType] = useState<string>("digicert");
  const [config, setConfig] = useState(CONFIG_TEMPLATES.digicert);
  const [credentialRef, setCredentialRef] = useState("");
  const [schedule, setSchedule] = useState("0");

  const credentialRequired = type !== "adcs_export";
  let configValid = true;
  try {
    JSON.parse(config);
  } catch {
    configValid = false;
  }
  const scheduleNum = Number(schedule);
  const scheduleValid =
    Number.isInteger(scheduleNum) && scheduleNum >= 0 && scheduleNum <= 10080;
  const canSubmit =
    name.trim() !== "" &&
    configValid &&
    scheduleValid &&
    (!credentialRequired || credentialRef !== "");

  const create = useMutation({
    mutationFn: () =>
      api.createInventorySource({
        name: name.trim(),
        type,
        config_json: config,
        ...(credentialRef ? { credential_ref: credentialRef } : {}),
        schedule_minutes: scheduleNum,
      }),
    onSuccess: () => {
      toast.success("Inventory source created");
      setName("");
      setConfig(CONFIG_TEMPLATES[type]);
      setCredentialRef("");
      setSchedule("0");
      return queryClient.invalidateQueries({ queryKey: ["inventory-sources"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Panel
      title="Add a source"
      subtitle="Pull certificates from another CA into inventory. Synced certificates arrive as external."
    >
      <form
        className="grid grid-cols-1 gap-3 md:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (canSubmit) create.mutate();
        }}
      >
        <label className="block space-y-1 text-sm text-foreground">
          <span>Name</span>
          <Input
            aria-label="Source name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label className="block space-y-1 text-sm text-foreground">
          <span>Type</span>
          <Select
            aria-label="Source type"
            value={type}
            onChange={(e) => {
              setType(e.target.value);
              setConfig(CONFIG_TEMPLATES[e.target.value]);
              setCredentialRef("");
            }}
          >
            {TYPES.map((t) => (
              <option key={t} value={t}>
                {typeLabel(t)}
              </option>
            ))}
          </Select>
        </label>
        <label className="block space-y-1 text-sm text-foreground">
          <span>Credential</span>
          <Select
            aria-label="Credential"
            value={credentialRef}
            onChange={(e) => setCredentialRef(e.target.value)}
          >
            <option value="">
              {credentialRequired ? "Select a credential" : "None"}
            </option>
            {credentials.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </Select>
        </label>
        <label className="block space-y-1 text-sm text-foreground">
          <span>Sync every (minutes, 0 = manual)</span>
          <Input
            aria-label="Schedule minutes"
            type="number"
            min={0}
            max={10080}
            value={schedule}
            onChange={(e) => setSchedule(e.target.value)}
          />
        </label>
        <label className="block space-y-1 text-sm text-foreground md:col-span-2">
          <span>Configuration (JSON)</span>
          <Textarea
            aria-label="Configuration JSON"
            rows={4}
            className="font-mono"
            value={config}
            onChange={(e) => setConfig(e.target.value)}
          />
          {!configValid ? (
            <span className="text-xs text-state-over">
              Configuration is not valid JSON.
            </span>
          ) : null}
        </label>
        <div className="md:col-span-2">
          <Button
            type="submit"
            tone="primary"
            disabled={!canSubmit || create.isPending}
          >
            Add source
          </Button>
        </div>
      </form>
    </Panel>
  );
}

function SourceRow({
  source,
  onDelete,
}: {
  source: InventorySourceRecord;
  onDelete: (s: InventorySourceRecord) => void;
}) {
  const queryClient = useQueryClient();
  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ["inventory-sources"] });
  const sync = useMutation({
    mutationFn: () => api.syncInventorySource(source.id),
    onSuccess: (res) => {
      toast.success(
        `Synced: ${res.data.synced} new, ${res.data.skipped} existing`,
      );
      return refresh();
    },
    onError: (e: Error) => {
      toast.error(e.message);
      return refresh();
    },
  });

  return (
    <tr className="border-t border-border align-top">
      <td className="py-2 pr-3 font-medium text-foreground">{source.name}</td>
      <td className="py-2 pr-3">
        <Badge>{typeLabel(source.type)}</Badge>
      </td>
      <td className="py-2 pr-3">{scheduleLabel(source.schedule_minutes)}</td>
      <td className="py-2 pr-3">
        {source.last_sync_at ? formatDateTime(source.last_sync_at) : "Never"}
      </td>
      <td className="py-2 pr-3">
        <ResultCell raw={source.last_sync_result} />
      </td>
      <td className="py-2">
        <div className="flex gap-2">
          <Button
            aria-label={`Sync ${source.name} now`}
            disabled={sync.isPending}
            onClick={() => sync.mutate()}
          >
            <RefreshCw
              className={`h-4 w-4 ${sync.isPending ? "animate-spin" : ""}`}
            />
            Sync now
          </Button>
          <Button
            tone="danger"
            aria-label={`Delete ${source.name}`}
            onClick={() => onDelete(source)}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </td>
    </tr>
  );
}

export default function InventorySources() {
  const queryClient = useQueryClient();
  const [pendingDelete, setPendingDelete] =
    useState<InventorySourceRecord | null>(null);
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["inventory-sources"],
    queryFn: api.inventorySources,
  });
  const sources = data?.data ?? [];

  const remove = useMutation({
    mutationFn: (id: string) => api.deleteInventorySource(id),
    onSuccess: () => {
      toast.success("Source deleted");
      setPendingDelete(null);
      return queryClient.invalidateQueries({ queryKey: ["inventory-sources"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Administration"
        title="Inventory Sources"
        description="Direct-CA feeds that sync certificates into inventory on a schedule or on demand."
      />

      <Panel title="Sources">
        {isLoading ? (
          <StateMessage title="Loading" message="Fetching inventory sources…" />
        ) : error ? (
          <StateMessage
            tone="error"
            title="Unavailable"
            message="Could not load inventory sources."
            action={<Button onClick={() => refetch()}>Retry</Button>}
          />
        ) : sources.length === 0 ? (
          <StateMessage
            title="No inventory sources"
            message="Add a source below to start syncing certificates from a CA."
          />
        ) : (
          <div className="overflow-x-auto" {...scrollableProps}>
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-muted-foreground">
                <tr>
                  <th className="pb-2 pr-3">Name</th>
                  <th className="pb-2 pr-3">Type</th>
                  <th className="pb-2 pr-3">Schedule</th>
                  <th className="pb-2 pr-3">Last sync</th>
                  <th className="pb-2 pr-3">Result</th>
                  <th className="pb-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sources.map((s) => (
                  <SourceRow key={s.id} source={s} onDelete={setPendingDelete} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <CreateForm />

      <Dialog
        open={pendingDelete !== null}
        title="Delete inventory source"
        description={
          pendingDelete
            ? `Delete ${pendingDelete.name}? Already-synced certificates stay in inventory.`
            : undefined
        }
        onClose={() => setPendingDelete(null)}
        size="sm"
      >
        <div className="flex justify-end gap-2">
          <Button tone="secondary" onClick={() => setPendingDelete(null)}>
            Cancel
          </Button>
          <Button
            tone="danger"
            disabled={remove.isPending}
            onClick={() => pendingDelete && remove.mutate(pendingDelete.id)}
          >
            Delete source
          </Button>
        </div>
      </Dialog>
    </div>
  );
}
