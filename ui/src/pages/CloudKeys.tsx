import { useMemo, useState } from "react";
import { scrollableProps } from "../lib/scrollable";
import { useQuery } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, Copy, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { api, type CloudKey } from "../lib/api";
import {
  Badge,
  Button,
  Input,
  MetricCard,
  Panel,
  Select,
  StateMessage,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { EmptyState } from "../components/EmptyState";

// Metadata only: the inventory endpoint never returns key material, so every
// field rendered here is an identifier or a label.

type SortKey =
  | "provider"
  | "location"
  | "key_id"
  | "algorithm"
  | "usage"
  | "state"
  | "rotation_enabled"
  | "created_at"
  | "pqc_readiness";

const COLUMNS: { key: SortKey; label: string }[] = [
  { key: "provider", label: "Provider" },
  { key: "location", label: "Location" },
  { key: "key_id", label: "Key" },
  { key: "algorithm", label: "Algorithm" },
  { key: "usage", label: "Usage" },
  { key: "state", label: "State" },
  { key: "rotation_enabled", label: "Rotation" },
  { key: "created_at", label: "Created" },
  { key: "pqc_readiness", label: "PQC readiness" },
];

const PROVIDER_LABELS: Record<string, string> = {
  "aws-kms": "AWS KMS",
  "azure-kv": "Azure Key Vault",
  "gcp-kms": "GCP KMS",
};

const providerLabel = (p: string) => PROVIDER_LABELS[p] ?? p;

function stateTone(
  state?: string,
): "success" | "warning" | "danger" | "neutral" {
  const s = (state ?? "").toLowerCase().replace(/[^a-z]/g, "");
  if (s === "enabled" || s === "active") return "success";
  if (s.includes("pending") || s.includes("destroy") || s.includes("delet"))
    return "danger";
  if (s === "disabled") return "warning";
  return "neutral";
}

function pqcTone(r?: string): "success" | "danger" | "neutral" {
  if (r === "quantum_safe") return "success";
  if (r === "vulnerable") return "danger";
  return "neutral";
}

const pqcLabel = (r?: string) =>
  r === "quantum_safe"
    ? "Quantum safe"
    : r === "vulnerable"
      ? "Vulnerable"
      : "Unknown";

// Cloud key ARNs / resource paths are long; keep both ends (account and key
// id are at opposite ends) and expose the full value via title + copy.
function middleTruncate(v: string, max = 40): string {
  if (v.length <= max) return v;
  const head = Math.ceil((max - 1) * 0.45);
  const tail = max - 1 - head;
  return `${v.slice(0, head)}…${v.slice(v.length - tail)}`;
}

async function copy(value: string) {
  try {
    await navigator.clipboard.writeText(value);
    toast.success("Key identifier copied");
  } catch {
    toast.error("Could not copy to clipboard");
  }
}

// The server sanitises errors to "cloud key inventory unavailable: <provider>".
function errorProvider(e: string): string | null {
  const i = e.lastIndexOf(": ");
  return i >= 0 ? e.slice(i + 2).trim() || null : null;
}

function compare(a: CloudKey, b: CloudKey, key: SortKey): number {
  if (key === "rotation_enabled") {
    return Number(!!a.rotation_enabled) - Number(!!b.rotation_enabled);
  }
  return (a[key] ?? "").localeCompare(b[key] ?? "");
}

export default function CloudKeys() {
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["cloud-key-inventory"],
    queryFn: api.cloudKeyInventory,
    staleTime: 60_000,
    retry: false,
  });
  const [provider, setProvider] = useState("");
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({
    key: "provider",
    dir: "asc",
  });

  const inv = data?.data;
  const keys = useMemo(() => inv?.keys ?? [], [inv]);
  const errors = useMemo(() => inv?.errors ?? [], [inv]);

  const providers = useMemo(
    () =>
      Array.from(new Set(keys.map((k) => k.provider ?? "")))
        .filter(Boolean)
        .sort(),
    [keys],
  );

  const sources = useMemo(() => {
    const counts = new Map<string, number>();
    for (const k of keys)
      counts.set(k.provider ?? "", (counts.get(k.provider ?? "") ?? 0) + 1);
    const failed = errors.map((e) => ({ raw: e, provider: errorProvider(e) }));
    return { counts: Array.from(counts.entries()), failed };
  }, [keys, errors]);

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    const filtered = keys.filter((k) => {
      if (provider && k.provider !== provider) return false;
      if (!q) return true;
      return [
        k.key_id,
        k.location,
        k.algorithm,
        k.usage,
        k.state,
        k.provider,
      ].some((v) => (v ?? "").toLowerCase().includes(q));
    });
    const dir = sort.dir === "asc" ? 1 : -1;
    return [...filtered].sort((a, b) => dir * compare(a, b, sort.key));
  }, [keys, provider, search, sort]);

  const status = (error as { status?: number } | null)?.status;

  const toggleSort = (key: SortKey) =>
    setSort((s) =>
      s.key === key
        ? { key, dir: s.dir === "asc" ? "desc" : "asc" }
        : { key, dir: "asc" },
    );

  const pqc = inv?.pqc_summary ?? {};

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Analysis"
        title="Cloud Keys"
        description="Read-only inventory of KMS keys across AWS, Azure and GCP. Metadata only; no key material is fetched or shown."
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

      <p className="text-xs text-muted-foreground">
        PQC keys are not held in cloud KMS: custody is software-only
        (docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md).
      </p>

      {isLoading ? (
        <StateMessage title="Loading" message="Querying cloud key sources…" />
      ) : status === 403 ? (
        <StateMessage
          tone="error"
          title="Access denied"
          message="Your role can't view cloud keys."
        />
      ) : error || !inv ? (
        <StateMessage
          tone="error"
          title="Cloud key inventory unavailable"
          message={
            error instanceof Error
              ? error.message
              : "The cloud key inventory could not be loaded."
          }
        />
      ) : (
        <>
          <section aria-label="Source status" className="space-y-2">
            {sources.failed.length > 0 ? (
              <StateMessage
                tone="error"
                title="Partial result: some cloud sources failed"
                message="Keys from the failing sources are missing from the table below."
              />
            ) : null}
            {sources.counts.length > 0 || sources.failed.length > 0 ? (
              <ul
                className="flex flex-wrap gap-2 text-xs"
                aria-label="Per-source status"
              >
                {sources.counts.map(([p, n]) => (
                  <li key={p}>
                    <Badge tone="success">
                      {providerLabel(p)}: ok, {n} {n === 1 ? "key" : "keys"}
                    </Badge>
                  </li>
                ))}
                {sources.failed.map((f) => (
                  <li key={f.raw}>
                    <Badge tone="danger">
                      {f.provider
                        ? `${providerLabel(f.provider)}: error`
                        : "error"}
                      {" — "}
                      {f.raw}
                    </Badge>
                  </li>
                ))}
              </ul>
            ) : null}
          </section>

          {keys.length === 0 && errors.length === 0 ? (
            <EmptyState
              title="No cloud keys found"
              description="No cloud key source is configured, or the configured sources hold no keys. Cloud inventory needs credentials in the hub environment: AWS_REGION (or AWS_DEFAULT_REGION) with the default AWS credential chain; AZURE_KEYVAULT_URL and AZURE_ACCESS_TOKEN; GCP_KMS_KEYRING and GOOGLE_ACCESS_TOKEN."
            />
          ) : (
            <>
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                <MetricCard label="Keys" value={inv.total ?? keys.length} />
                <MetricCard
                  label="Quantum safe"
                  value={pqc.quantum_safe ?? 0}
                  tone="success"
                />
                <MetricCard
                  label="Vulnerable"
                  value={pqc.vulnerable ?? 0}
                  tone={(pqc.vulnerable ?? 0) > 0 ? "warning" : "neutral"}
                />
                <MetricCard label="Unknown" value={pqc.unknown ?? 0} />
              </div>

              <Panel title="Keys">
                <div className="mb-4 flex flex-wrap items-end gap-3">
                  <div className="min-w-[12rem] flex-1">
                    <label
                      htmlFor="cloud-keys-search"
                      className="mb-1 block text-xs text-muted-foreground"
                    >
                      Search keys
                    </label>
                    <Input
                      id="cloud-keys-search"
                      type="search"
                      placeholder="Key id, location, algorithm…"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                    />
                  </div>
                  <div>
                    <label
                      htmlFor="cloud-keys-provider"
                      className="mb-1 block text-xs text-muted-foreground"
                    >
                      Provider
                    </label>
                    <Select
                      id="cloud-keys-provider"
                      value={provider}
                      onChange={(e) => setProvider(e.target.value)}
                    >
                      <option value="">All providers</option>
                      {providers.map((p) => (
                        <option key={p} value={p}>
                          {providerLabel(p)}
                        </option>
                      ))}
                    </Select>
                  </div>
                </div>

                {rows.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    {keys.length === 0
                      ? "No keys were returned by the sources that responded."
                      : "No keys match the current filters."}
                  </p>
                ) : (
                  <div className="overflow-x-auto" {...scrollableProps}>
                    <table className="w-full text-sm">
                      <caption className="sr-only">Cloud KMS keys</caption>
                      <thead>
                        <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                          {COLUMNS.map((c) => (
                            <th
                              key={c.key}
                              scope="col"
                              className="py-2 pr-4"
                              aria-sort={
                                sort.key === c.key
                                  ? sort.dir === "asc"
                                    ? "ascending"
                                    : "descending"
                                  : "none"
                              }
                            >
                              <button
                                type="button"
                                onClick={() => toggleSort(c.key)}
                                className="inline-flex items-center gap-1 uppercase tracking-wide hover:text-foreground focus:outline-none focus:ring-2 focus:ring-ring/60"
                              >
                                {c.label}
                                {sort.key === c.key ? (
                                  sort.dir === "asc" ? (
                                    <ArrowUp size={11} aria-hidden="true" />
                                  ) : (
                                    <ArrowDown size={11} aria-hidden="true" />
                                  )
                                ) : null}
                              </button>
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {rows.map((k) => (
                          <tr
                            key={`${k.provider}|${k.location}|${k.key_id}`}
                            className="border-b border-border"
                          >
                            <td className="py-2 pr-4 text-foreground">
                              {providerLabel(k.provider ?? "")}
                            </td>
                            <td className="py-2 pr-4 text-foreground">
                              {k.location || "—"}
                            </td>
                            <td className="py-2 pr-4 font-mono text-xs text-foreground">
                              <span className="inline-flex items-center gap-1">
                                <span title={k.key_id}>
                                  {middleTruncate(k.key_id ?? "—")}
                                </span>
                                {k.key_id ? (
                                  <button
                                    type="button"
                                    onClick={() => copy(k.key_id ?? "")}
                                    aria-label={`Copy key id ${k.key_id}`}
                                    className="rounded p-1 text-muted-foreground hover:text-foreground focus:outline-none focus:ring-2 focus:ring-ring/60"
                                  >
                                    <Copy size={12} aria-hidden="true" />
                                  </button>
                                ) : null}
                              </span>
                            </td>
                            <td className="py-2 pr-4 text-foreground">
                              {k.algorithm || "—"}
                            </td>
                            <td className="py-2 pr-4 text-foreground">
                              {k.usage || "—"}
                            </td>
                            <td className="py-2 pr-4">
                              {k.state ? (
                                <Badge tone={stateTone(k.state)}>
                                  {k.state}
                                </Badge>
                              ) : (
                                "—"
                              )}
                            </td>
                            <td className="py-2 pr-4">
                              <Badge
                                tone={
                                  k.rotation_enabled ? "success" : "warning"
                                }
                              >
                                {k.rotation_enabled ? "Enabled" : "Not enabled"}
                              </Badge>
                            </td>
                            <td className="py-2 pr-4 text-foreground">
                              {k.created_at &&
                              !Number.isNaN(Date.parse(k.created_at))
                                ? new Date(k.created_at).toLocaleDateString()
                                : k.created_at || "—"}
                            </td>
                            <td className="py-2 pr-4">
                              <Badge tone={pqcTone(k.pqc_readiness)}>
                                {pqcLabel(k.pqc_readiness)}
                              </Badge>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <p className="mt-3 text-xs text-muted-foreground">
                  Showing {rows.length} of {keys.length}
                  {inv.generated_at
                    ? ` · generated ${new Date(inv.generated_at).toLocaleString()}`
                    : ""}
                </p>
              </Panel>
            </>
          )}
        </>
      )}
    </div>
  );
}
