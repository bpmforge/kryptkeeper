import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Plus,
  RotateCw,
  Download,
  Upload,
  Trash2,
  RefreshCw,
} from "lucide-react";
import { api } from "../lib/api";
import { useAuthz } from "../lib/auth";
import {
  runBulkAction,
  useBulkSelection,
  type BulkProgress,
} from "../lib/bulk";
import { TableRowsSkeleton } from "../components/Skeletons";
import {
  Badge,
  Button,
  Dialog,
  Input,
  Panel,
  Select,
  SectionLabel,
  StateMessage,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";

type KeyMeta = { id: string; algorithm: string; created_at: string };

const ALGORITHMS = [
  "ECDSA-P256",
  "ECDSA-P384",
  "Ed25519",
  "RSA-2048",
  "RSA-4096",
  "ML-DSA-44",
  "ML-DSA-65",
  "ML-DSA-87",
];

function algoTone(algo: string): "info" | "success" | "warning" | "neutral" {
  if (algo.startsWith("ML-DSA")) return "success";
  if (algo.startsWith("ECDSA") || algo === "Ed25519") return "info";
  if (algo.startsWith("RSA")) return "warning";
  return "neutral";
}

// A 202 under KRYPTKEEPER_KEY_DUAL_CONTROL returns {data:{status:"proposed"}}
// and means NOTHING happened yet — reporting it as done would be a lie.
function isDualControlProposal(data: unknown): boolean {
  return (
    typeof data === "object" &&
    data !== null &&
    (data as { data?: { status?: string } }).data?.status === "proposed"
  );
}

export default function Keys() {
  const qc = useQueryClient();
  const authz = useAuthz();
  // Mirrors the server's isAdminRole: every /api/v1/keys* endpoint requires
  // pki-admin, so a non-admin gets a read-only notice instead of a live
  // admin surface that 403s on every click.
  const isKeyAdmin = (authz.data?.role ?? "").trim() === "pki-admin";
  const [genOpen, setGenOpen] = useState(false);
  const [rotateId, setRotateId] = useState<string | null>(null);
  const [exportId, setExportId] = useState<string | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [genId, setGenId] = useState("");
  const [genAlgo, setGenAlgo] = useState("ECDSA-P256");
  const [rotateAlgo, setRotateAlgo] = useState("ECDSA-P256");
  const [exportPass, setExportPass] = useState("");
  const [importId, setImportId] = useState("");
  const [importPem, setImportPem] = useState("");
  const [importPass, setImportPass] = useState("");
  const keySelection = useBulkSelection<string>();
  const [bulkAction, setBulkAction] = useState<
    "bulk-rotate" | "bulk-delete" | null
  >(null);
  const [bulkRotateAlgo, setBulkRotateAlgo] = useState("ECDSA-P256");
  const [bulkProgress, setBulkProgress] = useState<BulkProgress | null>(null);
  const setError = (msg: string | null) => {
    if (msg) toast.error(msg);
  };
  const setSuccess = (msg: string) => toast.success(msg);

  const keysQ = useQuery({ queryKey: ["keys"], queryFn: api.keys });
  const keys = (keysQ.data?.data ?? []) as KeyMeta[];

  const invalidate = () => qc.invalidateQueries({ queryKey: ["keys"] });

  const generateMut = useMutation({
    mutationFn: () => api.generateKey({ id: genId.trim(), algorithm: genAlgo }),
    onSuccess: () => {
      setGenOpen(false);
      setGenId("");
      setSuccess("Key generated.");
      invalidate();
    },
    onError: (e: Error) => setError(e.message),
  });

  const rotateMut = useMutation({
    mutationFn: () => api.rotateKey(rotateId!, rotateAlgo),
    onSuccess: (data) => {
      setRotateId(null);
      if (isDualControlProposal(data)) {
        setSuccess(
          "Rotation proposed — key dual control is on, so a second approver must approve it before anything changes.",
        );
      } else {
        setSuccess("Key rotated. Old version archived.");
      }
      invalidate();
    },
    onError: (e: Error) => setError(e.message),
  });

  const exportMut = useMutation({
    mutationFn: () => api.exportKey(exportId!, exportPass),
    onSuccess: (data) => {
      if (data.proposed) {
        setExportId(null);
        setExportPass("");
        setSuccess(
          "Export proposed — key dual control is on, so a second approver must approve it before any key material moves.",
        );
        return;
      }
      const blob = new Blob([data.pem], { type: "application/x-pem-file" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `key-${exportId}-backup.pem`;
      a.click();
      URL.revokeObjectURL(url);
      setExportId(null);
      setExportPass("");
      setSuccess("Key exported. Store the backup passphrase securely.");
    },
    onError: (e: Error) => setError(e.message),
  });

  const importMut = useMutation({
    mutationFn: () =>
      api.importKey({
        id: importId.trim(),
        backup_pem: importPem.trim(),
        passphrase: importPass,
      }),
    onSuccess: () => {
      setImportOpen(false);
      setImportId("");
      setImportPem("");
      setImportPass("");
      setSuccess("Key imported.");
      invalidate();
    },
    onError: (e: Error) => setError(e.message),
  });

  const deleteMut = useMutation({
    mutationFn: () => api.deleteKey(deleteId!),
    onSuccess: (data) => {
      setDeleteId(null);
      if (isDualControlProposal(data)) {
        setSuccess(
          "Deletion proposed — key dual control is on, so a second approver must approve it before the key is removed.",
        );
      } else {
        setSuccess("Key deleted.");
      }
      invalidate();
    },
    onError: (e: Error) => setError(e.message),
  });

  const bulkRotateMut = useMutation({
    mutationFn: async () => {
      const ids = [...keySelection.selected];
      const errors = await runBulkAction(
        ids,
        (id) => api.rotateKey(id, bulkRotateAlgo),
        setBulkProgress,
      );
      return { total: ids.length, errors };
    },
    onSuccess: ({ total, errors }) => {
      if (errors.length > 0) {
        setError(`${errors.length} of ${total} rotations failed. First: ${errors[0]}`);
      } else {
        setSuccess(`${total} key${total !== 1 ? "s" : ""} rotated.`);
      }
      setBulkAction(null);
      setBulkProgress(null);
      keySelection.clear();
      invalidate();
    },
    onError: (e: Error) => {
      setError(e.message);
      setBulkProgress(null);
    },
  });

  const bulkDeleteMut = useMutation({
    mutationFn: async () => {
      const ids = [...keySelection.selected];
      const errors = await runBulkAction(
        ids,
        (id) => api.deleteKey(id),
        setBulkProgress,
      );
      return { total: ids.length, errors };
    },
    onSuccess: ({ total, errors }) => {
      if (errors.length > 0) {
        setError(`${errors.length} of ${total} deletions failed. First: ${errors[0]}`);
      } else {
        setSuccess(`${total} key${total !== 1 ? "s" : ""} deleted.`);
      }
      setBulkAction(null);
      setBulkProgress(null);
      keySelection.clear();
      invalidate();
    },
    onError: (e: Error) => {
      setError(e.message);
      setBulkProgress(null);
    },
  });

  const allKeysSelected =
    keys.length > 0 && keys.every((k) => keySelection.selected.includes(k.id));
  const selectedKeyCount = keySelection.selected.length;

  const openBulkAction = (next: "bulk-rotate" | "bulk-delete") => {
    setBulkAction(next);
    setBulkProgress(null);
  };

  if (authz.data && !isKeyAdmin) {
    return (
      <div className="p-6 space-y-6 max-w-5xl mx-auto fade-in-up">
        <PageHeader
          eyebrow="Inventory"
          title="Key Management"
          description="Generate, rotate, export and import cryptographic keys."
        />
        <StateMessage
          title="Admin role required"
          message="Key management requires the pki-admin role. Ask an administrator if you need a key generated, rotated or exported."
        />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto fade-in-up">
      <PageHeader
        eyebrow="Inventory"
        title="Key Management"
        description="Generate, rotate, export and import cryptographic keys."
        actions={
          <div className="flex gap-2">
            <Button tone="secondary" onClick={() => setImportOpen(true)}>
              <Upload size={14} /> Import
            </Button>
            <Button tone="primary" onClick={() => setGenOpen(true)}>
              <Plus size={14} /> Generate Key
            </Button>
          </div>
        }
      />

      {/* Key list */}
      <Panel
        title="Stored Keys"
        subtitle={`${keys.length} key${keys.length !== 1 ? "s" : ""} in the keystore`}
      >
        {keysQ.isLoading && <TableRowsSkeleton rows={4} />}
        {keysQ.error && (
          <StateMessage
            tone="error"
            title="Could not load keys"
            message={(keysQ.error as Error).message}
          />
        )}
        {!keysQ.isLoading && keys.length === 0 && (
          <StateMessage
            title="No keys yet"
            message="Generate your first key to get started."
          />
        )}
        {keys.length > 0 && (
          <>
            <div className="mb-3 flex flex-wrap items-center gap-2 text-sm text-foreground">
              <Button
                onClick={() => keySelection.toggleAll(keys.map((k) => k.id))}
              >
                {allKeysSelected ? "Clear selection" : "Select all"}
              </Button>
              <Button
                onClick={() => openBulkAction("bulk-rotate")}
                disabled={selectedKeyCount === 0}
              >
                <RotateCw size={13} /> Bulk rotate
              </Button>
              <Button
                tone="danger"
                onClick={() => openBulkAction("bulk-delete")}
                disabled={selectedKeyCount === 0}
              >
                <Trash2 size={13} /> Bulk delete
              </Button>
              <span className="text-muted-foreground">
                {selectedKeyCount} selected
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left">
                    <th className="pb-3 pr-4 text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                      Select
                    </th>
                    <th className="pb-3 pr-4 text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                      Key ID
                    </th>
                    <th className="pb-3 pr-4 text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                      Algorithm
                    </th>
                    <th className="pb-3 pr-4 text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                      Created
                    </th>
                    <th className="pb-3 text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {keys.map((k) => (
                    <tr
                      key={k.id}
                      className="group hover:bg-foreground/[0.02] transition"
                    >
                      <td className="py-3 pr-4">
                        <input
                          type="checkbox"
                          aria-label={`Select ${k.id}`}
                          checked={keySelection.selected.includes(k.id)}
                          onChange={() => keySelection.toggle(k.id)}
                          className="h-4 w-4 rounded border-border bg-background text-primary focus:ring-ring"
                        />
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs text-primary">
                        {k.id}
                      </td>
                      <td className="py-3 pr-4">
                        <Badge tone={algoTone(k.algorithm)}>
                          {k.algorithm}
                        </Badge>
                      </td>
                      <td className="py-3 pr-4 text-muted-foreground">
                        {k.created_at
                          ? new Date(k.created_at).toLocaleDateString()
                          : "—"}
                      </td>
                      <td className="py-3">
                        <div className="flex items-center gap-1.5 opacity-0 group-hover:opacity-100 transition">
                          <button
                            title="Rotate key"
                            onClick={() => {
                              setRotateId(k.id);
                              setRotateAlgo(k.algorithm);
                            }}
                            className="p-1.5 rounded-lg hover:bg-primary/10 hover:text-primary text-muted-foreground transition"
                          >
                            <RotateCw size={13} />
                          </button>
                          <button
                            title="Export backup"
                            onClick={() => {
                              setExportId(k.id);
                              setExportPass("");
                            }}
                            className="p-1.5 rounded-lg hover:bg-primary/10 hover:text-primary text-muted-foreground transition"
                          >
                            <Download size={13} />
                          </button>
                          <button
                            title="Delete key"
                            onClick={() => setDeleteId(k.id)}
                            className="p-1.5 rounded-lg hover:bg-state-over/10 hover:text-state-over text-muted-foreground transition"
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Panel>

      {/* Generate dialog */}
      <Dialog
        open={genOpen}
        title="Generate New Key"
        description="The private key will be encrypted at rest with Argon2id + AES-256-GCM."
        onClose={() => setGenOpen(false)}
      >
        <div className="space-y-4">
          <div>
            <SectionLabel>Key ID</SectionLabel>
            <Input
              className="mt-1.5"
              placeholder="e.g. root-ca-2026"
              value={genId}
              onChange={(e) => setGenId(e.target.value)}
            />
          </div>
          <div>
            <SectionLabel>Algorithm</SectionLabel>
            <Select
              className="mt-1.5"
              value={genAlgo}
              onChange={(e) => setGenAlgo(e.target.value)}
            >
              {ALGORITHMS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </Select>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={() => setGenOpen(false)}>Cancel</Button>
            <Button
              tone="primary"
              disabled={!genId.trim() || generateMut.isPending}
              onClick={() => generateMut.mutate()}
            >
              {generateMut.isPending ? "Generating…" : "Generate"}
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Rotate dialog */}
      <Dialog
        open={!!rotateId}
        title={`Rotate Key — ${rotateId}`}
        description="A new key pair will be generated. The old key is archived (not deleted) for disaster recovery."
        onClose={() => setRotateId(null)}
      >
        <div className="space-y-4">
          <div>
            <SectionLabel>New Algorithm</SectionLabel>
            <Select
              className="mt-1.5"
              value={rotateAlgo}
              onChange={(e) => setRotateAlgo(e.target.value)}
            >
              {ALGORITHMS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </Select>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={() => setRotateId(null)}>Cancel</Button>
            <Button
              tone="primary"
              disabled={rotateMut.isPending}
              onClick={() => rotateMut.mutate()}
            >
              <RefreshCw size={13} />{" "}
              {rotateMut.isPending ? "Rotating…" : "Rotate Key"}
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Export dialog */}
      <Dialog
        open={!!exportId}
        title={`Export Key Backup — ${exportId}`}
        description="Enter a backup passphrase. This is separate from the keystore passphrase. Store it securely — it cannot be recovered."
        onClose={() => setExportId(null)}
      >
        <div className="space-y-4">
          <div>
            <SectionLabel>Backup Passphrase</SectionLabel>
            <Input
              type="password"
              className="mt-1.5"
              placeholder="Strong passphrase…"
              value={exportPass}
              onChange={(e) => setExportPass(e.target.value)}
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={() => setExportId(null)}>Cancel</Button>
            <Button
              tone="primary"
              disabled={!exportPass || exportMut.isPending}
              onClick={() => exportMut.mutate()}
            >
              <Download size={13} />{" "}
              {exportMut.isPending ? "Exporting…" : "Download Backup"}
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Import dialog */}
      <Dialog
        open={importOpen}
        title="Import Key Backup"
        description="Paste the backup PEM and enter the passphrase used when the backup was created."
        onClose={() => setImportOpen(false)}
      >
        <div className="space-y-4">
          <div>
            <SectionLabel>Key ID</SectionLabel>
            <Input
              className="mt-1.5"
              placeholder="e.g. root-ca-2026"
              value={importId}
              onChange={(e) => setImportId(e.target.value)}
            />
          </div>
          <div>
            <SectionLabel>Backup PEM</SectionLabel>
            <textarea
              className="mt-1.5 w-full rounded-xl border border-border bg-background px-3 py-2 text-xs font-mono text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring h-32 resize-none"
              placeholder="-----BEGIN KRYPTKEEPER BACKUP KEY-----"
              value={importPem}
              onChange={(e) => setImportPem(e.target.value)}
            />
          </div>
          <div>
            <SectionLabel>Backup Passphrase</SectionLabel>
            <Input
              type="password"
              className="mt-1.5"
              value={importPass}
              onChange={(e) => setImportPass(e.target.value)}
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={() => setImportOpen(false)}>Cancel</Button>
            <Button
              tone="primary"
              disabled={
                !importId.trim() ||
                !importPem.trim() ||
                !importPass ||
                importMut.isPending
              }
              onClick={() => importMut.mutate()}
            >
              <Upload size={13} />{" "}
              {importMut.isPending ? "Importing…" : "Import Key"}
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Delete confirm */}
      <Dialog
        open={!!deleteId}
        title="Delete Key"
        description={`This permanently removes "${deleteId}" from the keystore. Any CA using this key will stop working. This cannot be undone.`}
        onClose={() => setDeleteId(null)}
      >
        <div className="flex justify-end gap-2">
          <Button onClick={() => setDeleteId(null)}>Cancel</Button>
          <Button
            tone="danger"
            disabled={deleteMut.isPending}
            onClick={() => deleteMut.mutate()}
          >
            {deleteMut.isPending ? "Deleting…" : "Delete Key"}
          </Button>
        </div>
      </Dialog>

      {/* Bulk rotate confirm */}
      <Dialog
        open={bulkAction === "bulk-rotate"}
        title={`Bulk Rotate ${selectedKeyCount} Key${selectedKeyCount !== 1 ? "s" : ""}`}
        description="Each selected key is rotated individually with the chosen algorithm. Old versions are archived, not deleted."
        onClose={() => {
          setBulkAction(null);
          setBulkProgress(null);
        }}
      >
        <div className="space-y-4">
          <div>
            <SectionLabel>New Algorithm</SectionLabel>
            <Select
              className="mt-1.5"
              value={bulkRotateAlgo}
              onChange={(e) => setBulkRotateAlgo(e.target.value)}
            >
              {ALGORITHMS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </Select>
          </div>
          {bulkProgress ? (
            <div className="rounded-xl border border-border bg-background/60 p-3 text-sm text-foreground">
              <div className="mb-1 font-medium">
                Progress: {bulkProgress.done} / {bulkProgress.total}
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-2 rounded-full bg-primary transition-all"
                  style={{
                    width: `${Math.round((bulkProgress.done / bulkProgress.total) * 100)}%`,
                  }}
                />
              </div>
              {bulkProgress.errors.length > 0 ? (
                <div className="mt-2 text-state-over">
                  {bulkProgress.errors.length} failed so far
                </div>
              ) : null}
            </div>
          ) : null}
          <div className="flex justify-end gap-2 pt-2">
            <Button
              onClick={() => {
                setBulkAction(null);
                setBulkProgress(null);
              }}
            >
              Cancel
            </Button>
            <Button
              tone="primary"
              disabled={bulkRotateMut.isPending}
              onClick={() => bulkRotateMut.mutate()}
            >
              <RefreshCw size={13} />{" "}
              {bulkRotateMut.isPending
                ? "Rotating…"
                : `Rotate ${selectedKeyCount}`}
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Bulk delete confirm */}
      <Dialog
        open={bulkAction === "bulk-delete"}
        title={`Bulk Delete ${selectedKeyCount} Key${selectedKeyCount !== 1 ? "s" : ""}`}
        description="This permanently removes the selected keys from the keystore. Any CA using one of them will stop working. This cannot be undone."
        onClose={() => {
          setBulkAction(null);
          setBulkProgress(null);
        }}
      >
        <div className="space-y-4">
          {bulkProgress ? (
            <div className="rounded-xl border border-border bg-background/60 p-3 text-sm text-foreground">
              <div className="mb-1 font-medium">
                Progress: {bulkProgress.done} / {bulkProgress.total}
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-2 rounded-full bg-state-over transition-all"
                  style={{
                    width: `${Math.round((bulkProgress.done / bulkProgress.total) * 100)}%`,
                  }}
                />
              </div>
              {bulkProgress.errors.length > 0 ? (
                <div className="mt-2 text-state-over">
                  {bulkProgress.errors.length} failed so far
                </div>
              ) : null}
            </div>
          ) : null}
          <div className="flex justify-end gap-2">
            <Button
              onClick={() => {
                setBulkAction(null);
                setBulkProgress(null);
              }}
            >
              Cancel
            </Button>
            <Button
              tone="danger"
              disabled={bulkDeleteMut.isPending}
              onClick={() => bulkDeleteMut.mutate()}
            >
              {bulkDeleteMut.isPending
                ? "Deleting…"
                : `Delete ${selectedKeyCount}`}
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
