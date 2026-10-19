import { useState } from "react";
import { scrollableProps } from "../lib/scrollable";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Plus,
  RotateCw,
  Download,
  Upload,
  Trash2,
  RefreshCw,
  Undo2,
  ShieldCheck,
  ShieldAlert,
} from "lucide-react";
import { api, fetchJSON, type GrantResult, type KeyPolicy } from "../lib/api";
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
  Textarea,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { BlastRadiusPanel } from "../components/BlastRadiusPanel";

type KeyMeta = {
  id: string;
  algorithm: string;
  created_at: string;
  state?: "active" | "pending_deletion";
  deletion_scheduled_at?: string;
};

const ALGORITHMS = [
  "ECDSA-P256",
  "ECDSA-P384",
  "Ed25519",
  "RSA-2048",
  "RSA-3072",
  "RSA-4096",
  "ML-DSA-44",
  "ML-DSA-65",
  "ML-DSA-87",
];

// One principal per line or comma separated; trimmed and de-duplicated.
function parseAcl(text: string): string[] {
  return [
    ...new Set(
      text
        .split(/[\n,]/)
        .map((p) => p.trim())
        .filter(Boolean),
    ),
  ];
}

// Must match PQCCustodyStatement in internal/bootstrap/handlers_key_custody.go
// (ADR D-086); a Go test fails on drift. Keep on one line.
const PQC_CUSTODY_STATEMENT = "ML-DSA and hybrid keys are generated and held in the software keystore only (Argon2id + AES-256-GCM). HSM, KMS and Vault backends refuse them with a citation of docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md (D-086). Hardware-backed PQC key custody is not provided.";

type MetaFips = {
  fips?: { mode_140_3?: boolean; enforced?: boolean; module_version?: string };
};

function fipsLine(meta: MetaFips | undefined): string {
  const f = meta?.fips;
  if (!f) return "FIPS posture unavailable.";
  if (!f.mode_140_3) {
    return "FIPS 140-3 mode is off. ML-DSA runs in software and is not covered by a validated module.";
  }
  if (f.enforced) {
    return "FIPS 140-3 enforced mode: ML-DSA and hybrid keys are refused.";
  }
  return `FIPS 140-3 mode is on (module ${f.module_version ?? ""}). ML-DSA runs in software outside the validated Go module; hybrid keys are refused.`;
}

function PqcCustodyNotice() {
  const metaQ = useQuery({
    queryKey: ["meta-fips"],
    queryFn: () => fetchJSON<MetaFips>("/meta"),
    retry: false,
  });
  return (
    <section aria-label="PQC key custody" className="space-y-2 text-sm">
      <p>{PQC_CUSTODY_STATEMENT}</p>
      <p className="text-xs text-muted-foreground">
        Decision record: <code>docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md</code>
      </p>
      <p className="text-xs text-muted-foreground">
        {metaQ.isError ? fipsLine(undefined) : fipsLine(metaQ.data)}
      </p>
    </section>
  );
}

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

type GrantKind = "escrow" | "recover" | "byok";

// One dual-control request tracked client-side. Passphrases are never kept;
// the bundle is dual-custody ciphertext, retained only so the redeem call
// re-sends the identical bytes the proposal digest was computed over.
type GrantEntry = {
  actionId: string;
  kind: GrantKind;
  label: string;
  bundleText: string;
  keyId: string;
  provider: string;
  region: string;
  redeemed: boolean;
};

const GRANT_TITLES: Record<GrantKind, string> = {
  escrow: "Escrow key",
  recover: "Recover escrowed key",
  byok: "BYOK export",
};

function grantStatusLabel(status: string | undefined): string {
  switch (status) {
    case "approved":
      return "Approved - redeem now";
    case "rejected":
      return "Rejected";
    case "failed":
      return "Failed";
    default:
      return "Pending approval";
  }
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
  const [cancelId, setCancelId] = useState<string | null>(null);
  const [genId, setGenId] = useState("");
  const [genAlgo, setGenAlgo] = useState("ECDSA-P256");
  const [rotateAlgo, setRotateAlgo] = useState("ECDSA-P256");
  const [exportPass, setExportPass] = useState("");
  const [importId, setImportId] = useState("");
  const [importPem, setImportPem] = useState("");
  const [importPass, setImportPass] = useState("");
  const [grantKind, setGrantKind] = useState<GrantKind | null>(null);
  const [redeemFor, setRedeemFor] = useState<string | null>(null);
  const [grants, setGrants] = useState<GrantEntry[]>([]);
  const [gKeyId, setGKeyId] = useState("");
  const [gBundle, setGBundle] = useState("");
  const [gPassA, setGPassA] = useState("");
  const [gPassB, setGPassB] = useState("");
  const [gProvider, setGProvider] = useState("aws");
  const [gRegion, setGRegion] = useState("");
  const [gDest, setGDest] = useState("");
  // W23-40: policy (owner/ACL/max-age) and compromise flow.
  const [policyId, setPolicyId] = useState<string | null>(null);
  const [polOwner, setPolOwner] = useState("");
  const [polAcl, setPolAcl] = useState("");
  const [polMaxAge, setPolMaxAge] = useState("0");
  const [polError, setPolError] = useState<string | null>(null);
  const [policies, setPolicies] = useState<Record<string, KeyPolicy>>({});
  const [compromiseId, setCompromiseId] = useState<string | null>(null);
  const [compromiseConfirm, setCompromiseConfirm] = useState("");
  const [compromiseProposals, setCompromiseProposals] = useState<
    { keyId: string; actionId?: string }[]
  >([]);
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

  const [polLoading, setPolLoading] = useState(false);
  const [polLoaded, setPolLoaded] = useState(false);
  const [polLoadError, setPolLoadError] = useState<string | null>(null);
  const [polExists, setPolExists] = useState(true);

  // Lazy: only when the dialog opens, never per row.
  const openPolicy = (id: string) => {
    setPolError(null);
    setPolLoadError(null);
    setPolOwner("");
    setPolAcl("");
    setPolMaxAge("0");
    setPolLoaded(false);
    setPolLoading(true);
    setPolicyId(id);
    api
      .keyPolicy(id)
      .then((res) => {
        const pol = res?.data;
        setPolExists(!!pol);
        setPolOwner(pol?.owner ?? "");
        setPolAcl((pol?.acl ?? []).join("\n"));
        setPolMaxAge(String(pol?.max_age_days ?? 0));
        if (pol) setPolicies((m) => ({ ...m, [id]: pol }));
        setPolLoaded(true);
      })
      .catch((e: Error) => setPolLoadError(e.message))
      .finally(() => setPolLoading(false));
  };

  const policyMut = useMutation({
    mutationFn: async () => {
      const owner = polOwner.trim();
      const maxAge = Number(polMaxAge);
      if (!owner) throw new Error("Owner is required.");
      if (polMaxAge.trim() === "" || !Number.isInteger(maxAge) || maxAge < 0) {
        throw new Error("Max age must be a whole number of days, 0 or more.");
      }
      return api.setKeyPolicy(policyId!, {
        owner,
        acl: parseAcl(polAcl),
        max_age_days: maxAge,
      });
    },
    onSuccess: (res) => {
      if (res?.data && policyId) {
        const saved = res.data;
        setPolicies((m) => ({ ...m, [policyId]: saved }));
      }
      setPolicyId(null);
      toast.success("Key policy saved");
      invalidate();
    },
    onError: (e: Error) => setPolError(e.message),
  });

  // Always dual control: a 202 means "proposed". The key is never marked
  // compromised locally; that happens only after a second admin approves.
  const compromiseMut = useMutation({
    mutationFn: () => api.compromiseKey(compromiseId!),
    onSuccess: (res) => {
      const keyId = compromiseId!;
      setCompromiseId(null);
      setCompromiseProposals((p) => [...p, { keyId, actionId: res.actionId }]);
      toast.success(
        "Compromise proposed - a second approver must approve it in Pending Actions before anything changes.",
      );
      invalidate();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // Server-side status of our open proposals (and the bundle digest the
  // approver sees under Pending Actions).
  const hasOpenGrants = grants.some((g) => !g.redeemed);
  const grantsQ = useQuery({
    queryKey: ["pending-actions", "key-grants"],
    queryFn: () => api.pendingActions(),
    enabled: hasOpenGrants,
    refetchInterval: 5000,
  });
  const grantRow = (actionId: string) =>
    (grantsQ.data?.data ?? []).find((a) => a.id === actionId);

  const clearGrantForm = () => {
    setGPassA("");
    setGPassB("");
    setGKeyId("");
    setGBundle("");
    setGRegion("");
    setGDest("");
    setGProvider("aws");
  };

  const openGrant = (kind: GrantKind, entry?: GrantEntry) => {
    clearGrantForm();
    setRedeemFor(entry?.actionId ?? null);
    if (entry) {
      setGKeyId(entry.keyId);
      setGBundle(entry.bundleText);
      setGProvider(entry.provider || "aws");
      setGRegion(entry.region);
      setGDest(entry.keyId);
    }
    setGrantKind(kind);
  };

  const closeGrant = () => {
    clearGrantForm();
    setRedeemFor(null);
    setGrantKind(null);
  };

  const grantMut = useMutation({
    mutationFn: async () => {
      const kind = grantKind!;
      const redeem = redeemFor;
      const common = {
        custodian_a_passphrase: gPassA,
        custodian_b_passphrase: gPassB,
        ...(redeem ? { approved_action_id: redeem } : {}),
      };
      if (gPassA === gPassB) {
        throw new Error(
          "Custodian passphrases must differ - dual control needs two secrets.",
        );
      }
      let res: GrantResult<unknown>;
      if (kind === "escrow") {
        res = await api.escrowKey({ key_id: gKeyId, ...common });
      } else {
        let bundle: unknown;
        try {
          bundle = JSON.parse(gBundle);
        } catch {
          throw new Error("The escrow bundle is not valid JSON.");
        }
        res =
          kind === "recover"
            ? await api.recoverEscrowedKey({ bundle, ...common })
            : await api.byokExport({
                bundle,
                provider: gProvider,
                ...(gRegion.trim() ? { region: gRegion.trim() } : {}),
                key_id: gDest.trim(),
                ...common,
              });
      }
      return {
        kind,
        redeem,
        res,
        entry: {
          kind,
          label: GRANT_TITLES[kind],
          bundleText: gBundle,
          keyId: kind === "byok" ? gDest.trim() : gKeyId,
          provider: gProvider,
          region: gRegion.trim(),
        },
      };
    },
    onSuccess: ({ kind, redeem, res, entry }) => {
      closeGrant();
      if (res.state === "pending") {
        setGrants((prev) => [
          ...prev,
          { ...entry, actionId: res.actionId, redeemed: false },
        ]);
        setSuccess(
          `${GRANT_TITLES[kind]} proposed - pending approval. A different administrator must approve it in Pending Actions before anything happens.`,
        );
        return;
      }
      if (redeem) {
        setGrants((prev) =>
          prev.map((g) =>
            g.actionId === redeem ? { ...g, bundleText: "", redeemed: true } : g,
          ),
        );
      }
      if (kind === "escrow") {
        const blob = new Blob([res.data as string], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `escrow-${entry.keyId}.json`;
        a.click();
        URL.revokeObjectURL(url);
        setSuccess("Escrow bundle downloaded. Give each custodian only their own passphrase.");
      } else if (kind === "recover") {
        setSuccess("Key recovered under its original ID.");
        invalidate();
      } else {
        setSuccess("Key material imported into the destination KMS.");
      }
    },
    onError: (e: Error) => {
      // Passphrases never outlive the submit, success or not.
      setGPassA("");
      setGPassB("");
      setError(e.message);
    },
  });

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

  const cancelMut = useMutation({
    mutationFn: () => api.cancelKeyDeletion(cancelId!),
    onSuccess: (data) => {
      setCancelId(null);
      if (isDualControlProposal(data)) {
        setSuccess(
          "Cancellation proposed — a second approver must approve it in Pending Actions before the key returns to service.",
        );
      } else {
        setSuccess("Deletion cancelled. Key re-enabled.");
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

  const liveKeys = keys.filter((k) => k.state !== "pending_deletion");
  const allKeysSelected =
    liveKeys.length > 0 &&
    liveKeys.every((k) => keySelection.selected.includes(k.id));
  const selectedKeyCount = keySelection.selected.length;

  const openBulkAction = (next: "bulk-rotate" | "bulk-delete") => {
    setBulkAction(next);
    setBulkProgress(null);
  };

  if (authz.data && !isKeyAdmin) {
    return (
      <div className="p-6 space-y-6 fade-in-up">
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
    <div className="p-6 space-y-6 fade-in-up">
      <PageHeader
        eyebrow="Inventory"
        title="Key Management"
        description="Generate, rotate, export and import cryptographic keys."
        actions={
          <div className="flex flex-wrap gap-2">
            <Button tone="secondary" onClick={() => openGrant("escrow")}>
              Escrow
            </Button>
            <Button tone="secondary" onClick={() => openGrant("recover")}>
              Recover
            </Button>
            <Button tone="secondary" onClick={() => openGrant("byok")}>
              BYOK export
            </Button>
            <Button tone="secondary" onClick={() => setImportOpen(true)}>
              <Upload size={14} /> Import
            </Button>
            <Button tone="primary" onClick={() => setGenOpen(true)}>
              <Plus size={14} /> Generate Key
            </Button>
          </div>
        }
      />

      {grants.length > 0 && (
        <Panel
          title="Approval status"
          subtitle="Escrow, recovery and BYOK export need a second administrator"
        >
          <ul className="space-y-3 text-sm">
            {grants.map((g) => {
              const row = grantRow(g.actionId);
              const digest = (row?.params as { bundle_sha256?: string } | undefined)
                ?.bundle_sha256;
              const status = g.redeemed ? undefined : row?.status;
              return (
                <li
                  key={g.actionId}
                  data-testid={`grant-${g.actionId}`}
                  className="rounded-xl border border-border bg-background/60 p-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <span className="font-medium text-foreground">{g.label}</span>{" "}
                      <span className="font-mono text-xs text-muted-foreground">
                        {g.actionId}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge tone={g.redeemed ? "success" : status === "approved" ? "info" : "warning"}>
                        {g.redeemed ? "Redeemed" : grantStatusLabel(status)}
                      </Badge>
                      {!g.redeemed && status === "approved" && (
                        <Button tone="primary" onClick={() => openGrant(g.kind, g)}>
                          Redeem
                        </Button>
                      )}
                    </div>
                  </div>
                  {digest && (
                    <div className="mt-2 text-xs text-muted-foreground">
                      SHA-256 of bundle:{" "}
                      <span
                        data-testid="bundle-digest"
                        className="font-mono text-foreground"
                      >
                        {digest}
                      </span>
                      <div>
                        The approver sees this same digest under Pending
                        Actions; compare them before approving.
                      </div>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </Panel>
      )}

      {keys.some(
        (k) => k.algorithm.startsWith("ML-DSA") || k.algorithm.startsWith("Hybrid"),
      ) && (
        <Panel title="PQC key custody">
          <PqcCustodyNotice />
        </Panel>
      )}

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
                onClick={() => keySelection.toggleAll(liveKeys.map((k) => k.id))}
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
            <div className="overflow-x-auto" {...scrollableProps}>
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
                  {keys.map((k) => {
                    const pendingDeletion = k.state === "pending_deletion";
                    return (
                    <tr
                      key={k.id}
                      className="group hover:bg-foreground/[0.02] transition"
                    >
                      <td className="py-3 pr-4">
                        <input
                          type="checkbox"
                          aria-label={`Select ${k.id}`}
                          checked={keySelection.selected.includes(k.id)}
                          disabled={pendingDeletion}
                          onChange={() => keySelection.toggle(k.id)}
                          className="h-4 w-4 rounded border-border bg-background text-primary focus:ring-ring"
                        />
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs text-primary">
                        {k.id}
                      </td>
                      <td className="py-3 pr-4">
                        <span
                          title={
                            k.algorithm.startsWith("ML-DSA") ||
                            k.algorithm.startsWith("Hybrid")
                              ? PQC_CUSTODY_STATEMENT
                              : undefined
                          }
                        >
                          <Badge tone={algoTone(k.algorithm)}>
                            {k.algorithm}
                          </Badge>
                        </span>
                        {policies[k.id]?.compromised_at ? (
                          <div className="mt-1">
                            <Badge tone="danger">compromised</Badge>
                          </div>
                        ) : null}
                        {policies[k.id] ? (
                          <div className="mt-1 text-xs text-muted-foreground">
                            Owner {policies[k.id].owner || "—"} · max age{" "}
                            {policies[k.id].max_age_days
                              ? `${policies[k.id].max_age_days}d`
                              : "never"}
                          </div>
                        ) : null}
                        {pendingDeletion && (
                          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                            <Badge tone="warning">Pending deletion</Badge>
                            <span>
                              Deletes{" "}
                              {k.deletion_scheduled_at
                                ? new Date(
                                    k.deletion_scheduled_at,
                                  ).toLocaleDateString()
                                : "—"}
                            </span>
                          </div>
                        )}
                      </td>
                      <td className="py-3 pr-4 text-muted-foreground whitespace-nowrap">
                        {k.created_at
                          ? new Date(k.created_at).toLocaleDateString()
                          : "—"}
                      </td>
                      <td className="py-3">
                        {pendingDeletion ? (
                          <button
                            title="Cancel deletion"
                            aria-label="Cancel deletion"
                            onClick={() => setCancelId(k.id)}
                            className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-primary hover:bg-primary/10 transition"
                          >
                            <Undo2 size={13} /> Cancel deletion
                          </button>
                        ) : (
                        <div className="flex items-center gap-1.5 opacity-70 group-hover:opacity-100 focus-within:opacity-100 transition">
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
                            title="Key policy"
                            aria-label={`Policy ${k.id}`}
                            onClick={() => openPolicy(k.id)}
                            className="p-1.5 rounded-lg hover:bg-primary/10 hover:text-primary text-muted-foreground transition"
                          >
                            <ShieldCheck size={13} />
                          </button>
                          <button
                            title="Mark compromised"
                            aria-label={`Compromised ${k.id}`}
                            onClick={() => {
                              compromiseMut.reset();
                              setCompromiseConfirm("");
                              setCompromiseId(k.id);
                            }}
                            className="p-1.5 rounded-lg hover:bg-state-over/10 hover:text-state-over text-muted-foreground transition"
                          >
                            <ShieldAlert size={13} />
                          </button>
                          <button
                            title="Delete key"
                            onClick={() => setDeleteId(k.id)}
                            className="p-1.5 rounded-lg hover:bg-state-over/10 hover:text-state-over text-muted-foreground transition"
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                        )}
                      </td>
                    </tr>
                    );
                  })}
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
            {genAlgo.startsWith("ML-DSA") && (
              <div className="mt-2">
                <PqcCustodyNotice />
              </div>
            )}
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

      {compromiseProposals.map((p) => (
        <StateMessage
          key={`${p.keyId}-${p.actionId ?? ""}`}
          title={`Compromise of ${p.keyId} pending approval`}
          message={`A different administrator must approve${
            p.actionId ? ` action ${p.actionId}` : " the proposal"
          } in Pending Actions. Nothing has changed yet.`}
        />
      ))}

      {/* Policy dialog */}
      <Dialog
        open={!!policyId}
        title={`Key policy — ${policyId}`}
        description="Owner, ACL and maximum age. Once a policy exists, rotate, delete and export are limited to the owner and ACL principals."
        onClose={() => setPolicyId(null)}
      >
        <form
          noValidate
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            setPolError(null);
            policyMut.mutate();
          }}
        >
          {polLoadError ? (
            <StateMessage
              tone="error"
              title="Could not load policy"
              message={polLoadError}
            />
          ) : null}
          {polLoaded && !polExists ? (
            <p className="text-sm text-muted-foreground">
              This key has no policy yet.
            </p>
          ) : null}
          <label className="block space-y-1.5 text-sm">
            <SectionLabel>Owner</SectionLabel>
            <Input
              aria-label="Owner"
              disabled={polLoading}
              value={polOwner}
              onChange={(e) => setPolOwner(e.target.value)}
            />
          </label>
          <label className="block space-y-1.5 text-sm">
            <SectionLabel>ACL (one principal per line or comma separated)</SectionLabel>
            <Textarea
              aria-label="ACL"
              disabled={polLoading}
              rows={3}
              value={polAcl}
              onChange={(e) => setPolAcl(e.target.value)}
            />
          </label>
          <label className="block space-y-1.5 text-sm">
            <SectionLabel>Max age days (0 = never)</SectionLabel>
            <Input
              aria-label="Max age days"
              disabled={polLoading}
              type="number"
              min={0}
              value={polMaxAge}
              onChange={(e) => setPolMaxAge(e.target.value)}
            />
          </label>
          {polError ? (
            <StateMessage tone="error" title="Policy not saved" message={polError} />
          ) : null}
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" onClick={() => setPolicyId(null)}>
              Cancel
            </Button>
            <Button
              tone="primary"
              type="submit"
              disabled={policyMut.isPending || polLoading}
            >
              {policyMut.isPending ? "Saving…" : "Save policy"}
            </Button>
          </div>
        </form>
      </Dialog>

      {/* Compromise dialog */}
      <Dialog
        open={!!compromiseId}
        title={`Mark compromised — ${compromiseId}`}
        description="Marks the key compromised, force-rotates it first, revokes every certificate issued under the old key and re-issues where a managed target exists. Irreversible; a second administrator must approve."
        onClose={() => setCompromiseId(null)}
      >
        <div className="space-y-4 text-sm">
          <label className="block space-y-1.5">
            <span>
              Type <strong>{compromiseId}</strong> to confirm
            </span>
            <Input
              aria-label="Confirm key id"
              value={compromiseConfirm}
              onChange={(e) => setCompromiseConfirm(e.target.value)}
            />
          </label>
          {compromiseId ? (
            <BlastRadiusPanel
              action="revoke"
              target={compromiseId}
              confirmLabel="Propose compromise"
              confirming={compromiseMut.isPending}
              confirmDisabled={compromiseConfirm !== compromiseId}
              onConfirm={() => compromiseMut.mutate()}
              onCancel={() => setCompromiseId(null)}
            />
          ) : null}
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

      {/* Escrow / recover / BYOK (dual control) */}
      <Dialog
        open={grantKind !== null}
        title={grantKind ? GRANT_TITLES[grantKind] + (redeemFor ? " - redeem" : "") : ""}
        description={
          grantKind === "escrow"
            ? "Splits the key between two custodians. Requires a second approver."
            : grantKind === "recover"
              ? "Restores a key from an escrow bundle using both custodian passphrases. Requires a second approver."
              : "Wraps an escrowed root and imports it into your KMS. Requires an approver-role administrator and a second approver."
        }
        onClose={closeGrant}
      >
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            grantMut.mutate();
          }}
        >
          {grantKind === "escrow" && (
            <label className="block space-y-1 text-sm text-foreground">
              <span>Key to escrow</span>
              <Select
                value={gKeyId}
                onChange={(e) => setGKeyId(e.target.value)}
                required
              >
                <option value="">Select a key</option>
                {keys.map((k) => (
                  <option key={k.id} value={k.id}>
                    {k.id}
                  </option>
                ))}
              </Select>
            </label>
          )}
          {(grantKind === "recover" || grantKind === "byok") && (
            <label className="block space-y-1 text-sm text-foreground">
              <span>Escrow bundle (JSON)</span>
              <Textarea
                value={gBundle}
                onChange={(e) => setGBundle(e.target.value)}
                rows={6}
                className="font-mono text-xs"
                required
              />
            </label>
          )}
          {grantKind === "byok" && (
            <>
              <label className="block space-y-1 text-sm text-foreground">
                <span>Provider</span>
                <Select value={gProvider} onChange={(e) => setGProvider(e.target.value)}>
                  <option value="aws">AWS KMS</option>
                </Select>
              </label>
              <label className="block space-y-1 text-sm text-foreground">
                <span>Region</span>
                <Input
                  value={gRegion}
                  onChange={(e) => setGRegion(e.target.value)}
                  placeholder="us-east-1"
                />
              </label>
              <label className="block space-y-1 text-sm text-foreground">
                <span>Destination KMS key ID</span>
                <Input
                  value={gDest}
                  onChange={(e) => setGDest(e.target.value)}
                  required
                />
              </label>
            </>
          )}
          <label className="block space-y-1 text-sm text-foreground">
            <span>Custodian A passphrase</span>
            <Input
              type="password"
              autoComplete="off"
              value={gPassA}
              onChange={(e) => setGPassA(e.target.value)}
              required
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Custodian B passphrase</span>
            <Input
              type="password"
              autoComplete="off"
              value={gPassB}
              onChange={(e) => setGPassB(e.target.value)}
              required
            />
          </label>
          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={closeGrant}>Cancel</Button>
            <Button tone="primary" type="submit" disabled={grantMut.isPending}>
              {grantMut.isPending
                ? "Submitting…"
                : redeemFor
                  ? "Redeem approved action"
                  : "Submit for approval"}
            </Button>
          </div>
        </form>
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

      {/* Cancel scheduled deletion */}
      <Dialog
        open={!!cancelId}
        title={`Cancel deletion — ${cancelId}`}
        description="Restores this key at the provider. With dual control on, a different administrator must approve the cancellation in Pending Actions before the key returns to service."
        onClose={() => setCancelId(null)}
      >
        <div className="flex justify-end gap-2">
          <Button onClick={() => setCancelId(null)}>Keep scheduled</Button>
          <Button
            tone="primary"
            disabled={cancelMut.isPending}
            onClick={() => cancelMut.mutate()}
          >
            {cancelMut.isPending ? "Cancelling…" : "Confirm cancel deletion"}
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
