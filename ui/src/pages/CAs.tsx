import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { api } from "../lib/api";
import {
  Badge,
  Button,
  Dialog,
  Input,
  Panel,
  Select,
  StateMessage,
} from "../components/ops-ui";
import { Textarea } from "../components/ui";
import { BlastRadiusPanel } from "../components/BlastRadiusPanel";
import { Wizard, type WizardStepDef } from "../components/Wizard";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";
import { canManageCAs, useAuthz } from "../lib/auth";
import { extractList } from "../lib/models";
import { humanizeEnum } from "../lib/utils";
import type { CaRecord, PendingAction, RotateCaKeyResult } from "../lib/models";

type CANode = CaRecord & { children: CANode[] };

function noCasDescription(canManage: boolean): string {
  return canManage
    ? "Create a root CA to establish your first trust anchor."
    : "Ask an administrator to create a root CA.";
}

function buildTree(cas: CaRecord[]): CANode[] {
  const map = new Map<string, CANode>();
  for (const ca of cas) map.set(ca.id, { ...ca, children: [] });
  const roots: CANode[] = [];
  for (const ca of cas) {
    const node = map.get(ca.id)!;
    const parent = ca.parent_ca_id ? map.get(ca.parent_ca_id) : undefined;
    if (parent) parent.children.push(node);
    else roots.push(node);
  }
  return roots;
}

function CATreeNode({
  node,
  depth,
  navigate,
}: {
  node: CANode;
  depth: number;
  navigate: (path: string) => void;
}): ReactNode {
  return (
    <div style={{ paddingLeft: depth * 24 }}>
      <button
        type="button"
        onClick={() => navigate(`/cas/${node.id}`)}
        className="mb-1 flex w-full items-center gap-3 rounded-xl border border-border bg-background/60 px-4 py-2.5 text-left text-sm transition hover:border-primary focus:outline-none focus:ring-2 focus:ring-ring"
      >
        {depth > 0 && <span className="text-muted-foreground select-none">└─</span>}
        {/* Literal spaces between the spans: the button's name comes from its
            content, and without them the name runs together ("acme-rootrootactive"). */}
        <span className="font-medium text-foreground flex-1">
          {node.display_name || node.name || node.id}
        </span>{" "}
        <span className="text-xs text-muted-foreground">{humanizeEnum(node.type)}</span>{" "}
        {node.type === "external" ? <Badge tone="neutral">External</Badge> : null}{" "}
        {node.active_issued_certificates != null && (
          <>
            <span className="text-xs text-muted-foreground">
              {node.active_issued_certificates} certs
            </span>{" "}
          </>
        )}
        <Badge
          tone={
            node.status === "active"
              ? "success"
              : node.status === "revoked"
                ? "danger"
                : node.status === "suspended" ||
                    node.status.startsWith("pending_")
                  ? "warning"
                  : "neutral"
          }
        >
          {humanizeEnum(node.status)}
        </Badge>
      </button>
      {node.children.map((child) => (
        <CATreeNode
          key={child.id}
          node={child}
          depth={depth + 1}
          navigate={navigate}
        />
      ))}
    </div>
  );
}

function HierarchyView({
  casQuery,
  navigate,
  canManage,
  onCreate,
}: {
  casQuery: ReturnType<typeof useQuery>;
  navigate: (path: string) => void;
  canManage: boolean;
  onCreate: () => void;
}) {
  const cas = extractList<CaRecord>(
    (casQuery.data as { data?: unknown } | undefined)?.data,
    ["items"],
  );
  const roots = buildTree(cas);

  if (casQuery.isLoading) {
    return <StateMessage title="Building hierarchy" message="Loading CAs…" />;
  }
  if (casQuery.error) {
    return (
      <StateMessage
        tone="error"
        title="Could not load hierarchy"
        message="Check service health."
      />
    );
  }
  if (cas.length === 0) {
    return (
      <EmptyState
        title="No CAs configured"
        description={noCasDescription(canManage)}
        actionLabel={canManage ? "Create your first CA" : undefined}
        onAction={canManage ? onCreate : undefined}
      />
    );
  }
  return (
    <Panel
      title="CA Hierarchy"
      subtitle="Root and issuing CAs shown as a trust tree"
    >
      <div className="space-y-1">
        {roots.map((node) => (
          <CATreeNode key={node.id} node={node} depth={0} navigate={navigate} />
        ))}
      </div>
    </Panel>
  );
}

// The nine CA key algorithms the API accepts (openapi createCA.algorithm).
const CA_ALGORITHMS: { value: string; label: string }[] = [
  { value: "ECDSA-P256", label: "ECDSA P-256" },
  { value: "ECDSA-P384", label: "ECDSA P-384" },
  { value: "RSA-2048", label: "RSA 2048" },
  { value: "RSA-3072", label: "RSA 3072" },
  { value: "RSA-4096", label: "RSA 4096" },
  { value: "Ed25519", label: "Ed25519 (internal / SSH / workload CAs)" },
  { value: "ML-DSA-44", label: "ML-DSA-44 (post-quantum)" },
  { value: "ML-DSA-65", label: "ML-DSA-65 (post-quantum)" },
  { value: "ML-DSA-87", label: "ML-DSA-87 (post-quantum)" },
];

const ED25519_NOTE =
  "Windows/ADCS clients and many TLS stacks do not validate Ed25519 chains.";

type DialogKind =
  | "activate"
  | "suspend"
  | "revoke"
  | "update"
  | "create"
  | "import"
  | "csr"
  | "upload"
  | "remove"
  | "rekey";

// A dual-control proposal (202) waiting for a second approver. Nothing has
// happened yet; redeeming re-sends the original request with the grant id.
type PendingGrant =
  | { kind: "import"; actionId: string; payload: { name: string; certificate_pem: string } }
  | { kind: "remove"; actionId: string; payload: { caId: string } }
  | {
      kind: "rekey";
      actionId: string;
      payload: { caId: string; crossSign: boolean; algorithm: string };
    };

type RekeyForm = {
  caId: string;
  algorithm: string; // "" keeps the CA's current algorithm
  crossSign: boolean;
  acknowledged: boolean;
};

// The hub files CA dual-control grants as pending actions (key_dual_control.go). Reading them
// back is what lets the "Redeem approved action" prompt survive a reload or a second tab.
const CA_GRANT_KINDS: Record<string, PendingGrant["kind"]> = {
  key_ca_import: "import",
  key_ca_trust_anchor_remove: "remove",
  key_ca_rotate: "rekey",
};
// Mirrors grantTTL on the hub: an approval older than this can no longer be redeemed.
const GRANT_TTL_MS = 10 * 60 * 1000;

type ServerGrant = {
  kind: PendingGrant["kind"];
  actionId: string;
  status: "pending" | "approved";
  caId: string;
};

function serverGrantsFor(actions: PendingAction[], principal: string | undefined, now: number): ServerGrant[] {
  if (!principal) return [];
  const out: ServerGrant[] = [];
  for (const a of actions) {
    const kind = CA_GRANT_KINDS[a.action_type];
    if (!kind || a.proposed_by !== principal) continue;
    if (a.status !== "pending" && a.status !== "approved") continue;
    if (a.status === "approved") {
      const decided = a.decided_at ? Date.parse(a.decided_at) : NaN;
      if (Number.isNaN(decided) || now - decided > GRANT_TTL_MS) continue;
    }
    const caId = (a.params as { key_id?: string } | null)?.key_id ?? "";
    out.push({ kind, actionId: a.id, status: a.status, caId });
  }
  return out;
}

function isProposed(v: unknown): v is { status: "proposed"; action_id: string } {
  return (
    typeof v === "object" &&
    v !== null &&
    (v as { status?: string }).status === "proposed"
  );
}

function CSRBlock({ name, csrPem }: { name: string; csrPem: string }) {
  const [copied, setCopied] = useState(false);
  const download = () => {
    const url = URL.createObjectURL(
      new Blob([csrPem], { type: "application/pkcs10" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = `${name}.csr`;
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="space-y-2">
      <div className="font-medium text-foreground">
        Certificate signing request
      </div>
      <pre
        data-testid="csr-pem"
        className="max-h-48 overflow-auto rounded-xl border border-border bg-background p-3 font-mono text-xs text-foreground"
      >
        {csrPem}
      </pre>
      <div className="flex gap-2">
        <Button
          onClick={() => {
            void navigator.clipboard.writeText(csrPem).then(() => setCopied(true));
          }}
        >
          {copied ? "Copied" : "Copy"}
        </Button>
        <Button onClick={download}>Download .csr</Button>
      </div>
    </div>
  );
}

type CAFilters = {
  type: string;
  status: string;
};

type CAEditForm = {
  displayName: string;
  crlDistributionPoints: string;
  ocspServiceUrl: string;
};

type CACreateForm = {
  type: string;
  subjectCn: string;
  subjectOrg: string;
  algorithm: string;
  validityStr: string;
  parentCaId: string;
};

const emptyForm: CAEditForm = {
  displayName: "",
  crlDistributionPoints: "",
  ocspServiceUrl: "",
};

const emptyCreateForm: CACreateForm = {
  type: "root",
  subjectCn: "",
  subjectOrg: "",
  algorithm: "ECDSA-P256",
  validityStr: "10y",
  parentCaId: "",
};

export default function CAs() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { id } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const authz = useAuthz();
  const [filters, setFilters] = useState<CAFilters>(() => ({
    type: searchParams.get("type") ?? "",
    status: searchParams.get("status") ?? "",
  }));
  const [cursor, setCursor] = useState<string | null>(
    searchParams.get("cursor") ?? null,
  );
  const updateFilter = (patch: Partial<CAFilters>) => {
    setCursor(null);
    setFilters((curr) => ({ ...curr, ...patch }));
  };

  useEffect(() => {
    const next = new URLSearchParams();
    if (filters.type) next.set("type", filters.type);
    if (filters.status) next.set("status", filters.status);
    if (cursor) next.set("cursor", cursor);
    setSearchParams(next, { replace: true });
  }, [filters, cursor]); // eslint-disable-line react-hooks/exhaustive-deps
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [dialog, setDialog] = useState<DialogKind | null>(null);
  const [importForm, setImportForm] = useState({ name: "", pem: "" });
  const [csrForm, setCsrForm] = useState({ subjectCn: "", algorithm: "ECDSA-P256" });
  const [uploadPem, setUploadPem] = useState("");
  const [pendingGrant, setPendingGrant] = useState<PendingGrant | null>(null);
  // A grant redeemed from server state: the dialog that re-collects the original request submits with it.
  const [redeem, setRedeem] = useState<{ kind: PendingGrant["kind"]; actionId: string } | null>(null);
  const [redeemedIds, setRedeemedIds] = useState<string[]>([]);
  const [rekeyForm, setRekeyForm] = useState<RekeyForm>({
    caId: "",
    algorithm: "",
    crossSign: false,
    acknowledged: false,
  });
  const [rekeyResult, setRekeyResult] = useState<RotateCaKeyResult | null>(null);
  const [suspendConfirm, setSuspendConfirm] = useState("");
  const [revokeConfirm, setRevokeConfirm] = useState("");
  const [editForm, setEditForm] = useState<CAEditForm>(emptyForm);
  const [createForm, setCreateForm] = useState<CACreateForm>(emptyCreateForm);
  const [statusMessage, setStatusMessage] = useState<{
    tone: "success" | "error" | "neutral";
    title: string;
    message: string;
  } | null>(null);

  const [view, setView] = useState<"list" | "hierarchy">("list");

  const queryParams = useMemo(
    () => ({
      type: filters.type,
      status: filters.status,
      limit: 50,
      ...(cursor ? { cursor } : {}),
    }),
    [filters.type, filters.status, cursor],
  );

  const casQuery = useQuery({
    queryKey: ["cas", queryParams],
    queryFn: () => api.cas(queryParams),
  });

  const allCasQuery = useQuery({
    queryKey: ["cas-all"],
    queryFn: () => api.cas({ limit: 200 }),
    enabled: view === "hierarchy",
  });

  const parentCasQuery = useQuery({
    queryKey: ["cas-parents"],
    queryFn: () => api.cas({ limit: 200 }),
    enabled: dialog === "create" && createForm.type === "intermediate",
  });
  // A parent must be live: suspended, revoked or still-pending CAs cannot sign.
  const parentCandidates = extractList<CaRecord>(parentCasQuery.data?.data, ["items"]).filter(
    (c) => c.status === "active",
  );

  const cas: CaRecord[] = extractList<CaRecord>(casQuery.data?.data, ["items"]);
  const casMeta = casQuery.data?.meta;
  const selectedKey = id ?? selectedId ?? null;
  const selected = selectedKey
    ? (cas.find((ca) => ca.id === selectedKey) ?? null)
    : (cas[0] ?? null);
  const canManage = canManageCAs(authz.data?.role, authz.data?.scopes);
  const principal = authz.data?.principal;
  const grantsQuery = useQuery({
    queryKey: ["pending-actions", "ca-grants"],
    queryFn: async () => {
      const [pending, approved] = await Promise.all([
        api.pendingActions("pending"),
        api.pendingActions("approved"),
      ]);
      return [...(pending.data ?? []), ...(approved.data ?? [])];
    },
    select: (actions) => serverGrantsFor(actions, principal, Date.now()),
    enabled: canManage && Boolean(principal),
    refetchInterval: 30_000,
    retry: false,
  });
  const serverGrant = grantsQuery.data?.find((g) => !redeemedIds.includes(g.actionId)) ?? null;
  // Only pki-admin can propose a CA revocation (backend 403s anyone else).
  const isAdmin = (authz.data?.role ?? "").trim() === "pki-admin";
  const isRevoked = selected?.status === "revoked";

  const refreshCAs = async () => {
    await queryClient.invalidateQueries({ queryKey: ["cas"] });
  };
  const markRedeemed = (grant?: PendingGrant) => {
    if (grant) setRedeemedIds((ids) => [...ids, grant.actionId]);
    setRedeem(null);
    void queryClient.invalidateQueries({ queryKey: ["pending-actions"] });
  };

  const connectorsQuery = useQuery({
    queryKey: ["connectors"],
    queryFn: () => api.connectors(),
    retry: false,
  });
  const connectorNames = new Map(
    (connectorsQuery.data?.data ?? []).map((c) => [c.id, c.name] as const),
  );
  const viaConnector = (ca: CaRecord) =>
    ca.connector_id ? (connectorNames.get(ca.connector_id) ?? ca.connector_id) : "";
  // An external CA's key, CRL and OCSP belong to the upstream issuer, so the hub
  // offers no key lifecycle or revocation-publishing controls for it.
  const isExternalCa = selected?.type === "external";
  const isOfflineRoot =
    selected?.type === "root" && selected?.key_storage_type === "external";
  const awaitingCert = selected?.status === "pending_certificate";
  const csrQuery = useQuery({
    queryKey: ["ca-csr", selected?.id],
    queryFn: () => api.caCsr(selected!.id),
    enabled: awaitingCert && !selected?.csr_pem,
  });
  const csrPem = selected?.csr_pem ?? csrQuery.data?.data?.csr_pem;

  const errMsg = (e: unknown, fallback: string) =>
    e instanceof Error ? e.message : fallback;

  const importMutation = useMutation({
    mutationFn: async (grant?: PendingGrant) => {
      const payload =
        grant?.kind === "import"
          ? grant.payload
          : { name: importForm.name.trim(), certificate_pem: importForm.pem.trim() };
      const res = await api.importCa({
        ...payload,
        type: "root",
        key_storage_type: "external",
        ...(grant ? { approved_action_id: grant.actionId } : {}),
      });
      return { res, payload };
    },
    onSuccess: async ({ res, payload }, grant) => {
      setDialog(null);
      if (isProposed(res.data)) {
        setPendingGrant({ kind: "import", actionId: res.data.action_id, payload });
        setStatusMessage(null);
        void queryClient.invalidateQueries({ queryKey: ["pending-actions"] });
        return;
      }
      markRedeemed(grant);
      setPendingGrant(null);
      setImportForm({ name: "", pem: "" });
      setStatusMessage({
        tone: "success",
        title: "Root imported",
        message: "The external root is now a keyless trust anchor.",
      });
      await refreshCAs();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Import failed",
        message: errMsg(e, "Try again."),
      });
    },
  });

  const removeMutation = useMutation({
    mutationFn: async (grant?: PendingGrant) => {
      const caId = grant?.kind === "remove" ? grant.payload.caId : selected?.id;
      if (!caId) throw new Error("No CA selected");
      const res = await api.removeCaTrustAnchor(
        caId,
        grant?.actionId,
      );
      return { res, caId };
    },
    onSuccess: async ({ res, caId }, grant) => {
      setDialog(null);
      if (res && isProposed(res.data)) {
        setPendingGrant({ kind: "remove", actionId: res.data.action_id, payload: { caId } });
        setStatusMessage(null);
        void queryClient.invalidateQueries({ queryKey: ["pending-actions"] });
        return;
      }
      markRedeemed(grant);
      setPendingGrant(null);
      setStatusMessage({
        tone: "success",
        title: "Trust anchor removed",
        message: "The imported root is no longer trusted.",
      });
      await refreshCAs();
    },
    onError: (e) => {
      setDialog(null);
      setStatusMessage({
        tone: "error",
        title: "Trust anchor not removed",
        message: errMsg(e, "Try again."),
      });
    },
  });

  const csrMutation = useMutation({
    mutationFn: async () => {
      if (!selected) throw new Error("No CA selected");
      return api.createCa({
        type: "intermediate",
        parent_ca_id: selected.id,
        subject_cn: csrForm.subjectCn.trim(),
        algorithm: csrForm.algorithm,
      });
    },
    onSuccess: async (res) => {
      setDialog(null);
      setCsrForm({ subjectCn: "", algorithm: "ECDSA-P256" });
      if (res.data?.id) setSelectedId(res.data.id);
      setStatusMessage({
        tone: "success",
        title: "Issuing CA awaiting certificate",
        message: "Sign the CSR offline with the root, then upload the certificate.",
      });
      await refreshCAs();
    },
  });

  const uploadMutation = useMutation({
    mutationFn: async () => {
      if (!selected) throw new Error("No CA selected");
      return api.completeCaCertificate(selected.id, uploadPem.trim());
    },
    onSuccess: async () => {
      setDialog(null);
      setUploadPem("");
      setStatusMessage({
        tone: "success",
        title: "CA activated",
        message: "The signed certificate was accepted.",
      });
      await refreshCAs();
    },
  });

  const activateMutation = useMutation({
    mutationFn: async () => {
      if (!selected) throw new Error("No CA selected");
      return api.activateCa(selected.id);
    },
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "CA activated",
        message: "The trust anchor is now active.",
      });
      setDialog(null);
      await refreshCAs();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Activation failed",
        message: e instanceof Error ? e.message : "Try again in a moment.",
      });
    },
  });

  const rekeyMutation = useMutation({
    mutationFn: async (grant?: PendingGrant) => {
      const p =
        grant?.kind === "rekey"
          ? grant.payload
          : {
              caId: rekeyForm.caId,
              crossSign: rekeyForm.crossSign,
              algorithm: rekeyForm.algorithm,
            };
      if (!p.caId) throw new Error("No CA selected");
      const res = await api.rotateCaKey(p.caId, {
        mode: p.crossSign ? "cross-sign" : undefined,
        algorithm: p.algorithm,
        approvedActionId: grant?.actionId,
      });
      return { res, payload: p };
    },
    onSuccess: async ({ res, payload }, grant) => {
      setDialog(null);
      if (res.proposed) {
        // 202: nothing has been re-keyed yet.
        setPendingGrant({ kind: "rekey", actionId: res.actionId, payload });
        setStatusMessage(null);
        void queryClient.invalidateQueries({ queryKey: ["pending-actions"] });
        return;
      }
      markRedeemed(grant);
      setPendingGrant(null);
      setRekeyResult(res.result);
      setStatusMessage({
        tone: "success",
        title: "CA re-keyed",
        message: res.result.key_id
          ? `New signing key ${res.result.key_id} is active.`
          : "The CA has a new signing key.",
      });
      await refreshCAs();
    },
    onError: (e) => {
      setDialog(null);
      setStatusMessage({
        tone: "error",
        title: "Re-key failed",
        message: errMsg(e, "Try again."),
      });
    },
  });

  const openRekey = () => {
    if (!selected) return;
    setRedeem(null);
    // Capture the target now: the selection can change while the wizard is open.
    setRekeyForm({
      caId: selected.id,
      algorithm: "",
      crossSign: false,
      acknowledged: false,
    });
    setRekeyResult(null);
    setDialog("rekey");
    setStatusMessage(null);
  };

  const rekeySteps: WizardStepDef[] = [
    {
      id: "blast",
      title: "Blast radius",
      validate: () =>
        rekeyForm.acknowledged
          ? null
          : "Review the blast radius and acknowledge it to continue",
      render: () => (
        <div className="space-y-2">
          <BlastRadiusPanel
            action="retire_ca"
            target={rekeyForm.caId}
            confirmLabel="Acknowledge impact"
            onConfirm={() => setRekeyForm((f) => ({ ...f, acknowledged: true }))}
            confirming={rekeyForm.acknowledged}
          />
          {rekeyForm.acknowledged ? (
            <p role="status" className="text-xs text-muted-foreground">
              Impact acknowledged.
            </p>
          ) : null}
        </div>
      ),
    },
    {
      id: "options",
      title: "Options",
      render: () => (
        <div className="space-y-3">
          <label className="block space-y-1 text-sm text-foreground">
            <span>New key algorithm</span>
            <Select
              value={rekeyForm.algorithm}
              onChange={(e) =>
                setRekeyForm((f) => ({ ...f, algorithm: e.target.value }))
              }
            >
              <option value="">Keep current algorithm</option>
              {CA_ALGORITHMS.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label}
                </option>
              ))}
            </Select>
          </label>
          <label className="flex items-center gap-2 text-sm text-foreground">
            <input
              type="checkbox"
              checked={rekeyForm.crossSign}
              onChange={(e) =>
                setRekeyForm((f) => ({ ...f, crossSign: e.target.checked }))
              }
            />
            <span>Cross-sign for zero-downtime rollover</span>
          </label>
        </div>
      ),
    },
  ];

  const suspendMutation = useMutation({
    mutationFn: async () => {
      if (!selected) throw new Error("No CA selected");
      return api.suspendCa(selected.id);
    },
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "CA suspended",
        message: "The trust anchor has been paused.",
      });
      setDialog(null);
      await refreshCAs();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Suspend failed",
        message: e instanceof Error ? e.message : "Try again in a moment.",
      });
    },
  });

  // Revoke is always dual control: a 202 means "proposed", never "revoked".
  // The CA is NOT marked revoked locally; status changes only after approval.
  const revokeMutation = useMutation({
    mutationFn: async () => {
      if (!selected) throw new Error("No CA selected");
      return api.revokeCa(selected.id);
    },
    onSuccess: async (res) => {
      toast.success(
        "Revocation proposed - a second approver must approve it in Pending Actions before anything changes.",
      );
      setStatusMessage({
        tone: "neutral",
        title: "Revocation pending approval",
        message: `A different administrator must approve${
          res.actionId ? ` action ${res.actionId}` : " the proposal"
        } in Pending Actions. The CA stays ${selected?.status ?? "unchanged"} until then.`,
      });
      setDialog(null);
      await refreshCAs();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Revoke failed",
        message: e instanceof Error ? e.message : "Try again in a moment.",
      });
    },
  });

  const updateMutation = useMutation({
    mutationFn: async () => {
      if (!selected) throw new Error("No CA selected");
      const payload: Record<string, unknown> = {};
      const displayName = editForm.displayName.trim();
      if (displayName !== (selected.display_name || selected.name || "")) {
        payload.display_name = displayName;
      }
      const crlDistributionPoints = editForm.crlDistributionPoints
        .split("\n")
        .map((value) => value.trim())
        .filter(Boolean);
      if (crlDistributionPoints.length > 0) {
        payload.crl_distribution_points = crlDistributionPoints;
      }
      const ocspServiceUrl = editForm.ocspServiceUrl.trim();
      if (ocspServiceUrl) {
        payload.ocsp_service_url = ocspServiceUrl;
      }
      return api.updateCa(selected.id, payload);
    },
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "CA updated",
        message: "Trust metadata was saved.",
      });
      setDialog(null);
      await refreshCAs();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Update failed",
        message:
          e instanceof Error ? e.message : "Check the form and try again.",
      });
    },
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const payload: Record<string, unknown> = {
        type: createForm.type,
        subject_cn: createForm.subjectCn.trim(),
        subject_org: createForm.subjectOrg.trim(),
        algorithm: createForm.algorithm,
        validity: createForm.validityStr.trim(),
      };
      if (createForm.type === "intermediate" && createForm.parentCaId.trim()) {
        payload.parent_ca_id = createForm.parentCaId.trim();
      }
      return api.createCa(payload);
    },
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "CA created",
        message: "The new CA is ready.",
      });
      setDialog(null);
      setCreateForm(emptyCreateForm);
      await refreshCAs();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Create failed",
        message: e instanceof Error ? e.message : "Try again.",
      });
    },
  });

  const openUpdate = () => {
    if (!selected) return;
    setEditForm({
      displayName: selected.display_name || selected.name || "",
      crlDistributionPoints: Array.isArray(selected.crl_distribution_points)
        ? selected.crl_distribution_points.join("\n")
        : "",
      ocspServiceUrl: selected.ocsp_service_url || "",
    });
    setDialog("update");
    setStatusMessage(null);
  };

  const openActivate = () => {
    setDialog("activate");
    setStatusMessage(null);
  };

  const openSuspend = () => {
    setSuspendConfirm("");
    setDialog("suspend");
    setStatusMessage(null);
  };

  const openRevoke = () => {
    setRevokeConfirm("");
    revokeMutation.reset();
    setDialog("revoke");
    setStatusMessage(null);
  };

  const redeemServerGrant = (g: ServerGrant) => {
    if (g.kind === "remove") {
      void removeMutation
        .mutateAsync({ kind: "remove", actionId: g.actionId, payload: { caId: g.caId } })
        .catch(() => {});
      return;
    }
    // The hub never stores the root PEM or the re-key options (the grant is bound to a
    // fingerprint, or to mode+algorithm), so the original request is collected again.
    if (g.kind === "import") {
      openImport();
      setRedeem({ kind: g.kind, actionId: g.actionId });
    } else {
      setRedeem({ kind: g.kind, actionId: g.actionId });
      setRekeyForm({ caId: g.caId, algorithm: "", crossSign: false, acknowledged: false });
      setRekeyResult(null);
      setDialog("rekey");
      setStatusMessage(null);
    }
  };

  const openImport = () => {
    setRedeem(null);
    importMutation.reset();
    setImportForm({ name: "", pem: "" });
    setDialog("import");
    setStatusMessage(null);
  };

  const openCsr = () => {
    csrMutation.reset();
    setCsrForm({ subjectCn: "", algorithm: "ECDSA-P256" });
    setDialog("csr");
    setStatusMessage(null);
  };

  const openUpload = () => {
    uploadMutation.reset();
    setUploadPem("");
    setDialog("upload");
    setStatusMessage(null);
  };

  const openRemove = () => {
    setDialog("remove");
    setStatusMessage(null);
  };

  const openCreate = () => {
    setCreateForm(emptyCreateForm);
    setDialog("create");
    setStatusMessage(null);
  };

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Trust"
        title="Certificate Authorities"
        description="Review CA posture, storage type, and lifecycle state."
        actions={
          canManage ? (
            <div className="flex gap-2">
              <Button onClick={openImport}>Import external root</Button>
              <Button tone="primary" onClick={openCreate}>
                New CA
              </Button>
            </div>
          ) : undefined
        }
      />

      {pendingGrant ? (
        <StateMessage
          title={
            pendingGrant.kind === "rekey"
              ? "Re-key pending approval"
              : "Waiting for a second approver"
          }
          message={`A different administrator must approve action ${pendingGrant.actionId} in Pending Actions, then you can redeem it.`}
          action={
            <div className="flex items-center gap-3">
              <Link to="/pending-actions" className="text-sm underline">
                Open Pending Actions
              </Link>
              <Button
                tone="primary"
                disabled={
                  importMutation.isPending ||
                  removeMutation.isPending ||
                  rekeyMutation.isPending
                }
                onClick={() =>
                  void (pendingGrant.kind === "import"
                    ? importMutation.mutateAsync(pendingGrant)
                    : pendingGrant.kind === "remove"
                      ? removeMutation.mutateAsync(pendingGrant)
                      : rekeyMutation.mutateAsync(pendingGrant)
                  ).catch(() => {})
                }
              >
                Redeem approved action
              </Button>
            </div>
          }
        />
      ) : serverGrant ? (
        <StateMessage
          title={
            serverGrant.status === "approved"
              ? "Approved action ready to redeem"
              : "Waiting for a second approver"
          }
          message={
            serverGrant.status === "approved"
              ? `Action ${serverGrant.actionId} (${serverGrant.kind === "import" ? "import external root" : serverGrant.kind === "remove" ? "remove trust anchor" : "re-key"}) was approved. Redeem it within 10 minutes${serverGrant.kind === "remove" ? "." : "; you will be asked to re-enter the original request."}`
              : `A different administrator must approve action ${serverGrant.actionId} in Pending Actions, then you can redeem it here.`
          }
          action={
            <div className="flex items-center gap-3">
              <Link to="/pending-actions" className="text-sm underline">
                Open Pending Actions
              </Link>
              {serverGrant.status === "approved" ? (
                <Button
                  tone="primary"
                  disabled={removeMutation.isPending}
                  onClick={() => redeemServerGrant(serverGrant)}
                >
                  Redeem approved action
                </Button>
              ) : null}
            </div>
          }
        />
      ) : null}

      <div className="flex gap-1 rounded-xl border border-border bg-background/60 p-1 w-fit">
        {(["list", "hierarchy"] as const).map((v) => (
          <button
            key={v}
            type="button"
            onClick={() => setView(v)}
            className={`rounded-lg px-4 py-1.5 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-ring ${view === v ? "bg-primary text-primary-foreground" : "text-foreground hover:text-foreground"}`}
          >
            {v === "list" ? "List" : "Hierarchy"}
          </button>
        ))}
      </div>

      {view === "hierarchy" ? (
        <HierarchyView
          casQuery={allCasQuery}
          navigate={navigate}
          canManage={canManage}
          onCreate={openCreate}
        />
      ) : null}

      {view === "list" ? (
        <>
          <Panel title="Filters" subtitle="Narrow the CA inventory">
            <div className="grid gap-3 md:grid-cols-3">
              <label className="space-y-2 text-sm text-foreground">
                <span>Type</span>
                <Select
                  aria-label="Filter by CA type"
                  value={filters.type}
                  onChange={(e) => updateFilter({ type: e.target.value })}
                >
                  <option value="">All types</option>
                  <option value="root">Root</option>
                  <option value="intermediate">Intermediate</option>
                </Select>
              </label>
              <label className="space-y-2 text-sm text-foreground">
                <span>Status</span>
                <Select
                  aria-label="Filter by CA status"
                  value={filters.status}
                  onChange={(e) => updateFilter({ status: e.target.value })}
                >
                  <option value="">All statuses</option>
                  <option value="active">Active</option>
                  <option value="suspended">Suspended</option>
                  <option value="retired">Retired</option>
                </Select>
              </label>
              <Button
                onClick={() => {
                  setCursor(null);
                  setFilters({ type: "", status: "" });
                }}
              >
                Reset
              </Button>
            </div>
          </Panel>

          <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
            <Panel
              title="CA inventory"
              subtitle="Click a CA to inspect trust posture"
            >
              {casQuery.isLoading ? (
                <StateMessage
                  title="Loading CAs"
                  message="Fetching trust inventory..."
                />
              ) : null}
              {casQuery.error ? (
                <StateMessage
                  tone="error"
                  title="CA inventory unavailable"
                  message="Try again shortly."
                />
              ) : null}
              <div className="grid gap-3">
                {cas.map((ca) => (
                  <button
                    key={ca.id}
                    type="button"
                    onClick={() => {
                      setSelectedId(ca.id);
                      navigate(`/cas/${ca.id}`);
                    }}
                    className={`rounded-2xl border px-4 py-4 text-left transition focus:outline-none focus:ring-2 focus:ring-ring ${selected?.id === ca.id ? "border-primary bg-card/80" : "border-border bg-background/60 hover:border-border"}`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="font-semibold text-foreground">
                          {ca.display_name || ca.name}
                        </div>{" "}
                        <div className="mt-1 text-sm text-muted-foreground">
                          {humanizeEnum(ca.type)} · {humanizeEnum(ca.key_storage_type)}
                        </div>
                        {ca.type === "external" ? (
                          <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
                            <Badge tone="neutral">External</Badge>
                            {ca.connector_id ? <span>via {viaConnector(ca)}</span> : null}
                          </div>
                        ) : null}
                      </div>{" "}
                      <Badge
                        tone={
                          ca.status === "active"
                            ? "success"
                            : ca.status === "revoked"
                              ? "danger"
                              : ca.status === "suspended" ||
                                ca.status.startsWith("pending_")
                              ? "warning"
                              : "neutral"
                        }
                      >
                        {humanizeEnum(ca.status)}
                      </Badge>
                    </div>
                  </button>
                ))}
                {cas.length === 0 && (filters.type || filters.status) ? (
                  <EmptyState
                    title="No CAs match these filters"
                    description="Try a different type or status."
                    actionLabel="Reset filters"
                    onAction={() => {
                      setCursor(null);
                      setFilters({ type: "", status: "" });
                    }}
                  />
                ) : null}
                {cas.length === 0 && !filters.type && !filters.status ? (
                  <EmptyState
                    title="No CAs configured"
                    description={noCasDescription(canManage)}
                    actionLabel={canManage ? "Create your first CA" : undefined}
                    onAction={canManage ? openCreate : undefined}
                  />
                ) : null}
              </div>
              <div className="mt-4 flex items-center justify-between text-sm text-muted-foreground">
                <span>
                  {casMeta?.total != null
                    ? `${casMeta.total} total · page size ${casMeta.limit ?? 50}`
                    : ""}
                </span>
                <div className="flex gap-2">
                  <Button
                    disabled={!casMeta?.prev_cursor}
                    onClick={() => setCursor(casMeta?.prev_cursor ?? null)}
                  >
                    ← Previous
                  </Button>
                  <Button
                    disabled={!casMeta?.next_cursor}
                    onClick={() => setCursor(casMeta?.next_cursor ?? null)}
                  >
                    Next →
                  </Button>
                </div>
              </div>
            </Panel>

            <Panel
              title="CA detail"
              subtitle="Lifecycle state and trust posture"
            >
              {selected ? (
                <div className="space-y-4">
                  {selectedKey ? (
                    <div className="flex justify-between gap-3">
                      <div />
                      <Button onClick={() => navigate("/cas")}>
                        Back to list
                      </Button>
                    </div>
                  ) : null}
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">
                      {selected.display_name || selected.name}
                    </h2>
                    <p className="mt-1 text-sm text-muted-foreground">{selected.id}</p>
                    {isExternalCa ? (
                      <p className="mt-1 flex items-center gap-2 text-sm text-muted-foreground">
                        <Badge tone="neutral">External</Badge>
                        {selected.connector_id ? <span>via {viaConnector(selected)}</span> : null}
                      </p>
                    ) : null}
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <div className="text-muted-foreground">Type</div>
                      <div className="text-foreground">{humanizeEnum(selected.type)}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Storage</div>
                      <div className="text-foreground">
                        {humanizeEnum(selected.key_storage_type)}
                      </div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Status</div>
                      <div className="text-foreground">{humanizeEnum(selected.status)}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Issued</div>
                      <div className="text-foreground">
                        {selected.active_issued_certificates ?? 0}
                      </div>
                    </div>
                  </div>
                  {(selected.warnings ?? []).map((w) => (
                    <StateMessage
                      key={w}
                      title="Compatibility warning"
                      message={w}
                    />
                  ))}
                  {awaitingCert && csrPem ? (
                    <CSRBlock
                      name={selected.display_name || selected.name || selected.id}
                      csrPem={csrPem}
                    />
                  ) : null}
                  <div className="rounded-xl border border-border bg-background/60 p-4 text-sm text-muted-foreground">
                    <div className="font-medium text-foreground">
                      Operational controls
                    </div>
                    <p className="mt-2">
                      Use suspend/activate when managing trust posture or
                      maintenance windows.
                    </p>
                    {isExternalCa ? (
                      <p className="mt-2">
                        This CA issues through an external issuer. Its key, CRL and OCSP
                        are operated there, so Kryptkeeper publishes none of them.
                      </p>
                    ) : null}
                    {isRevoked ? (
                      <StateMessage
                        title="CA revoked"
                        message="Issuance and enrolment through this CA are refused."
                      />
                    ) : canManage ? (
                      <div className="mt-3 flex flex-wrap gap-2">
                        <Button
                          tone="primary"
                          onClick={openActivate}
                          disabled={
                            selected.status === "active" ||
                            activateMutation.isPending
                          }
                        >
                          Activate
                        </Button>
                        <Button
                          tone="danger"
                          onClick={openSuspend}
                          disabled={
                            selected.status === "suspended" ||
                            suspendMutation.isPending
                          }
                        >
                          Suspend
                        </Button>
                        {isAdmin ? (
                          <Button tone="danger" onClick={openRevoke}>
                            Revoke CA
                          </Button>
                        ) : null}
                        {isExternalCa ? null : (
                          <>
                            <Button onClick={openUpdate}>Update</Button>
                            <Button onClick={openRekey}>Re-key</Button>
                          </>
                        )}
                        {isOfflineRoot ? (
                          <>
                            <Button onClick={openCsr}>
                              Request issuing CA (CSR)
                            </Button>
                            <Button tone="danger" onClick={openRemove}>
                              Remove trust anchor
                            </Button>
                          </>
                        ) : null}
                        {awaitingCert ? (
                          <Button tone="primary" onClick={openUpload}>
                            Upload signed certificate
                          </Button>
                        ) : null}
                      </div>
                    ) : (
                      <StateMessage
                        title="Read-only access"
                        message="Your role can review CA posture but not change lifecycle state."
                      />
                    )}
                  </div>
                </div>
              ) : (
                <StateMessage
                  title="No CA selected"
                  message="Pick a CA from the inventory list."
                />
              )}
            </Panel>
          </div>

          {rekeyResult?.cross_cert_pem ? (
            <Panel title="Cross-sign bridge certificates">
              <div className="space-y-3 text-sm">
                <label className="block space-y-1">
                  <span>Bridge certificate (new key, old signature)</span>
                  <Textarea readOnly rows={5} value={rekeyResult.cross_cert_pem} />
                </label>
                {rekeyResult.old_cert_pem ? (
                  <label className="block space-y-1">
                    <span>Retired certificate</span>
                    <Textarea readOnly rows={5} value={rekeyResult.old_cert_pem} />
                  </label>
                ) : null}
              </div>
            </Panel>
          ) : null}
          {statusMessage ? (
            <StateMessage
              tone={statusMessage.tone}
              title={statusMessage.title}
              message={statusMessage.message}
            />
          ) : null}
        </>
      ) : null}

      <Dialog
        open={dialog === "create"}
        title="New Certificate Authority"
        description="Generate a root or intermediate CA."
        onClose={() => setDialog(null)}
      >
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void createMutation.mutateAsync().catch(() => {
              /* surfaced inline below */
            });
          }}
        >
          {createMutation.isError ? (
            <StateMessage
              tone="error"
              title="CA not created"
              message={(createMutation.error as Error).message}
            />
          ) : null}
          <label className="block space-y-1 text-sm text-foreground">
            <span>Type</span>
            <Select
              value={createForm.type}
              onChange={(e) =>
                setCreateForm((f) => ({ ...f, type: e.target.value }))
              }
            >
              <option value="root">Root</option>
              <option value="intermediate">Intermediate</option>
            </Select>
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Subject CN</span>
            <Input
              value={createForm.subjectCn}
              onChange={(e) =>
                setCreateForm((f) => ({ ...f, subjectCn: e.target.value }))
              }
              placeholder="My Root CA"
              required
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>
              Subject Org <span className="text-muted-foreground">(optional)</span>
            </span>
            <Input
              value={createForm.subjectOrg}
              onChange={(e) =>
                setCreateForm((f) => ({ ...f, subjectOrg: e.target.value }))
              }
              placeholder="Acme Corp"
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Algorithm</span>
            <Select
              value={createForm.algorithm}
              onChange={(e) =>
                setCreateForm((f) => ({ ...f, algorithm: e.target.value }))
              }
            >
              {CA_ALGORITHMS.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label}
                </option>
              ))}
            </Select>
          </label>
          {createForm.algorithm === "Ed25519" ? (
            <p className="text-xs text-muted-foreground">{ED25519_NOTE}</p>
          ) : null}
          <label className="block space-y-1 text-sm text-foreground">
            <span>
              Validity <span className="text-muted-foreground">(e.g. 10y, 365d)</span>
            </span>
            <Input
              value={createForm.validityStr}
              onChange={(e) =>
                setCreateForm((f) => ({ ...f, validityStr: e.target.value }))
              }
              placeholder="10y"
            />
          </label>
          {createForm.type === "intermediate" ? (
            <label className="block space-y-1 text-sm text-foreground">
              <span>Parent CA</span>
              <Select
                value={createForm.parentCaId}
                onChange={(e) =>
                  setCreateForm((f) => ({ ...f, parentCaId: e.target.value }))
                }
                required
              >
                <option value="">
                  {parentCasQuery.isLoading ? "Loading CAs…" : "Select a parent CA"}
                </option>
                {parentCandidates.map((c) => (
                  <option key={c.id} value={c.id}>
                    {`${c.display_name || c.name || c.id} (${humanizeEnum(c.type)}${c.key_storage_type === "external" ? ", offline: produces a CSR" : ""})`}
                  </option>
                ))}
              </Select>
              {!parentCasQuery.isLoading && parentCandidates.length === 0 ? (
                <span className="block text-xs text-muted-foreground">
                  No active CA can act as a parent yet. Create or activate a root CA first.
                </span>
              ) : null}
            </label>
          ) : null}
          <div className="flex gap-2 pt-2">
            <Button
              tone="primary"
              type="submit"
              disabled={createMutation.isPending}
            >
              Create CA
            </Button>
            <Button onClick={() => setDialog(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={dialog === "import"}
        title="Import external root"
        description="Register an offline self-signed root as a keyless trust anchor. Requires a second approver."
        onClose={() => setDialog(null)}
      >
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void importMutation
              .mutateAsync(
                redeem?.kind === "import"
                  ? {
                      kind: "import",
                      actionId: redeem.actionId,
                      payload: { name: importForm.name.trim(), certificate_pem: importForm.pem.trim() },
                    }
                  : undefined,
              )
              .catch(() => {});
          }}
        >
          {importMutation.isError ? (
            <StateMessage
              tone="error"
              title="Import failed"
              message={(importMutation.error as Error).message}
            />
          ) : null}
          <label className="block space-y-1 text-sm text-foreground">
            <span>Name</span>
            <Input
              value={importForm.name}
              onChange={(e) => setImportForm((f) => ({ ...f, name: e.target.value }))}
              placeholder="Corporate Root CA"
              required
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Certificate PEM</span>
            <Textarea
              value={importForm.pem}
              onChange={(e) => setImportForm((f) => ({ ...f, pem: e.target.value }))}
              rows={8}
              className="font-mono text-xs"
              placeholder="-----BEGIN CERTIFICATE-----"
              required
            />
          </label>
          <div className="flex gap-2 pt-2">
            <Button tone="primary" type="submit" disabled={importMutation.isPending}>
              Import root
            </Button>
            <Button onClick={() => setDialog(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={dialog === "csr"}
        title="Request issuing CA (CSR)"
        description="The hub generates the issuing key and a CSR for you to sign offline with the root."
        onClose={() => setDialog(null)}
      >
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void csrMutation.mutateAsync().catch(() => {});
          }}
        >
          {csrMutation.isError ? (
            <StateMessage
              tone="error"
              title="CSR not created"
              message={(csrMutation.error as Error).message}
            />
          ) : null}
          <label className="block space-y-1 text-sm text-foreground">
            <span>Subject CN</span>
            <Input
              value={csrForm.subjectCn}
              onChange={(e) => setCsrForm((f) => ({ ...f, subjectCn: e.target.value }))}
              placeholder="Issuing CA 1"
              required
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Algorithm</span>
            <Select
              value={csrForm.algorithm}
              onChange={(e) => setCsrForm((f) => ({ ...f, algorithm: e.target.value }))}
            >
              {CA_ALGORITHMS.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label}
                </option>
              ))}
            </Select>
          </label>
          {csrForm.algorithm === "Ed25519" ? (
            <p className="text-xs text-muted-foreground">{ED25519_NOTE}</p>
          ) : null}
          <div className="flex gap-2 pt-2">
            <Button tone="primary" type="submit" disabled={csrMutation.isPending}>
              Generate CSR
            </Button>
            <Button onClick={() => setDialog(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={dialog === "upload"}
        title="Upload signed certificate"
        description="Paste the certificate the offline root signed for this issuing CA."
        onClose={() => setDialog(null)}
      >
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void uploadMutation.mutateAsync().catch(() => {});
          }}
        >
          {uploadMutation.isError ? (
            <StateMessage
              tone="error"
              title="Certificate rejected"
              message={(uploadMutation.error as Error).message}
            />
          ) : null}
          <label className="block space-y-1 text-sm text-foreground">
            <span>Signed certificate PEM</span>
            <Textarea
              value={uploadPem}
              onChange={(e) => setUploadPem(e.target.value)}
              rows={8}
              className="font-mono text-xs"
              placeholder="-----BEGIN CERTIFICATE-----"
              required
            />
          </label>
          <div className="flex gap-2 pt-2">
            <Button tone="primary" type="submit" disabled={uploadMutation.isPending}>
              Upload certificate
            </Button>
            <Button onClick={() => setDialog(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={dialog === "remove"}
        title="Remove trust anchor"
        description="Stop trusting this imported root. Requires a second approver."
        onClose={() => setDialog(null)}
      >
        <div className="space-y-4 text-sm text-foreground">
          <p>
            Remove{" "}
            <strong>{selected?.display_name || selected?.name || "this root"}</strong>{" "}
            as a trust anchor? Roots with active child CAs cannot be removed.
          </p>
          <div className="flex gap-2">
            <Button
              tone="danger"
              onClick={() => void removeMutation.mutateAsync(undefined).catch(() => {})}
              disabled={removeMutation.isPending}
            >
              Confirm removal
            </Button>
            <Button onClick={() => setDialog(null)}>Cancel</Button>
          </div>
        </div>
      </Dialog>

      <Dialog
        open={dialog === "activate"}
        title="Activate CA"
        description="Restore this CA to service."
        onClose={() => setDialog(null)}
      >
        <div className="space-y-4 text-sm text-foreground">
          <p>
            Activation will mark{" "}
            {selected?.display_name || selected?.name || "this CA"} as active.
          </p>
          <div className="flex gap-2">
            <Button
              tone="primary"
              onClick={() => void activateMutation.mutateAsync().catch(() => {})}
              disabled={activateMutation.isPending}
            >
              Confirm activate
            </Button>
            <Button onClick={() => setDialog(null)}>Cancel</Button>
          </div>
        </div>
      </Dialog>

      <Dialog
        open={dialog === "suspend"}
        title="Suspend CA"
        description="Pause this CA until maintenance is complete."
        onClose={() => setDialog(null)}
      >
        <div className="space-y-4 text-sm text-foreground">
          <p>
            Suspending{" "}
            <strong>
              {selected?.display_name || selected?.name || "this CA"}
            </strong>{" "}
            will stop it from serving as active trust.
          </p>
          <label className="block space-y-2">
            <span>
              Type{" "}
              <strong>{selected?.display_name || selected?.name || ""}</strong>{" "}
              to confirm
            </span>
            <Input
              value={suspendConfirm}
              onChange={(e) => setSuspendConfirm(e.target.value)}
              placeholder="CA name"
            />
          </label>
          <div className="flex gap-2">
            <Button
              tone="danger"
              onClick={() => void suspendMutation.mutateAsync().catch(() => {})}
              disabled={
                suspendMutation.isPending ||
                suspendConfirm !==
                  (selected?.display_name || selected?.name || "")
              }
            >
              Confirm suspend
            </Button>
            <Button onClick={() => setDialog(null)}>Cancel</Button>
          </div>
        </div>
      </Dialog>

      <Dialog
        open={dialog === "revoke"}
        title="Revoke CA"
        description="Review the blast radius first. A second administrator must approve."
        onClose={() => setDialog(null)}
      >
        <div className="space-y-4 text-sm text-foreground">
          <p>
            Revoking{" "}
            <strong>
              {selected?.display_name || selected?.name || "this CA"}
            </strong>{" "}
            (reason: key compromise) makes it and its descendants refuse
            issuance. This is irreversible; a second administrator must
            approve.
          </p>
          <label className="block space-y-2">
            <span>
              Type <strong>{selected?.id ?? ""}</strong> to confirm
            </span>
            <Input
              value={revokeConfirm}
              onChange={(e) => setRevokeConfirm(e.target.value)}
              placeholder="CA id"
            />
          </label>
          {selected ? (
            <BlastRadiusPanel
              action="retire_ca"
              target={selected.id}
              confirmLabel="Propose revocation"
              confirming={revokeMutation.isPending}
              confirmDisabled={revokeConfirm !== selected.id}
              onConfirm={() => void revokeMutation.mutateAsync().catch(() => {})}
              onCancel={() => setDialog(null)}
            />
          ) : null}
        </div>
      </Dialog>

      <Dialog
        open={dialog === "rekey"}
        title="Re-key CA"
        description="Preview the impact, choose options, then submit for approval."
        onClose={() => setDialog(null)}
      >
        <Wizard
          key={rekeyForm.caId}
          steps={rekeySteps}
          summary={() => (
            <dl className="space-y-1 text-sm text-foreground">
              <div>
                <dt className="inline text-muted-foreground">CA: </dt>
                <dd className="inline">{rekeyForm.caId}</dd>
              </div>
              <div>
                <dt className="inline text-muted-foreground">Algorithm: </dt>
                <dd className="inline">
                  {rekeyForm.algorithm || "Keep current algorithm"}
                </dd>
              </div>
              <div>
                <dt className="inline text-muted-foreground">Cross-sign: </dt>
                <dd className="inline">{rekeyForm.crossSign ? "Yes" : "No"}</dd>
              </div>
              <p className="pt-2 text-xs text-muted-foreground">
                A second administrator must approve this re-key before it takes
                effect.
              </p>
            </dl>
          )}
          onComplete={async () => {
            await rekeyMutation
              .mutateAsync(
                redeem?.kind === "rekey"
                  ? {
                      kind: "rekey",
                      actionId: redeem.actionId,
                      payload: {
                        caId: rekeyForm.caId,
                        crossSign: rekeyForm.crossSign,
                        algorithm: rekeyForm.algorithm,
                      },
                    }
                  : undefined,
              )
              .catch(() => {});
          }}
          onCancel={() => setDialog(null)}
        />
      </Dialog>

      <Dialog
        open={dialog === "update"}
        title="Update CA metadata"
        description="Edit display name and trust metadata."
        onClose={() => setDialog(null)}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void updateMutation.mutateAsync().catch(() => {});
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Display name</span>
            <Input
              value={editForm.displayName}
              onChange={(e) =>
                setEditForm((curr) => ({
                  ...curr,
                  displayName: e.target.value,
                }))
              }
              placeholder="Root CA"
            />
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>CRL distribution points</span>
            <textarea
              value={editForm.crlDistributionPoints}
              onChange={(e) =>
                setEditForm((curr) => ({
                  ...curr,
                  crlDistributionPoints: e.target.value,
                }))
              }
              placeholder="One URL per line"
              rows={4}
              className="w-full rounded-xl border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>OCSP service URL</span>
            <Input
              value={editForm.ocspServiceUrl}
              onChange={(e) =>
                setEditForm((curr) => ({
                  ...curr,
                  ocspServiceUrl: e.target.value,
                }))
              }
              placeholder="https://ocsp.example.com"
            />
          </label>
          <div className="flex gap-2">
            <Button
              tone="primary"
              type="submit"
              disabled={updateMutation.isPending}
            >
              Save changes
            </Button>
            <Button onClick={() => setDialog(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>
    </div>
  );
}
