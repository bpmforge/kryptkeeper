import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
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
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";
import { canManageCAs, useAuthz } from "../lib/auth";
import { extractList } from "../lib/models";
import type { CaRecord } from "../lib/models";

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
        aria-label={`${node.display_name || node.name || node.id}, ${node.type} CA${
          node.active_issued_certificates != null
            ? `, ${node.active_issued_certificates} certificates`
            : ""
        }, ${node.status}`}
        className="mb-1 flex w-full items-center gap-3 rounded-xl border border-border bg-background/60 px-4 py-2.5 text-left text-sm transition hover:border-primary focus:outline-none focus:ring-2 focus:ring-ring"
      >
        {depth > 0 && <span className="text-muted-foreground select-none">└─</span>}
        <span className="font-medium text-foreground flex-1">
          {node.display_name || node.name || node.id}
        </span>
        <span className="text-xs text-muted-foreground">{node.type}</span>
        {node.active_issued_certificates != null && (
          <span className="text-xs text-muted-foreground">
            {node.active_issued_certificates} certs
          </span>
        )}
        <Badge
          tone={
            node.status === "active"
              ? "success"
              : node.status === "suspended"
                ? "warning"
                : "neutral"
          }
        >
          {node.status}
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
  const [dialog, setDialog] = useState<
    "activate" | "suspend" | "update" | "create" | null
  >(null);
  const [suspendConfirm, setSuspendConfirm] = useState("");
  const [editForm, setEditForm] = useState<CAEditForm>(emptyForm);
  const [createForm, setCreateForm] = useState<CACreateForm>(emptyCreateForm);
  const [statusMessage, setStatusMessage] = useState<{
    tone: "success" | "error";
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

  const cas: CaRecord[] = extractList<CaRecord>(casQuery.data?.data, ["items"]);
  const casMeta = casQuery.data?.meta;
  const selectedKey = id ?? selectedId ?? null;
  const selected = selectedKey
    ? (cas.find((ca) => ca.id === selectedKey) ?? null)
    : (cas[0] ?? null);
  const canManage = canManageCAs(authz.data?.role, authz.data?.scopes);

  const refreshCAs = async () => {
    await queryClient.invalidateQueries({ queryKey: ["cas"] });
  };

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
            <Button tone="primary" onClick={openCreate}>
              New CA
            </Button>
          ) : undefined
        }
      />

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
                    aria-label={`${ca.display_name || ca.name}, ${ca.type} CA, ${ca.key_storage_type} storage, ${ca.status}`}
                    className={`rounded-2xl border px-4 py-4 text-left transition focus:outline-none focus:ring-2 focus:ring-ring ${selected?.id === ca.id ? "border-primary bg-card/80" : "border-border bg-background/60 hover:border-border"}`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="font-semibold text-foreground">
                          {ca.display_name || ca.name}
                        </div>
                        <div className="mt-1 text-sm text-muted-foreground">
                          {ca.type} · {ca.key_storage_type}
                        </div>
                      </div>
                      <Badge
                        tone={
                          ca.status === "active"
                            ? "success"
                            : ca.status === "suspended"
                              ? "warning"
                              : "neutral"
                        }
                      >
                        {ca.status}
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
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <div className="text-muted-foreground">Type</div>
                      <div className="text-foreground">{selected.type}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Storage</div>
                      <div className="text-foreground">
                        {selected.key_storage_type}
                      </div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Status</div>
                      <div className="text-foreground">{selected.status}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Issued</div>
                      <div className="text-foreground">
                        {selected.active_issued_certificates ?? 0}
                      </div>
                    </div>
                  </div>
                  <div className="rounded-xl border border-border bg-background/60 p-4 text-sm text-muted-foreground">
                    <div className="font-medium text-foreground">
                      Operational controls
                    </div>
                    <p className="mt-2">
                      Use suspend/activate when managing trust posture or
                      maintenance windows.
                    </p>
                    {canManage ? (
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
                        <Button onClick={openUpdate}>Update</Button>
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
              <option value="ECDSA-P256">ECDSA P-256</option>
              <option value="ECDSA-P384">ECDSA P-384</option>
              <option value="RSA-2048">RSA 2048</option>
              <option value="RSA-4096">RSA 4096</option>
            </Select>
          </label>
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
              <span>Parent CA ID</span>
              <Input
                value={createForm.parentCaId}
                onChange={(e) =>
                  setCreateForm((f) => ({ ...f, parentCaId: e.target.value }))
                }
                placeholder="ca-..."
                required
              />
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
