import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plug, Plus } from "lucide-react";
import { api } from "../lib/api";
import { extractList, type CaRecord } from "../lib/models";
import { canManageUsers, useAuthz } from "../lib/auth";
import { issuerTypeLabel } from "../lib/issuerTypes";
import { AddIssuerWizard } from "../components/AddIssuerWizard";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";
import { StatusCueMark } from "../components/StatusCue";
import { Badge, Button, Dialog, Panel, StateMessage } from "../components/ui";

type Connector = Awaited<ReturnType<typeof api.connectors>>["data"][number];

function healthBadge(h?: { status: string; detail?: string }) {
  const status = h?.status ?? "unknown";
  const cue =
    status === "healthy"
      ? ({ icon: "check", text: "Healthy" } as const)
      : status === "degraded"
        ? ({ icon: "alert", text: "Degraded" } as const)
        : ({ icon: "minus", text: "Unknown" } as const);
  return (
    <span title={h?.detail}>
      <Badge
        tone={
          status === "healthy"
            ? "success"
            : status === "degraded"
              ? "warning"
              : "neutral"
        }
      >
        <StatusCueMark cue={cue} />
        {status}
      </Badge>
    </span>
  );
}

export default function Issuers() {
  const qc = useQueryClient();
  const authz = useAuthz();
  // Test, create and delete are pki-admin on the server.
  const canWrite = canManageUsers(authz.data?.role, authz.data?.scopes);
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState<Connector | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, string>>({});

  const connectors = useQuery({
    queryKey: ["issuers"],
    queryFn: api.connectors,
  });
  const cas = useQuery({
    queryKey: ["cas", "issuers"],
    queryFn: () => api.cas(),
  });

  const usedBy = (id: string) =>
    extractList<CaRecord>(cas.data?.data)
      .filter((c) => c.connector_id === id)
      .map((c) => c.display_name ?? c.name ?? c.id);

  const test = useMutation({
    mutationFn: (c: Connector) => api.testConnector(c.id),
    onSuccess: (r, c) => {
      setResults((m) => ({
        ...m,
        [c.id]: `${r.status}${r.detail ? `: ${r.detail}` : ""}`,
      }));
      void qc.invalidateQueries({ queryKey: ["issuers"] });
    },
    onError: (e, c) =>
      setResults((m) => ({
        ...m,
        [c.id]: e instanceof Error ? e.message : "Test failed",
      })),
  });

  const remove = useMutation({
    mutationFn: (c: Connector) => api.deleteConnector(c.id),
    onSuccess: () => {
      setDeleting(null);
      void qc.invalidateQueries({ queryKey: ["issuers"] });
    },
    // A 409 carries the server's message naming the referencing CA.
    onError: (e) =>
      setDeleteError(e instanceof Error ? e.message : "Delete failed"),
  });

  const rows = connectors.data?.data ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Estate"
        title="Issuers"
        description="The CAs you already use, connected so Kryptkeeper can issue and revoke through them."
        actions={
          canWrite ? (
            <Button tone="primary" onClick={() => setAdding(true)}>
              <Plus className="h-4 w-4" aria-hidden="true" />
              Add issuer
            </Button>
          ) : undefined
        }
      />

      {connectors.isLoading ? (
        <StateMessage title="Loading issuers" />
      ) : connectors.isError ? (
        <StateMessage
          tone="error"
          title="Could not load issuers"
          message={
            connectors.error instanceof Error
              ? connectors.error.message
              : undefined
          }
        />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={<Plug className="h-6 w-6" aria-hidden="true" />}
          title="No issuers yet"
          description="Add the CA you already use (Vault, EJBCA, AWS Private CA, Google CAS, Sectigo, GlobalSign, Entrust, DigiCert or any ACME CA) and issue through it from every Kryptkeeper protocol."
          actionLabel={canWrite ? "Add issuer" : undefined}
          onAction={canWrite ? () => setAdding(true) : undefined}
        />
      ) : (
        <Panel>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Issuers</caption>
              <thead className="text-xs text-muted-foreground">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Name
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Type
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Health
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Tenant
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Used by
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((c) => {
                  const used = usedBy(c.id);
                  return (
                    <tr key={c.id} className="border-t border-border align-top">
                      <th
                        scope="row"
                        className="px-3 py-2 font-medium text-foreground"
                      >
                        {c.name}
                      </th>
                      <td className="px-3 py-2">{issuerTypeLabel(c.type)}</td>
                      <td className="px-3 py-2">{healthBadge(c.health)}</td>
                      <td className="px-3 py-2">{c.tenant || "—"}</td>
                      <td className="px-3 py-2">
                        {used.length ? used.join(", ") : "—"}
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-2">
                          <Button
                            aria-label={`Test ${c.name}`}
                            disabled={!canWrite || test.isPending}
                            onClick={() => test.mutate(c)}
                          >
                            Test
                          </Button>
                          <Button
                            tone="danger"
                            aria-label={`Delete ${c.name}`}
                            disabled={!canWrite}
                            onClick={() => {
                              setDeleteError(null);
                              setDeleting(c);
                            }}
                          >
                            Delete
                          </Button>
                        </div>
                        {results[c.id] && (
                          <p
                            role="status"
                            className="mt-1 text-xs text-muted-foreground"
                          >
                            {results[c.id]}
                          </p>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {adding && (
        <AddIssuerWizard
          open
          onClose={() => setAdding(false)}
          onDone={() => {
            void qc.invalidateQueries({ queryKey: ["issuers"] });
            void qc.invalidateQueries({ queryKey: ["cas"] });
          }}
        />
      )}

      <Dialog
        open={deleting !== null}
        title="Delete issuer"
        size="sm"
        onClose={() => setDeleting(null)}
        footer={
          <>
            <Button onClick={() => setDeleting(null)}>Cancel</Button>
            <Button
              tone="danger"
              disabled={remove.isPending}
              onClick={() => deleting && remove.mutate(deleting)}
            >
              Delete issuer
            </Button>
          </>
        }
      >
        <p className="text-sm text-foreground">
          Delete {deleting?.name}? This cannot be undone. An issuer that a CA
          still uses cannot be deleted.
        </p>
        {deleteError && (
          <p role="alert" className="mt-3 text-xs text-state-over">
            {deleteError}
          </p>
        )}
      </Dialog>
    </div>
  );
}
