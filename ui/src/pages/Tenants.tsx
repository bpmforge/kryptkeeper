import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Link2, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { api } from "../lib/api";
import { extractList } from "../lib/models";
import type {
  CaRecord,
  TemplateRecord,
  Tenant,
  TenantContext,
} from "../lib/models";
import {
  Badge,
  Button,
  Input,
  Panel,
  Select,
  StateMessage,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";

export default function Tenants() {
  const queryClient = useQueryClient();
  const ctxQuery = useQuery({
    queryKey: ["tenant-context"],
    queryFn: () => api.tenantContext(),
    staleTime: 30_000,
  });
  const ctx: TenantContext | undefined = ctxQuery.data?.data;
  const tenants: Tenant[] = ctx?.tenants ?? [];
  const isSuperAdmin = !!ctx?.super_admin;
  const enabled = !!ctx?.enabled;

  // CA / template lists for the mapping forms (super-admin only).
  const casQuery = useQuery({
    queryKey: ["tenant-cas"],
    queryFn: () => api.cas(),
    enabled: isSuperAdmin,
    staleTime: 30_000,
  });
  const cas = extractList<CaRecord>(casQuery.data?.data);
  const templatesQuery = useQuery({
    queryKey: ["tenant-templates"],
    queryFn: () => api.templates(),
    enabled: isSuperAdmin,
    staleTime: 30_000,
  });
  const templates = extractList<TemplateRecord>(templatesQuery.data?.data);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["tenant-context"] });

  const [newId, setNewId] = useState("");
  const [newName, setNewName] = useState("");
  const createMutation = useMutation({
    mutationFn: () =>
      api.createTenant({ id: newId.trim(), name: newName.trim() }),
    onSuccess: async () => {
      setNewId("");
      setNewName("");
      await invalidate();
    },
  });

  const [caId, setCaId] = useState("");
  const [caTenant, setCaTenant] = useState("");
  const mapCaMutation = useMutation({
    mutationFn: () => api.mapCATenant({ ca_id: caId, tenant_id: caTenant }),
    onError: (err: Error) => toast.error(err.message),
  });

  const [tplId, setTplId] = useState("");
  const [tplTenant, setTplTenant] = useState("");
  const mapTplMutation = useMutation({
    mutationFn: () =>
      api.mapTemplateTenant({ template_id: tplId, tenant_id: tplTenant }),
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Administration"
        title="Tenants"
        description="Isolation boundaries. Each CA, certificate, template, and approval belongs to exactly one tenant; principals see only their own."
        actions={
          <Button tone="secondary" onClick={() => ctxQuery.refetch()}>
            <RefreshCw size={13} aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      {enabled ? (
        <div
          role="status"
          className="flex items-center gap-2 rounded-xl border border-border px-4 py-3 text-sm text-foreground"
        >
          <Badge tone="warning">Experimental</Badge>
          <span>
            Experimental: tenant isolation is not a security boundary in this
            release.
          </span>
        </div>
      ) : null}

      {ctxQuery.isLoading ? (
        <StateMessage title="Loading" message="Fetching tenant context…" />
      ) : !enabled ? (
        <StateMessage
          tone="neutral"
          title="Multi-tenancy is off"
          message="The platform is running single-tenant. Set MULTI_TENANCY=on (and restart) to enforce per-tenant isolation. Everyone is a super-admin in the default tenant until then."
        />
      ) : !isSuperAdmin ? (
        <Panel title="Your tenant">
          <p className="text-sm text-foreground">
            You are scoped to tenant <Badge tone="info">{ctx?.tenant}</Badge>.
            Tenant administration is restricted to super-admins.
          </p>
        </Panel>
      ) : (
        <>
          <Panel title="Tenants">
            {tenants.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No tenants yet. Create one below — existing data stays in the
                <span className="font-mono"> default </span> tenant.
              </p>
            ) : (
              <ul className="divide-y divide-border">
                {tenants.map((t) => (
                  <li
                    key={t.id}
                    className="flex items-center justify-between gap-3 py-2"
                  >
                    <div>
                      <span className="font-medium text-foreground">
                        {t.name}
                      </span>{" "}
                      <span className="font-mono text-xs text-muted-foreground">
                        {t.id}
                      </span>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {t.created_at}
                    </span>
                  </li>
                ))}
              </ul>
            )}

            <div className="mt-4 flex flex-wrap items-end gap-2">
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  Tenant ID
                </label>
                <Input
                  value={newId}
                  onChange={(e) => setNewId(e.target.value)}
                  placeholder="acme"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  Display name
                </label>
                <Input
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="Acme Corp"
                />
              </div>
              <Button
                tone="primary"
                onClick={() => createMutation.mutate()}
                disabled={
                  createMutation.isPending || !newId.trim() || !newName.trim()
                }
              >
                <Plus size={13} aria-hidden="true" />
                Create tenant
              </Button>
            </div>
            {createMutation.isError ? (
              <p className="mt-2 text-xs text-state-over">
                {createMutation.error instanceof Error
                  ? createMutation.error.message
                  : "Create failed."}
              </p>
            ) : null}
          </Panel>

          <Panel title="Assign a CA to a tenant">
            <div className="flex flex-wrap items-end gap-2">
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">CA</label>
                <Select value={caId} onChange={(e) => setCaId(e.target.value)}>
                  <option value="">Select a CA…</option>
                  {cas.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.display_name || c.name || c.id}
                    </option>
                  ))}
                </Select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  Tenant
                </label>
                <Select
                  value={caTenant}
                  onChange={(e) => setCaTenant(e.target.value)}
                >
                  <option value="">Select a tenant…</option>
                  {tenants.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))}
                </Select>
              </div>
              <Button
                tone="primary"
                onClick={() => mapCaMutation.mutate()}
                disabled={mapCaMutation.isPending || !caId || !caTenant}
              >
                <Link2 size={13} aria-hidden="true" />
                Assign CA
              </Button>
              {mapCaMutation.isSuccess ? (
                <span className="text-xs text-state-auto">Mapped ✓</span>
              ) : null}
            </div>
          </Panel>

          <Panel title="Assign a template to a tenant">
            <p className="mb-3 text-xs text-muted-foreground">
              Unmapped templates stay in the default tenant — a shared catalog
              entry visible to default-tenant principals.
            </p>
            <div className="flex flex-wrap items-end gap-2">
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  Template
                </label>
                <Select
                  value={tplId}
                  onChange={(e) => setTplId(e.target.value)}
                >
                  <option value="">Select a template…</option>
                  {templates.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.display_name || t.name || t.id}
                    </option>
                  ))}
                </Select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  Tenant
                </label>
                <Select
                  value={tplTenant}
                  onChange={(e) => setTplTenant(e.target.value)}
                >
                  <option value="">Select a tenant…</option>
                  {tenants.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))}
                </Select>
              </div>
              <Button
                tone="primary"
                onClick={() => mapTplMutation.mutate()}
                disabled={mapTplMutation.isPending || !tplId || !tplTenant}
              >
                <Link2 size={13} aria-hidden="true" />
                Assign template
              </Button>
              {mapTplMutation.isSuccess ? (
                <span className="text-xs text-state-auto">Mapped ✓</span>
              ) : null}
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}
