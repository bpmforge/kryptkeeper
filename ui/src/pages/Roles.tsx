import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { canManageUsers, useAuthz } from "../lib/auth";
import {
  PERMISSIONS,
  rolesApi,
  sodViolations,
  type RoleDraft,
  type RoleEntry,
} from "../lib/rolesApi";
import { Badge, Button, Input, Panel, StateMessage } from "../components/ui";
import { sortRoles } from "../lib/pageHelpers";
import { PageHeader } from "../components/PageHeader";
import { scrollableProps } from "../lib/scrollable";

function permissionLabel(r: RoleEntry): string {
  const n = (r.permissions ?? []).length;
  if (n > 0) return `${n} permission${n === 1 ? "" : "s"}`;
  return r.builtin ? "Built-in set" : "0 permissions";
}

const NAME_RE = /^[a-z0-9-]+$/;

function RoleForm({
  initial,
  builtinNames,
  constraints,
  busy,
  onSubmit,
  onCancel,
}: {
  initial?: RoleEntry;
  builtinNames: Set<string>;
  constraints: Parameters<typeof sodViolations>[1];
  busy: boolean;
  onSubmit: (d: RoleDraft) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [perms, setPerms] = useState<string[]>(initial?.permissions ?? []);

  const violations = sodViolations(perms, constraints);
  // Client hint only: the server owns the real naming rules.
  const nameError = initial
    ? null
    : name === ""
      ? null
      : !NAME_RE.test(name)
        ? "Use lowercase letters, digits and hyphens only"
        : builtinNames.has(name)
          ? "That name belongs to a built-in role"
          : null;
  const canSave = name !== "" && !nameError && violations.length === 0 && !busy;

  const toggle = (p: string) =>
    setPerms((cur) => (cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p]));

  const reads = PERMISSIONS.filter((p) => p.endsWith(".read"));
  const writes = PERMISSIONS.filter((p) => !p.endsWith(".read"));

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        if (canSave) onSubmit({ name, description, permissions: perms });
      }}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="text-xs text-muted-foreground">
          Role name
          <Input value={name} disabled={!!initial} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="text-xs text-muted-foreground">
          Description
          <Input value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
      </div>
      {nameError ? <p className="text-xs text-state-over">{nameError}</p> : null}

      {[
        ["Read permissions", reads],
        ["Write permissions", writes],
      ].map(([title, list]) => (
        <fieldset key={title as string} className="space-y-1">
          <legend className="text-xs font-semibold text-muted-foreground">{title as string}</legend>
          <div className="grid gap-1 sm:grid-cols-3">
            {(list as string[]).map((p) => (
              <label key={p} className="flex items-center gap-2 text-sm text-foreground">
                <input type="checkbox" checked={perms.includes(p)} onChange={() => toggle(p)} />
                {p}
              </label>
            ))}
          </div>
        </fieldset>
      ))}

      {violations.map((v) => (
        <p key={`${v.permission_a}|${v.permission_b}`} role="alert" className="text-xs text-state-over">
          {v.permission_a} and {v.permission_b} cannot be held by one role
        </p>
      ))}

      <div className="flex gap-2">
        <Button type="submit" tone="primary" disabled={!canSave}>
          {initial ? "Save role" : "Create role"}
        </Button>
        <Button tone="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

export default function Roles() {
  const authz = useAuthz();
  const qc = useQueryClient();
  const allowed = canManageUsers(authz.data?.role, authz.data?.scopes);
  const [editing, setEditing] = useState<RoleEntry | "new" | null>(null);

  const roles = useQuery({ queryKey: ["roles"], queryFn: rolesApi.list, enabled: allowed });
  const sod = useQuery({ queryKey: ["roles-sod"], queryFn: rolesApi.sod, enabled: allowed });

  const done = (msg: string) => {
    toast.success(msg);
    setEditing(null);
    void qc.invalidateQueries({ queryKey: ["roles"] });
  };
  const save = useMutation({
    mutationFn: ({ draft, isNew }: { draft: RoleDraft; isNew: boolean }) =>
      isNew ? rolesApi.create(draft) : rolesApi.update(draft),
    onSuccess: (_r, v) => done(v.isNew ? "Role created" : "Role updated"),
    onError: (err: Error) => toast.error(err.message),
  });
  const remove = useMutation({
    mutationFn: (name: string) => rolesApi.remove(name),
    onSuccess: () => done("Role deleted"),
    onError: (err: Error) => toast.error(err.message),
  });

  if (authz.isLoading) return <StateMessage title="Loading" message="Checking permissions…" />;
  if (!allowed) {
    return (
      <div className="p-6">
        <StateMessage tone="error" title="Not permitted" message="Managing roles needs an administrator." />
      </div>
    );
  }

  const list = sortRoles(roles.data?.data ?? []);
  const builtinNames = new Set(list.filter((r) => r.builtin).map((r) => r.name));

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Administration"
        title="Roles"
        description="Custom roles built from the permission list. Separation-of-duties pairs are checked before you save."
        actions={
          <div className="flex gap-2">
            <Button tone="secondary" onClick={() => void roles.refetch()} disabled={roles.isFetching}>
              <RefreshCw className={`h-4 w-4 ${roles.isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <Button tone="primary" onClick={() => setEditing("new")}>
              <Plus className="h-4 w-4" />
              New role
            </Button>
          </div>
        }
      />

      {editing ? (
        <Panel title={editing === "new" ? "New role" : `Edit ${editing.name}`}>
          <RoleForm
            key={editing === "new" ? "new" : editing.name}
            initial={editing === "new" ? undefined : editing}
            builtinNames={builtinNames}
            constraints={sod.data?.data ?? []}
            busy={save.isPending}
            onCancel={() => setEditing(null)}
            onSubmit={(draft) => save.mutate({ draft, isNew: editing === "new" })}
          />
        </Panel>
      ) : null}

      <Panel title="Roles">
        {roles.isLoading ? (
          <StateMessage title="Loading" message="Fetching roles…" />
        ) : roles.error ? (
          <StateMessage tone="error" title="Unavailable" message="Could not load roles." />
        ) : (
          <div className="overflow-x-auto" {...scrollableProps}>
          <table className="w-full min-w-[28rem] text-sm">
            <thead>
              <tr className="text-left text-xs text-muted-foreground">
                <th className="py-2 pr-4">Name</th>
                <th className="pr-4">Type</th>
                <th className="pr-4">Permissions</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.map((r) => (
                <tr key={r.name} className="border-t border-border">
                  <td className="py-2 pr-4 font-medium text-foreground">{r.name}</td>
                  <td className="pr-4">
                    {r.builtin ? (
                      <Badge tone="neutral">Built-in</Badge>
                    ) : (
                      <Badge tone="info">{r.tenant_id ? `Tenant ${r.tenant_id}` : "Custom"}</Badge>
                    )}
                  </td>
                  <td className="pr-4 text-muted-foreground">{permissionLabel(r)}</td>
                  <td className="space-x-2 whitespace-nowrap text-right">
                    {r.builtin ? null : (
                      <>
                        <Button tone="secondary" aria-label={`Edit ${r.name}`} onClick={() => setEditing(r)}>
                          Edit
                        </Button>
                        <Button
                          tone="danger"
                          aria-label={`Delete ${r.name}`}
                          disabled={remove.isPending}
                          onClick={() => {
                            if (window.confirm(`Delete role "${r.name}"?`)) remove.mutate(r.name);
                          }}
                        >
                          Delete
                        </Button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
