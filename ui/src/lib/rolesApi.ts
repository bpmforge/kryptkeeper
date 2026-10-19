import { fetchJSON, queryString } from "./api";

export type RoleEntry = {
  name: string;
  description?: string;
  permissions?: string[];
  builtin: boolean;
  // Present for custom roles owned by a tenant; absent for global roles.
  tenant_id?: string;
};
export type SodConstraint = {
  id?: string;
  permission_a: string;
  permission_b: string;
  builtin?: boolean;
};
export type RoleDraft = { name: string; description: string; permissions: string[] };
export type RolePreview = {
  groups: string[];
  mapped: boolean;
  role: string;
  matched_claim_value: string;
  unmapped_policy: "deny" | "read-only";
  effective_role: string;
  would_login: boolean;
};

// Closed vocabulary; mirrors permissionVocabulary in
// internal/bootstrap/authz_custom_roles.go. There is no listing endpoint, and
// the server rejects unknown permissions anyway.
export const PERMISSIONS: readonly string[] = [
  "certificate.read",
  "certificate.issue",
  "certificate.renew",
  "certificate.revoke",
  "ca.manage",
  "key.manage",
  "action.propose",
  "action.approve",
  "report.read",
  "audit.read",
  "discovery.manage",
  "notification.manage",
  "protocol.manage",
  "dashboard.manage",
  "tenant.manage",
  "user.manage",
];

export const rolesApi = {
  list: () => fetchJSON<{ data: RoleEntry[] }>("/roles"),
  create: (r: RoleDraft) =>
    fetchJSON<{ data: RoleDraft }>("/roles", { method: "POST", body: JSON.stringify(r) }),
  update: (r: RoleDraft) =>
    fetchJSON<{ data: RoleDraft }>(`/roles/${encodeURIComponent(r.name)}`, {
      method: "PUT",
      body: JSON.stringify(r),
    }),
  remove: (name: string) =>
    fetchJSON<void>(`/roles/${encodeURIComponent(name)}`, { method: "DELETE" }),
  sod: () => fetchJSON<{ data: SodConstraint[] }>("/roles/sod-constraints"),
  preview: (groups: string[]) =>
    fetchJSON<{ data: RolePreview }>(
      `/auth/role-map/preview${queryString({ groups: groups.join(",") })}`,
    ),
};

// Every constraint whose BOTH permissions are selected. Constraints are
// order-insensitive pairs, so a duplicate listing never repeats a result.
export function sodViolations(selected: string[], constraints: SodConstraint[]): SodConstraint[] {
  const have = new Set(selected);
  const seen = new Set<string>();
  return constraints.filter((c) => {
    if (!have.has(c.permission_a) || !have.has(c.permission_b)) return false;
    const key = [c.permission_a, c.permission_b].sort().join("|");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
