import type { PolicyRules } from "./policiesApi";
import type { RoleEntry } from "./rolesApi";

// Built-in roles first, then custom, each alphabetical, so row order never
// depends on the server's response order.
export function sortRoles(list: RoleEntry[]): RoleEntry[] {
  return [...list].sort(
    (a, b) => Number(!!b.builtin) - Number(!!a.builtin) || a.name.localeCompare(b.name),
  );
}

export function ruleChips(r: PolicyRules): string[] {
  const chips: string[] = [];
  for (const alg of r.allowed_algorithms ?? []) chips.push(alg);
  if (r.min_rsa_bits) chips.push(`RSA ≥ ${r.min_rsa_bits}`);
  if (r.max_validity_days) chips.push(`Validity ≤ ${r.max_validity_days}d`);
  if (r.allow_ca_certs) chips.push("CA certs allowed");
  return chips;
}

// Colour carries state: expired is a breach, the next-30-days buckets are
// "needs attention", everything further out is healthy.
export function expiryBucketClass(label: string): string {
  if (/expired/i.test(label)) return "bg-state-over";
  const range = /(\d+)\s*[-–]\s*(\d+)/.exec(label);
  if (range && Number(range[2]) <= 30) return "bg-state-attn";
  return "bg-state-auto";
}

