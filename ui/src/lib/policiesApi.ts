import { fetchJSON } from "./api";

export type PolicyRules = {
  allowed_algorithms?: string[];
  min_rsa_bits?: number;
  max_validity_days?: number;
  allow_ca_certs?: boolean;
};
export type Policy = {
  id: string;
  name: string;
  enabled: boolean;
  ca_id: string;
  rules: PolicyRules;
};
export type PolicyWrite = Partial<Omit<Policy, "id">>;
export type DryRunInput = {
  ca_id?: string;
  algorithm?: string;
  rsa_bits?: number;
  validity_days: number;
  is_ca: boolean;
};
export type Violation = {
  policy_id: string;
  policy: string;
  rule: string;
  detail: string;
  observed: string;
};
export type DryRunResult = {
  allowed: boolean;
  evaluated_policies: string[];
  violations: Violation[];
};
// PATCH answers 202 with this body when the change loosens a rule and needs
// a second approver (W22-15); the stored row is unchanged until then.
export type PendingPolicyChange = {
  status: "pending_approval";
  pending_action_id?: string;
  reasons?: string[];
};

// Mirrors keystore.Algorithm; exported once so the form and the dry-run
// panel cannot drift apart.
export const POLICY_ALGORITHMS: readonly string[] = [
  "RSA-2048",
  "RSA-3072",
  "RSA-4096",
  "ECDSA-P256",
  "ECDSA-P384",
  "Ed25519",
  "ML-DSA-44",
  "ML-DSA-65",
  "ML-DSA-87",
  "Hybrid-ECDSA-P256-ML-DSA-65",
  "Hybrid-ECDSA-P384-ML-DSA-87",
];

export const policiesApi = {
  list: () => fetchJSON<{ data: Policy[] }>("/policies"),
  create: (body: PolicyWrite) =>
    fetchJSON<{ data: Policy }>("/policies", { method: "POST", body: JSON.stringify(body) }),
  update: (id: string, patch: PolicyWrite) =>
    fetchJSON<{ data: Policy | PendingPolicyChange }>(`/policies/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),
  remove: (id: string) =>
    fetchJSON<void>(`/policies/${encodeURIComponent(id)}`, { method: "DELETE" }),
  dryRun: (input: DryRunInput) =>
    fetchJSON<{ data: DryRunResult }>("/policies/dry-run", {
      method: "POST",
      body: JSON.stringify(input),
    }),
};

export type ParsedViolation = { policy: string; rule: string; detail: string } | null;

// The server refuses with `issuance policy "<name>": rule <rule>: <detail>`
// (internal/ca/policy_engine.go); wrappers may prefix it.
export function parsePolicyViolation(message: string): ParsedViolation {
  const m = /issuance policy "([^"]+)": rule (\w+): (.+)$/.exec(message);
  return m ? { policy: m[1], rule: m[2], detail: m[3] } : null;
}

export function isPendingChange(d: Policy | PendingPolicyChange | undefined): d is PendingPolicyChange {
  return !!d && (d as PendingPolicyChange).status === "pending_approval";
}
