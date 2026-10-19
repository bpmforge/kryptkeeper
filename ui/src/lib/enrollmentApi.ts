import { fetchJSON } from "./api";
import { canManageUsers } from "./auth";

// Wire shapes: docs/openapi.yaml /scep/challenges, /est/users, /cmp/credentials.
export type ScepChallenge = {
  id: string;
  ca_id: string;
  common_name: string;
  dns_names?: string[] | null;
  created_by: string;
  created_at: string;
  expires_at: string;
  used_at?: string | null;
};
export type ScepCreated = ScepChallenge & { challenge: string };
export type EstUser = {
  username: string;
  allowed_dns_suffixes: string[];
  disabled: boolean;
  created_by: string;
  created_at: string;
  password_rotated_at?: string | null;
  shadowed_by_file?: boolean;
};
export type EstUserSecret = {
  username: string;
  password: string;
  allowed_dns_suffixes?: string[];
  created_at?: string;
};
export type CmpCredential = {
  id: string;
  kind: "pbm" | "trust_anchor";
  label?: string;
  reference?: string;
  cert_sha256?: string;
  enforced?: boolean;
  allowed_dns_suffixes?: string[] | null;
  created_by?: string;
  created_at: string;
  rotated_at?: string | null;
  revoked_at?: string | null;
  last_used_at?: string | null;
};
export type CmpPbmCreated = CmpCredential & { secret: string };

const json = (b: unknown) => JSON.stringify(b);
const seg = encodeURIComponent;

export const enrollmentApi = {
  /** Feature flag probe: lets the SCEP tab skip the list call (a 404 console error) when SCEP is off. */
  scepEnabled: () => fetchJSON<{ data: { scep_enabled: boolean; scep_off_reason?: string } }>("/integrations/microsoft"),
  scepList: () => fetchJSON<{ data: ScepChallenge[] }>("/scep/challenges"),
  scepCreate: (b: { common_name: string; dns_names: string[]; ttl: string }) =>
    fetchJSON<{ data: ScepCreated }>("/scep/challenges", { method: "POST", body: json(b) }),
  scepRevoke: (id: string) =>
    fetchJSON<void>(`/scep/challenges/${seg(id)}`, { method: "DELETE" }),
  estList: () => fetchJSON<{ data: EstUser[] }>("/est/users"),
  estCreate: (b: { username: string; allowed_dns_suffixes: string[] }) =>
    fetchJSON<{ data: EstUserSecret }>("/est/users", { method: "POST", body: json(b) }),
  estRotate: (u: string) =>
    fetchJSON<{ data: EstUserSecret }>(`/est/users/${seg(u)}/rotate`, { method: "POST" }),
  estPatch: (u: string, b: { disabled?: boolean; allowed_dns_suffixes?: string[] }) =>
    fetchJSON<{ data: EstUser }>(`/est/users/${seg(u)}`, { method: "PATCH", body: json(b) }),
  estDelete: (u: string) => fetchJSON<void>(`/est/users/${seg(u)}`, { method: "DELETE" }),
  cmpList: () => fetchJSON<{ data: CmpCredential[] }>("/cmp/credentials"),
  cmpCreatePbm: (b: { label: string; allowed_dns_suffixes: string[] }) =>
    fetchJSON<{ data: CmpPbmCreated }>("/cmp/credentials", {
      method: "POST",
      body: json({ kind: "pbm", ...b }),
    }),
  cmpRegisterAnchor: (b: { label: string; certificate_pem: string }) =>
    fetchJSON<{ data: CmpCredential }>("/cmp/credentials", {
      method: "POST",
      body: json({ kind: "trust_anchor", ...b }),
    }),
  cmpRotate: (id: string) =>
    fetchJSON<{ data: { id: string; reference: string; secret: string } }>(
      `/cmp/credentials/${seg(id)}/rotate`,
      { method: "POST" },
    ),
  cmpRevoke: (id: string) =>
    fetchJSON<void>(`/cmp/credentials/${seg(id)}`, { method: "DELETE" }),
};

// SCEP is open to pki-operator as well; EST and CMP stay admin-only.
export function canManageEnrollment(role?: string, scopes?: string[]): boolean {
  return canManageUsers(role, scopes) || (role ?? "").trim() === "pki-operator";
}

function validLabels(host: string): string | null {
  if (host.length > 253) return "Longer than 253 characters";
  for (const l of host.split(".")) {
    if (l === "") return "Empty label (stray or doubled dot)";
    if (l.length > 63) return "Each label must be at most 63 characters";
    if (l.startsWith("-") || l.endsWith("-")) return "A label cannot start or end with a hyphen";
    if (!/^[a-z0-9-]+$/.test(l)) return "Use lowercase letters, digits and hyphens only";
  }
  return null;
}

// Mirrors validDeviceName in handlers_scep_challenges.go: no wildcard, no space.
export function validateHostName(raw: string): string | null {
  const v = raw.trim();
  if (v === "") return "Name is empty";
  if (v.includes("*")) return "Wildcards are not allowed";
  if (/\s/.test(v)) return "No spaces allowed";
  return validLabels(v);
}

// EST/CMP suffix: leading dot, e.g. ".devices.example.com".
export function validateSuffix(raw: string): string | null {
  const v = raw.trim();
  if (v.length < 2 || !v.startsWith(".")) return "Start with a dot, e.g. .devices.example.com";
  if (v.includes("*")) return "Wildcards are not allowed";
  if (/\s/.test(v)) return "No spaces allowed";
  return validLabels(v.slice(1));
}

export function validateEstUsername(raw: string): string | null {
  if (!/^[A-Za-z0-9._@-]{1,64}$/.test(raw)) {
    return "1-64 characters: letters, digits, . _ @ - (no colon)";
  }
  return null;
}

export function parseLines(raw: string): string[] {
  return [...new Set(raw.split(/[\n,]/).map((s) => s.trim()).filter(Boolean))];
}
