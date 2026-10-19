import { fetchJSON } from "./api";

// Wire shapes: docs/openapi.yaml /acme/eab-keys and /acme/provisioners.
export type EabKey = {
  kid: string;
  label: string;
  provisioner?: string;
  template_id?: string;
  created_by?: string;
  created_at: string;
  revoked_at?: string | null;
  last_used_at?: string | null;
  uses: number;
};
// The 201 body carries only the creation fields plus the one-time secret.
export type EabCreated = {
  kid: string;
  hmac_key: string;
  label?: string;
  provisioner?: string;
  template_id?: string;
  created_at: string;
};
export type Provisioner = {
  name: string;
  ca_id: string;
  template_id?: string;
  allow_names: string[];
  challenges: string[];
  directory_url: string;
};
export type ProvisionerInput = {
  name: string;
  ca_id: string;
  template_id?: string;
  allow_names: string[];
  challenges: ("http-01" | "dns-01")[];
};

export const acmeApi = {
  eabList: () => fetchJSON<{ data: EabKey[] }>("/acme/eab-keys"),
  eabCreate: (b: { label: string; provisioner?: string; template_id?: string }) =>
    fetchJSON<{ data: EabCreated }>("/acme/eab-keys", {
      method: "POST",
      body: JSON.stringify(b),
    }),
  eabRevoke: (kid: string) =>
    fetchJSON<void>(`/acme/eab-keys/${encodeURIComponent(kid)}`, { method: "DELETE" }),
  provList: () => fetchJSON<{ data: Provisioner[] }>("/acme/provisioners"),
  provCreate: (p: ProvisionerInput) =>
    fetchJSON<{ data: Provisioner }>("/acme/provisioners", {
      method: "POST",
      body: JSON.stringify(p),
    }),
  // name is path-only on update (the input schema's name is create-only).
  provUpdate: (p: ProvisionerInput) => {
    const { name, ...body } = p;
    return fetchJSON<{ data: Provisioner }>(
      `/acme/provisioners/${encodeURIComponent(name)}`,
      { method: "PUT", body: JSON.stringify(body) },
    );
  },
  provDelete: (name: string) =>
    fetchJSON<void>(`/acme/provisioners/${encodeURIComponent(name)}`, { method: "DELETE" }),
};

const LABEL_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

function validLabels(host: string): string | null {
  if (host === "" || host.length > 253) return "Name is empty or longer than 253 characters";
  const labels = host.split(".");
  for (const l of labels) {
    if (l === "") return "Empty label (stray or doubled dot)";
    if (l.length > 63) return "Each label must be at most 63 characters";
    if (!LABEL_RE.test(l)) return "Labels use lowercase letters, digits and hyphens, and cannot start or end with a hyphen";
  }
  if (/^\d+$/.test(labels[labels.length - 1])) return "The last label cannot be all digits (no IP addresses)";
  return null;
}

// Mirrors the server's allow-list check (W26-02): exact names or *.suffix.
export function validateAllowEntry(raw: string): string | null {
  const v = raw.trim().toLowerCase();
  if (v === "") return "Entry is empty";
  if (/\s/.test(v)) return "No spaces allowed";
  if (v.includes(":")) return "No ports or IPv6 addresses";
  if (v === "localhost" || v.endsWith(".localhost")) return "localhost is not allowed";
  const rest = v.startsWith("*.") ? v.slice(2) : v;
  if (rest.includes("*")) return "Only a leading *. wildcard is allowed";
  return validLabels(rest);
}

const RESERVED_NAMES = new Set(["directory", "new-nonce", "new-account", "new-order", "order", "authz", "challenge", "finalize", "cert", "renewalinfo", "revoke-cert", "key-change", "account", "acme", "api"]);

export function validateProvisionerName(raw: string): string | null {
  if (!/^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$/.test(raw)) {
    return "1-32 lowercase letters, digits or hyphens; cannot start or end with a hyphen";
  }
  if (RESERVED_NAMES.has(raw)) return "That name is reserved";
  return null;
}
