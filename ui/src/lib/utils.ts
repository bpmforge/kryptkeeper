import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// S-69: hand the browser a PEM as a named file download. Certificate bytes
// only — never key material, which must not reach the UI at all.
export function savePemFile(filename: string, pem: string) {
  const blob = new Blob([pem], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

// S-71: stored validity periods come in two shapes — ISO-8601 durations
// ("P90D", from templates created via the API/board drills) and shorthand
// ("90d", from this form). Normalize at render only; the stored value is the
// contract and must not be rewritten.
export function formatValidityPeriod(raw: string | undefined | null): string {
  if (!raw) return "—";
  const iso = /^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?$/i.exec(
    raw.trim(),
  );
  if (!iso) return raw;
  const [, y, m, w, d] = iso;
  const parts = [
    y ? `${Number(y)}y` : null,
    m ? `${Number(m)}mo` : null,
    w ? `${Number(w)}w` : null,
    d ? `${Number(d)}d` : null,
  ].filter(Boolean);
  return parts.length ? parts.join(" ") : raw;
}

// Enum and machine values (pending_ceremony, WEAK_KEY, adcs_export,
// codesign.oidc_trust_rule) shown to people: "Pending ceremony", "Weak key".
// Known acronyms keep their case.
const ACRONYMS: Record<string, string> = {
  adcs: "AD CS", acme: "ACME", est: "EST", scep: "SCEP", cmp: "CMP", ca: "CA",
  cas: "CAs", oidc: "OIDC", ssh: "SSH", tls: "TLS", pqc: "PQC", eku: "EKU",
  api: "API", nhi: "NHI", ct: "CT", kms: "KMS", hsm: "HSM", url: "URL",
  id: "ID", ip: "IP", rsa: "RSA", ecdsa: "ECDSA", sha1: "SHA-1", cbom: "CBOM",
  siem: "SIEM", itsm: "ITSM", spiffe: "SPIFFE", svid: "SVID", byok: "BYOK",
};
export function humanizeEnum(value: string | null | undefined): string {
  if (!value) return "";
  const words = value.trim().split(/[_.\s-]+/).filter(Boolean);
  return words
    .map((w, i) => {
      const lower = w.toLowerCase();
      if (ACRONYMS[lower]) return ACRONYMS[lower];
      return i === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
    })
    .join(" ");
}
