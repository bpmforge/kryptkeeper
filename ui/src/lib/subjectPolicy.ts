import type { SubjectPolicy } from "./models";

// "DC=foo,DC=bar" in DN reading order, right after the CN. A malformed part
// is sent as-is so the server's subject_policy error names it.
export function subjectPolicyFromText(text: string): SubjectPolicy | undefined {
  const parts = text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.length === 0) return undefined;
  return {
    fixed_rdns: parts.map((part) => {
      const eq = part.indexOf("=");
      return eq < 0
        ? { type: part, value: "" }
        : {
            type: part.slice(0, eq).trim().toUpperCase(),
            value: part.slice(eq + 1).trim(),
          };
    }),
  };
}

export function subjectPolicyText(p?: SubjectPolicy): string {
  return (p?.fixed_rdns ?? []).map((r) => `${r.type}=${r.value}`).join(",");
}
