// change_summary arrives as a (possibly truncated) JSON string. Render it as
// a short human line instead of raw JSON.
const LEAD_KEYS = ["cn", "common_name", "subject"];

function fmtValue(v: unknown, templateNames?: Map<string, string>, key?: string): string {
  if (typeof v === "string") {
    if (key === "template" || key === "template_id") return templateNames?.get(v) ?? v;
    return v;
  }
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return Array.isArray(v) ? v.map((x) => fmtValue(x)).join(", ") : "";
  return String(v);
}

export function summarizeChange(
  raw: string | undefined,
  templateNames?: Map<string, string>,
): string {
  const text = (raw ?? "").trim();
  if (!text) return "";
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch {
    // Truncated JSON or free text: pull "key":"value" pairs out best-effort.
    if (!text.startsWith("{")) return text;
    const pairs = [...text.matchAll(/"([\w.-]+)"\s*:\s*(?:"([^"]*)"|([\w.-]+))/g)];
    if (pairs.length === 0) return "";
    obj = Object.fromEntries(pairs.map((m) => [m[1], m[2] ?? m[3]]));
  }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return fmtValue(obj);
  const rec = obj as Record<string, unknown>;
  const parts: string[] = [];
  const used = new Set<string>();
  for (const k of LEAD_KEYS) {
    const v = fmtValue(rec[k]);
    if (v) {
      parts.push(v);
      used.add(k);
      break;
    }
  }
  if (rec.template || rec.template_id) {
    const key = rec.template ? "template" : "template_id";
    parts.push(`template ${fmtValue(rec[key], templateNames, "template")}`);
    used.add(key);
  }
  if (rec.reason) {
    parts.push(`reason: ${fmtValue(rec.reason)}`);
    used.add("reason");
  }
  for (const [k, v] of Object.entries(rec)) {
    if (used.has(k)) continue;
    const s = fmtValue(v);
    if (s) parts.push(`${k.replace(/_/g, " ")} ${s}`);
  }
  return parts.join(" · ");
}
