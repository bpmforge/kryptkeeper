import { humanizeEnum } from "./utils";

// Relative wording: "0h 12m" read as "Oh 12m" at a glance.
export function formatAge(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.floor(h / 24)} d ago`;
}

// The inbox summary is a server-built sentence that embeds raw ids and
// machine action kinds. Resolve what we can; keep everything else verbatim.
export function humanizeInboxSummary(
  summary: string,
  caNames: Map<string, string>,
  templateNames: Map<string, string>,
): string {
  let out = summary.replace(/template (\S+)/, (m, id: string) => {
    const name = templateNames.get(id);
    return name ? `template ${name}` : m;
  });
  out = out.replace(/\bCA (\S+)/, (m, id: string) => {
    const name = caNames.get(id);
    return name ? `CA ${name}` : m;
  });
  // Leading action kind such as "codesign.oidc_trust_rule" or "exception_create".
  out = out.replace(/^([a-z][a-z0-9]*(?:[._][a-z0-9]+)+)(?=\s|$)/, (kind) => humanizeEnum(kind));
  return out;
}
