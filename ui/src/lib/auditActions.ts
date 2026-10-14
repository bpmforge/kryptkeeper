// "Hide read-only events" classification. An action is read-only only when it
// is a pure lookup / permission check / report view. Anything that exports,
// downloads, mutates, approves, signs, issues, revokes or builds an evidence
// pack stays visible, and so does any action we cannot positively classify:
// hiding a security-relevant event by mistake is worse than showing noise.

// Verb suffixes that denote a pure read (key.list, authz.check, ...).
const READ_ONLY_SUFFIXES = [
  ".list",
  ".get",
  ".read",
  ".view",
  ".search",
  ".ping",
  ".summary",
  ".check",
];

// Single-method read endpoints whose names carry no read verb.
const READ_ONLY_ACTIONS = new Set([
  "certificate.chain",
  "spiffe.bundle_get",
  "dashboard.actions.history",
  "protocol.status",
  "protocol.readiness",
  "scheduler.renewal_status",
  "blast_radius.simulate", // what-if only, changes nothing
  "crypto_agility.roadmap",
  "inventory.keys",
  "inventory.code_signing",
  "inventory.code_signing_policy",
  "events.stream",
]);

// report.* are report views, except the ones that hand data out: bulk export,
// PDF downloads and compliance evidence packs.
function isReportView(a: string): boolean {
  return a.startsWith("report.") && !/export|download|evidence|_pdf$/.test(a);
}

export function isReadOnlyAction(action: string): boolean {
  const a = action.toLowerCase();
  return (
    READ_ONLY_SUFFIXES.some((suffix) => a.endsWith(suffix)) ||
    READ_ONLY_ACTIONS.has(a) ||
    isReportView(a)
  );
}
