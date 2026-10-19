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
  "codesign.policy.check",
  "events.stream",
  "policy.dry_run", // evaluates a request against policies, issues nothing
  "access_review.report", // report view; the campaign export stays visible
  "auth.role_map.preview", // what-if of the IdP group to role map
  "breakglass.status",
  "breakglass.reviews",
  "audit.transparency_checkpoint",
  "audit.transparency_inclusion",
  "audit.transparency_consistency",
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

// Human-readable names for the W22 audit actions (access review, approvals,
// policies, break-glass, tenancy-aware reads). Unlisted actions fall back to
// the raw name so a new action is never hidden or mislabelled.
export const AUDIT_ACTION_LABELS: Record<string, string> = {
  "access_review.open": "Access review opened",
  "access_review.decide": "Access review decision",
  "access_review.close": "Access review closed",
  "access_review.export": "Access review exported",
  "access_review.get": "Access review viewed",
  "access_review.list": "Access reviews listed",
  "access_review.report": "Access review report viewed",
  "action.expire": "Pending action expired",
  "approval.expire": "Approval request expired",
  "approval.expired": "Approval expired",
  "approval.delegate": "Approval delegated",
  "approval.inbox.list": "Approval inbox viewed",
  "approval.override": "Approval overridden (break-glass)",
  "audit.export": "Audit log exported",
  "audit.archive_propose": "Audit archive proposed",
  "audit.transparency_checkpoint": "Transparency checkpoint read",
  "audit.transparency_inclusion": "Transparency inclusion proof read",
  "audit.transparency_consistency": "Transparency consistency proof read",
  "auth.breakglass_login": "Break-glass login",
  "auth.role_map.preview": "Role mapping previewed",
  "breakglass.request": "Break-glass requested",
  "breakglass.activate": "Break-glass activated",
  "breakglass.review": "Break-glass reviewed",
  "breakglass.reviews": "Break-glass reviews listed",
  "breakglass.status": "Break-glass status viewed",
  "breakglass.used": "Break-glass access used",
  "codesign.request.deny": "Code-signing request denied",
  "codesign.key.generate": "Code-signing key generated in HSM/KMS",
  "codesign.policy.check": "Code-signing policy checked",
  "ownership.cmdb_import": "Ownership imported from CMDB",
  "policy.create": "Policy created",
  "policy.update": "Policy updated",
  "policy.delete": "Policy deleted",
  "policy.get": "Policy viewed",
  "policy.list": "Policies listed",
  "policy.dry_run": "Policy dry run",
  "policy.violation": "Policy violation",
};

export function auditActionLabel(action: string): string {
  return AUDIT_ACTION_LABELS[action] ?? action;
}
