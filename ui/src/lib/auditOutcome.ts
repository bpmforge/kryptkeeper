// The audit outcome vocabulary, mirroring AuditOutcome in
// internal/bootstrap/audit_outcome.go. Keep the two in step: the backend
// refuses ?outcome= values outside this list.

export type BadgeTone = "neutral" | "warning" | "danger" | "success" | "info";

export const AUDIT_OUTCOMES: ReadonlyArray<{
  value: string;
  label: string;
  tone: BadgeTone;
}> = [
  { value: "success", label: "Success", tone: "success" },
  { value: "executed", label: "Executed", tone: "success" },
  { value: "failure", label: "Failure", tone: "danger" },
  { value: "issuance_failed", label: "Issuance failed", tone: "danger" },
  { value: "denied", label: "Denied", tone: "warning" },
  { value: "partial", label: "Partial", tone: "warning" },
  { value: "skipped", label: "Skipped", tone: "neutral" },
  { value: "pending_approval", label: "Pending approval", tone: "neutral" },
  { value: "proposed", label: "Proposed", tone: "neutral" },
];

export function auditOutcomeTone(outcome: string): BadgeTone {
  return AUDIT_OUTCOMES.find((o) => o.value === outcome)?.tone ?? "neutral";
}

export function auditOutcomeLabel(outcome: string): string {
  return AUDIT_OUTCOMES.find((o) => o.value === outcome)?.label ?? outcome;
}

const DOT_CLASS: Record<BadgeTone, string> = {
  success: "bg-state-auto",
  warning: "bg-state-attn",
  danger: "bg-state-over",
  info: "bg-primary",
  neutral: "bg-muted-foreground",
};

export function auditOutcomeDotClass(outcome: string): string {
  return DOT_CLASS[auditOutcomeTone(outcome)];
}

// Every page view writes audit rows (ca.list, authz.check, report.*), so an
// unfiltered feed showed the viewer's own browsing. "Live activity" means
// things that changed; the full log stays one click away.
const READ_ONLY_ACTION =
  /(^report\.|^dashboard\.|^authz\.|\.(list|get|check|summary|view|search|read)$)/;
export function isReadOnlyAction(action?: string): boolean {
  return READ_ONLY_ACTION.test(action ?? "");
}
