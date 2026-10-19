import type { components } from "../generated/api-types";
import { fetchJSON } from "./api";

export type FindingException = components["schemas"]["Exception"];

// Exactly the five server-side justification enums; free text goes in the note.
export const JUSTIFICATIONS = [
  { value: "risk_accepted", label: "Risk accepted" },
  { value: "compensating_control", label: "Compensating control" },
  { value: "false_positive", label: "False positive" },
  { value: "planned_remediation", label: "Planned remediation" },
  { value: "not_applicable", label: "Not applicable" },
] as const;

export const MAX_EXCEPTION_DAYS = 365;
export const MAX_NOTE_LENGTH = 1000;

// Codes from docs/design/FINDING_ECONOMICS.md, for pages with no per-finding rows.
export const POSTURE_FINDING_CODES = [
  "EXPIRED",
  "WEAK_SIGNATURE",
  "WEAK_RSA_KEY",
  "WEAK_EC_KEY",
  "PQC_VULNERABLE",
  "PQC_MIGRATION_NEEDED",
  "SAN_SPRAWL",
  "NO_OCSP_URL",
] as const;

export type ExceptionRequest = components["schemas"]["ExceptionRequest"];

export const expiresAtFromDays = (days: number, now = new Date()) =>
  new Date(now.getTime() + days * 86_400_000).toISOString();

// A 202 means "pending a second approver", never "active".
export const proposeException = (b: ExceptionRequest) =>
  fetchJSON<{ data: { status: "pending"; pending_action_id: string } }>("/exceptions", {
    method: "POST",
    body: JSON.stringify(b),
  });

export const listExceptions = () => fetchJSON<{ data: FindingException[] }>("/exceptions");
