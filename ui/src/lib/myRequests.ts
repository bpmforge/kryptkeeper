import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { useAuthz } from "./auth";
import { isRequesterOnly } from "./nav";
import type {
  ApprovalRequest,
  CaRecord,
  CertificateRecord,
  TemplateRecord,
} from "./models";

export type RequestState = "pending" | "approved" | "issued" | "denied";

export type RequestRow = {
  key: string;
  state: RequestState;
  name: string;
  requestedAt: string;
  fingerprint?: string;
  reason?: string;
};

/**
 * Derives the four requester-facing states from an approval row: approved
 * with no issued_fingerprint is still being issued; approved with one is
 * issued; rejected is denied.
 */
export function approvalState(a: ApprovalRequest): RequestState {
  if (a.status === "rejected") return "denied";
  if (a.status === "approved")
    return a.issued_fingerprint ? "issued" : "approved";
  return "pending";
}

/**
 * Merges approval rows with directly issued certificates (auto-approved
 * issues return 201 and never create an approval), newest first.
 */
export function mergeRequests(
  approvals: ApprovalRequest[],
  certs: CertificateRecord[],
  templateNames: Record<string, string> = {},
): RequestRow[] {
  const certByFp = new Map(certs.map((c) => [c.fingerprint_sha256, c]));
  const seen = new Set<string>();
  const rows: RequestRow[] = approvals.map((a) => {
    const state = approvalState(a);
    const cert = a.issued_fingerprint
      ? certByFp.get(a.issued_fingerprint)
      : undefined;
    if (a.issued_fingerprint) seen.add(a.issued_fingerprint);
    return {
      key: `apr-${a.id}`,
      state,
      name: cert?.common_name || templateNames[a.template_id] || a.template_id,
      requestedAt: a.requested_at,
      fingerprint:
        state === "issued" ? (a.issued_fingerprint ?? undefined) : undefined,
      reason: a.reject_reason ?? undefined,
    };
  });
  for (const c of certs) {
    if (seen.has(c.fingerprint_sha256)) continue;
    rows.push({
      key: `crt-${c.fingerprint_sha256}`,
      state: "issued",
      name: c.common_name || c.fingerprint_sha256,
      requestedAt: c.valid_from ?? "",
      fingerprint: c.fingerprint_sha256,
    });
  }
  return rows.sort((x, y) => y.requestedAt.localeCompare(x.requestedAt));
}

/**
 * The CAs and templates the requester's team may use, from its team policy
 * (W33-20). An empty allow-list, a missing policy (404) or a failed lookup
 * places no restriction here; the server enforces (W33-21), so this is a
 * convenience that stops the form offering what will be refused.
 */
export function useTeamAllowedOptions() {
  const authz = useAuthz();
  const principal = authz.data?.principal ?? "";
  const requesterOnly = isRequesterOnly(authz.data?.role);
  const policy = useQuery({
    queryKey: ["team-policy", principal],
    queryFn: () => api.teamPolicy(principal),
    enabled: requesterOnly && principal !== "",
    retry: false,
  });
  const p = requesterOnly ? policy.data : null;
  const allowedCas = p?.allowed_cas ?? [];
  const allowedTemplates = p?.allowed_templates ?? [];
  return {
    loading: requesterOnly && policy.isLoading,
    filterCas: (cas: CaRecord[]) =>
      allowedCas.length > 0
        ? cas.filter((c) => allowedCas.includes(c.id))
        : cas,
    filterTemplates: (templates: TemplateRecord[]) =>
      allowedTemplates.length > 0
        ? templates.filter((t) => allowedTemplates.includes(t.id))
        : templates,
  };
}
