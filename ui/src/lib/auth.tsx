import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

export type AuthzResponse = {
  service: string;
  authenticated: boolean;
  principal: string;
  role?: string;
  scopes?: string[];
};

function hasScope(scopes: string[] | undefined, expected: string) {
  return (scopes ?? []).some((scope) => scope.trim() === expected);
}

export function canReadOperationalSummaries(role?: string, scopes?: string[]) {
  switch ((role ?? "").trim()) {
    case "pki-admin":
    case "pki-operator":
    case "pki-auditor":
    case "discovery-operator":
    case "service-account":
      return true;
    default:
      return hasScope(scopes, "*") || hasScope(scopes, "ops:read");
  }
}

// Mirrors the hub's key.manage-or-report.read gate on GET /inventory/keys
// (fixedRolePermissions + legacyRolePermissions). mcp-agent, service-account
// and cert-only roles are refused; the backend stays authoritative, and the
// page renders its own state if a custom role gets a 403.
export function canReadKeyInventory(role?: string) {
  switch ((role ?? "").trim()) {
    case "pki-admin":
    case "bootstrap":
    case "pki-operator":
    case "viewer":
    case "pki-viewer":
    case "auditor":
    case "pki-auditor":
    case "approver":
    case "discovery-operator":
    case "notification-operator":
    case "protocol-operator":
      return true;
    default:
      return false;
  }
}

// Mirrors canApproveActions on the hub (handlers_pending_actions.go): only these roles may
// approve or reject a pending action (key and CA dual control). `approver` is deliberately NOT
// among them: that role decides certificate requests on templates naming it, never pending
// actions (v1 decision, 2026-10-18). An unknown role (authz not loaded yet,
// or a role this build does not know) stays enabled so the hub remains the authority.
export function canDecidePendingActions(role?: string) {
  const r = (role ?? "").trim();
  if (r === "") return true;
  switch (r) {
    case "pki-admin":
    case "pki-operator":
      return true;
    case "approver":
    case "viewer":
    case "pki-viewer":
    case "auditor":
    case "pki-auditor":
    case "service-account":
    case "mcp-agent":
      return false;
    default:
      return true;
  }
}

export function canManageCertificates(role?: string, scopes?: string[]) {
  switch ((role ?? "").trim()) {
    case "pki-admin":
    case "pki-operator":
      return true;
    default:
      return (
        hasScope(scopes, "*") ||
        hasScope(scopes, "ops:write") ||
        hasScope(scopes, "certificates:write")
      );
  }
}

export function canManageDiscovery(role?: string, scopes?: string[]) {
  switch ((role ?? "").trim()) {
    case "pki-admin":
    case "discovery-operator":
      return true;
    default:
      return (
        hasScope(scopes, "*") ||
        hasScope(scopes, "ops:write") ||
        hasScope(scopes, "discovery:write")
      );
  }
}

export function canManageNotifications(role?: string, scopes?: string[]) {
  switch ((role ?? "").trim()) {
    case "pki-admin":
    case "pki-operator":
    case "notification-operator":
      return true;
    default:
      return (
        hasScope(scopes, "*") ||
        hasScope(scopes, "ops:write") ||
        hasScope(scopes, "notifications:write")
      );
  }
}

export function canManageCAs(role?: string, scopes?: string[]) {
  switch ((role ?? "").trim()) {
    case "pki-admin":
    case "pki-operator":
      return true;
    default:
      return (
        hasScope(scopes, "*") ||
        hasScope(scopes, "ops:write") ||
        hasScope(scopes, "ca:write")
      );
  }
}

export function canManageUsers(role?: string, scopes?: string[]) {
  switch ((role ?? "").trim()) {
    case "pki-admin":
      return true;
    default:
      return hasScope(scopes, "*") || hasScope(scopes, "users:write");
  }
}

export function useAuthz() {
  return useQuery<AuthzResponse>({
    queryKey: ["authz-check"],
    queryFn: api.authzCheck,
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
}
