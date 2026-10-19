import type { ComponentType } from "react";
import {
  LayoutDashboard,
  ShieldCheck,
  Building2,
  FileCheck2,
  Radar,
  Bell,
  History as HistoryIcon,
  Search as SearchIcon,
  BookOpen,
  Users as UsersIcon,
  BarChart2,
  Cpu,
  KeyRound,
  TrendingUp,
  Calendar,
  RotateCcw,
  ClipboardList,
  Gavel,
  AlertTriangle,
  Stamp,
  Settings as SettingsIcon,
  FileSignature,
  Workflow,
  Gauge,
  ShieldAlert,
  Fingerprint,
  Building,
  PlugZap,
  Puzzle,
  Plug,
  CalendarClock,
  Cloud,
  Database,
  ArrowRightLeft,
  Layers,
  Bot,
  Network,
  Terminal,
  FilePlus2,
  ListChecks,
} from "lucide-react";
import {
  canManageUsers,
  canReadKeyInventory,
  canReadOperationalSummaries,
} from "./auth";
import { canManageEnrollment } from "./enrollmentApi";

export type NavIcon = ComponentType<{ size?: number; className?: string }>;

export type NavPermission = (role?: string, scopes?: string[]) => boolean;

// Deployment flags that gate whole nav items. An unknown flag counts as off
// so an item never flashes in while the flag is still loading.
export type NavFlags = { multiTenancy?: boolean };

export type NavItem = {
  to: string;
  label: string;
  icon: NavIcon;
  // Absent means visible to every authenticated principal — matches today's
  // behaviour for pages whose own view is open to all roles and only their
  // action buttons gate on canManage*. Only present for nav items whose
  // underlying page already restricts the whole thing to a permission.
  permission?: NavPermission;
  // Hidden unless the named deployment flag is explicitly true.
  requiresFlag?: keyof NavFlags;
};

export type NavSection = {
  label: string;
  items: NavItem[];
};

// Grouped by what someone is trying to DO, not by what kind of object a
// page happens to show. The old shape sorted by system area, which is why
// "System" ended up holding Alerts, Users, Agents and Settings together —
// eleven unrelated items nobody could predict the contents of.
//
// Order follows how often the primary user needs each group: their job is
// keeping renewal automatic, so Today and Automation come before the
// inventory. Evidence is the reporting user's home.
export const navSections: NavSection[] = [
  {
    label: "Today",
    items: [
      { to: "/", label: "What needs a human", icon: LayoutDashboard },
      { to: "/inbox", label: "Approvals inbox", icon: Stamp },
      { to: "/alerts", label: "Alerts", icon: Bell },
      { to: "/search", label: "Search", icon: SearchIcon },
      { to: "/ssh-certificates", label: "SSH Certificates", icon: Terminal },
      { to: "/nhi", label: "Machine Identities", icon: Bot },
      { to: "/reports/anomalies", label: "Anomalies", icon: ShieldAlert },
      {
        to: "/ct-findings",
        label: "CT Findings",
        icon: ShieldAlert,
        permission: canReadOperationalSummaries,
      },
    ],
  },
  {
    label: "Automation",
    items: [
      { to: "/automation", label: "Automation", icon: Workflow },
      { to: "/targets", label: "Targets", icon: PlugZap },
      { to: "/targets/setup", label: "Target Setup", icon: PlugZap },
      { to: "/targets/renewal-policy", label: "Renewal Policy", icon: CalendarClock },
      {
        to: "/renewal/rollout-groups",
        label: "Rollout Groups",
        icon: Layers,
        permission: (role) => role === "pki-admin",
      },
      { to: "/delivery-plugins", label: "Delivery Plugins", icon: Puzzle },
      { to: "/agents", label: "Agents", icon: Cpu },
    ],
  },
  {
    // Split from Automation when v0.14 (Enrollment) and v0.15 (Rollout
    // Groups) together pushed it past the 8-item scan limit.
    label: "Connect",
    items: [
      { to: "/acme", label: "ACME", icon: Plug, permission: canManageUsers },
      { to: "/enrollment", label: "Enrollment Protocols", icon: Plug, permission: canManageEnrollment },
      {
        to: "/integrations",
        label: "Integrations",
        icon: Plug,
        permission: canReadOperationalSummaries,
      },
    ],
  },
  {
    label: "Estate",
    items: [
      { to: "/certificates", label: "Certificates", icon: ShieldCheck },
      { to: "/cas", label: "Certificate Authorities", icon: Building2 },
      {
        to: "/ceremonies",
        label: "Key Ceremonies",
        icon: Gavel,
        permission: (role) => role === "pki-admin",
      },
      { to: "/keys", label: "Keys", icon: KeyRound },
      { to: "/code-signing", label: "Code Signing", icon: FileSignature },
      { to: "/spiffe", label: "SPIFFE", icon: Fingerprint },
      { to: "/templates", label: "Templates", icon: FileCheck2 },
      { to: "/discovery", label: "Discovery", icon: Radar },
    ],
  },
  {
    label: "Evidence",
    items: [
      { to: "/reports/slo", label: "SLOs", icon: Gauge },
      { to: "/reports/compliance-evidence", label: "Compliance Evidence", icon: BookOpen },
      { to: "/reports/key-custody", label: "Key Custody", icon: KeyRound, permission: (role) => role === "pki-admin" },
      {
        to: "/audit",
        label: "Audit Log",
        icon: ShieldAlert,
        permission: canReadOperationalSummaries,
      },
      { to: "/reports/change-audit", label: "Change Audit", icon: ClipboardList },
      { to: "/history", label: "History", icon: HistoryIcon },
      { to: "/blast-radius", label: "Blast Radius", icon: Network },
    ],
  },
  {
    label: "Analysis",
    items: [
      { to: "/crypto-posture", label: "Crypto Posture", icon: BarChart2 },
      { to: "/reports/pqc-migration", label: "PQC Migration", icon: TrendingUp },
      { to: "/reports/algorithm-sunset", label: "Algorithm Sunset", icon: AlertTriangle },
      { to: "/reports/expiry-timeline", label: "Expiry Timeline", icon: Calendar },
      {
        to: "/inventory/keys",
        label: "Cloud Keys",
        icon: Cloud,
        permission: canReadKeyInventory,
      },
      { to: "/reports/ca-health", label: "CA Health", icon: Gavel },
      { to: "/reports/issuance-velocity", label: "Issuance Velocity", icon: TrendingUp },
      { to: "/reports/revocation-activity", label: "Revocation Activity", icon: RotateCcw },
    ],
  },
  {
    label: "Administration",
    items: [
      { to: "/users", label: "Users", icon: UsersIcon, permission: canManageUsers },
      { to: "/access-review", label: "Access Review", icon: ClipboardList, permission: canManageUsers },
      {
        to: "/tenants",
        label: "Tenants",
        icon: Building,
        requiresFlag: "multiTenancy",
      },
      { to: "/policies", label: "Policies", icon: ShieldCheck, permission: canManageUsers },
      { to: "/roles", label: "Roles", icon: KeyRound, permission: canManageUsers },
      { to: "/inventory-sources", label: "Inventory Sources", icon: Database },
      { to: "/migration", label: "Migration", icon: ArrowRightLeft },
      { to: "/settings", label: "Settings", icon: SettingsIcon },
    ],
  },
];

// W33-22: the requester role is an app owner's, not an operator's. It sees
// exactly two items; every other nav entry is hidden regardless of scopes.
export const isRequesterOnly = (role?: string) => (role ?? "").trim() === "requester";

export const requesterNavSections: NavSection[] = [
  {
    label: "Requests",
    items: [
      { to: "/certificates/issue", label: "Request", icon: FilePlus2 },
      { to: "/my-requests", label: "My Requests", icon: ListChecks },
    ],
  },
];

/**
 * Filters nav sections down to what `role`/`scopes` may see, dropping items
 * gated by a permission the principal lacks and dropping any section left
 * with no items. `role`/`scopes` undefined (auth still loading, or failed)
 * default-denies every gated item rather than flashing them.
 */
export function filterNavSections(
  sections: NavSection[],
  role?: string,
  scopes?: string[],
  flags: NavFlags = {},
): NavSection[] {
  if (isRequesterOnly(role)) return requesterNavSections;
  return sections
    .map((section) => ({
      ...section,
      items: section.items.filter(
        (item) =>
          (!item.permission || item.permission(role, scopes)) &&
          (!item.requiresFlag || flags[item.requiresFlag] === true),
      ),
    }))
    .filter((section) => section.items.length > 0);
}
