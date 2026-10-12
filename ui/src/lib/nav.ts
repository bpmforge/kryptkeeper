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
  ShieldAlert,
  Bot,
  Fingerprint,
  Building,
  PlugZap,
  Puzzle,
  Plug,
  CalendarClock,
  Cloud,
} from "lucide-react";
import {
  canManageUsers,
  canReadKeyInventory,
  canReadOperationalSummaries,
} from "./auth";

export type NavIcon = ComponentType<{ size?: number; className?: string }>;

export type NavPermission = (role?: string, scopes?: string[]) => boolean;

export type NavItem = {
  to: string;
  label: string;
  icon: NavIcon;
  // Absent means visible to every authenticated principal — matches today's
  // behaviour for pages whose own view is open to all roles and only their
  // action buttons gate on canManage*. Only present for nav items whose
  // underlying page already restricts the whole thing to a permission.
  permission?: NavPermission;
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
      { to: "/approvals", label: "Approvals", icon: Stamp },
      { to: "/pending-actions", label: "Pending Actions", icon: Bot },
      { to: "/alerts", label: "Alerts", icon: Bell },
    ],
  },
  {
    label: "Automation",
    items: [
      { to: "/automation", label: "Automation", icon: Workflow },
      { to: "/targets/setup", label: "Target Setup", icon: PlugZap },
      { to: "/targets/renewal-policy", label: "Renewal Policy", icon: CalendarClock },
      { to: "/delivery-plugins", label: "Delivery Plugins", icon: Puzzle },
      { to: "/agents", label: "Agents", icon: Cpu },
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
      { to: "/keys", label: "Keys", icon: KeyRound },
      { to: "/code-signing", label: "Code Signing", icon: FileSignature },
      { to: "/spiffe", label: "SPIFFE", icon: Fingerprint },
      { to: "/templates", label: "Templates", icon: FileCheck2 },
      { to: "/discovery", label: "Discovery", icon: Radar },
      { to: "/search", label: "Search", icon: SearchIcon },
    ],
  },
  {
    label: "Evidence",
    items: [
      { to: "/reports/compliance-evidence", label: "Compliance Evidence", icon: BookOpen },
      {
        to: "/audit",
        label: "Audit Log",
        icon: ShieldAlert,
        permission: canReadOperationalSummaries,
      },
      { to: "/reports/change-audit", label: "Change Audit", icon: ClipboardList },
      { to: "/history", label: "History", icon: HistoryIcon },
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
      { to: "/tenants", label: "Tenants", icon: Building },
      { to: "/settings", label: "Settings", icon: SettingsIcon },
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
): NavSection[] {
  return sections
    .map((section) => ({
      ...section,
      items: section.items.filter(
        (item) => !item.permission || item.permission(role, scopes),
      ),
    }))
    .filter((section) => section.items.length > 0);
}
