import {
  BrowserRouter,
  Routes,
  Route,
  NavLink,
  Link,
  Navigate,
  useNavigate,
  useLocation,
} from "react-router-dom";
import {
  QueryClient,
  QueryClientProvider,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { ShieldCheck, LogOut, ChevronRight } from "lucide-react";
import { useState } from "react";
import Dashboard from "./pages/Dashboard";
import Certificates from "./pages/Certificates";
import IssueWizard from "./pages/IssueWizard";
import CAs from "./pages/CAs";
import Issuers from "./pages/Issuers";
import Ceremonies from "./pages/Ceremonies";
import Discovery from "./pages/Discovery";
import Alerts from "./pages/Alerts";
import History from "./pages/History";
import SearchPage from "./pages/Search";
import Audit from "./pages/Audit";
import Templates from "./pages/Templates";
import DeliveryPlugins from "./pages/DeliveryPlugins";
import Users from "./pages/Users";
import AccessReview from "./pages/AccessReview";
import CryptoPosture from "./pages/CryptoPosture";
import Agents from "./pages/Agents";
import CTFindings from "./pages/CTFindings";
import TargetSetup from "./pages/TargetSetup";
import Targets from "./pages/Targets";
import RenewalPolicy from "./pages/RenewalPolicy";
import RolloutGroups from "./pages/RolloutGroups";
import Settings from "./pages/Settings";
import Integrations from "./pages/Integrations";
import CodeSigning from "./pages/CodeSigning";
import Spiffe from "./pages/Spiffe";
import Nhi from "./pages/Nhi";
import SshCertificates from "./pages/SshCertificates";
import Automation from "./pages/Automation";
import Login from "./pages/Login";
import Keys from "./pages/Keys";
import CAHealth from "./pages/CAHealth";
import ExpiryTimeline from "./pages/ExpiryTimeline";
import SLO from "./pages/SLO";
import RevocationActivity from "./pages/RevocationActivity";
import IssuanceVelocity from "./pages/IssuanceVelocity";
import Anomalies from "./pages/Anomalies";
import ChangeAudit from "./pages/ChangeAudit";
import ComplianceEvidence from "./pages/ComplianceEvidence";
import KeyCustody from "./pages/KeyCustody";
import AlgorithmSunset from "./pages/AlgorithmSunset";
import BlastRadius from "./pages/BlastRadius";
import PQCMigration from "./pages/PQCMigration";
import ApprovalInbox from "./pages/ApprovalInbox";
import MyRequests from "./pages/MyRequests";
import Tenants from "./pages/Tenants";
import Policies from "./pages/Policies";
import Roles from "./pages/Roles";
import CloudKeys from "./pages/CloudKeys";
import InventorySources from "./pages/InventorySources";
import AcmeEnrollment from "./pages/AcmeEnrollment";
import EnrollmentProtocols from "./pages/EnrollmentProtocols";
import Migration from "./pages/Migration";
import { useAuthz } from "./lib/auth";
import { navSections, filterNavSections, isRequesterOnly } from "./lib/nav";
import { ThemeToggle } from "./components/ThemeToggle";
import { api } from "./lib/api";
import { Toaster } from "./components/ui/sonner";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { CommandPalette } from "./components/CommandPalette";
import { MobileNav } from "./components/MobileNav";
import { DemoBanner } from "./components/DemoBanner";

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 30_000, retry: 1 } },
});

function TenantSwitcher({ collapsed }: { collapsed: boolean }) {
  const { data } = useQuery({
    queryKey: ["tenant-context"],
    queryFn: () => api.tenantContext(),
    staleTime: 30_000,
  });
  const ctx = data?.data;
  // Only meaningful when multi-tenancy is on. Operators are pinned to a single
  // tenant (read-only badge); super-admins get a "view-as" switcher.
  if (!ctx?.enabled || collapsed) return null;

  const current = sessionStorage.getItem("kk_tenant") ?? "";
  const onChange = (value: string) => {
    if (value) sessionStorage.setItem("kk_tenant", value);
    else sessionStorage.removeItem("kk_tenant");
    // A scope change invalidates every cached view; reload for a clean slate.
    window.location.reload();
  };

  if (!ctx.super_admin) {
    return (
      <div className="px-2.5 py-1.5 text-xs text-muted-foreground">
        Tenant: <span className="text-foreground">{ctx.tenant}</span>
      </div>
    );
  }

  return (
    <div className="px-2 pb-1">
      <label
        htmlFor="tenant-view-select"
        className="mb-1 block px-0.5 text-[10px] uppercase tracking-widest text-muted-foreground"
      >
        Viewing tenant
      </label>
      <select
        id="tenant-view-select"
        aria-label="Tenant view"
        value={current}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-lg border border-border bg-[var(--surface-2)] px-2 py-1.5 text-xs text-foreground"
      >
        <option value="">All tenants</option>
        {ctx.tenants.map((t) => (
          <option key={t.id} value={t.id}>
            {t.name}
          </option>
        ))}
      </select>
    </div>
  );
}

// A requester-only user has no dashboard in its nav; land it on My Requests.
function HomeRoute() {
  const authz = useAuthz();
  if (isRequesterOnly(authz.data?.role)) return <Navigate to="/my-requests" replace />;
  return <Dashboard />;
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const session = sessionStorage.getItem("kk_session");
  if (!session) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function SidebarBody({ collapsed }: { collapsed: boolean }) {
  const authz = useAuthz();
  const role = authz.data?.role ?? "—";
  const tenancy = useQuery({
    queryKey: ["tenant-context"],
    queryFn: () => api.tenantContext(),
    staleTime: 30_000,
    retry: false,
  });
  const sections = filterNavSections(
    navSections,
    authz.data?.role,
    authz.data?.scopes,
    { multiTenancy: tenancy.data?.data.enabled === true },
  );
  const navigate = useNavigate();
  const qc = useQueryClient();

  const logout = () => {
    sessionStorage.removeItem("kk_session");
    sessionStorage.removeItem("auth_token");
    qc.clear();
    void api.logout().catch(() => {});
    navigate("/login");
  };

  return (
    <>
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-border">
        <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-primary to-primary flex items-center justify-center shrink-0 glow-cyan">
          <ShieldCheck size={14} className="text-white" />
        </div>
        {!collapsed && (
          <>
            <span className="gradient-text font-bold text-base tracking-tight flex-1">
              Kryptkeeper
            </span>
            <button
              type="button"
              onClick={() =>
                document.dispatchEvent(
                  new KeyboardEvent("keydown", {
                    key: "k",
                    metaKey: true,
                    bubbles: true,
                  }),
                )
              }
              className="flex items-center gap-1 rounded-md border border-border bg-muted px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground hover:text-foreground hover:border-border transition"
              title="Open command palette (⌘K)"
            >
              ⌘K
            </button>
          </>
        )}
      </div>

      {/* Nav sections */}
      <nav
        className="flex-1 overflow-y-auto py-3 space-y-1 px-2"
        aria-label="Main navigation"
      >
        {sections.map((section) => (
          <div key={section.label} className="mb-1">
            {!collapsed && (
              <p className="px-2 mb-1 mt-2 text-[10px] font-semibold tracking-widest uppercase text-muted-foreground">
                {section.label}
              </p>
            )}
            {section.items.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                end={to === "/"}
                className={({ isActive }) =>
                  `group flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-all duration-150 ${
                    isActive
                      ? "nav-item-active font-medium"
                      : "text-muted-foreground hover:bg-accent hover:text-foreground border-l-2 border-transparent"
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <Icon
                      size={15}
                      className={`shrink-0 ${isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"}`}
                    />
                    {!collapsed && <span className="truncate">{label}</span>}
                  </>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-border px-2 py-3 space-y-1">
        <TenantSwitcher collapsed={collapsed} />
        {!collapsed && (
          <div className="flex items-center justify-between px-2.5 py-1.5">
            <span className="text-xs text-muted-foreground">Theme</span>
            <ThemeToggle />
          </div>
        )}
        {!collapsed && (
          <div className="flex items-center gap-2 px-2.5 py-1.5">
            <div className="w-6 h-6 rounded-full bg-gradient-to-br from-primary to-primary flex items-center justify-center text-[10px] font-bold text-white shrink-0">
              {role.charAt(0).toUpperCase()}
            </div>
            <span className="text-xs text-muted-foreground truncate">{role}</span>
          </div>
        )}
        <button
          type="button"
          onClick={logout}
          className="w-full flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm text-muted-foreground transition hover:bg-state-over/10 hover:text-state-over group"
          aria-label="Log out"
        >
          <LogOut size={14} className="shrink-0 group-hover:text-state-over" />
          {!collapsed && <span>Log out</span>}
        </button>
      </div>
    </>
  );
}

function Sidebar({
  collapsed,
  onToggle,
}: {
  collapsed: boolean;
  onToggle: () => void;
}) {
  return (
    <aside
      className={`relative hidden md:flex flex-col border-r border-border bg-[var(--surface-1)] motion-safe:transition-all motion-safe:duration-300 ${
        collapsed ? "w-[60px]" : "w-[220px]"
      } shrink-0 h-screen sticky top-0 z-20`}
    >
      <SidebarBody collapsed={collapsed} />

      {/* Collapse toggle */}
      <button
        type="button"
        onClick={onToggle}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        className="absolute -right-3 top-16 w-6 h-6 rounded-full bg-[var(--surface-2)] border border-border flex items-center justify-center text-muted-foreground hover:text-primary hover:border-primary/40 transition z-30"
      >
        <ChevronRight
          size={12}
          className={`transition-transform ${collapsed ? "" : "rotate-180"}`}
        />
      </button>
    </aside>
  );
}

function AppShell() {
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="min-h-screen flex bg-[var(--surface-0)]">
      <CommandPalette />
      {/* Skip link */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-slate-950"
      >
        Skip to main content
      </a>

      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} />

      <div className="flex min-w-0 flex-1 flex-col">
      {/* Below md: header menu button + navigation drawer (WCAG 1.4.10 Reflow) */}
      <MobileNav>
        <SidebarBody collapsed={false} />
      </MobileNav>

      <DemoBanner />

      {/* Main content */}
      <main
        id="main-content"
        tabIndex={-1}
        className="flex-1 min-w-0 overflow-y-auto focus:outline-none relative z-10"
      >
        {/* S-41: inside <main>, so a page that throws during render loses the
            page and not the sidebar. Keyed on pathname because a boundary stays
            latched until it remounts — without the key, one bad page would make
            every subsequent route render the error panel. */}
        <ErrorBoundary key={location.pathname}>
          <Routes>
            <Route path="/" element={<HomeRoute />} />
            <Route path="/certificates" element={<Certificates />} />
            <Route path="/certificates/issue" element={<IssueWizard />} />
            <Route path="/my-requests" element={<MyRequests />} />
            <Route
              path="/certificates/:fingerprint"
              element={<Certificates />}
            />
            <Route path="/cas" element={<CAs />} />
            <Route path="/issuers" element={<Issuers />} />
            <Route path="/ceremonies" element={<Ceremonies />} />
            <Route path="/cas/:id" element={<CAs />} />
            <Route path="/keys" element={<Keys />} />
            <Route path="/inventory/keys" element={<CloudKeys />} />
            <Route path="/inventory-sources" element={<InventorySources />} />
            <Route path="/acme" element={<AcmeEnrollment />} />
            <Route path="/enrollment" element={<EnrollmentProtocols />} />
            <Route path="/templates" element={<Templates />} />
            <Route path="/reports/anomalies" element={<Anomalies />} />
            <Route path="/inbox" element={<ApprovalInbox />} />
            <Route
              path="/approvals"
              element={<Navigate to="/inbox" replace />}
            />
            <Route
              path="/pending-actions"
              element={<Navigate to="/inbox" replace />}
            />
            <Route path="/delivery-plugins" element={<DeliveryPlugins />} />
            <Route path="/migration" element={<Migration />} />
            <Route path="/discovery" element={<Discovery />} />
            <Route path="/discovery/endpoints/:id" element={<Discovery />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/alerts/deliveries/:id" element={<Alerts />} />
            <Route path="/history" element={<History />} />
            <Route path="/history/:actionId" element={<History />} />
            <Route path="/search" element={<SearchPage />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/audit/:id" element={<Audit />} />
            <Route path="/users" element={<Users />} />
            <Route path="/access-review" element={<AccessReview />} />
            <Route path="/tenants" element={<Tenants />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/roles" element={<Roles />} />
            <Route path="/crypto-posture" element={<CryptoPosture />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/ct-findings" element={<CTFindings />} />
            <Route path="/targets" element={<Targets />} />
            <Route path="/targets/setup" element={<TargetSetup />} />
            <Route path="/targets/renewal-policy" element={<RenewalPolicy />} />
            <Route path="/renewal/rollout-groups" element={<RolloutGroups />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/integrations" element={<Integrations />} />
            <Route path="/automation" element={<Automation />} />
            <Route path="/code-signing" element={<CodeSigning />} />
            <Route path="/spiffe" element={<Spiffe />} />
            <Route path="/nhi" element={<Nhi />} />
            <Route path="/ssh-certificates" element={<SshCertificates />} />
            <Route path="/reports/ca-health" element={<CAHealth />} />
            <Route path="/reports/slo" element={<SLO />} />
            <Route
              path="/reports/expiry-timeline"
              element={<ExpiryTimeline />}
            />
            <Route
              path="/reports/revocation-activity"
              element={<RevocationActivity />}
            />
            <Route
              path="/reports/issuance-velocity"
              element={<IssuanceVelocity />}
            />
            <Route path="/reports/change-audit" element={<ChangeAudit />} />
            <Route
              path="/reports/compliance-evidence"
              element={<ComplianceEvidence />}
            />
            <Route path="/reports/key-custody" element={<KeyCustody />} />
            <Route
              path="/reports/algorithm-sunset"
              element={<AlgorithmSunset />}
            />
            <Route path="/reports/pqc-migration" element={<PQCMigration />} />
            <Route path="/blast-radius" element={<BlastRadius />} />
            <Route
              path="*"
              element={
                <div className="p-10 text-center">
                  <p className="text-4xl font-black text-foreground">404</p>
                  <p className="mt-2 text-sm text-muted-foreground">
                    This page doesn&apos;t exist.{" "}
                    <Link to="/" className="text-primary hover:underline">
                      Back to the dashboard
                    </Link>
                  </p>
                </div>
              }
            />
          </Routes>
        </ErrorBoundary>
      </main>
      </div>
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/*"
            element={
              <RequireAuth>
                <AppShell />
              </RequireAuth>
            }
          />
        </Routes>
      </BrowserRouter>
      <Toaster position="bottom-right" />
    </QueryClientProvider>
  );
}

export default App;
