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
import Discovery from "./pages/Discovery";
import Alerts from "./pages/Alerts";
import History from "./pages/History";
import SearchPage from "./pages/Search";
import Audit from "./pages/Audit";
import Templates from "./pages/Templates";
import DeliveryPlugins from "./pages/DeliveryPlugins";
import Users from "./pages/Users";
import CryptoPosture from "./pages/CryptoPosture";
import Agents from "./pages/Agents";
import TargetSetup from "./pages/TargetSetup";
import RenewalPolicy from "./pages/RenewalPolicy";
import Settings from "./pages/Settings";
import Integrations from "./pages/Integrations";
import CodeSigning from "./pages/CodeSigning";
import Spiffe from "./pages/Spiffe";
import Automation from "./pages/Automation";
import Login from "./pages/Login";
import Keys from "./pages/Keys";
import CAHealth from "./pages/CAHealth";
import ExpiryTimeline from "./pages/ExpiryTimeline";
import RevocationActivity from "./pages/RevocationActivity";
import IssuanceVelocity from "./pages/IssuanceVelocity";
import ChangeAudit from "./pages/ChangeAudit";
import ComplianceEvidence from "./pages/ComplianceEvidence";
import AlgorithmSunset from "./pages/AlgorithmSunset";
import PQCMigration from "./pages/PQCMigration";
import Approvals from "./pages/Approvals";
import PendingActions from "./pages/PendingActions";
import Tenants from "./pages/Tenants";
import CloudKeys from "./pages/CloudKeys";
import { useAuthz } from "./lib/auth";
import { navSections, filterNavSections } from "./lib/nav";
import { ThemeToggle } from "./components/ThemeToggle";
import { api } from "./lib/api";
import { Toaster } from "./components/ui/sonner";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { CommandPalette } from "./components/CommandPalette";

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

  const experimental = (
    <div
      className="px-2.5 pb-1 text-[10px] text-muted-foreground"
      title="Experimental: tenant isolation is not a security boundary in this release."
    >
      <span className="mr-1 rounded border border-amber-500/40 px-1 py-0.5 uppercase tracking-widest text-amber-500">
        Experimental
      </span>
      multi-tenancy
    </div>
  );

  if (!ctx.super_admin) {
    return (
      <>
        <div className="px-2.5 py-1.5 text-xs text-muted-foreground">
          Tenant: <span className="text-foreground">{ctx.tenant}</span>
        </div>
        {experimental}
      </>
    );
  }

  return (
    <div className="px-2 pb-1">
      {experimental}
      <label className="mb-1 block px-0.5 text-[10px] uppercase tracking-widest text-muted-foreground">
        Viewing tenant
      </label>
      <select
        aria-label="Tenant view"
        value={current}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-lg border border-white/10 bg-[var(--surface-2)] px-2 py-1.5 text-xs text-foreground"
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

function RequireAuth({ children }: { children: React.ReactNode }) {
  const session = sessionStorage.getItem("kk_session");
  if (!session) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function Sidebar({
  collapsed,
  onToggle,
}: {
  collapsed: boolean;
  onToggle: () => void;
}) {
  const authz = useAuthz();
  const role = authz.data?.role ?? "—";
  const sections = filterNavSections(
    navSections,
    authz.data?.role,
    authz.data?.scopes,
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
    <aside
      className={`relative flex flex-col border-r border-border bg-[var(--surface-1)] transition-all duration-300 ${
        collapsed ? "w-[60px]" : "w-[220px]"
      } shrink-0 h-screen sticky top-0 z-20`}
    >
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
              className="flex items-center gap-1 rounded-md border border-white/[0.08] bg-white/[0.03] px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground hover:text-foreground hover:border-white/[0.15] transition"
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
                      : "text-muted-foreground hover:bg-white/5 hover:text-foreground border-l-2 border-transparent"
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

      {/* Collapse toggle */}
      <button
        type="button"
        onClick={onToggle}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        className="absolute -right-3 top-16 w-6 h-6 rounded-full bg-[var(--surface-2)] border border-white/10 flex items-center justify-center text-muted-foreground hover:text-primary hover:border-primary/40 transition z-30"
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
            <Route path="/" element={<Dashboard />} />
            <Route path="/certificates" element={<Certificates />} />
            <Route path="/certificates/issue" element={<IssueWizard />} />
            <Route
              path="/certificates/:fingerprint"
              element={<Certificates />}
            />
            <Route path="/cas" element={<CAs />} />
            <Route path="/cas/:id" element={<CAs />} />
            <Route path="/keys" element={<Keys />} />
            <Route path="/inventory/keys" element={<CloudKeys />} />
            <Route path="/templates" element={<Templates />} />
            <Route path="/approvals" element={<Approvals />} />
            <Route path="/pending-actions" element={<PendingActions />} />
            <Route path="/delivery-plugins" element={<DeliveryPlugins />} />
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
            <Route path="/tenants" element={<Tenants />} />
            <Route path="/crypto-posture" element={<CryptoPosture />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/targets/setup" element={<TargetSetup />} />
            <Route path="/targets/renewal-policy" element={<RenewalPolicy />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/integrations" element={<Integrations />} />
            <Route path="/automation" element={<Automation />} />
            <Route path="/code-signing" element={<CodeSigning />} />
            <Route path="/spiffe" element={<Spiffe />} />
            <Route path="/reports/ca-health" element={<CAHealth />} />
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
            <Route
              path="/reports/algorithm-sunset"
              element={<AlgorithmSunset />}
            />
            <Route path="/reports/pqc-migration" element={<PQCMigration />} />
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
