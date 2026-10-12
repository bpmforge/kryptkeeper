import type {
  AgentInfo,
  AgentType,
  ApiDataResponse,
  ApiListResponse,
  ApprovalRequest,
  AuditRow,
  AuthzCheck,
  CaRecord,
  CertificateRecord,
  CryptoPostureReport,
  PostureTrendResponse,
  SchedulerStatusResponse,
  RenewalSLOReport,
  ExecutiveSummary,
  EvidenceSchedule,
  PQCMigrationRoadmap,
  PQCCountdownReport,
  WaveProgress,
  PendingAction,
  SpiffeStatus,
  SpiffeSVIDResult,
  CodeSigningInventory,
  SIEMStatus,
  SIEMTestResult,
  DashboardSummary,
  DiscoveryEndpointRecord,
  DiscoveryScanJobRecord,
  DiscoverySummary,
  HistoryRecord,
  LoginResponse,
  NotificationDeliveryRecord,
  NotificationRule,
  NotificationSummary,
  SearchResult,
  TemplateRecord,
  Tenant,
  TenantContext,
  UserRecord,
} from "./models";
import type { components, paths } from "../generated/api-types";
import type { DeliveryPlugin, DeliveryPluginVersion } from "./plugins";
import { toast } from "sonner";

const API_BASE = import.meta.env.VITE_API_BASE || "/api/v1";

type CloudKeyInventoryResponse =
  paths["/inventory/keys"]["get"]["responses"][200]["content"]["application/json"];
export type CloudKeyInventory = NonNullable<CloudKeyInventoryResponse["data"]>;
export type CloudKey = NonNullable<CloudKeyInventory["keys"]>[number];

// Managed target (W5-09) — kept here rather than models.ts since this
// ticket's write_scope doesn't include models.ts; field names are the wire
// contract from internal/bootstrap/managed_target_store.go, not invented.
export type ManagedTarget = {
  id: string;
  name: string;
  host: string;
  discovery_mode: string;
  install_mode: string;
  renewal_method: string;
  // Per-target override (W8-15, FR-P33) for the renewal scheduler's
  // RENEWAL_THRESHOLD_DAYS env default. 0 or absent means "no override".
  renewal_threshold_days?: number;
  credential_ref?: string;
  schedule?: string;
  // W20-20: install_mode "plugin" targets name their delivery plugin.
  plugin_id?: string;
  plugin_settings?: Record<string, string>;
  tenant: string;
  created_at: string;
  updated_at: string;
};

export type CredentialMeta = {
  id: string;
  name: string;
  credential_type: string;
  tenant: string;
  created_at: string;
  updated_at: string;
};

// W18-11: what a windows_password credential can do on its host, decided
// with one read-only WinRM session. Levels ordered by how far it gets.
export type CredentialPreflight = {
  credential_id: string;
  level:
    "unreachable" | "unauthenticated" | "no_shell" | "discover" | "install";
  can_discover: boolean;
  can_install: boolean;
  detail: string;
};

export type AgentRegistration = {
  agent_id: string;
  token: string;
};

// Runtime config (W8-03) — kept here rather than models.ts since this
// ticket's write_scope doesn't include models.ts; field names are the wire
// contract from internal/bootstrap/config_store.go's EffectiveSetting, not
// invented.
export type EffectiveSetting = {
  key: string;
  category: "notifications" | "renewal_policy" | "discovery" | "sso";
  env_var: string;
  secret: boolean;
  source: "database" | "env_default" | "unset";
  value?: string;
  configured: boolean;
  updated_at?: string;
  updated_by?: string;
};

// Wire shape of GET /protected/config (internal/bootstrap/handlers_protected_config.go).
export type ProtectedConfigFlags = {
  service: string;
  resource: string;
  auth_mode: string;
  config: {
    oidc_enabled: boolean;
    discovery_enabled: boolean;
    jwt_mode_enabled: boolean;
  };
};

const ACCESS_TOKEN_KEY = "auth_token";
const REFRESH_TOKEN_KEY = "kk_refresh_token";
// /auth/refresh itself 401ing means the refresh token is invalid, not stale --
// retrying it recursively would loop. /auth/login and /auth/logout never
// represent a stale-session 401 either, so all three skip the refresh path.
const NO_REFRESH_PATHS = new Set([
  "/auth/login",
  "/auth/logout",
  "/auth/refresh",
]);

type TokenPair = { access_token: string; refresh_token?: string };

function storeTokens(tokens: TokenPair) {
  sessionStorage.setItem(ACCESS_TOKEN_KEY, tokens.access_token);
  if (tokens.refresh_token) {
    sessionStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh_token);
  }
}

function clearTokens() {
  sessionStorage.removeItem(ACCESS_TOKEN_KEY);
  sessionStorage.removeItem(REFRESH_TOKEN_KEY);
  sessionStorage.removeItem("kk_session");
}

// S-59: the redirect below tears down the React tree — and the <Toaster/>
// with it — so a toast alone never actually renders. The notice is
// persisted for the Login page to display, and a latch guarantees one
// notice + one redirect no matter how many 401s burst in after expiry
// (each cleared-token retry used to re-enter here).
const LOGIN_NOTICE_KEY = "kk_login_notice";
let sessionExpiredFired = false;

/** Test-only: module state must not leak between vitest cases. */
export function __resetSessionExpiryForTests() {
  sessionExpiredFired = false;
}

function handleSessionExpired() {
  if (sessionExpiredFired) return;
  sessionExpiredFired = true;
  clearTokens();
  sessionStorage.setItem(
    LOGIN_NOTICE_KEY,
    "Your session has expired. Please sign in again.",
  );
  toast.error("Your session has expired. Please sign in again.");
  window.location.assign("/login");
}

// auth.Refresh (internal/bootstrap/auth_identity.go) deletes the presented
// refresh token before minting the next one -- it is single-use. Concurrent
// 401s (a page firing several queries at once) must share one in-flight
// refresh rather than each spending the same token, or every request after
// the first would get errInvalidRefreshToken. Chaining the failure notice
// onto that same shared promise (rather than a separate latch) also means
// handleSessionExpired fires exactly once per refresh attempt no matter how
// many callers are awaiting it -- one toast, one redirect, not N.
// S-59: refresh outcomes are a three-way split, not a boolean. Only a
// GENUINE token rejection (401) clears the session — a transient failure
// (offline/DNS/CORS throw, 5xx, the handler's own 30/min 429, or a
// malformed response) preserves the refresh token the server would still
// honour for up to 30 days, and logs the distinction to the console so
// the two cases are tellable apart afterwards.
type RefreshOutcome = "ok" | "invalid" | "transient";

let refreshInFlight: Promise<RefreshOutcome> | null = null;

function refreshAccessToken(): Promise<RefreshOutcome> {
  if (!refreshInFlight) {
    refreshInFlight = performRefresh()
      .then((outcome) => {
        if (outcome === "invalid") handleSessionExpired();
        return outcome;
      })
      .finally(() => {
        refreshInFlight = null;
      });
  }
  return refreshInFlight;
}

async function performRefresh(): Promise<RefreshOutcome> {
  const refreshToken = sessionStorage.getItem(REFRESH_TOKEN_KEY);
  if (!refreshToken) return "invalid";
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
  } catch (err) {
    console.error(
      "[auth] transient refresh failure (network) — session preserved:",
      err,
    );
    return "transient";
  }
  if (res.status === 401) {
    console.warn(
      "[auth] refresh token rejected as invalid/expired — signing out",
    );
    return "invalid";
  }
  if (!res.ok) {
    console.error(
      `[auth] transient refresh failure (HTTP ${res.status}) — session preserved`,
    );
    return "transient";
  }
  let body: { data?: TokenPair };
  try {
    body = await res.json();
  } catch (err) {
    console.error(
      "[auth] transient refresh failure (malformed response) — session preserved:",
      err,
    );
    return "transient";
  }
  if (!body?.data?.access_token) {
    console.error(
      "[auth] transient refresh failure (no token in response) — session preserved",
    );
    return "transient";
  }
  storeTokens(body.data);
  return "ok";
}

function buildHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  // API-key callers that explicitly stored a token in sessionStorage still get
  // the Authorization header. Browser sessions rely on the httpOnly cookie.
  const legacyToken = sessionStorage.getItem(ACCESS_TOKEN_KEY);
  if (legacyToken) headers["Authorization"] = `Bearer ${legacyToken}`;
  // Multi-tenancy: a selected tenant scopes every request (pin for operators,
  // "view-as" for super-admins). Absent => unscoped (single-tenant / see-all).
  const tenant = sessionStorage.getItem("kk_tenant");
  if (tenant) headers["X-Tenant"] = tenant;
  return headers;
}

async function parseJSON<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.message) msg = body.message;
    } catch {
      // ignore JSON parse errors
    }
    // status rides on the error so callers can tell a 403 (role can't see
    // this) from a transport failure without parsing the message text.
    throw Object.assign(new Error(msg), { status: res.status });
  }
  // 204/205 and other empty bodies carry no JSON — res.json() would reject
  // and turn a successful delete/save into a phantom failure toast.
  if (res.status === 204 || res.status === 205) return undefined as T;
  const text = await res.text();
  if (text === "") return undefined as T;
  return JSON.parse(text) as T;
}

// S-69: the certificate download endpoint returns raw PEM/DER bytes, not a
// JSON envelope, so it needs its own fetch path with the same auth/tenant
// header rules as fetchJSON.
// Report exports were plain <a href download> anchors, which carry no
// Authorization header — fine on cookie sessions, a 401 body saved as
// ".pdf" for Bearer-token clients. This fetches with the same header rules
// as fetchJSON and hands the bytes to the browser as a download.
export async function downloadAuthedFile(
  path: string,
  filename: string,
): Promise<void> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: buildHeaders(),
    credentials: "include",
  });
  if (!res.ok) {
    let msg = `Download failed: ${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.message) msg = body.message;
    } catch {
      // ignore JSON parse errors
    }
    throw new Error(msg);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function fetchText(path: string): Promise<string> {
  const headers: Record<string, string> = {};
  const legacyToken = sessionStorage.getItem("auth_token");
  if (legacyToken) headers["Authorization"] = `Bearer ${legacyToken}`;
  const tenant = sessionStorage.getItem("kk_tenant");
  if (tenant) headers["X-Tenant"] = tenant;
  const res = await fetch(`${API_BASE}${path}`, {
    headers,
    credentials: "include",
  });
  if (!res.ok) {
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.message) msg = body.message;
    } catch {
      // ignore JSON parse errors
    }
    throw new Error(msg);
  }
  return res.text();
}

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: buildHeaders(),
    credentials: "include",
  });

  if (res.status === 401 && !NO_REFRESH_PATHS.has(path)) {
    const outcome = await refreshAccessToken();
    if (outcome === "ok") {
      const retryRes = await fetch(`${API_BASE}${path}`, {
        ...init,
        headers: buildHeaders(),
        credentials: "include",
      });
      return parseJSON<T>(retryRes);
    }
    if (outcome === "transient") {
      // The session is intact — this request failed, not the login.
      throw new Error(
        "Temporary connection problem — your session was preserved; please retry.",
      );
    }
    throw new Error("Session expired");
  }

  return parseJSON<T>(res);
}

function queryString(
  params?: Record<string, string | number | boolean | undefined>,
) {
  if (!params) return "";
  const sp = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    sp.set(key, String(value));
  });
  const qs = sp.toString();
  return qs ? `?${qs}` : "";
}

export const api = {
  // Auth
  login: async (body: { email: string; password: string }) => {
    const result = await fetchJSON<LoginResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify(body),
    });
    // Login is the only place the refresh_token is ever issued -- capture it
    // here so every caller of api.login() gets transparent refresh for free,
    // without each page having to remember to store it itself.
    if (result?.data?.access_token) {
      storeTokens({
        access_token: result.data.access_token,
        refresh_token: result.data.refresh_token,
      });
    }
    return result;
  },
  logout: async () => {
    // The server revokes this refresh token even if the access cookie has
    // already expired (A2A7-003), so send it before clearTokens() drops it.
    const refreshToken = sessionStorage.getItem(REFRESH_TOKEN_KEY);
    try {
      return await fetchJSON<void>("/auth/logout", {
        method: "POST",
        ...(refreshToken
          ? { body: JSON.stringify({ refresh_token: refreshToken }) }
          : {}),
      });
    } finally {
      clearTokens();
    }
  },
  // Unauthenticated capability probe for the login page.
  authMethods: () =>
    fetchJSON<{ data: { password: boolean; oidc: boolean; saml: boolean } }>(
      "/auth/methods",
    ),
  authzCheck: () => fetchJSON<AuthzCheck>("/authz-check"),

  // Dashboard
  dashboardSummary: () =>
    fetchJSON<ApiDataResponse<DashboardSummary>>("/dashboard/summary"),

  // Certificates
  certificate: (fingerprint: string) =>
    fetchJSON<ApiDataResponse<CertificateRecord>>(
      `/certificates/${encodeURIComponent(fingerprint)}`,
    ),
  certificates: (
    params?: string | Record<string, string | number | boolean | undefined>,
  ) =>
    fetchJSON<ApiListResponse<CertificateRecord>>(
      `/certificates${typeof params === "string" ? (params ? "?" + params : "") : queryString(params)}`,
    ),
  issueCertificate: (body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<CertificateRecord>>("/certificates", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  connectors: () =>
    fetchJSON<{
      data: {
        id: string;
        name: string;
        type: string;
        health?: { status: string; detail?: string };
      }[];
    }>("/connectors"),
  estateTakeover: (body: {
    fingerprint: string;
    owner_email?: string;
    owner_team?: string;
    service_name?: string;
    renewal_path: { mode: string; connector_id?: string };
  }) =>
    fetchJSON<ApiDataResponse<CertificateRecord>>("/estate/takeover", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  bulkImportCertificates: (body: {
    format: string;
    bundle: string;
    team_id?: string;
    owner_email?: string;
    owner_team?: string;
    service_name?: string;
  }) =>
    fetchJSON<{
      data: {
        imported: number;
        skipped_duplicates: number;
        failed: { index: number; reason: string }[];
        fingerprints: string[];
      };
    }>("/certificates/bulk-import", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  downloadCertificatePem: (fingerprint: string, includeChain = false) =>
    fetchText(
      `/certificates/${fingerprint}/download${queryString({
        format: "pem",
        include_chain: includeChain || undefined,
      })}`,
    ),
  renewCertificate: (fingerprint: string, body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<CertificateRecord>>(
      `/certificates/${fingerprint}/renew`,
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    ),
  revokeCertificate: (fingerprint: string, body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<CertificateRecord>>(
      `/certificates/${fingerprint}/revoke`,
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    ),
  importCertificate: (body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<CertificateRecord>>("/certificates/import", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // CAs
  cas: (params?: Record<string, string | number | boolean | undefined>) =>
    fetchJSON<ApiListResponse<CaRecord>>(`/cas${queryString(params)}`),
  createCa: (body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<CaRecord>>("/cas", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateCa: (id: string, body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<CaRecord>>(`/cas/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  activateCa: (id: string) =>
    fetchJSON<ApiDataResponse<CaRecord>>(`/cas/${id}/activate`, {
      method: "POST",
    }),
  suspendCa: (id: string) =>
    fetchJSON<ApiDataResponse<CaRecord>>(`/cas/${id}/suspend`, {
      method: "POST",
    }),

  // Templates
  templates: (params?: Record<string, string | number | boolean | undefined>) =>
    fetchJSON<ApiListResponse<TemplateRecord>>(
      `/templates${queryString(params)}`,
    ),
  getTemplate: (id: string) =>
    fetchJSON<ApiDataResponse<TemplateRecord>>(`/templates/${id}`),
  createTemplate: (body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<TemplateRecord>>("/templates", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateTemplate: (id: string, body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<TemplateRecord>>(`/templates/${id}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  deleteTemplate: (id: string) =>
    fetchJSON<void>(`/templates/${id}`, { method: "DELETE" }),

  // Discovery
  discoverySummary: () =>
    fetchJSON<ApiDataResponse<DiscoverySummary>>("/discovery/summary"),
  discoveryEndpoints: (
    params?: string | Record<string, string | number | boolean | undefined>,
  ) =>
    fetchJSON<ApiListResponse<DiscoveryEndpointRecord>>(
      `/discovery/endpoints${typeof params === "string" ? (params ? "?" + params : "") : queryString(params)}`,
    ),
  discoveryScanJobs: (
    params?: Record<string, string | number | boolean | undefined>,
  ) =>
    fetchJSON<ApiListResponse<DiscoveryScanJobRecord>>(
      `/discovery/scan-jobs${queryString(params)}`,
    ),
  createDiscoveryScan: (body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<{ scan_job: DiscoveryScanJobRecord }>>(
      "/discovery/scans",
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    ),
  cancelDiscoveryScanJob: (body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<{ scan_job_id: string }>>(
      "/discovery/scan-jobs/cancel",
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    ),
  requeueDiscoveryScanJob: (body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<{ scan_job_id: string }>>(
      "/discovery/scan-jobs/requeue",
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    ),

  // Notifications
  notificationsSummary: () =>
    fetchJSON<ApiDataResponse<NotificationSummary>>("/notifications/summary"),
  notificationDeliveries: (
    params?: Record<string, string | number | boolean | undefined>,
  ) =>
    fetchJSON<ApiListResponse<NotificationDeliveryRecord>>(
      `/notifications/deliveries${queryString(params)}`,
    ),
  testNotificationDelivery: (body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<{ delivery: NotificationDeliveryRecord }>>(
      "/notifications/test-delivery",
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    ),
  retryNotificationDelivery: (body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<{ retry_job_id: string }>>(
      "/notifications/deliveries/retry",
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    ),
  acknowledgeNotificationDelivery: (body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<{ delivery_id: string }>>(
      "/notifications/deliveries/ack",
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    ),

  // Notification rules
  notificationRules: () =>
    fetchJSON<ApiListResponse<NotificationRule>>("/notifications/rules"),
  createNotificationRule: (body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<NotificationRule>>("/notifications/rules", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateNotificationRule: (id: string, body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<NotificationRule>>(`/notifications/rules/${id}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  deleteNotificationRule: (id: string) =>
    fetchJSON<void>(`/notifications/rules/${id}`, { method: "DELETE" }),

  // Users
  users: () => fetchJSON<ApiListResponse<UserRecord>>("/users"),
  inviteUser: (body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<UserRecord>>("/users/invite", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateUser: (id: string, body: Record<string, unknown>) =>
    fetchJSON<ApiDataResponse<UserRecord>>(`/users/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deactivateUser: (id: string) =>
    fetchJSON<void>(`/users/${id}`, { method: "DELETE" }),

  // History / Audit
  dashboardActionsHistory: (
    params?: Record<string, string | number | boolean | undefined>,
  ) =>
    fetchJSON<ApiListResponse<HistoryRecord>>(
      `/dashboard/actions/history${queryString(params)}`,
    ),
  auditList: (params?: Record<string, string | number | boolean | undefined>) =>
    fetchJSON<ApiDataResponse<AuditRow[]>>(`/audit${queryString(params)}`),

  // Search
  search: (q: string) =>
    fetchJSON<{ data: SearchResult[] }>(`/search${queryString({ q })}`),

  // Reports
  cryptoPosture: () =>
    fetchJSON<ApiDataResponse<CryptoPostureReport>>("/reports/crypto-posture"),
  cryptoPostureCsvUrl: () => `${API_BASE}/reports/crypto-posture?format=csv`,
  cryptoPostureTrend: (params?: { since?: string; limit?: number }) =>
    fetchJSON<ApiDataResponse<PostureTrendResponse>>(
      `/reports/crypto-posture/trend${params ? queryString(params) : ""}`,
    ),
  caHealth: () =>
    fetchJSON<ApiDataResponse<Record<string, unknown>>>("/reports/ca-health"),
  expiryTimeline: () =>
    fetchJSON<ApiDataResponse<Record<string, unknown>>>(
      "/reports/expiry-timeline",
    ),
  revocationActivity: (days?: number) =>
    fetchJSON<ApiDataResponse<Record<string, unknown>>>(
      `/reports/revocation-activity${days ? `?days=${days}` : ""}`,
    ),
  issuanceVelocity: () =>
    fetchJSON<ApiDataResponse<Record<string, unknown>>>(
      "/reports/issuance-velocity",
    ),
  changeAudit: (params?: { days?: number; fingerprint?: string }) =>
    fetchJSON<ApiDataResponse<Record<string, unknown>>>(
      `/reports/change-audit${queryString(params)}`,
    ),
  complianceEvidence: (framework?: string) =>
    fetchJSON<ApiDataResponse<Record<string, unknown>>>(
      `/reports/compliance-evidence${framework ? `?framework=${framework}` : ""}`,
    ),
  complianceEvidencePdfUrl: (framework: string) =>
    `${API_BASE}/reports/compliance-evidence?framework=${framework}&format=pdf`,
  executiveSummary: () =>
    fetchJSON<ApiDataResponse<ExecutiveSummary>>("/reports/executive-summary"),
  executiveSummaryPdfUrl: () =>
    `${API_BASE}/reports/executive-summary?format=pdf`,

  // Evidence delivery
  evidenceSchedules: () =>
    fetchJSON<ApiDataResponse<EvidenceSchedule[]>>(
      "/reports/evidence/schedules",
    ),
  createEvidenceSchedule: (body: {
    framework: string;
    cadence: string;
    recipients: string[];
    enabled: boolean;
  }) =>
    fetchJSON<ApiDataResponse<EvidenceSchedule>>(
      "/reports/evidence/schedules",
      { method: "POST", body: JSON.stringify(body) },
    ),
  deleteEvidenceSchedule: (id: string) =>
    fetchJSON<{ status: string }>(`/reports/evidence/schedules/${id}`, {
      method: "DELETE",
    }),
  sendEvidenceNow: (body: { framework: string; recipients: string[] }) =>
    fetchJSON<{ status: string; recipients: number }>(
      "/reports/evidence/send",
      { method: "POST", body: JSON.stringify(body) },
    ),
  // S-39: was ApiDataResponse<Record<string, unknown>>, which made the caller's
  // `as` cast unverifiable — the page asserted a shape nothing checked, and it
  // was wrong. Typed from the spec now.
  algorithmSunset: () =>
    fetchJSON<ApiDataResponse<components["schemas"]["AlgorithmSunsetReport"]>>(
      "/reports/algorithm-sunset",
    ),
  pqcMigration: () =>
    fetchJSON<ApiDataResponse<PQCMigrationRoadmap>>("/reports/pqc-migration"),
  // SPIFFE / SVID
  spiffeStatus: () =>
    fetchJSON<ApiDataResponse<SpiffeStatus>>("/spiffe/status"),
  mintSVID: (spiffeID: string) =>
    fetchJSON<ApiDataResponse<SpiffeSVIDResult>>("/spiffe/svid", {
      method: "POST",
      body: JSON.stringify({ spiffe_id: spiffeID }),
    }),

  // Pending actions (AI-proposed write queue)
  pendingActions: (status?: string) =>
    fetchJSON<ApiDataResponse<PendingAction[]>>(
      `/pending-actions${status ? `?status=${status}` : ""}`,
    ),
  approvePendingAction: (id: string) =>
    fetchJSON<ApiDataResponse<{ status: string; result: unknown }>>(
      `/pending-actions/${id}/approve`,
      { method: "POST" },
    ),
  rejectPendingAction: (id: string, reason: string) =>
    fetchJSON<ApiDataResponse<{ status: string }>>(
      `/pending-actions/${id}/reject`,
      { method: "POST", body: JSON.stringify({ reason }) },
    ),

  pqcCountdown: () =>
    fetchJSON<ApiDataResponse<PQCCountdownReport>>("/reports/pqc-countdown"),
  pqcCountdownPdfUrl: () => `${API_BASE}/reports/pqc-countdown?format=pdf`,
  pqcWaves: () =>
    fetchJSON<ApiDataResponse<WaveProgress[]>>("/reports/pqc-waves"),
  autoDerivePqcWaves: () =>
    fetchJSON<ApiDataResponse<WaveProgress[]>>(
      "/reports/pqc-waves/auto-derive",
      { method: "POST", body: "{}" },
    ),
  deletePqcWave: (id: string) =>
    fetchJSON<{ data: { status: string } }>(`/reports/pqc-waves/${id}`, {
      method: "DELETE",
    }),
  // W8-09 journey: create → add members → propose the W4-03 EXECUTE.
  createPqcWave: (body: {
    name: string;
    owner?: string;
    target_date?: string;
  }) =>
    fetchJSON<ApiDataResponse<WaveProgress>>("/reports/pqc-waves", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  addPqcWaveMember: (id: string, fingerprint: string) =>
    fetchJSON<{ data: { status: string } }>(
      `/reports/pqc-waves/${id}/members`,
      { method: "POST", body: JSON.stringify({ fingerprint }) },
    ),
  // The execute proposal REQUIRES a template carrying an ML-DSA/hybrid
  // algorithm — an empty body was a guaranteed 400 after the wave had
  // already been created.
  proposePqcWaveExecute: (id: string, templateId: string) =>
    fetchJSON<ApiDataResponse<{ id: string; status: string }>>(
      `/reports/pqc-waves/${id}/execute`,
      { method: "POST", body: JSON.stringify({ template_id: templateId }) },
    ),
  // pqc_migrate_wave actions are decided on this dedicated route, not the
  // generic pending-actions approve (whose executor has no case for them).
  approvePqcWaveExecute: (waveId: string, actionId: string) =>
    fetchJSON<ApiDataResponse<unknown>>(
      `/reports/pqc-waves/${waveId}/execute/${encodeURIComponent(actionId)}/approve`,
      { method: "POST" },
    ),
  acceptPqcWave: (id: string) =>
    fetchJSON<ApiDataResponse<unknown>>(`/reports/pqc-waves/${id}/accept`, {
      method: "POST",
    }),

  // Keys
  keys: () => fetchJSON<{ data: unknown[] }>("/keys"),
  getKey: (id: string) =>
    fetchJSON<{ data: unknown }>(`/keys/${encodeURIComponent(id)}`),
  generateKey: (body: { id: string; algorithm: string }) =>
    fetchJSON<{ data: unknown }>("/keys", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  rotateKey: (id: string, algorithm: string) =>
    fetchJSON<{ data: unknown }>(`/keys/${encodeURIComponent(id)}/rotate`, {
      method: "POST",
      body: JSON.stringify({ algorithm }),
    }),
  // Export answers with raw PEM (200, application/x-pem-file) — or, under
  // key dual control, a 202 JSON proposal that means NOTHING was exported
  // yet. fetchJSON would choke on the PEM and mistake the 202 for success.
  exportKey: async (
    id: string,
    passphrase: string,
  ): Promise<
    { proposed: true; actionId?: string } | { proposed: false; pem: string }
  > => {
    const res = await fetch(
      `${API_BASE}/keys/${encodeURIComponent(id)}/export`,
      {
        method: "POST",
        headers: buildHeaders(),
        credentials: "include",
        body: JSON.stringify({ passphrase }),
      },
    );
    if (!res.ok) {
      let msg = `API error: ${res.status} ${res.statusText}`;
      try {
        const body = await res.json();
        if (body?.message) msg = body.message;
      } catch {
        // ignore JSON parse errors
      }
      throw new Error(msg);
    }
    if (res.status === 202) {
      const body = (await res.json()) as {
        data?: { action_id?: string };
      };
      return { proposed: true, actionId: body?.data?.action_id };
    }
    return { proposed: false, pem: await res.text() };
  },
  importKey: (body: { id: string; backup_pem: string; passphrase: string }) =>
    fetchJSON<{ data: unknown }>("/keys/import", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteKey: (id: string) =>
    fetchJSON<void>(`/keys/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // Certificate ownership
  updateCertOwnership: (
    fingerprint: string,
    body: {
      owner_email?: string;
      owner_team?: string;
      service_name?: string;
      labels?: string[];
    },
  ) =>
    fetchJSON<{ data: unknown }>(`/certificates/${fingerprint}/ownership`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),

  // Scheduler
  renewalSchedulerStatus: () =>
    fetchJSON<ApiDataResponse<SchedulerStatusResponse>>(
      "/scheduler/renewal/status",
    ),

  // Code-signing inventory
  // Outbound credentials (metadata only — the API never returns secrets).
  credentials: () =>
    fetchJSON<ApiDataResponse<{ items: CredentialMeta[] }>>("/credentials"),
  createCredential: (body: {
    name: string;
    credential_type: string;
    payload: Record<string, unknown>;
  }) =>
    fetchJSON<ApiDataResponse<CredentialMeta>>("/credentials", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  preflightCredential: (id: string) =>
    fetchJSON<ApiDataResponse<CredentialPreflight>>(
      `/credentials/${encodeURIComponent(id)}/preflight`,
      { method: "POST" },
    ),
  codeSigningInventory: () =>
    fetchJSON<ApiDataResponse<CodeSigningInventory>>("/inventory/code-signing"),

  // Cloud KMS key inventory (metadata only; live fan-out to cloud providers).
  cloudKeyInventory: () =>
    fetchJSON<CloudKeyInventoryResponse>("/inventory/keys"),

  // Renewal Autopilot SLO
  renewalSLO: () =>
    fetchJSON<ApiDataResponse<RenewalSLOReport>>("/reports/renewal-slo"),

  // SIEM integration
  siemStatus: () =>
    fetchJSON<ApiDataResponse<SIEMStatus>>("/integrations/siem"),
  siemTest: () =>
    fetchJSON<ApiDataResponse<SIEMTestResult>>("/integrations/siem/test", {
      method: "POST",
    }),

  // Agents
  agents: () => fetchJSON<{ agents: AgentInfo[] }>("/agents"),
  registerAgent: (body: { name: string; type?: AgentType }) =>
    fetchJSON<AgentRegistration>("/agent/register", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // Delivery plugins (W20-20): install, enable (may go to Approvals),
  // disable, remove.
  deliveryPlugins: () =>
    fetchJSON<ApiDataResponse<DeliveryPlugin[]>>("/delivery-plugins"),
  installDeliveryPlugin: (
    manifestBase64: string,
    wasmBase64: string,
    signature?: string,
  ) =>
    fetchJSON<ApiDataResponse<DeliveryPluginVersion>>("/delivery-plugins", {
      method: "POST",
      body: JSON.stringify({
        manifest_base64: manifestBase64,
        wasm_base64: wasmBase64,
        ...(signature ? { signature } : {}),
      }),
    }),
  enableDeliveryPlugin: (id: string, version: string) =>
    fetchJSON<
      ApiDataResponse<{
        status: string;
        version?: string;
        pending_action_id?: string;
        message?: string;
      }>
    >(
      `/delivery-plugins/${encodeURIComponent(id)}/versions/${encodeURIComponent(version)}/enable`,
      { method: "POST" },
    ),
  disableDeliveryPlugin: (id: string) =>
    fetchJSON<ApiDataResponse<{ status: string }>>(
      `/delivery-plugins/${encodeURIComponent(id)}/disable`,
      { method: "POST" },
    ),
  removeDeliveryPlugin: (id: string) =>
    fetchJSON<void>(`/delivery-plugins/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),

  // Managed targets (W5-09, agentless mode)
  targets: () => fetchJSON<ApiDataResponse<ManagedTarget[]>>("/targets"),
  createTarget: (body: {
    name: string;
    host: string;
    discovery_mode: string;
    install_mode: string;
    renewal_method?: string;
    credential_ref?: string;
    schedule?: string;
    auto_renew?: boolean;
    install_server_type?: string;
    install_cert_path?: string;
    install_key_path?: string;
    plugin_id?: string;
    plugin_settings?: Record<string, string>;
  }) =>
    fetchJSON<ApiDataResponse<ManagedTarget>>("/targets", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  // Per-target renewal policy (W8-07, W8-15, FR-P33) — PATCH /targets/{id}.
  // renewal_threshold_days: 0 clears the override, reverting to the
  // scheduler's RENEWAL_THRESHOLD_DAYS env default.
  updateTarget: (
    id: string,
    body: {
      renewal_method?: string;
      renewal_threshold_days?: number;
    },
  ) =>
    fetchJSON<ApiDataResponse<ManagedTarget>>(
      `/targets/${encodeURIComponent(id)}`,
      {
        method: "PATCH",
        body: JSON.stringify(body),
      },
    ),

  // Approvals
  approvals: (params?: Record<string, string | number | boolean | undefined>) =>
    fetchJSON<ApiListResponse<ApprovalRequest>>(
      `/approvals${queryString(params)}`,
    ),
  approveRequest: (id: string) =>
    fetchJSON<ApiDataResponse<CertificateRecord>>(
      `/approvals/${encodeURIComponent(id)}/approve`,
      { method: "POST" },
    ),
  rejectRequest: (id: string, reason: string) =>
    fetchJSON<{ status: string }>(
      `/approvals/${encodeURIComponent(id)}/reject`,
      {
        method: "POST",
        body: JSON.stringify({ reason }),
      },
    ),

  // Tenants (multi-tenancy, v2.2)
  tenantContext: () =>
    fetchJSON<ApiDataResponse<TenantContext>>("/tenants/context"),
  tenants: () => fetchJSON<ApiDataResponse<Tenant[]>>("/tenants"),
  createTenant: (body: { id: string; name: string }) =>
    fetchJSON<ApiDataResponse<Tenant>>("/tenants", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  mapCATenant: (body: { ca_id: string; tenant_id: string }) =>
    fetchJSON<ApiDataResponse<{ status: string }>>("/tenants/ca-mapping", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  mapTemplateTenant: (body: { template_id: string; tenant_id: string }) =>
    fetchJSON<ApiDataResponse<{ status: string }>>(
      "/tenants/template-mapping",
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    ),

  // Runtime config (W8-03) — notifications/renewal_policy/discovery/sso.
  runtimeConfig: () =>
    fetchJSON<ApiDataResponse<EffectiveSetting[]>>("/config"),
  setRuntimeConfig: (key: string, value: string) =>
    fetchJSON<void>(`/config/${encodeURIComponent(key)}`, {
      method: "PUT",
      body: JSON.stringify({ value }),
    }),
  resetRuntimeConfig: (key: string) =>
    fetchJSON<void>(`/config/${encodeURIComponent(key)}`, {
      method: "DELETE",
    }),

  // Auth-mode flags actually in effect on the running server (diagnostic;
  // used to show whether a saved SSO override has taken effect yet — see
  // W8-13, config overrides for SSO are not re-read until a restart).
  protectedConfig: () => fetchJSON<ProtectedConfigFlags>("/protected/config"),
};
