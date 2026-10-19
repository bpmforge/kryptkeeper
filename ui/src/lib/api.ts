import type {
  AgentInfo,
  AgentType,
  ApiDataResponse,
  ApiListResponse,
  ApprovalRequest,
  BlastRadiusAction,
  RotateCaKeyResult,
  TemplateRevision,
  BlastRadiusResult,
  AuditRow,
  AuthzCheck,
  CaRecord,
  Ceremony,
  StartCeremonyRequest,
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
  AuthorizedIssuer,
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
import type { components, operations, paths } from "../generated/api-types";
import type { DeliveryPlugin, DeliveryPluginVersion } from "./plugins";

type AgilityOp = operations["deriveCryptoAgilityRoadmap"];
export type AgilityRoadmapRequest = NonNullable<
  AgilityOp["requestBody"]
>["content"]["application/json"];
export type AgilityRoadmapResult = NonNullable<
  AgilityOp["responses"][200]["content"]["application/json"]["data"]
>;
import { toast } from "sonner";

// GET /certificates/quota (W33-21). remaining is null when the quota is
// unlimited (limit 0); a team with no policy row reports limit 0 too.
export type TeamQuota = {
  team_id: string;
  period: string;
  limit: number;
  used: number;
  remaining: number | null;
  warn: boolean;
  resets_at: string;
};

export type TeamPolicy = components["schemas"]["TeamPolicy"];

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
  // The scheduler renews onto this target only when set (and onto bound certificates only).
  auto_renew?: boolean;
  credential_ref?: string;
  schedule?: string;
  // W20-20: install_mode "plugin" targets name their delivery plugin.
  plugin_id?: string;
  plugin_settings?: Record<string, string>;
  // W24-09: operator-confirmed SSH host key pin (ssh/keychain install modes).
  ssh_host_key?: string;
  ssh_host_key_fingerprint?: string;
  // W34-10/11: what the latest scan could do, and why renewal is Blocked.
  credential_privileged?: boolean;
  renewal_privilege_required?: boolean;
  last_privilege_mode?: string;
  unreadable_count?: number;
  last_scanned_at?: string;
  blocked?: { kind: "privilege" | "rollback"; reason: string; fix: string; since?: string };
  install_cert_path?: string;
  install_key_path?: string;
  tenant: string;
  created_at: string;
  updated_at: string;
};

// W27-24: per-domain DCV validation lifetime, from
// GET /connectors/dcv-validations (docs/openapi.yaml listDcvValidations).
export interface DcvValidationRow {
  domain: string;
  connector_id: string;
  validated_at: string;
  expires_at: string;
  reuse_days: number;
  days_remaining: number;
  warn: boolean;
}
export interface DcvValidationsResponse {
  data: DcvValidationRow[];
  schedule: { effective: string; days: number }[];
  current_reuse_days: number;
}

export type MigrationFieldReport = {
  field: string;
  status: "mapped" | "partial" | "unmapped";
  target?: string;
  note?: string;
};
export type MigrationDiffEntry = {
  source_key: string;
  name: string;
  action: "create" | "skip" | "conflict" | "update";
  reason?: string;
  notes?: string[];
  fields: MigrationFieldReport[];
  template_id?: string;
};
export type MigrationDiff = {
  source: string;
  entries: MigrationDiffEntry[];
  counts: { create: number; skip: number; conflict: number; update?: number };
  unmapped: number;
  unsupported: number;
};
export type MigrationBatch = {
  id: string;
  source: string;
  status: "applied" | "rolled_back";
  created_by: string;
  created_at: string;
  rolled_back_at?: string;
  items?: number;
};
export type MigrationRequest = {
  source: string;
  content?: string;
  credential_ref?: string;
  options?: Record<string, string>;
};
export type MigrationRollback = {
  batch_id: string;
  already_rolled_back: boolean;
  disabled: number;
  // Templates the batch updated, put back to their pre-import state (S-05).
  restored?: number;
  kept: number;
  items: {
    name: string;
    template_id: string;
    outcome: string;
    reason?: string;
  }[];
};

export type BulkTakeoverRow = {
  fingerprint: string;
  status: "ok" | "error" | "skipped";
  code?: string;
  error?: string;
  reason?: "already_managed" | "other_tenant" | "not_permitted";
};

export type TakeoverSuggestion = {
  fingerprint: string;
  owner_email: string;
  owner_team: string;
  service_name: string;
  source: "existing_ownership" | "sibling_certificate" | "none" | "unavailable";
  confidence: "high" | "medium" | "low" | "none";
};

// Fingerprints per suggestions request: keeps the query string well under
// common proxy URL limits (the endpoint itself accepts up to 500).
const SUGGESTION_CHUNK = 100;

export type CertTargetBinding = components["schemas"]["CertTargetBinding"];
export type UserPrefs = components["schemas"]["UserPrefs"];
export type TargetGroup = components["schemas"]["TargetGroup"];
export type TargetPolicyRow = components["schemas"]["TargetPolicyRow"];

export type InventorySourceRecord = {
  id: string;
  name: string;
  type: string;
  config_json: string;
  credential_ref?: string;
  schedule_minutes: number;
  tenant: string;
  last_sync_at?: string;
  last_sync_result?: string;
  created_at: string;
  updated_at: string;
};

export type InventorySyncResult = {
  synced: number;
  skipped: number;
  revoked_marked: number;
  failed?: string[];
};

export type CredentialMeta = {
  id: string;
  name: string;
  credential_type: string;
  tenant: string;
  created_at: string;
  updated_at: string;
  // W34-11: high-impact account on the hosts it reaches. Flag and audit only.
  privileged?: boolean;
  privileged_reason?: string;
  privileged_set_by?: string;
  privileged_set_at?: string;
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
export type PreflightRow = {
  capability: string;
  status: "ok" | "fail" | "skipped";
  detail?: string;
  fix?: string;
};

export type PrivilegePreflight = {
  checked_at: string;
  mode: "none" | "nopasswd" | "password" | "helper";
  roles?: string[];
  rows: PreflightRow[];
  ok: boolean;
  privileged_all: boolean;
};

export type PrivilegeBundle = {
  mode: string;
  user: string;
  sudoers: string;
  helper?: string;
  helper_sha256?: string;
  helper_path?: string;
  checklist: string[];
  warnings: string[];
};

export type EffectiveSetting = {
  key: string;
  category:
    | "notifications"
    | "renewal_policy"
    | "discovery"
    | "sso"
    | "saml"
    | "scim"
    | "key_backend"
    | "slo"
    | "agentless";
  env_var: string;
  secret: boolean;
  source: "database" | "env_default" | "unset";
  effective_source: "env" | "override";
  restart_required?: boolean;
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

// W29-06 shape (canonical since the W33/train merge). redeemed_at and
// revoked_at are "" while unset.
export interface AgentEnrollmentToken {
  id: string;
  label: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  redeemed_at: string;
  redeemed_agent_id: string;
  revoked_at: string;
}

export async function fetchJSON<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  // Caller headers (e.g. If-Match) are merged over the auth/tenant headers.
  const extraHeaders = init?.headers as Record<string, string> | undefined;
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { ...buildHeaders(), ...extraHeaders },
    credentials: "include",
  });

  if (res.status === 401 && !NO_REFRESH_PATHS.has(path)) {
    const outcome = await refreshAccessToken();
    if (outcome === "ok") {
      const retryRes = await fetch(`${API_BASE}${path}`, {
        ...init,
        headers: { ...buildHeaders(), ...extraHeaders },
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

export function queryString(
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

export type KeyPolicy = {
  key_id?: string;
  owner?: string;
  acl?: string[];
  max_age_days?: number;
  rotated_at?: string;
  compromised_at?: string | null;
};

export type GrantResult<T> =
  { state: "pending"; actionId: string } | { state: "done"; data: T };

// Raw fetch (like exportKey): a 202 is a dual-control proposal, not a result.
async function grantRequest<T>(
  path: string,
  body: unknown,
  parse: (res: Response) => Promise<T>,
): Promise<GrantResult<T>> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: buildHeaders(),
    credentials: "include",
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let msg = `API error: ${res.status} ${res.statusText}`;
    try {
      const b = await res.json();
      if (b?.message) msg = b.message;
    } catch {
      // ignore JSON parse errors
    }
    throw new Error(msg);
  }
  if (res.status === 202) {
    const b = (await res.json()) as { data?: { action_id?: string } };
    return { state: "pending", actionId: b?.data?.action_id ?? "" };
  }
  return { state: "done", data: await parse(res) };
}

export type CTFinding = {
  id: string;
  log_id: string;
  domain: string;
  common_name?: string;
  dns_names?: string[];
  ca: string;
  serial: string;
  not_before?: string;
  not_after?: string;
  source: string;
  status: "open" | "acknowledged" | "known_issuer";
  resolved_by?: string;
  resolved_at?: string | null;
  created_at?: string;
  ours: boolean;
  revoke_url?: string;
};

export type HostKeyProbe = {
  host: string;
  port: number;
  algorithm: string;
  ssh_host_key: string;
  fingerprint_sha256: string;
};

export type DiscoverySchedule = {
  key: string;
  scan_type: string;
  target: string;
  name?: string;
  source: "env" | "managed";
  interval_seconds: number | null;
  effective_interval_seconds: number | null;
  last_run: string | null;
  next_run: string | null;
  running: boolean;
  running_job_id?: string;
};

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
  // An admin's quota read must name the team (400 otherwise); other roles
  // always get their own team and the server ignores team_id.
  teamQuota: (teamId?: string) =>
    fetchJSON<ApiDataResponse<TeamQuota>>(
      teamId
        ? `/certificates/quota?team_id=${encodeURIComponent(teamId)}`
        : "/certificates/quota",
    ),
  // 404 means the team has no policy row, i.e. it is unrestricted (D-195).
  teamPolicy: async (team: string): Promise<TeamPolicy | null> => {
    try {
      const res = await fetchJSON<ApiDataResponse<TeamPolicy>>(
        `/team-policies/${encodeURIComponent(team)}`,
      );
      return res.data;
    } catch (e) {
      if ((e as { status?: number }).status === 404) return null;
      throw e;
    }
  },
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
  dcvValidations: () =>
    fetchJSON<DcvValidationsResponse>("/connectors/dcv-validations"),
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
  estateBulkTakeover: (body: {
    items: {
      fingerprint: string;
      owner_email?: string;
      owner_team?: string;
      service_name?: string;
      renewal_path: { mode: string; connector_id?: string };
    }[];
  }) =>
    fetchJSON<
      ApiDataResponse<{
        total: number;
        succeeded: number;
        failed: number;
        skipped: number;
        results: BulkTakeoverRow[];
      }>
    >("/estate/takeover/bulk", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  estateTakeoverSuggestions: async (fingerprints: string[]) => {
    const out: TakeoverSuggestion[] = [];
    for (let i = 0; i < fingerprints.length; i += SUGGESTION_CHUNK) {
      const qs = fingerprints
        .slice(i, i + SUGGESTION_CHUNK)
        .map((fp) => `fingerprint=${encodeURIComponent(fp)}`)
        .join("&");
      const res = await fetchJSON<ApiDataResponse<TakeoverSuggestion[]>>(
        `/estate/takeover/suggestions?${qs}`,
      );
      out.push(...res.data);
    }
    return out;
  },
  estateRevert: (fingerprint: string) =>
    fetchJSON<ApiDataResponse<CertificateRecord>>("/estate/revert", {
      method: "POST",
      body: JSON.stringify({ fingerprint }),
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
    fetchJSON<
      ApiDataResponse<components["schemas"]["CertificateRevokeResult"]>
    >(`/certificates/${fingerprint}/revoke`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
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
  // W23-36: revoke is always dual control -> 202 {action_id}; nothing is
  // revoked until a different admin approves. No redeem step on this API.
  revokeCa: async (
    id: string,
  ): Promise<{ proposed: true; actionId?: string }> => {
    const r = await grantRequest(
      `/cas/${encodeURIComponent(id)}/revoke`,
      { reason: "cACompromise" },
      async () => undefined,
    );
    if (r.state !== "pending") {
      throw new Error("Unexpected non-pending response to CA revoke");
    }
    return { proposed: true, actionId: r.actionId || undefined };
  },
  // W23-05: offline-root workflow (import keyless root, CSR, signed cert).
  importCa: (body: {
    name: string;
    type: "root";
    key_storage_type: "external";
    certificate_pem: string;
    approved_action_id?: string;
  }) =>
    fetchJSON<{
      data:
        CaRecord | { status: "proposed"; action_id: string; message?: string };
    }>("/cas/import", { method: "POST", body: JSON.stringify(body) }),
  caCsr: (id: string) =>
    fetchJSON<ApiDataResponse<{ ca_id: string; csr_pem: string }>>(
      `/cas/${encodeURIComponent(id)}/csr`,
    ),
  completeCaCertificate: (id: string, certificate_pem: string) =>
    fetchJSON<ApiDataResponse<CaRecord>>(
      `/cas/${encodeURIComponent(id)}/certificate`,
      { method: "POST", body: JSON.stringify({ certificate_pem }) },
    ),
  removeCaTrustAnchor: (id: string, approvedActionId?: string) =>
    fetchJSON<{ data?: { status: "proposed"; action_id: string } } | undefined>(
      `/cas/${encodeURIComponent(id)}${
        approvedActionId
          ? `?approved_action_id=${encodeURIComponent(approvedActionId)}`
          : ""
      }`,
      { method: "DELETE" },
    ),

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
  // PUT replaces the template and the server requires If-Match: <revision>.
  updateTemplate: (
    id: string,
    body: Record<string, unknown>,
    revision?: number,
  ) =>
    fetchJSON<ApiDataResponse<TemplateRecord>>(`/templates/${id}`, {
      method: "PUT",
      body: JSON.stringify(body),
      headers:
        revision !== undefined ? { "If-Match": String(revision) } : undefined,
    }),
  templateRevisions: (id: string) =>
    fetchJSON<{ data: TemplateRevision[] }>(`/templates/${id}/revisions`),
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
  ctFindings: (status?: string) =>
    fetchJSON<ApiDataResponse<{ findings: CTFinding[]; total: number }>>(
      `/ct/findings${queryString({ status })}`,
    ),
  acknowledgeCTFinding: (id: string) =>
    fetchJSON<ApiDataResponse<CTFinding>>(
      `/ct/findings/${encodeURIComponent(id)}/acknowledge`,
      { method: "POST" },
    ),
  markCTFindingKnownIssuer: (id: string) =>
    fetchJSON<ApiDataResponse<CTFinding>>(
      `/ct/findings/${encodeURIComponent(id)}/known-issuer`,
      { method: "POST" },
    ),
  authorizedIssuers: () =>
    fetchJSON<ApiDataResponse<AuthorizedIssuer[]>>(
      "/discovery/authorized-issuers",
    ),
  createAuthorizedIssuer: (body: {
    name: string;
    kind: AuthorizedIssuer["kind"];
    value: string;
    notes?: string;
  }) =>
    fetchJSON<ApiDataResponse<AuthorizedIssuer>>(
      "/discovery/authorized-issuers",
      { method: "POST", body: JSON.stringify(body) },
    ),
  deleteAuthorizedIssuer: (id: string) =>
    fetchJSON<void>(
      `/discovery/authorized-issuers/${encodeURIComponent(id)}`,
      { method: "DELETE" },
    ),
  discoverySchedules: () =>
    fetchJSON<ApiDataResponse<DiscoverySchedule[]>>("/discovery/schedules"),
  updateDiscoverySchedule: (body: {
    key: string;
    interval_seconds: number | null;
  }) =>
    fetchJSON<ApiDataResponse<DiscoverySchedule>>("/discovery/schedules", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
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

  // ITSM connections (admin-only endpoint; a rule's itsm target is a connection id)
  itsmConnections: () =>
    fetchJSON<ApiListResponse<{ id: string; name: string; kind: string }>>(
      "/itsm/connections",
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
  // W22-05: server-streamed export of every matching row.
  auditExport: (
    params: Record<string, string | number | boolean | undefined>,
  ) =>
    downloadAuthedFile(
      `/audit/export${queryString(params)}`,
      params.format === "json" ? "audit-evidence.json" : "audit-evidence.csv",
    ),

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
  keyCustody: () =>
    fetchJSON<ApiDataResponse<Record<string, unknown>>>("/reports/key-custody"),
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

  // Key ceremonies (M-of-N root CA activation)
  ceremonies: () => fetchJSON<ApiDataResponse<Ceremony[]>>("/ceremonies"),
  startCeremony: (body: StartCeremonyRequest) =>
    fetchJSON<ApiDataResponse<Ceremony>>("/ceremonies", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  approveCeremony: (id: string) =>
    fetchJSON<ApiDataResponse<Ceremony>>(
      `/ceremonies/${encodeURIComponent(id)}/approve`,
      { method: "POST" },
    ),
  abortCeremony: (id: string) =>
    fetchJSON<ApiDataResponse<Ceremony>>(
      `/ceremonies/${encodeURIComponent(id)}/abort`,
      { method: "POST" },
    ),

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
  cryptoAgilityRoadmap: (body: AgilityRoadmapRequest) =>
    fetchJSON<ApiDataResponse<AgilityRoadmapResult>>(
      "/crypto-agility/roadmap",
      { method: "POST", body: JSON.stringify(body) },
    ),
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
  // W23-40: key policy (owner/ACL/max-age) and the compromise flow.
  keyPolicy: async (id: string): Promise<{ data: KeyPolicy | null }> => {
    try {
      return await fetchJSON<{ data: KeyPolicy }>(
        `/keys/${encodeURIComponent(id)}/policy`,
      );
    } catch (e) {
      if (e instanceof Error && /\b404\b|not found/i.test(e.message)) {
        return { data: null };
      }
      throw e;
    }
  },
  setKeyPolicy: (
    id: string,
    body: { owner: string; acl: string[]; max_age_days: number },
  ) =>
    fetchJSON<{ data: KeyPolicy }>(`/keys/${encodeURIComponent(id)}/policy`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  // Always dual control: 202 = proposal filed, nothing compromised yet.
  compromiseKey: async (
    id: string,
  ): Promise<{ proposed: true; actionId?: string }> => {
    const r = await grantRequest(
      `/keys/${encodeURIComponent(id)}/compromise`,
      {},
      async () => undefined,
    );
    if (r.state !== "pending") {
      throw new Error("Unexpected non-pending response to key compromise");
    }
    return { proposed: true, actionId: r.actionId || undefined };
  },
  importKey: (body: { id: string; backup_pem: string; passphrase: string }) =>
    fetchJSON<{ data: unknown }>("/keys/import", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteKey: (id: string) =>
    fetchJSON<void>(`/keys/${encodeURIComponent(id)}`, { method: "DELETE" }),
  cancelKeyDeletion: (id: string) =>
    fetchJSON<{ data?: { status?: string; action_id?: string } } | undefined>(
      `/keys/${encodeURIComponent(id)}/cancel-deletion`,
      { method: "POST" },
    ),
  // W23-21: dual-control grant flow. First call -> 202 {action_id}; after a
  // different admin approves, repeat with approved_action_id.
  escrowKey: (b: {
    key_id: string;
    custodian_a_passphrase: string;
    custodian_b_passphrase: string;
    approved_action_id?: string;
  }) => grantRequest<string>("/keys/escrow", b, (res) => res.text()),
  recoverEscrowedKey: (b: {
    bundle: unknown;
    custodian_a_passphrase: string;
    custodian_b_passphrase: string;
    approved_action_id?: string;
  }) =>
    grantRequest<{ id: string }>("/keys/escrow/recover", b, async (res) => {
      const body = (await res.json()) as { data?: { id?: string } };
      return { id: body?.data?.id ?? "" };
    }),
  byokExport: (b: {
    bundle: unknown;
    custodian_a_passphrase: string;
    custodian_b_passphrase: string;
    provider: string;
    region?: string;
    key_id: string;
    approved_action_id?: string;
  }) =>
    grantRequest<unknown>("/keys/byok/export", b, async (res) => {
      const body = (await res.json()) as { data?: unknown };
      return body?.data;
    }),

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
  setCredentialPrivileged: (id: string, privileged: boolean, reason?: string) =>
    fetchJSON<ApiDataResponse<CredentialMeta>>(
      `/credentials/${encodeURIComponent(id)}/privileged`,
      { method: "PUT", body: JSON.stringify({ privileged, reason }) },
    ),
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
  renewalRetry: (fingerprint: string) =>
    fetchJSON<ApiDataResponse<{ fingerprint: string; status: string }>>(
      "/renewal/retry",
      { method: "POST", body: JSON.stringify({ fingerprint }) },
    ),

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

  // Single-use agent enrollment tokens (W29-06 API, used by W33-25). The
  // minted token is in this response only; callers must keep it in memory,
  // never in storage.
  mintAgentEnrollmentToken: (body?: { ttl_seconds?: number; label?: string }) =>
    fetchJSON<
      ApiDataResponse<{
        id: string;
        token: string;
        expires_at: string;
        label: string;
      }>
    >("/agent/enrollment-tokens", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  agentEnrollmentTokens: () =>
    fetchJSON<ApiDataResponse<AgentEnrollmentToken[]>>(
      "/agent/enrollment-tokens",
    ),
  revokeAgentEnrollmentToken: (id: string) =>
    fetchJSON<void>(`/agent/enrollment-tokens/${encodeURIComponent(id)}`, {
      method: "DELETE",
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

  // Direct-CA inventory sources (W11-05 / W24-30)
  inventorySources: () =>
    fetchJSON<ApiDataResponse<InventorySourceRecord[]>>("/inventory-sources"),
  createInventorySource: (body: {
    name: string;
    type: string;
    config_json: string;
    credential_ref?: string;
    schedule_minutes: number;
  }) =>
    fetchJSON<ApiDataResponse<InventorySourceRecord>>("/inventory-sources", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  syncInventorySource: (id: string) =>
    fetchJSON<ApiDataResponse<InventorySyncResult>>(
      `/inventory-sources/${encodeURIComponent(id)}/sync`,
      { method: "POST" },
    ),
  deleteInventorySource: (id: string) =>
    fetchJSON<void>(`/inventory-sources/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),

  // Template migration (W24-38/39/44)
  migrationSources: () =>
    fetchJSON<ApiDataResponse<string[]>>("/migration/sources"),
  migrationDryRun: (body: MigrationRequest) =>
    fetchJSON<ApiDataResponse<MigrationDiff>>("/migration/dryrun", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  migrationApply: (body: MigrationRequest) =>
    fetchJSON<
      ApiDataResponse<{
        status: "pending_approval" | "nothing_to_apply";
        pending_action_id?: string;
        diff: MigrationDiff;
      }>
    >("/migration/apply", { method: "POST", body: JSON.stringify(body) }),
  migrationBatches: () =>
    fetchJSON<ApiDataResponse<MigrationBatch[]>>("/migration/batches"),
  migrationReport: (id: string) =>
    fetchJSON<
      ApiDataResponse<{
        batch: MigrationBatch;
        report: {
          batch_id: string;
          created: number;
          entries: MigrationDiffEntry[];
        };
      }>
    >(`/migration/${encodeURIComponent(id)}/report`),
  migrationRollback: (id: string) =>
    fetchJSON<ApiDataResponse<MigrationRollback>>(
      `/migration/${encodeURIComponent(id)}/rollback`,
      { method: "POST" },
    ),

  // Managed targets (W5-09, agentless mode)
  targets: () => fetchJSON<ApiDataResponse<ManagedTarget[]>>("/targets"),
  unblockTarget: (id: string) =>
    fetchJSON<void>(`/targets/${encodeURIComponent(id)}/unblock`, { method: "POST" }),
  certTargetBindings: (targetId: string) =>
    fetchJSON<ApiDataResponse<CertTargetBinding[]>>(
      `/targets/${encodeURIComponent(targetId)}/bindings`,
    ),
  bindCertToTarget: (targetId: string, certFingerprint: string) =>
    fetchJSON<ApiDataResponse<CertTargetBinding>>(
      `/targets/${encodeURIComponent(targetId)}/bindings`,
      {
        method: "POST",
        body: JSON.stringify({ cert_fingerprint: certFingerprint }),
      },
    ),
  unbindCertFromTarget: (targetId: string, fingerprint: string) =>
    fetchJSON<void>(
      `/targets/${encodeURIComponent(targetId)}/bindings/${encodeURIComponent(fingerprint)}`,
      { method: "DELETE" },
    ),
  targetPolicy: () =>
    fetchJSON<ApiDataResponse<TargetPolicyRow[]>>("/target-policy"),
  upsertTargetGroup: (
    name: string,
    body: { renewal_threshold_days: number; target_ids: string[] },
  ) =>
    fetchJSON<ApiDataResponse<TargetGroup>>(
      `/target-groups/${encodeURIComponent(name)}`,
      { method: "PUT", body: JSON.stringify(body) },
    ),
  // W34-16: privilege bundle for a stored target (targetId) or, in the setup
  // wizard before one exists, from the install profile alone.
  privilegeBundle: (q: {
    targetId?: string;
    mode: string;
    user?: string;
    serverType?: string;
    certPath?: string;
    keyPath?: string;
  }) => {
    const p = new URLSearchParams({ mode: q.mode });
    if (q.user) p.set("user", q.user);
    if (!q.targetId) {
      if (q.serverType) p.set("server_type", q.serverType);
      if (q.certPath) p.set("cert_path", q.certPath);
      if (q.keyPath) p.set("key_path", q.keyPath);
    }
    const base = q.targetId ? `/targets/${encodeURIComponent(q.targetId)}/privilege-bundle` : "/targets/privilege-bundle";
    return fetchJSON<ApiDataResponse<PrivilegeBundle>>(`${base}?${p.toString()}`);
  },
  // W34-15: per-capability privilege preflight for an ssh target.
  preflightTarget: (targetId: string) =>
    fetchJSON<ApiDataResponse<PrivilegePreflight>>(`/targets/${encodeURIComponent(targetId)}/preflight`, { method: "POST" }),
  targetPreflight: (targetId: string) =>
    fetchJSON<ApiDataResponse<PrivilegePreflight>>(`/targets/${encodeURIComponent(targetId)}/preflight`),
  probeTargetHostKey: (body: { host: string; port?: number }) =>
    fetchJSON<ApiDataResponse<HostKeyProbe>>("/targets/hostkey", {
      method: "POST",
      body: JSON.stringify(body),
    }),
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
    ssh_host_key?: string;
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

  // Per-user UI prefs (W33-03); the server keys on the caller, never a client id.
  userPrefs: () => fetchJSON<ApiDataResponse<UserPrefs>>("/users/me/prefs"),
  setUserPrefs: (body: UserPrefs) =>
    fetchJSON<ApiDataResponse<UserPrefs>>("/users/me/prefs", {
      method: "PUT",
      body: JSON.stringify(body),
    }),

  // Auth-mode flags actually in effect on the running server (diagnostic;
  // used to show whether a saved SSO override has taken effect yet — see
  // W8-13, config overrides for SSO are not re-read until a restart).
  protectedConfig: () => fetchJSON<ProtectedConfigFlags>("/protected/config"),

  // Pre-flight impact preview (W23-17). The server accepts only
  // revoke | retire_ca | deprecate_algorithm.
  // POST /cas/{id}/rotate-key. A 202 is a dual-control proposal: NOTHING has
  // been re-keyed yet. Redeem by repeating the same call (same mode and
  // algorithm) with approvedActionId once a second admin has approved.
  rotateCaKey: async (
    id: string,
    opts: {
      mode?: "cross-sign";
      algorithm?: string;
      approvedActionId?: string;
    },
  ): Promise<
    | { proposed: true; actionId: string }
    | { proposed: false; result: RotateCaKeyResult }
  > => {
    const res = await fetch(
      `${API_BASE}/cas/${encodeURIComponent(id)}/rotate-key${opts.mode ? "?mode=cross-sign" : ""}`,
      {
        method: "POST",
        headers: buildHeaders(),
        credentials: "include",
        body: JSON.stringify({
          algorithm: opts.algorithm || undefined,
          approved_action_id: opts.approvedActionId || undefined,
        }),
      },
    );
    if (!res.ok) {
      let msg = `API error: ${res.status} ${res.statusText}`;
      try {
        const b = await res.json();
        if (b?.message) msg = b.message;
      } catch {
        // ignore JSON parse errors
      }
      throw new Error(msg);
    }
    const body = (await res.json()) as {
      data?: RotateCaKeyResult & { action_id?: string };
    };
    if (res.status === 202) {
      return { proposed: true, actionId: body?.data?.action_id ?? "" };
    }
    return { proposed: false, result: body?.data ?? {} };
  },
  blastRadius: (action: BlastRadiusAction, target: string) =>
    fetchJSON<ApiDataResponse<BlastRadiusResult>>(
      `/blast-radius${queryString({ action, target })}`,
    ),
};
