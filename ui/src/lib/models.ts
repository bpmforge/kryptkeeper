import type { TrustClassCounts } from "./trustClass";
export type ListMeta = {
  total?: number;
  limit?: number;
  prev_cursor?: string | null;
  next_cursor?: string | null;
};

export type ApiListResponse<T> = {
  data: { items: T[] } | T[];
  meta?: ListMeta;
  principal?: string;
};

export type ApiDataResponse<T> = {
  data: T;
  meta?: ListMeta;
  principal?: string;
};

export type CertificateRecord = {
  fingerprint_sha256: string;
  common_name?: string;
  subject_dn?: string;
  issuer_cn?: string;
  issuer_dn?: string;
  valid_from?: string;
  valid_until?: string;
  grade?: string;
  risk_score?: number;
  renewal_status?: string;
  // How this certificate gets renewed: acme|est|scep|api|manual. Ships on
  // the wire already (CertificateItem.RenewalMethod) but was never modelled
  // here, so nothing in the UI could tell an automated certificate from one
  // that needs a human.
  renewal_method?: string;
  status?: string;
  team_id?: string;
  owner_email?: string;
  owner_team?: string;
  service_name?: string;
  labels?: string[];
  ca_id?: string;
  serial_number?: string;
  public_key_algorithm?: string;
  // ML-DSA parameter set (e.g. "ML-DSA-65"); absent for other key types.
  key_algorithm_display?: string;
  key_size_bits?: number;
  subject_alt_names?: string[];
  uri_sans?: string[];
  extended_key_usage?: string[];
  cert_pem?: string;
  // W11-01 estate model.
  origin?: string;
  management_state?: string;
  revoked_at?: string;
  revocation_reason?: string;
  // Discovery: whose certificate this is (managed|public|private_other|
  // self_signed|unknown) and what the served chain looked like.
  trust_class?: string;
  chain_complete?: boolean;
  chain_trusted?: boolean;
  risk_flags?: string[];
};

export type CaRecord = {
  id: string;
  display_name?: string;
  name?: string;
  type: string;
  key_storage_type: string;
  status: string;
  parent_ca_id?: string;
  crl_distribution_points?: string[];
  ocsp_service_url?: string;
  active_issued_certificates?: number;
  csr_pem?: string;
  warnings?: string[];
};

export type NotificationRule = {
  id: string;
  name: string;
  threshold_days: number;
  channel: string;
  target: string;
  enabled: boolean;
  created_at: string;
};

export type UserRecord = {
  id: string;
  email: string;
  role: string;
  status: string;
  created_at: string;
  last_seen_at?: string;
};

export type DiscoveryEndpointRecord = {
  id: string;
  hostname?: string;
  ip_address?: string;
  port?: number;
  protocol: string;
  risk_score?: number;
  // True under the documented risky rule (score >= 70, or a high-severity
  // flag or finding); the badge and "Risky only" read it so they agree.
  risky?: boolean;
  // Endpoint findings: "NOT_TLS: ...", "TLS_HANDSHAKE_FAILED: ...",
  // "DEPRECATED_TLS_VERSION: TLSv1.0", or cipheraudit text.
  issues?: string[];
  last_seen_at?: string;
  server_tech?: string;
  // W34-06: least-trusted inventory class among the endpoint's leaf certs.
  inventory_class?: string;
  recommended_install_mode?: string;
  ssh_banner?: string;
  ssh_host_key_algorithms?: string[];
  // W34-08: posture of the discovered file holding the served leaf.
  install_posture?: {
    file_id?: string;
    posture: "standard" | "privileged" | "root_service" | "unknown";
    path: string;
    host: string;
    owner?: string;
    mode?: string;
    service_tech?: string;
    findings?: string[];
    accepted_findings?: string[];
  };
  crypto_posture?: {
    negotiated_version?: string;
    negotiated_cipher?: string;
    negotiated_group?: string;
    offered_versions?: string[];
    weak_findings?: string[];
    pqc?: {
      hybrid_negotiated?: boolean;
      hybrid_offered?: boolean;
      group?: string;
    };
  };
  mapped_certs?: {
    fingerprint: string;
    common_name?: string;
    valid_until?: string;
    risk_score: number;
    risk_flags?: string[];
    trust_class?: string;
    // W34-06: trust_class refined with the operator's authorized issuers, the
    // headline class derived from it, and the issuer as observed (what the
    // Authorize this issuer action declares).
    issuer_class?: string;
    inventory_class?: string;
    issuer_dn?: string;
    // An intermediate/root the endpoint served alongside its leaf.
    chain_ca?: boolean;
    // Absent = could not be judged for this endpoint; false = an intermediate
    // is provably missing from what the server sent.
    chain_complete?: boolean;
    chain_trusted?: boolean;
  }[];
};

export type DiscoveryScanJobRecord = {
  id: string;
  scan_type: string;
  target: string;
  status: string;
  queued_at?: string;
  // Why the job failed, or what a completed_with_errors job could not read.
  error?: string;
};

export type NotificationDeliveryRecord = {
  id: string;
  channel: string;
  target: string;
  status: string;
  queued_at?: string;
  delivered_at?: string;
  /** Set when the hub knows why it failed and what to change (e.g. the egress guard refused the destination). */
  failure_reason?: string;
};

export type HistoryRecord = {
  action_id: string;
  category: string;
  status: string;
  updated_by: string;
  updated_at: string;
  note?: string;
};

export type AuditRow = {
  id: number | string;
  timestamp: string;
  action: string;
  actor_type: string;
  actor_id: string;
  resource_type: string;
  resource_id: string;
  // Read-time display name; absent when unresolved. Never part of the stored record.
  resource_name?: string;
  trace_id?: string;
  outcome: string;
};

export type DashboardSummary = {
  certificates?: {
    // Active certificates (not revoked, not superseded); revoked is the
    // complement, reported separately.
    total?: number;
    revoked?: number;
    expiring_30_days?: number;
    expired?: number;
    // W11-01 estate split by management_state (zeros on file summaries).
    managed?: number;
    external?: number;
    unmanaged?: number;
    // Active certificates with no owner team (W22-24); same predicate as ?owner=unassigned.
    unowned?: number;
  };
  discovery?: {
    discovered_endpoints?: number;
    risky_endpoints?: number;
    trust_classes?: TrustClassCounts;
  };
  notifications?: { pending_notifications?: number };
  protocols?: { status?: string };
};

export type AuthorizedIssuer = {
  id: string;
  name: string;
  kind: "ca_cert" | "issuer_dn" | "spki_sha256";
  value: string;
  notes?: string;
  created_by: string;
  created_at: string;
};

export type DiscoverySummary = {
  discovered_endpoints?: number;
  mapped_certificates?: number;
  risky_endpoints?: number;
  active_scan_jobs?: number;
  trust_classes?: TrustClassCounts;
  inventory_classes?: Record<string, number>;
};

export type NotificationSummary = {
  pending_notifications?: number;
  ownership_escalations?: number;
  delivery_failures_24h?: number;
};

export type AuthzCheck = {
  service: string;
  authenticated: boolean;
  principal: string;
  role?: string;
  scopes?: string[];
};

export type LoginResponse = {
  data: {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token: string;
    refresh_expires_in: number;
    principal: { user_id: string; role: string };
  };
};

export type SSHPolicy = {
  cert_types: Array<"user" | "host">;
  allowed_principals?: string[];
  host_patterns?: string[];
  max_ttl_hours: number;
};

export type NamePolicy = {
  allowed_dns_suffixes?: string[];
  allowed_dns_names?: string[];
  allow_ip_sans?: boolean;
  allow_uri_sans?: boolean;
  allowed_uri_prefixes?: string[];
  cn_must_be_san?: boolean;
};

export type TemplateRecord = {
  id: string;
  name: string;
  display_name: string;
  oid?: string;
  key_usage: string[];
  extended_key_usage: string[];
  allowed_algorithms: string[];
  min_key_size?: number;
  validity_period: string;
  renewal_overlap?: string;
  auto_enroll: boolean;
  enrollee_type?: "machine" | "user";
  require_approval?: boolean;
  approval_roles?: string[];
  enrollment_permissions?: { enroll: string[] };
  ssh_policy?: SSHPolicy;
  name_policy?: NamePolicy;
  active: boolean;
  revision: number;
  issued_count: number;
  created_at: string;
  updated_at: string;
};

export type TemplateFieldChange = { field: string; old: unknown; new: unknown };
export type TemplateRevision = {
  revision: number;
  changed_at: string;
  snapshot: TemplateRecord;
  changes: TemplateFieldChange[] | null;
};

export type SearchResult = {
  kind: string;
  id: string;
  label: string;
  description?: string;
  url: string;
};

export type CryptoPostureReport = {
  generated_at: string;
  total_certs: number;
  algorithm_breakdown: Record<string, number>;
  pqc_readiness: {
    quantum_safe: number;
    quantum_safe_leaf_only: number;
    migration_ready: number;
    vulnerable: number;
    not_applicable: number;
    pqc_score_percent: number;
    quantum_safe_percent: number;
  };
  expiry_buckets: {
    expired: number;
    expiring_47d: number;
    expiring_90d: number;
    expiring_200d: number;
    expiring_1yr: number;
  };
  grade_distribution: Record<string, number>;
  automation_coverage: {
    automated: number;
    manual: number;
    automation_percent: number;
  };
  risk_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
};

export type PostureSnapshot = {
  id: string;
  captured_at: string;
  total_certs: number;
  pqc_score_percent: number;
  automation_percent: number;
  risk_critical: number;
  risk_high: number;
  risk_medium: number;
  risk_low: number;
  expired: number;
  expiring_47d: number;
  report: CryptoPostureReport;
};

export type PostureTrendResponse = {
  snapshots: PostureSnapshot[];
};

export type RenewalSchedulerStatus = {
  running: boolean;
  threshold_days: number;
  poll_interval_hours: number;
  last_run_at?: string;
  next_run_at?: string;
  last_candidates: number;
  last_expired_skipped: number;
  last_auto_renew_triggers: number;
  last_notifications: number;
};

export type SchedulerStatusResponse = {
  has_run: boolean;
  status: RenewalSchedulerStatus;
};

export type SIEMStatus = {
  enabled: boolean;
  webhook_enabled: boolean;
  webhook_target?: string;
  webhook_has_token: boolean;
  syslog_enabled: boolean;
  syslog_addr?: string;
  syslog_proto?: string;
};

export type SIEMTestResult = {
  enabled: boolean;
  webhook_tested: boolean;
  webhook_ok: boolean;
  webhook_error?: string;
  syslog_tested: boolean;
  syslog_ok: boolean;
  syslog_error?: string;
};

export type CodeSigningCert = {
  fingerprint_sha256: string;
  common_name?: string;
  issuer_cn?: string;
  team_id?: string;
  public_key_algorithm?: string;
  key_size_bits?: number;
  valid_from?: string;
  valid_until?: string;
  risk_score?: number;
  risk_flags?: string[];
  grade?: string;
  expired: boolean;
  revoked_at?: string | null;
};

export type CodeSigningInventory = {
  generated_at: string;
  total: number;
  expired: number;
  revoked: number;
  certs: CodeSigningCert[];
};

export type FailedRenewal = {
  agent_id: string;
  task_id: string;
  fingerprint: string;
  outcome: string;
  rolled_back: boolean;
  detail?: string;
  served_fingerprint?: string;
  reported_at: string;
  type?: "execute_failure" | "notification_dead_letter" | "agent_result";
  target_id?: string;
  attempt?: number;
  max_attempts?: number;
  next_attempt_at?: string;
  gave_up?: boolean;
};

export type RenewalConnectorBudget = {
  connector_id: string;
  in_flight: number;
  cap: number;
  daily_used?: number;
  daily_limit?: number;
};

export type RenewalQueueMetrics = {
  depth: number;
  eta_seconds: number;
  eta_known?: boolean;
  workers?: number;
  connector_budgets: RenewalConnectorBudget[];
};

export type RenewalSLOReport = {
  generated_at: string;
  agents_total: number;
  agents_active: number;
  endpoints_managed: number;
  outcomes: Record<string, number>;
  total_renewals: number;
  success_rate_percent: number;
  mean_time_to_renew_secs: number;
  mttr_samples: number;
  failed_renewals: FailedRenewal[];
  queue?: RenewalQueueMetrics;
  // W30-05: per-SLO 30-day error budget (ratio SLOs only).
  slos?: RenewalSLOBudget[];
};

export type RenewalSLOBudget = {
  name: string;
  objective: number;
  window_days: number;
  has_data: boolean;
  budget_remaining_pct: number;
  burn_rate_1h: number;
  burn_rate_6h: number;
  breached: boolean;
};

export type ExecutiveSummary = {
  generated_at: string;
  org: string;
  total_certs: number;
  pqc_score_percent: number;
  quantum_safe_percent?: number;
  automation_percent: number;
  compliance_pass_percent: number;
  compliance: { pass: number; warn: number; fail: number };
  expired: number;
  expiring_47d: number;
  risk_critical: number;
  risk_high: number;
  top_risks: string[];
};

export type EvidenceSchedule = {
  id: string;
  framework: string;
  cadence: string;
  recipients: string[];
  enabled: boolean;
  last_sent_at?: string;
  created_at: string;
};

export type ExpiryBucket = {
  label: string;
  days_from: number;
  days_to: number;
  count: number;
};

export type ExpiryTimelineReport = {
  generated_at: string;
  total_certs: number;
  buckets: ExpiryBucket[];
  by_ca: Record<string, number>;
  by_owner_team: Record<string, number>;
};

export type PQCMigrationItem = {
  fingerprint: string;
  common_name: string;
  priority: "critical" | "high" | "medium" | "low";
  reason: string;
  action: string;
  deadline: string;
};

export type MigrationWaveMember = {
  fingerprint: string;
  common_name: string;
};

export type WaveProgress = {
  id: string;
  name: string;
  status?: string;
  owner?: string;
  target_date?: string;
  created_at: string;
  members: MigrationWaveMember[];
  total: number;
  migrated: number;
  progress_percent: number;
};

export type PQCDeadline = {
  name: string;
  date: string;
  days_remaining: number;
  passed: boolean;
};

export type PQCCountdownReport = {
  generated_at: string;
  org: string;
  total_certs: number;
  vulnerable: number;
  migration_ready: number;
  quantum_safe: number;
  quantum_safe_leaf_only: number;
  pqc_score_percent: number;
  quantum_safe_percent: number;
  status: "complete" | "on_track" | "at_risk" | "behind";
  deadlines: PQCDeadline[];
  trend: { captured_at: string; pqc_score_percent: number }[];
  waves: WaveProgress[];
};

export type PQCMigrationRoadmap = {
  generated_at: string;
  total_certs: number;
  vulnerable: number;
  migration_ready: number;
  quantum_safe: number;
  quantum_safe_leaf_only: number;
  not_applicable: number;
  pqc_score_percent: number;
  quantum_safe_percent: number;
  items: PQCMigrationItem[];
};

export type Ceremony = {
  id: string;
  ca_id: string;
  ca_name: string;
  common_name: string;
  algorithm: string;
  validity_days: number;
  initiator: string;
  approvers: string[];
  quorum: number;
  approvals: string[];
  status: "pending" | "completed" | "aborted" | "expired";
  created_at: string;
  expires_at?: string;
};

export type StartCeremonyRequest = {
  name: string;
  common_name: string;
  algorithm: string;
  validity_days: number;
  approvers: string[];
  quorum: number;
};

export type PendingAction = {
  id: string;
  action_type: string;
  params: unknown;
  proposed_by: string;
  rationale?: string;
  status: "pending" | "approved" | "rejected" | "failed";
  approved_by?: string;
  decided_at?: string;
  result?: unknown;
  created_at: string;
};

export type SpiffeStatus = {
  enabled: boolean;
  trust_domain: string;
  signing_ca_id: string;
  svid_ttl_seconds: number;
};

export type SpiffeSVIDResult = {
  spiffe_id: string;
  svid_pem: string;
  key_pem: string;
  bundle_pem: string;
  expires_at: string;
};

export type ApprovalStatus = "pending" | "approved" | "rejected";

export type ApprovalRequest = {
  id: string;
  template_id: string;
  ca_id: string;
  requester: string;
  status: ApprovalStatus;
  csr_pem: string;
  team_id?: string;
  requested_at: string;
  decided_at?: string | null;
  decided_by?: string | null;
  reject_reason?: string | null;
  issued_fingerprint?: string | null;
};

export type AgentStatus = "active" | "stale" | "offline";
export type AgentType = "linux" | "mac" | "windows";

export type AgentInfo = {
  id: string;
  name: string;
  type: AgentType;
  registered_at: string;
  last_seen?: string | null;
  status: AgentStatus;
  inventory_count: number;
  host_report?: AgentHostReport;
};

// W34-09: the agent's latest host pass. posture_known=false means the agent
// predates privilege reporting; its files are unknown, never assumed standard.
export type AgentHostReport = {
  received_at: string;
  posture_known: boolean;
  privilege_mode?: string;
  scan_user?: string;
  unreadable_count: number;
  unreadable_paths?: { path: string; error: string }[];
  findings?: string[];
  files?: {
    path: string;
    kind: string;
    owner?: string;
    mode?: string;
    posture: string;
    service_tech?: string;
    findings?: string[];
  }[];
  posture_counts?: Record<string, number>;
  listener_count: number;
  listeners_hidden: number;
};

// Multi-tenancy (v2.2)
export type Tenant = {
  id: string;
  name: string;
  created_at: string;
};

export type TenantContext = {
  enabled: boolean;
  super_admin: boolean;
  tenant: string;
  scoped: boolean;
  tenants: Tenant[];
};

export function extractList<T>(
  payload: unknown,
  keys: string[] = ["items"],
): T[] {
  if (Array.isArray(payload)) return payload as T[];
  if (!payload || typeof payload !== "object") return [];
  const record = payload as Record<string, unknown>;
  for (const key of keys) {
    const value = record[key];
    if (Array.isArray(value)) return value as T[];
  }
  return [];
}

export type RotateCaKeyResult = {
  id?: string;
  status?: string;
  key_id?: string;
  rotated_at?: string;
  ledger_id?: string;
  ledger_persisted?: boolean;
  cross_cert_pem?: string;
  old_cert_pem?: string;
  old_key_id?: string;
};

export type BlastRadiusAction = "revoke" | "retire_ca" | "deprecate_algorithm";
export type BlastRadiusResult = {
  action: string;
  target: string;
  total_affected: number;
  severity: "none" | "low" | "medium" | "high" | "critical";
  affected_by_kind: Record<string, string[]>;
  graph_size: string;
};
