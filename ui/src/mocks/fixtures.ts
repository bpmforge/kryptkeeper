// Realistic fixture data for MSW mock handlers.
//
// `components` is generated from docs/openapi.yaml (`npm run gen:api-types`,
// wired into `build`/`test` via the `prebuild`/`pretest` hooks) — every
// export below that corresponds to a real spec schema builds its core shape
// as that generated type first, so a field renamed/removed in the spec (or
// in this file) fails `tsc -b` instead of silently drifting apart the way
// the pre-W1-11 fixtures did (closes L-03/G-56's fixture-drift class for
// every route the spec actually models). Report-style exports with no
// corresponding openapi.yaml schema (dashboardSummary, caHealth, etc.) are
// left as hand-authored mocks — there's nothing generated to check them
// against yet.
import type { components } from "../generated/api-types";
import type {
  ApprovalRequest,
  ExpiryTimelineReport,
  PQCCountdownReport,
  PQCMigrationItem,
  PQCMigrationRoadmap,
  WaveProgress,
} from "../lib/models";

const now = new Date().toISOString();
const days = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString();

const paginationMeta = (
  total: number,
  limit = 20,
): components["schemas"]["PaginationMeta"] => ({
  total,
  limit,
  next_cursor: null,
  prev_cursor: null,
});

// role MUST be one of the strings lib/auth.tsx actually switches on —
// pki-admin, pki-operator, pki-auditor, discovery-operator,
// notification-operator, service-account. It was "admin", which is not among
// them, so every can*() predicate returned false for the whole dev session:
// `npm run dev` came up permanently read-only, the issuance wizard rendered
// "Your role can view certificates but not issue new ones", and 12 of the 31
// sidebar destinations (the entire System group plus PQC Migration) were never
// rendered. The message named the wrong cause — the role was not restricted,
// it was unrecognised. scopes is supplied for the same reason: the predicates
// take (role, scopes) and several consult both.
export const authzCheck = {
  role: "pki-admin",
  scopes: ["*"],
  email: "admin@kryptkeeper.local",
};

export const dashboardSummary = {
  data: {
    certificates: { total: 247, expiring_30_days: 18, expired: 3 },
    discovery: { discovered_endpoints: 84, risky_endpoints: 12 },
    notifications: { pending_notifications: 5 },
  },
};

// CAItem only declares id/name/type/status — the real CAListItem response
// (internal/bootstrap/ca_provider.go) carries more, but this is the subset
// the spec models today.
const caItems: components["schemas"]["CAItem"][] = [
  {
    id: "ca-root-2024",
    name: "Kryptkeeper Root CA",
    type: "root",
    status: "active",
  },
  {
    id: "ca-int-2024",
    name: "Kryptkeeper Intermediate CA",
    type: "intermediate",
    status: "active",
  },
  {
    id: "ca-pqc-2025",
    name: "PQC Issuance CA (ML-DSA)",
    type: "intermediate",
    status: "active",
  },
];

export const cas = {
  data: caItems.map((ca, i) => ({
    ...ca,
    display_name: ca.name,
    key_storage_type: "software",
    parent_ca_id: i === 0 ? null : "ca-root-2024",
    active_issued_certificates: [183, 58, 6][i],
  })),
  meta: paginationMeta(3),
};

// CertificateItem's declared fields, satisfied first; the real
// CertificateItem response (internal/bootstrap/certificate_provider.go) is
// much wider, so the additional fields Certificates.tsx actually reads
// (owner_team, subject_alt_names, etc.) are layered on via the map below
// rather than folded into this literal (which would trip the excess-property
// check against the narrower generated schema).
const certificateItems: components["schemas"]["CertificateItem"][] = [
  {
    fingerprint_sha256: "sha256:aabbcc001",
    serial_number: "01a1b1c1",
    common_name: "api.internal.example.com",
    issuer_cn: "Kryptkeeper Intermediate CA",
    valid_from: days(-90),
    valid_until: days(275),
    grade: "A",
    risk_score: 15,
    renewal_status: "active",
  },
  {
    fingerprint_sha256: "sha256:aabbcc002",
    serial_number: "01a1b1c2",
    common_name: "db.prod.example.com",
    issuer_cn: "Kryptkeeper Intermediate CA",
    valid_from: days(-180),
    valid_until: days(22),
    grade: "C",
    risk_score: 55,
    renewal_status: "active",
  },
  {
    fingerprint_sha256: "sha256:aabbcc003",
    serial_number: "01a1b1c3",
    common_name: "legacy.example.com",
    issuer_cn: "External CA",
    valid_from: days(-400),
    valid_until: days(-5),
    grade: "F",
    risk_score: 90,
    renewal_status: "expired",
  },
  {
    fingerprint_sha256: "sha256:aabbcc004",
    serial_number: "01a1b1c4",
    common_name: "mesh.internal.example.com",
    issuer_cn: "Kryptkeeper Intermediate CA",
    valid_from: days(-10),
    valid_until: days(80),
    grade: "B",
    risk_score: 20,
    renewal_status: "active",
  },
  {
    fingerprint_sha256: "sha256:aabbcc005",
    serial_number: "01a1b1c5",
    common_name: "pqc-service.example.com",
    issuer_cn: "PQC Issuance CA (ML-DSA)",
    valid_from: days(-5),
    valid_until: days(90),
    grade: "A",
    risk_score: 5,
    renewal_status: "active",
  },
];

const certificateOwnerTeams = [
  "platform",
  "data",
  "infra",
  "platform",
  "security",
];
const certificateSubjectAltNames = [
  ["api.internal.example.com", "api-v2.internal.example.com"],
  ["db.prod.example.com"],
  ["legacy.example.com"],
  ["mesh.internal.example.com"],
  ["pqc-service.example.com"],
];
const certificatePublicKeyAlgorithms = [
  "ECDSA-P256",
  "RSA-2048",
  "RSA-2048",
  "ECDSA-P256",
  "ML-DSA-65",
];

// The real response field is public_key_algorithm
// (internal/bootstrap/certificate_provider.go:40) -- found during W1-11 that
// Certificates.tsx's detail panel instead read a phantom `key_algorithm`
// (models.ts:39) the backend never sent; fixed in models.ts/Certificates.tsx
// by S-21/G-85, so this fixture's real field name now matches both sides.
export const certificates = {
  data: certificateItems.map((cert, i) => ({
    ...cert,
    status: cert.renewal_status,
    subject_dn: `CN=${cert.common_name}`,
    issuer_dn: `CN=${cert.issuer_cn}`,
    owner_team: certificateOwnerTeams[i],
    subject_alt_names: certificateSubjectAltNames[i],
    public_key_algorithm: certificatePublicKeyAlgorithms[i],
    ca_id: cert.issuer_cn === "External CA" ? undefined : "ca-int-2024",
    ...(cert.renewal_status === "expired" ? { revoked_at: undefined } : {}),
  })),
  meta: paginationMeta(247, 20),
};

export const keys = {
  data: [
    { id: "root-key-2024", algorithm: "ECDSA-P384", created_at: days(-730) },
    { id: "int-key-2024", algorithm: "ECDSA-P256", created_at: days(-365) },
    { id: "pqc-key-2025", algorithm: "ML-DSA-65", created_at: days(-30) },
    { id: "tls-signing-key", algorithm: "ECDSA-P256", created_at: days(-180) },
  ] satisfies components["schemas"]["KeyMetadata"][],
};

export const auditList = {
  data: [
    {
      id: "1",
      timestamp: now,
      action: "certificate.issued",
      actor: "admin@kryptkeeper.local",
      resource: "sha256:aabbcc001",
      source_ip: "10.0.1.5",
    },
    {
      id: "2",
      timestamp: days(-1),
      action: "ca.activated",
      actor: "admin@kryptkeeper.local",
      resource: "ca-pqc-2025",
      source_ip: "10.0.1.5",
    },
    {
      id: "3",
      timestamp: days(-2),
      action: "key.generated",
      actor: "admin@kryptkeeper.local",
      resource: "pqc-key-2025",
      source_ip: "10.0.1.5",
    },
    {
      id: "4",
      timestamp: days(-3),
      action: "certificate.revoked",
      actor: "ops@kryptkeeper.local",
      resource: "sha256:aabbcc003",
      source_ip: "10.0.1.8",
    },
  ],
};

// The spec's CryptoPostureReport schema omits algorithm_breakdown even
// though the real response always includes it
// (internal/bootstrap/handlers_reports.go:25) and CryptoPosture.tsx reads it
// unconditionally -- another schema-completeness gap found via W1-11 (logged
// separately). Building the schema-covered fields as the generated type
// first, then layering the real field on top, keeps the covered fields
// checked without losing the one the spec doesn't model.
const cryptoPostureReport: components["schemas"]["CryptoPostureReport"] = {
  generated_at: now,
  total_certs: 247,
  pqc_readiness: {
    quantum_safe: 6,
    hybrid_quantum_safe: 0,
    migration_ready: 190,
    vulnerable: 51,
    not_applicable: 0,
    pqc_score_percent: 2,
  },
  expiry_buckets: {
    expired: 3,
    expiring_47d: 20,
    expiring_90d: 34,
    expiring_200d: 58,
    expiring_1yr: 132,
  },
  grade_distribution: { A: 110, B: 82, C: 41, D: 11, F: 3 },
  automation_coverage: {
    automated: 210,
    manual: 37,
    automation_percent: 85,
  },
  risk_breakdown: { critical: 3, high: 20, medium: 61, low: 163 },
};

export const cryptoPosture = {
  data: {
    ...cryptoPostureReport,
    algorithm_breakdown: {
      "ECDSA-P256": 142,
      "ECDSA-P384": 38,
      "RSA-2048": 52,
      "RSA-4096": 9,
      "ML-DSA-65": 6,
    },
  },
};

export const caHealth = {
  data: {
    generated_at: now,
    total_cas: 3,
    items: [
      {
        id: "ca-root-2024",
        name: "Kryptkeeper Root CA",
        status: "active",
        algorithm: "ECDSA-P384",
        expires_at: days(3650),
        days_until_expiry: 3650,
        algorithm_strength: "strong",
      },
      {
        id: "ca-int-2024",
        name: "Kryptkeeper Intermediate CA",
        status: "active",
        algorithm: "ECDSA-P256",
        expires_at: days(1825),
        days_until_expiry: 1825,
        algorithm_strength: "strong",
      },
      {
        id: "ca-pqc-2025",
        name: "PQC Issuance CA (ML-DSA)",
        status: "active",
        algorithm: "ML-DSA-65",
        expires_at: days(1825),
        days_until_expiry: 1825,
        algorithm_strength: "strong",
      },
    ],
    summary: {
      active: 3,
      expiring_90d: 0,
      expiring_1yr: 0,
      weak_algorithm: 0,
      sunset_algorithm: 0,
    },
  },
};

const mkBucket = (daysAgo: number, count: number) => ({
  date: new Date(Date.now() - daysAgo * 86_400_000).toISOString().slice(0, 10),
  count,
});

export const issuanceVelocity = {
  data: {
    generated_at: now,
    total_issued: 247,
    windows: { last_7d: 14, last_30d: 52, last_90d: 138 },
    daily_buckets: Array.from({ length: 90 }, (_, i) =>
      mkBucket(89 - i, Math.floor(Math.random() * 6)),
    ),
    by_ca: {
      "Kryptkeeper Intermediate CA": 183,
      "PQC Issuance CA (ML-DSA)": 6,
      "Kryptkeeper Root CA": 58,
    },
    by_team: { platform: 94, data: 61, infra: 52, security: 40 },
    by_template: { "TLS Server": 142, "mTLS Client": 78, "Code Signing": 27 },
    anomaly_days: [
      new Date(Date.now() - 12 * 86_400_000).toISOString().slice(0, 10),
    ],
  },
};

// Typed against the page's contract so a drifted shape fails tsc, not the
// browser (the untyped fixture crashed Expiry Timeline in demo mode).
export const expiryTimeline: { data: ExpiryTimelineReport } = {
  data: {
    generated_at: now,
    total_certs: 247,
    buckets: [
      { label: "Expired", days_from: -9999, days_to: 0, count: 3 },
      { label: "0–7 days", days_from: 0, days_to: 7, count: 2 },
      { label: "7–30 days", days_from: 7, days_to: 30, count: 16 },
      { label: "30–47 days", days_from: 30, days_to: 47, count: 11 },
      { label: "47–90 days", days_from: 47, days_to: 90, count: 23 },
      { label: "90–200 days", days_from: 90, days_to: 200, count: 58 },
      { label: "200–397 days", days_from: 200, days_to: 397, count: 87 },
      { label: "397+ days", days_from: 397, days_to: 9999, count: 47 },
    ],
    by_ca: { "ca-int-2024": 183, "ca-root-2024": 58, "ca-pqc-2025": 6 },
    by_owner_team: { platform: 94, data: 61, infra: 52, security: 40 },
  },
};

const approvalCsr =
  "-----BEGIN CERTIFICATE REQUEST-----\nDEMO-PLACEHOLDER-NOT-A-REAL-CSR\n-----END CERTIFICATE REQUEST-----";

export const approvals: { data: ApprovalRequest[] } = {
  data: [
    {
      id: "apr-1001",
      template_id: "tpl-code",
      ca_id: "ca-int-2024",
      requester: "dev-release-bot",
      status: "pending",
      csr_pem: approvalCsr,
      team_id: "platform",
      requested_at: days(-0.2),
    },
    {
      id: "apr-1002",
      template_id: "tpl-tls",
      ca_id: "ca-int-2024",
      requester: "alice",
      status: "pending",
      csr_pem: approvalCsr,
      team_id: "data",
      requested_at: days(-1),
    },
    {
      id: "apr-0998",
      template_id: "tpl-mtls",
      ca_id: "ca-int-2024",
      requester: "bob",
      status: "approved",
      csr_pem: approvalCsr,
      team_id: "infra",
      requested_at: days(-3),
      decided_at: days(-2.9),
      decided_by: "secops-lead",
      issued_fingerprint: "sha256:aabbcc004",
    },
    {
      id: "apr-0997",
      template_id: "tpl-code",
      ca_id: "ca-int-2024",
      requester: "contractor-ci",
      status: "rejected",
      csr_pem: approvalCsr,
      requested_at: days(-5),
      decided_at: days(-4.8),
      decided_by: "secops-lead",
      reject_reason: "Code signing is limited to the release pipeline.",
    },
  ],
};

const pqcItems: PQCMigrationItem[] = [
  {
    fingerprint: "sha256:aabbcc003",
    common_name: "legacy.example.com",
    priority: "critical",
    reason:
      "RSA-2048 with SHA-1 signature; quantum-vulnerable and already weak",
    action: "Reissue on ML-DSA-65 or hybrid template",
    deadline: days(30),
  },
  {
    fingerprint: "sha256:aabbcc001",
    common_name: "api.internal.example.com",
    priority: "high",
    reason: "ECDSA P-256 on a long-lived public endpoint",
    action: "Move to hybrid ECDSA+ML-DSA at next renewal",
    deadline: days(180),
  },
  {
    fingerprint: "sha256:aabbcc002",
    common_name: "db.prod.example.com",
    priority: "medium",
    reason: "RSA-3072; quantum-vulnerable",
    action: "Add to a migration wave",
    deadline: days(365),
  },
  {
    fingerprint: "sha256:aabbcc004",
    common_name: "mesh.internal.example.com",
    priority: "low",
    reason: "Short-lived mesh certificate; rotates automatically",
    action: "Switch the mesh issuer template",
    deadline: days(540),
  },
];

export const pqcMigration: { data: PQCMigrationRoadmap } = {
  data: {
    generated_at: now,
    total_certs: 247,
    vulnerable: 198,
    migration_ready: 43,
    quantum_safe: 6,
    items: pqcItems,
  },
};

export const pqcWaves: { data: WaveProgress[] } = {
  data: [
    {
      id: "wave-1",
      name: "Wave 1 — public edge",
      status: "in_progress",
      owner: "platform",
      target_date: days(60),
      created_at: days(-20),
      members: [
        {
          fingerprint: "sha256:aabbcc001",
          common_name: "api.internal.example.com",
        },
        { fingerprint: "sha256:aabbcc003", common_name: "legacy.example.com" },
      ],
      total: 2,
      migrated: 1,
      progress_percent: 50,
    },
    {
      id: "wave-2",
      name: "Wave 2 — databases",
      status: "planned",
      owner: "data",
      target_date: days(200),
      created_at: days(-5),
      members: [
        { fingerprint: "sha256:aabbcc002", common_name: "db.prod.example.com" },
      ],
      total: 1,
      migrated: 0,
      progress_percent: 0,
    },
  ],
};

export const pqcCountdown: { data: PQCCountdownReport } = {
  data: {
    generated_at: now,
    org: "Example Corp",
    total_certs: 247,
    vulnerable: 198,
    migration_ready: 43,
    quantum_safe: 6,
    pqc_score_percent: 20,
    quantum_safe_percent: 2,
    status: "at_risk",
    deadlines: [
      {
        name: "CNSA 2.0: prefer PQC for new web/cloud",
        date: "2025-01-01T00:00:00Z",
        days_remaining: 0,
        passed: true,
      },
      {
        name: "CNSA 2.0: PQC exclusive for web/cloud",
        date: "2033-01-01T00:00:00Z",
        days_remaining: Math.round(
          (Date.parse("2033-01-01") - Date.now()) / 86_400_000,
        ),
        passed: false,
      },
      {
        name: "NIST IR 8547: deprecate RSA/ECC-112",
        date: "2030-12-31T00:00:00Z",
        days_remaining: Math.round(
          (Date.parse("2030-12-31") - Date.now()) / 86_400_000,
        ),
        passed: false,
      },
      {
        name: "NIST IR 8547: disallow RSA/ECC",
        date: "2035-12-31T00:00:00Z",
        days_remaining: Math.round(
          (Date.parse("2035-12-31") - Date.now()) / 86_400_000,
        ),
        passed: false,
      },
    ],
    trend: [90, 60, 30, 0].map((d, i) => ({
      captured_at: days(-d),
      pqc_score_percent: [8, 12, 16, 20][i],
    })),
    waves: pqcWaves.data,
  },
};

export const revocationActivity = {
  data: {
    generated_at: now,
    period_days: 30,
    total_revoked: 7,
    by_reason: {
      keyCompromise: 2,
      superseded: 3,
      cessationOfOperation: 2,
    },
    by_ca: {
      "Kryptkeeper Intermediate CA": 6,
      "External CA": 1,
    },
    timeline: Array.from({ length: 30 }, (_, i) => ({
      date: new Date(Date.now() - (29 - i) * 86_400_000)
        .toISOString()
        .slice(0, 10),
      count: Math.random() > 0.8 ? 1 : 0,
    })),
  },
};

export const changeAudit = {
  data: {
    generated_at: now,
    total_changes: 24,
    items: auditList.data.map((a) => ({
      ...a,
      change_summary: "Automated renewal via ACME ARI",
    })),
  },
};

export const complianceEvidence = {
  data: {
    generated_at: now,
    framework: "SOC2",
    controls: [
      {
        id: "CC6.7",
        title: "Encryption at rest and in transit",
        status: "pass",
        evidence: "247 certs issued via Kryptkeeper; 186 use ECDSA/PQC",
      },
      {
        id: "CC6.1",
        title: "Logical access controls",
        status: "pass",
        evidence: "RBAC enforced; audit log complete",
      },
      {
        id: "CC7.2",
        title: "System monitoring",
        status: "warning",
        evidence: "3 expired certificates detected",
      },
    ],
  },
};

// S-39: this fixture used to be a third shape — `items[]` with `risk`/`action`,
// no `groups`, no `summary` — matching neither the server nor the page. The
// page would have crashed against this mock too, which is how it survived: no
// test ever rendered it. Typed against the spec so it cannot drift again.
export const algorithmSunset: {
  data: components["schemas"]["AlgorithmSunsetReport"];
} = {
  data: {
    generated_at: now,
    total_certs: 238,
    groups: [
      {
        algorithm: "RSA-2048",
        deadline: "2030-12-31T00:00:00Z",
        standard: "CNSA 2.0 / NIST IR 8413",
        status: "sunset_2030",
        urgency: "medium",
        count: 52,
        recommended_replacement: "ML-DSA-65, ML-DSA-87, or Hybrid ECDSA+ML-DSA",
        fingerprints: [
          "cd57cafe8bca3b632ee294b9d49054177b4d1ac4ca43fbd0336b95e71257423e",
          "ba857132c7d711fdb79f9ff196eb2129d99f2e15739410e621050cf61fc98914",
        ],
      },
      {
        algorithm: "SHA-1",
        deadline: "2020-01-01T00:00:00Z",
        standard: "CA/B Forum Baseline Requirements",
        status: "banned",
        urgency: "immediate",
        count: 2,
        recommended_replacement: "SHA-256 or better",
        fingerprints: [
          "8f66b6ef1c967343cf53559a439d0e38d3ff4479cd68c4f69d7b091abaaadc0f",
        ],
      },
    ],
    summary: { banned_now: 2, sunset_2030: 52, compliant: 184 },
  },
};

export const discoverySummary = {
  data: {
    discovered_endpoints: 84,
    risky_endpoints: 12,
    last_scan: days(-1),
  },
};

export const discoveryEndpoints = {
  data: [
    {
      id: "ep-1",
      host: "api.internal.example.com",
      port: 443,
      status: "healthy",
      risk_score: 10,
      last_seen: days(-1),
      cert_fingerprint: "sha256:aabbcc001",
    },
    {
      id: "ep-2",
      host: "db.prod.example.com",
      port: 5432,
      status: "expiring",
      risk_score: 55,
      last_seen: days(-1),
      cert_fingerprint: "sha256:aabbcc002",
    },
    {
      id: "ep-3",
      host: "legacy.example.com",
      port: 443,
      status: "expired",
      risk_score: 90,
      last_seen: days(-7),
      cert_fingerprint: "sha256:aabbcc003",
    },
  ],
  total: 84,
  page: 1,
  page_size: 20,
};

// docs/openapi.yaml's DiscoveryScanJob was corrected to the real response
// shape by S-22/G-84 -- now genuinely satisfiable. Envelope is
// {data: {scan_jobs: [...]}, meta}, matching handlers_discovery.go's actual
// nesting (not a bare array under data, unlike most other list endpoints).
export const discoveryScanJobs = {
  data: {
    scan_jobs: [
      {
        id: "scan-1700000000000000001",
        scan_type: "full",
        target: "10.0.0.0/24",
        status: "completed",
        queued_at: days(-1),
      },
      {
        id: "scan-1700000000000000002",
        scan_type: "targeted",
        target: "10.0.1.0/24",
        status: "running",
        queued_at: now,
      },
    ] satisfies components["schemas"]["DiscoveryScanJob"][],
  },
  meta: paginationMeta(2),
};

export const notificationsSummary = {
  data: { pending_notifications: 5, rules_count: 3 },
};

export const notificationDeliveries = {
  data: [
    {
      id: "nd-1",
      rule_id: "rule-1",
      channel: "slack",
      status: "delivered",
      sent_at: days(-1),
      message: "Certificate expiring: db.prod.example.com in 22 days",
    },
    {
      id: "nd-2",
      rule_id: "rule-1",
      channel: "email",
      status: "pending",
      sent_at: null,
      message: "Certificate expired: legacy.example.com",
    },
  ],
  total: 2,
};

export const notificationRules = {
  data: [
    {
      id: "rule-1",
      name: "Expiry Warning",
      threshold_days: 30,
      channel: "slack",
      target: "#pki-alerts",
      enabled: true,
      created_at: days(-200),
    },
  ] satisfies components["schemas"]["NotificationRule"][],
};

const templateItems: components["schemas"]["TemplateRecord"][] = [
  {
    id: "tpl-tls",
    name: "tls-server",
    display_name: "TLS Server",
    validity_period: "P90D",
    key_usage: ["digitalSignature", "keyEncipherment"],
    extended_key_usage: ["serverAuth"],
    allowed_algorithms: ["ECDSA-P256"],
    auto_enroll: true,
    active: true,
    revision: 3,
  },
  {
    id: "tpl-mtls",
    name: "mtls-client",
    display_name: "mTLS Client",
    validity_period: "P365D",
    key_usage: ["digitalSignature"],
    extended_key_usage: ["clientAuth"],
    allowed_algorithms: ["ECDSA-P256"],
    auto_enroll: false,
    active: true,
    revision: 1,
  },
  {
    id: "tpl-code",
    name: "code-signing",
    display_name: "Code Signing",
    validity_period: "P365D",
    key_usage: ["digitalSignature"],
    extended_key_usage: ["codeSigning"],
    allowed_algorithms: ["ECDSA-P384"],
    auto_enroll: false,
    active: true,
    revision: 2,
  },
];

export const templates = {
  data: templateItems.map((tpl, i) => ({
    ...tpl,
    issued_count: [142, 78, 27][i],
  })),
  meta: paginationMeta(3),
};

export const users = {
  data: [
    {
      id: "u-1",
      email: "admin@kryptkeeper.local",
      role: "admin",
      status: "active",
      created_at: days(-365),
    },
    {
      id: "u-2",
      email: "ops@kryptkeeper.local",
      role: "operator",
      status: "active",
      created_at: days(-180),
    },
    {
      id: "u-3",
      email: "viewer@kryptkeeper.local",
      role: "viewer",
      status: "active",
      created_at: days(-30),
    },
  ] satisfies components["schemas"]["UserRecord"][],
};

export const actionsHistory = {
  data: auditList.data.map((a) => ({
    ...a,
    id: `h-${a.id}`,
    status: "success",
  })),
  total: 4,
};

export const agents = {
  agents: [
    {
      id: "agent-renewal",
      name: "Renewal Scheduler",
      type: "linux",
      registered_at: days(-200),
      last_seen: days(-1),
      status: "active",
      inventory_count: 42,
    },
    {
      id: "agent-siem",
      name: "SIEM Router",
      type: "linux",
      registered_at: days(-150),
      last_seen: now,
      status: "active",
      inventory_count: 18,
    },
  ] satisfies components["schemas"]["AgentInfo"][],
};

export const searchResults = (q: string) => ({
  data: [
    ...certificates.data
      .filter(
        (c) =>
          c.common_name?.includes(q) ||
          c.fingerprint_sha256?.includes(q) ||
          c.owner_team?.includes(q),
      )
      .map((c) => ({
        type: "certificate",
        id: c.fingerprint_sha256,
        label: c.common_name,
      })),
    ...cas.data
      .filter((c) => c.name?.toLowerCase().includes(q.toLowerCase()))
      .map((c) => ({ type: "ca", id: c.id, label: c.name })),
  ],
});

// W20-21: delivery plugins for the dev UI.
export const deliveryPlugins = {
  data: [
    {
      id: "kryptkeeper.example-device",
      enabled_version: "1.0.0",
      versions: [
        {
          plugin_id: "kryptkeeper.example-device",
          version: "1.0.0",
          sha256:
            "3f1c9a0b7e2d4c6f8a1b3d5e7f9a0c2e4b6d8f0a1c3e5b7d9f1a3c5e7b9d1f3a",
          trust_tier: "community",
          capability_tier: "critical",
          status: "enabled",
          manifest: {
            api_version: "kryptkeeper.delivery/v1",
            id: "kryptkeeper.example-device",
            name: "Example HTTPS device",
            version: "1.0.0",
            publisher: "Kryptkeeper Authors",
            source:
              "https://github.com/bpmforge/kryptkeeper/tree/main/plugins/example",
            artifact: {
              file: "plugin.wasm",
              sha256:
                "3f1c9a0b7e2d4c6f8a1b3d5e7f9a0c2e4b6d8f0a1c3e5b7d9f1a3c5e7b9d1f3a",
            },
            capabilities: {
              receive_private_key: true,
              network: { hosts_from_credential: "base_url" },
              tls_verify: true,
            },
            credential_schema: {
              base_url: { type: "url", required: true },
              token: { type: "string", required: true, secret: true },
            },
            target_schema: { listener: { type: "string", required: true } },
          },
          installed_by: "admin",
          installed_at: "2026-10-08T12:00:00Z",
          approved_by: "second-admin",
          approved_at: "2026-10-08T12:05:00Z",
        },
      ],
    },
  ],
};
