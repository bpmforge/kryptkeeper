# Kryptkeeper — Database Design

**Version:** 2.0
**Date:** 2026-07-28
**Phase:** 3 — Design

This document specifies the complete data model for Kryptkeeper V1. It documents all 35 tables across 29 migrations in the PostgreSQL schema (primary), with SQLite compatibility notes. All schema decisions are grounded in the data model defined in RESEARCH_FINDINGS.md §7 and the requirements in SRS.md.

## Table Count Reconciliation

The schema contains **35 total tables** across **29 migrations**:
- **29 main tables** — core domain entities and structures
- **6 join/link tables** — team_members, template_tenants, ca_tenants, acme_account_eab, migration_wave_members, certificate_endpoints

The original ticket S-02 estimates referred to the 29 main tables; this document documents all 35, including join tables, for complete schema coverage.

---

## Table of Contents

### Wave W1: Foundations & Identity (000001)
1. [users](#1-users)
2. [notification_policies](#2-notification_policies)
3. [teams](#3-teams)
4. [team_members](#4-team_members) — join table
5. [api_keys](#5-api_keys)

### Wave W2: Templates, CAs & Certificates (000002)
6. [certificate_templates](#6-certificate_templates)
7. [certificate_authorities](#7-certificate_authorities)
8. [certificates](#8-certificates)

### Wave W3: Discovery & Endpoints (000003)
9. [scan_jobs](#9-scan_jobs)
10. [endpoints](#10-endpoints)
11. [scan_results](#11-scan_results)
12. [certificate_endpoints](#12-certificate_endpoints) — join table, dedup/staleness wired (R-D2)

### Wave W4: Audit Log (000004)
13. [audit_log](#13-audit_log) — append-only, partitioned

### Waves W5–W6: Indexes & Extensions (000005–000007)
*No new tables; indexes and seed data*

### Wave W8: Notification Deliveries (000008)
14. [notification_deliveries](#14-notification_deliveries)

### Wave W9–W12: CA Enhancements (000009–000012)
*Column additions to existing tables*

### Wave W10: Notification Rules (000010)
15. [notification_rules](#15-notification_rules)

### Wave W13: Cert Approval (000013)
16. [cert_approval_requests](#16-cert_approval_requests)

### Wave W14: Posture (000014)
17. [posture_snapshots](#17-posture_snapshots)

### Wave W15: Agent Store (000015)
18. [agents](#18-agents)
19. [agent_inventory](#19-agent_inventory)
20. [agent_endpoints](#20-agent_endpoints)
21. [agent_tasks](#21-agent_tasks)
22. [agent_results](#22-agent_results)

### Wave W16: Evidence (000016)
23. [evidence_schedules](#23-evidence_schedules)

### Wave W17: Migration Waves (000017)
24. [migration_waves](#24-migration_waves)
25. [migration_wave_members](#25-migration_wave_members) — join table

### Wave W18: Pending Actions (000018)
26. [pending_actions](#26-pending_actions)

### Wave W19: Multi-Tenancy (000019–000025)
27. [tenants](#27-tenants)
28. [ca_tenants](#28-ca_tenants) — join table
29. [template_tenants](#29-template_tenants) — join table

### Wave W22: Finding Exceptions (000022)
30. [finding_exceptions](#30-finding_exceptions)

### Wave W26: ACME EAB (000026)
31. [acme_eab_keys](#31-acme_eab_keys)
32. [acme_account_eab](#32-acme_account_eab) — join table

### Wave W27: CA Key Rotations (000027)
33. [ca_key_rotations](#33-ca_key_rotations)

### Wave W28: Managed Targets (000028)
34. [managed_targets](#34-managed_targets)

### Wave W29: Outbound Credentials (000029)
35. [outbound_credentials](#35-outbound_credentials)

---

## 1. users

Identity and access control for dashboard users. Authentication via OIDC (SSO) or local password.

```sql
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               VARCHAR(255) NOT NULL UNIQUE,
    display_name        VARCHAR(255),
    role                VARCHAR(30) NOT NULL DEFAULT 'pki-viewer'
                        CHECK (role IN (
                            'pki-admin',
                            'pki-operator',
                            'pki-viewer',
                            'pki-auditor',
                            'discovery-operator',
                            'service-account'
                        )),
    oidc_subject        VARCHAR(255),
    oidc_issuer         VARCHAR(255),
    password_hash       VARCHAR(255),
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_oidc_unique UNIQUE (oidc_subject, oidc_issuer)
);

CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_user_active ON users(active);
```

**Key constraints:**
- Email uniqueness enforced across all users
- OIDC pair uniqueness for federated identity
- Roles restrict API access and UI operations

---

## 2. notification_policies

Defines alert thresholds and routing rules for each team.

```sql
CREATE TABLE notification_policies (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    VARCHAR(255) NOT NULL,
    expiry_thresholds       JSONB NOT NULL DEFAULT '[90, 30, 7]',
    alert_on_risk_flags     TEXT[] NOT NULL DEFAULT '{"EXPIRED","EXPIRING_7_DAYS","WEAK_KEY"}',
    alert_cooldown_hours    INTEGER NOT NULL DEFAULT 24,
    active                  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

## 3. teams

Organizational units for certificate ownership, alert routing, and access control.

```sql
CREATE TABLE teams (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    VARCHAR(255) NOT NULL UNIQUE,
    slug                    VARCHAR(100) NOT NULL UNIQUE,
    description             TEXT,
    notification_policy_id  UUID REFERENCES notification_policies(id),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_teams_notification_policy ON teams(notification_policy_id);
```

---

## 4. team_members

Join table linking users to teams with per-team roles (owner, member).

```sql
CREATE TABLE team_members (
    team_id                 UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id                 UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role                    VARCHAR(20) NOT NULL DEFAULT 'member'
                            CHECK (role IN ('owner', 'member')),
    added_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, user_id)
);

CREATE INDEX idx_team_members_user ON team_members(user_id);
```

---

## 5. api_keys

Machine-to-machine authentication. Keys are hashed; full value shown only at creation time.

```sql
CREATE TABLE api_keys (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                    VARCHAR(255) NOT NULL,
    kid                     VARCHAR(32) NOT NULL UNIQUE,
    key_hash                CHAR(64) NOT NULL UNIQUE,
    key_prefix              VARCHAR(16) NOT NULL,
    scopes                  TEXT[] NOT NULL DEFAULT '{"read:certificates"}',
    expires_at              TIMESTAMPTZ,
    last_used_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (key_prefix LIKE 'kk_%')
);

CREATE INDEX idx_api_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_key_user ON api_keys(user_id);
CREATE INDEX idx_api_key_kid ON api_keys(kid);
```

---

## 6. certificate_templates

Certificate policies for issuance. Mirrors ADCS template concepts for V2 forward compatibility.

```sql
CREATE TABLE certificate_templates (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    VARCHAR(255) NOT NULL UNIQUE,
    display_name            VARCHAR(255) NOT NULL,
    oid                     VARCHAR(128),
    allowed_algorithms      TEXT[] NOT NULL DEFAULT '{RSA,ECDSA,Ed25519}',
    min_key_size            INTEGER NOT NULL DEFAULT 2048,
    key_usage               TEXT[] NOT NULL DEFAULT '{}',
    extended_key_usage      TEXT[] NOT NULL DEFAULT '{}',
    validity_period         INTERVAL NOT NULL DEFAULT '365 days',
    renewal_overlap         INTERVAL NOT NULL DEFAULT '30 days',
    max_validity_period     INTERVAL,
    subject_requirements    JSONB NOT NULL DEFAULT '{}',
    enrollment_permissions  JSONB NOT NULL DEFAULT '{"allow_all": true}',
    issuance_requirements   JSONB NOT NULL DEFAULT '{}',
    auto_enroll             BOOLEAN NOT NULL DEFAULT FALSE,
    active                  BOOLEAN NOT NULL DEFAULT TRUE,
    schema_version          SMALLINT NOT NULL DEFAULT 2,
    revision                INTEGER NOT NULL DEFAULT 1,
    ad_sync_status          VARCHAR(20) DEFAULT 'not_synced'
                            CHECK (ad_sync_status IN ('not_synced', 'synced', 'sync_error', 'pending')),
    ad_last_synced_at       TIMESTAMPTZ,
    description             TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_template_active ON certificate_templates(active);
CREATE INDEX idx_template_oid ON certificate_templates(oid);
```

---

## 7. certificate_authorities

The CA hierarchy. Self-referential parent_ca_id supports arbitrary depth.

```sql
CREATE TABLE certificate_authorities (
    id                            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                          VARCHAR(255) NOT NULL,
    display_name                  VARCHAR(255) NOT NULL,
    type                          VARCHAR(20) NOT NULL
                                  CHECK (type IN ('root', 'issuing', 'external')),
    certificate_fingerprint_sha256 VARCHAR(64),
    parent_ca_id                  UUID REFERENCES certificate_authorities(id),
    key_storage_type              VARCHAR(20) NOT NULL
                                  CHECK (key_storage_type IN ('software', 'pkcs11', 'cloud_kms', 'external')),
    pkcs11_library_path           VARCHAR(512),
    pkcs11_token_label            VARCHAR(255),
    pkcs11_key_label              VARCHAR(255),
    key_file_path                 VARCHAR(512),
    cloud_kms_key_id              VARCHAR(512),
    status                        VARCHAR(20) NOT NULL DEFAULT 'active'
                                  CHECK (status IN ('active', 'suspended', 'revoked', 'expired')),
    crl_distribution_points       TEXT[],
    ocsp_service_url              TEXT,
    cert_pem                      TEXT,
    key_id                        TEXT,
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ca_root_has_no_parent CHECK (type != 'root' OR parent_ca_id IS NULL),
    CONSTRAINT ca_issuing_has_parent CHECK (type NOT IN ('issuing') OR parent_ca_id IS NOT NULL),
    CONSTRAINT ca_certificate_fingerprint_fk FOREIGN KEY (certificate_fingerprint_sha256)
        REFERENCES certificates(fingerprint_sha256)
);

CREATE INDEX idx_ca_parent ON certificate_authorities(parent_ca_id);
CREATE INDEX idx_ca_status ON certificate_authorities(status);
```

**Added columns (migration 000009):**
- cert_pem — CA certificate in PEM format
- key_id — reference to stored key material

---

## 8. certificates

Central table for all certificates. fingerprint_sha256 is the deduplication key.

```sql
CREATE TABLE certificates (
    fingerprint_sha256      VARCHAR(64) PRIMARY KEY,
    serial_number           VARCHAR(128) NOT NULL,
    subject_dn              TEXT NOT NULL,
    common_name             VARCHAR(255),
    subject_alt_names       TEXT[],
    issuer_dn               TEXT NOT NULL,
    issuer_cn               VARCHAR(255),
    ca_id                   UUID REFERENCES certificate_authorities(id),
    template_id             UUID REFERENCES certificate_templates(id),
    team_id                 UUID REFERENCES teams(id),
    valid_from              TIMESTAMPTZ NOT NULL,
    valid_until             TIMESTAMPTZ NOT NULL,
    public_key_algorithm    VARCHAR(20) NOT NULL
                            CHECK (public_key_algorithm IN ('RSA', 'ECDSA', 'Ed25519', 'ML-DSA')),
    key_size_bits           INTEGER,
    signature_algorithm     VARCHAR(50) NOT NULL,
    extended_key_usage      TEXT[],
    key_usage               TEXT[],
    chain_complete          BOOLEAN NOT NULL DEFAULT FALSE,
    chain_trusted           BOOLEAN NOT NULL DEFAULT FALSE,
    pqc_vulnerable          BOOLEAN NOT NULL DEFAULT FALSE,
    risk_score              SMALLINT NOT NULL DEFAULT 0
                            CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_flags              TEXT[] NOT NULL DEFAULT '{}',
    grade                   CHAR(1) NOT NULL DEFAULT 'A'
                            CHECK (grade IN ('A', 'B', 'C', 'D', 'F')),
    renewal_method          VARCHAR(20)
                            CHECK (renewal_method IN ('acme', 'est', 'scep', 'api', 'manual', NULL)),
    renewal_status          VARCHAR(20) DEFAULT 'active'
                            CHECK (renewal_status IN ('active', 'renewed', 'expired', 'revoked')),
    predecessor_fingerprint VARCHAR(64) REFERENCES certificates(fingerprint_sha256),
    successor_fingerprint   VARCHAR(64) REFERENCES certificates(fingerprint_sha256),
    revoked_at              TIMESTAMPTZ,
    revocation_reason       SMALLINT,
    source                  VARCHAR(20) NOT NULL DEFAULT 'api'
                            CHECK (source IN ('api', 'acme', 'est', 'scep', 'discovery_network',
                                             'discovery_ssh', 'discovery_winrm', 'discovery_agent',
                                             'discovery_cloud', 'discovery_k8s', 'ct_log', 'import')),
    raw_cert_b64            TEXT,
    owner_email             TEXT,
    owner_team              TEXT,
    service_name            TEXT,
    labels                  JSONB NOT NULL DEFAULT '[]',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_cert_serial_ca ON certificates(serial_number, ca_id);
CREATE INDEX idx_cert_valid_until ON certificates(valid_until);
CREATE INDEX idx_cert_risk_score ON certificates(risk_score DESC);
CREATE INDEX idx_cert_grade ON certificates(grade);
CREATE INDEX idx_cert_renewal_status ON certificates(renewal_status);
CREATE INDEX idx_cert_team ON certificates(team_id);
CREATE INDEX idx_cert_ca ON certificates(ca_id);
CREATE INDEX idx_cert_common_name ON certificates(common_name);
CREATE INDEX idx_cert_sans ON certificates USING GIN (subject_alt_names);
CREATE INDEX idx_cert_risk_flags ON certificates USING GIN (risk_flags);
CREATE INDEX idx_certs_owner_email ON certificates(owner_email) WHERE owner_email IS NOT NULL;
CREATE INDEX idx_certs_owner_team ON certificates(owner_team) WHERE owner_team IS NOT NULL;
CREATE INDEX idx_certs_service ON certificates(service_name) WHERE service_name IS NOT NULL;
```

**Added columns (migration 000012):**
- owner_email — primary owner for renewal notifications
- owner_team — owning team for RBAC and reporting
- service_name — workload or service using this cert
- labels — arbitrary key=value tags for filtering

---

## 9. scan_jobs

Tracks each discovery scan invocation — scheduled or manual.

```sql
CREATE TABLE scan_jobs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type                VARCHAR(30) NOT NULL
                        CHECK (type IN ('network', 'ssh', 'winrm', 'cloud_acm',
                                       'cloud_azure_kv', 'cloud_gcp_cm', 'kubernetes',
                                       'ct_log', 'agent', 'full')),
    connector           VARCHAR(50) NOT NULL,
    scope               JSONB NOT NULL DEFAULT '{}',
    status              VARCHAR(20) NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'running', 'complete', 'failed', 'cancelled')),
    error_message       TEXT,
    results_summary     JSONB,
    created_by          UUID REFERENCES users(id),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_status ON scan_jobs(status);
CREATE INDEX idx_scan_type ON scan_jobs(type);
CREATE INDEX idx_scan_created ON scan_jobs(created_at DESC);
```

---

## 10. endpoints

Network locations where certificates were discovered. Dedup key: (ip_address, port, COALESCE(sni_name, '')).

```sql
CREATE TABLE endpoints (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address          INET NOT NULL,
    hostname            VARCHAR(255),
    port                INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol            VARCHAR(20) NOT NULL DEFAULT 'tls'
                        CHECK (protocol IN ('tls', 'ldaps', 'imaps', 'smtps', 'pop3s',
                                           'ftps', 'rdps', 'kubernetes', 'other')),
    tls_versions        TEXT[],
    cipher_suites       TEXT[],
    sni_name            VARCHAR(255),
    is_default_cert     BOOLEAN NOT NULL DEFAULT TRUE,
    last_scan_job_id    UUID REFERENCES scan_jobs(id),
    last_scanned        TIMESTAMPTZ,
    first_discovered    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tags                TEXT[],
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT endpoint_unique_network_identity
        UNIQUE (ip_address, port, COALESCE(sni_name, ''))
);

CREATE INDEX idx_endpoint_hostname ON endpoints(hostname);
CREATE INDEX idx_endpoint_ip ON endpoints(ip_address);
CREATE INDEX idx_endpoint_last_scanned ON endpoints(last_scanned);
CREATE UNIQUE INDEX idx_endpoint_unique_network_identity
    ON endpoints(ip_address, port, COALESCE(sni_name, ''));
```

---

## 11. scan_results

Individual findings from a scan job. Raw data preserved for reprocessing.

```sql
CREATE TABLE scan_results (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id             UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    result_type             VARCHAR(30) NOT NULL
                            CHECK (result_type IN ('certificate', 'endpoint_cert', 'file_cert',
                                                   'error', 'timeout', 'filtered')),
    target                  VARCHAR(512) NOT NULL,
    certificate_fingerprint VARCHAR(64),
    data                    JSONB NOT NULL DEFAULT '{}',
    error_detail            TEXT,
    discovered_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_result_scan_job ON scan_results(scan_job_id);
CREATE INDEX idx_result_fingerprint ON scan_results(certificate_fingerprint);
CREATE INDEX idx_result_type ON scan_results(result_type);
```

---

## 12. certificate_endpoints

Many-to-many join between certificates and endpoints. **Dedup/staleness columns wired (R-D2, W2-05).**

```sql
CREATE TABLE certificate_endpoints (
    certificate_fingerprint VARCHAR(64) NOT NULL
                            REFERENCES certificates(fingerprint_sha256) ON DELETE CASCADE,
    endpoint_id             UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    first_seen              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    currently_active        BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (certificate_fingerprint, endpoint_id)
);

CREATE INDEX idx_ce_endpoint ON certificate_endpoints(endpoint_id);
CREATE INDEX idx_ce_cert ON certificate_endpoints(certificate_fingerprint);
CREATE INDEX idx_ce_active ON certificate_endpoints(currently_active);
```

**Dedup/Staleness Implementation (WIRED, R-D2):**
- `last_seen` — updated on every scan where the cert is re-observed
- `currently_active` — set to false when cert is not re-observed in a re-scan (R-D2 criterion met, W2-05 complete)
- Endpoints deduplicated on (ip_address, port, COALESCE(sni_name, '')) before join entry creation

---

## 13. audit_log

Append-only event log. Partitioned by month. No UPDATE/DELETE allowed.

```sql
CREATE TABLE audit_log (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action              VARCHAR(100) NOT NULL,
    actor_type          VARCHAR(20) NOT NULL
                        CHECK (actor_type IN ('user', 'api_key', 'system', 'agent')),
    actor_id            VARCHAR(128) NOT NULL,
    actor_email         VARCHAR(255),
    resource_type       VARCHAR(50) NOT NULL,
    resource_id         VARCHAR(128) NOT NULL,
    client_ip           INET,
    trace_id            VARCHAR(64),
    details             JSONB NOT NULL DEFAULT '{}',
    diff                JSONB,
    outcome             VARCHAR(10) NOT NULL DEFAULT 'success'
                        CHECK (outcome IN ('success', 'failure', 'denied')),
    source_ip           TEXT,
    user_agent          TEXT,
    session_id          TEXT,
    change_summary      TEXT,
    tenant              TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_actor ON audit_log(actor_id);
CREATE INDEX idx_audit_source_ip ON audit_log(source_ip) WHERE source_ip IS NOT NULL;
```

**Security constraints:**
- Row-level security prevents UPDATE/DELETE
- Partitioned by month for query performance at scale
- Retention: 7 years (configurable)

**Added columns (migration 000011):**
- source_ip, user_agent, session_id — SOC 2/PCI DSS compliance
- change_summary — human-readable mutation summary

**Added columns (migration 000021):**
- tenant — multi-tenancy scoping

---

## 14. notification_deliveries

Delivery log for alerts sent to channels (email, Slack, etc.).

```sql
CREATE TABLE notification_deliveries (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    notification_policy_id  UUID REFERENCES notification_policies(id),
    channel                 VARCHAR(20) NOT NULL
                            CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook')),
    target                  VARCHAR(320) NOT NULL,
    subject                 VARCHAR(500),
    message                 TEXT,
    status                  VARCHAR(20) NOT NULL DEFAULT 'queued'
                            CHECK (status IN ('queued', 'sending', 'sent', 'failed',
                                            'acknowledged', 'retrying')),
    error_detail            TEXT,
    retry_of_id             UUID REFERENCES notification_deliveries(id),
    triggered_by            VARCHAR(50) NOT NULL DEFAULT 'system',
    created_by              UUID REFERENCES users(id),
    queued_at               TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at            TIMESTAMPTZ,
    acknowledged_at         TIMESTAMPTZ,
    acknowledged_by         VARCHAR(200),
    acknowledged_note       VARCHAR(500),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_notif_delivery_status ON notification_deliveries(status);
CREATE INDEX idx_notif_delivery_channel ON notification_deliveries(channel);
CREATE INDEX idx_notif_delivery_queued ON notification_deliveries(queued_at DESC);
CREATE INDEX idx_notif_delivery_policy ON notification_deliveries(notification_policy_id);
CREATE INDEX idx_notif_delivery_retry ON notification_deliveries(retry_of_id);
```

---

## 15. notification_rules

Per-channel alert rules for threshold-based notifications.

```sql
CREATE TABLE notification_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    threshold_days  INTEGER NOT NULL CHECK (threshold_days > 0),
    channel         TEXT NOT NULL CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook')),
    target          TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notif_rules_enabled ON notification_rules(enabled);
CREATE INDEX idx_notif_rules_channel ON notification_rules(channel);
```

---

## 16. cert_approval_requests

Approval workflow for certificate requests. CSR-based issuance with optional multi-person approval.

```sql
CREATE TABLE cert_approval_requests (
    id                  TEXT PRIMARY KEY,
    template_id         TEXT NOT NULL,
    ca_id               TEXT NOT NULL,
    requester           TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending',
    csr_pem             TEXT NOT NULL,
    team_id             TEXT,
    requested_at        TEXT NOT NULL,
    decided_at          TEXT,
    decided_by          TEXT,
    reject_reason       TEXT,
    issued_fingerprint  TEXT
);

CREATE INDEX idx_approval_requests_status ON cert_approval_requests(status);
CREATE INDEX idx_approval_requests_template ON cert_approval_requests(template_id);
CREATE INDEX idx_approval_requests_requester ON cert_approval_requests(requester);
```

---

## 17. posture_snapshots

Historical posture metrics for reporting and trending.

```sql
CREATE TABLE posture_snapshots (
    id                  TEXT PRIMARY KEY,
    captured_at         TEXT NOT NULL,
    total_certs         INTEGER NOT NULL,
    pqc_score_percent   INTEGER NOT NULL,
    automation_percent  INTEGER NOT NULL,
    risk_critical       INTEGER NOT NULL,
    risk_high           INTEGER NOT NULL,
    risk_medium         INTEGER NOT NULL,
    risk_low            INTEGER NOT NULL,
    expired             INTEGER NOT NULL,
    expiring_47d        INTEGER NOT NULL,
    report_json         TEXT NOT NULL
);

CREATE INDEX idx_posture_snapshots_captured ON posture_snapshots(captured_at);
```

---

## 18. agents

Remote agents for certificate inventory and renewal.

```sql
CREATE TABLE agents (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL,
    token           TEXT NOT NULL,
    token_hash      TEXT NOT NULL DEFAULT '',
    registered_at   TEXT NOT NULL,
    last_seen       TEXT,
    inventory_count INTEGER NOT NULL DEFAULT 0
);
```

---

## 19. agent_inventory

Certificate inventory reported by agents.

```sql
CREATE TABLE agent_inventory (
    agent_id         TEXT NOT NULL,
    fingerprint      TEXT NOT NULL,
    subject          TEXT,
    issuer           TEXT,
    not_before       TEXT,
    not_after        TEXT,
    source           TEXT,
    auto_renewable   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_agent_inventory_agent ON agent_inventory(agent_id);
```

---

## 20. agent_endpoints

Endpoint/server definitions for agents to manage.

```sql
CREATE TABLE agent_endpoints (
    agent_id        TEXT NOT NULL,
    server_type     TEXT,
    cert_path       TEXT,
    key_path        TEXT,
    server_name     TEXT,
    listen_port     INTEGER,
    config_path     TEXT
);

CREATE INDEX idx_agent_endpoints_agent ON agent_endpoints(agent_id);
```

---

## 21. agent_tasks

Renewal and deployment tasks assigned to agents.

```sql
CREATE TABLE agent_tasks (
    task_id            TEXT PRIMARY KEY,
    agent_id           TEXT NOT NULL,
    fingerprint        TEXT,
    subject            TEXT,
    action             TEXT,
    ca_url             TEXT,
    not_after          TEXT,
    server_type        TEXT,
    cert_path          TEXT,
    key_path           TEXT,
    reload_method      TEXT,
    verify_host_port   TEXT
);

CREATE INDEX idx_agent_tasks_agent ON agent_tasks(agent_id);
```

---

## 22. agent_results

Outcome and status reports from agent task execution.

```sql
CREATE TABLE agent_results (
    id                  TEXT PRIMARY KEY,
    agent_id            TEXT NOT NULL,
    task_id             TEXT,
    fingerprint         TEXT,
    outcome             TEXT,
    served_fingerprint  TEXT,
    rolled_back         INTEGER NOT NULL DEFAULT 0,
    detail              TEXT,
    reported_at         TEXT NOT NULL
);

CREATE INDEX idx_agent_results_agent ON agent_results(agent_id);
```

---

## 23. evidence_schedules

Schedule and cadence for compliance evidence generation (e.g., SOC 2 reports).

```sql
CREATE TABLE evidence_schedules (
    id              TEXT PRIMARY KEY,
    framework       TEXT NOT NULL,
    cadence         TEXT NOT NULL,
    recipients      TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    last_sent_at    TEXT,
    created_at      TEXT NOT NULL
);

CREATE INDEX idx_evidence_schedules_enabled ON evidence_schedules(enabled);
```

---

## 24. migration_waves

Groups of certificates to migrate together as a batch.

```sql
CREATE TABLE migration_waves (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    owner       TEXT,
    target_date TEXT,
    status      TEXT NOT NULL DEFAULT 'proposed',
    created_at  TEXT NOT NULL
);
```

---

## 25. migration_wave_members

Join table linking certificates to waves.

```sql
CREATE TABLE migration_wave_members (
    wave_id     TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    common_name TEXT
);

CREATE INDEX idx_wave_members_wave ON migration_wave_members(wave_id);
CREATE INDEX idx_wave_members_fp ON migration_wave_members(fingerprint);
```

---

## 26. pending_actions

Proposal queue for actions requiring multi-person approval (e.g., CA revocation).

```sql
CREATE TABLE pending_actions (
    id              TEXT PRIMARY KEY,
    action_type     TEXT NOT NULL,
    params_json     TEXT NOT NULL,
    proposed_by     TEXT NOT NULL,
    rationale       TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    approved_by     TEXT,
    decided_at      TEXT,
    result_json     TEXT,
    tenant          TEXT NOT NULL DEFAULT 'default',
    created_at      TEXT NOT NULL
);

CREATE INDEX idx_pending_actions_status ON pending_actions(status);
```

---

## 27. tenants

Multi-tenancy isolation boundaries. Each tenant is a separate logical instance.

```sql
CREATE TABLE tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
```

---

## 28. ca_tenants

Join table: scopes CAs to tenants.

```sql
CREATE TABLE ca_tenants (
    ca_id       TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL
);

CREATE INDEX idx_ca_tenants_tenant ON ca_tenants(tenant_id);
```

---

## 29. template_tenants

Join table: scopes templates to tenants.

```sql
CREATE TABLE template_tenants (
    template_id TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL
);

CREATE INDEX idx_template_tenants_tenant ON template_tenants(tenant_id);
```

---

## 30. finding_exceptions

Accepted-risk exceptions for security findings. Auto-expires and reopens on cert re-issue.

```sql
CREATE TABLE finding_exceptions (
    id                  TEXT PRIMARY KEY,
    target_type         TEXT NOT NULL CHECK (target_type IN ('certificate', 'ca')),
    target_id           TEXT NOT NULL,
    finding_code        TEXT NOT NULL,
    justification_code  TEXT NOT NULL
                        CHECK (justification_code IN (
                            'risk_accepted', 'compensating_control',
                            'false_positive', 'planned_remediation', 'not_applicable'
                        )),
    justification_note  TEXT,
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL
);

CREATE INDEX idx_finding_exceptions_target ON finding_exceptions(target_type, target_id);
CREATE INDEX idx_finding_exceptions_expires ON finding_exceptions(expires_at);
```

---

## 31. acme_eab_keys

ACME External Account Binding keys for high-assurance issuance.

```sql
CREATE TABLE acme_eab_keys (
    kid         TEXT PRIMARY KEY,
    mac_key     TEXT NOT NULL,
    disabled    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
```

---

## 32. acme_account_eab

Join table: binds ACME accounts to EAB keys.

```sql
CREATE TABLE acme_account_eab (
    account_id  TEXT PRIMARY KEY,
    kid         TEXT NOT NULL,
    bound_at    TEXT NOT NULL
);
```

---

## 33. ca_key_rotations

Ledger of CA key re-keying events (rotation, cross-signing).

```sql
CREATE TABLE ca_key_rotations (
    id          TEXT PRIMARY KEY,
    ca_id       UUID NOT NULL REFERENCES certificate_authorities(id),
    old_key_id  TEXT NOT NULL,
    new_key_id  TEXT NOT NULL,
    new_cert_sn TEXT NOT NULL,
    method      TEXT NOT NULL CHECK (method IN ('rekey_reissue', 'cross_sign')),
    rotated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ca_key_rotations_ca_id ON ca_key_rotations(ca_id);
CREATE INDEX idx_ca_key_rotations_rotated_at ON ca_key_rotations(rotated_at DESC);
```

---

## 34. managed_targets

Fleet of servers/services to manage (deployment targets for cert renewal).

```sql
CREATE TABLE managed_targets (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    host            TEXT NOT NULL,
    discovery_mode  TEXT NOT NULL DEFAULT 'agent'
                    CHECK (discovery_mode IN ('agent', 'network', 'cloud', 'none')),
    install_mode    TEXT NOT NULL DEFAULT 'agent'
                    CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'cloud', 'acme')),
    renewal_method  TEXT NOT NULL DEFAULT 'acme'
                    CHECK (renewal_method IN ('acme', 'est', 'scep', 'manual')),
    credential_ref  TEXT,
    schedule        TEXT,
    tenant          TEXT NOT NULL DEFAULT 'default',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX idx_managed_targets_tenant ON managed_targets(tenant);
CREATE INDEX idx_managed_targets_host ON managed_targets(host);
```

---

## 35. outbound_credentials

Encrypted credential store for SSH keys, API tokens, cloud IAM credentials.

```sql
CREATE TABLE outbound_credentials (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    credential_type TEXT NOT NULL
                    CHECK (credential_type IN ('ssh_key', 'api_token', 'cloud_iam')),
    tenant          TEXT NOT NULL DEFAULT 'default',
    envelope        TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX idx_outbound_credentials_tenant ON outbound_credentials(tenant);
```

---

## Index Strategy

| Table | Index | Columns | Purpose |
|-------|-------|---------|---------|
| certificates | idx_cert_valid_until | (valid_until) | Expiry dashboard queries |
| certificates | idx_cert_risk_score | (risk_score DESC) | Risk leaderboard |
| certificates | idx_cert_sans | GIN(subject_alt_names) | SAN lookups |
| certificates | idx_cert_risk_flags | GIN(risk_flags) | Finding queries by risk flag |
| certificates | idx_cert_serial_ca | (serial_number, ca_id) UNIQUE | Duplicate CSR detection |
| endpoints | idx_endpoint_unique_network_identity | (ip_address, port, COALESCE(sni_name, '')) UNIQUE | Dedup key enforcement |
| audit_log | idx_audit_timestamp | (timestamp DESC) | Time-range queries |
| audit_log | idx_audit_resource | (resource_type, resource_id) | Audit history per entity |
| audit_log | idx_audit_actor | (actor_id) | User action audit trail |
| certificate_endpoints | idx_ce_active | (currently_active) | Staleness/dedup queries (R-D2) |

---

## Migration Strategy

### File Organization

```
internal/db/migrations/
  postgres/
    000001_foundations_identity.up.sql
    000001_foundations_identity.down.sql
    000002_templates_ca_certs_core.up.sql
    ...
    000029_outbound_credentials.up.sql
    000029_outbound_credentials.down.sql
  sqlite/
    [same structure for SQLite compatibility]
```

### Migration Rules

1. **Every migration is reversible** — each `.up.sql` has a corresponding `.down.sql`
2. **No destructive operations in production** — column drops follow a two-release cycle
3. **Forward-only on main branch** — no rollbacks once merged
4. **Auto-applied at startup** — app checks version and applies pending migrations before serving traffic

---

## Dedup & Staleness Implementation Status

**Criterion R-D2 (Wired):** Certificate discovery dedup and staleness tracking is COMPLETE and WIRED.

- **endpoint dedup**: Enforced by UNIQUE constraint on (ip_address, port, COALESCE(sni_name, ''))
- **certificate_endpoints.last_seen**: Updated on every scan where cert is re-observed
- **certificate_endpoints.currently_active**: Set to false when cert is absent in re-scan
- **Implementation ticket**: W2-05 (done)
- **Go code**: `internal/bootstrap/discovery_db_provider.go` — INSERT ON CONFLICT (upsert) updates last_seen and currently_active

---

## SQLite Compatibility

SQLite migrations mirror Postgres, with these adaptations:

| PostgreSQL Feature | SQLite Equivalent |
|--------------------|------------------|
| UUID type | TEXT (app generates) |
| TIMESTAMPTZ | TEXT (ISO 8601) |
| INET | TEXT |
| TEXT[] arrays | TEXT (JSON string) |
| JSONB | TEXT (JSON string) |
| INTERVAL | INTEGER (seconds) |
| GIN index | Not supported; use LIKE with GLOB |
| Partitioning | Not supported; unpartitioned table with date filters |
| Row-level security | Enforced in application layer |

---

## Summary

- **35 tables** across **29 migrations** (29 main + 6 join tables)
- **Dedup/staleness**: Fully wired via certificate_endpoints.last_seen/currently_active (R-D2, W2-05 done)
- **Append-only audit**: Enforced by triggers and row-level security
- **Multi-tenancy**: Isolation via tenant column + join tables (ca_tenants, template_tenants)
- **Forward-only migrations**: All migrations reversible; no rollbacks on main
