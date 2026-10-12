-- Wave W7 (PostgreSQL)
-- Purpose: deterministic seed data for CI/test
-- Depends on: W1..W6
-- Rollback pair: 000007_seed_baseline_data.down.sql

BEGIN;

-- Deterministic seed namespace: ci-seed-*

INSERT INTO notification_policies (id, name, expiry_thresholds, alert_on_risk_flags, alert_cooldown_hours, active)
VALUES (
    '00000000-0000-0000-0000-000000000101',
    'ci-seed-policy',
    '[90,30,7]',
    '{"EXPIRED","EXPIRING_7_DAYS","WEAK_KEY"}',
    24,
    TRUE
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO teams (id, name, slug, description, notification_policy_id)
VALUES (
    '00000000-0000-0000-0000-000000000102',
    'CI Seed Team',
    'ci-seed-team',
    'Deterministic CI seed team',
    '00000000-0000-0000-0000-000000000101'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, email, display_name, role, active)
VALUES
    ('00000000-0000-0000-0000-000000000103', 'ci-seed-admin@example.com', 'CI Seed Admin', 'pki-admin', TRUE),
    ('00000000-0000-0000-0000-000000000104', 'ci-seed-operator@example.com', 'CI Seed Operator', 'pki-operator', TRUE)
ON CONFLICT (id) DO NOTHING;

INSERT INTO team_members (team_id, user_id, role)
VALUES
    ('00000000-0000-0000-0000-000000000102', '00000000-0000-0000-0000-000000000103', 'owner'),
    ('00000000-0000-0000-0000-000000000102', '00000000-0000-0000-0000-000000000104', 'member')
ON CONFLICT (team_id, user_id) DO NOTHING;

INSERT INTO api_keys (id, user_id, name, kid, key_hash, key_prefix, scopes)
VALUES (
    '00000000-0000-0000-0000-000000000105',
    '00000000-0000-0000-0000-000000000103',
    'ci-seed-api-key',
    'kid_ci_seed_01',
    repeat('a', 64),
    'kk_ci_',
    '{"read:certificates"}'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO certificate_templates (
    id, name, display_name, allowed_algorithms, min_key_size, key_usage,
    extended_key_usage, validity_period, renewal_overlap, subject_requirements,
    enrollment_permissions, issuance_requirements, auto_enroll, active, description
)
VALUES (
    '00000000-0000-0000-0000-000000000106',
    'ci-seed-tls-template',
    'CI Seed TLS Template',
    '{RSA,ECDSA,Ed25519}',
    2048,
    '{digitalSignature,keyEncipherment}',
    '{serverAuth}',
    '365 days',
    '30 days',
    '{"common_name_required": true}',
    '{"allow_all": true}',
    '{}',
    FALSE,
    TRUE,
    'Deterministic CI seed template'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO certificate_authorities (
    id, name, display_name, type, parent_ca_id, key_storage_type, status,
    crl_distribution_points, ocsp_service_url
)
VALUES (
    '00000000-0000-0000-0000-000000000107',
    'ci-seed-root-ca',
    'CI Seed Root CA',
    'root',
    NULL,
    'software',
    'active',
    '{https://ci-seed.example/crl}',
    'https://ci-seed.example/ocsp'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO certificates (
    fingerprint_sha256, serial_number, subject_dn, common_name, subject_alt_names,
    issuer_dn, issuer_cn, ca_id, template_id, team_id, valid_from, valid_until,
    public_key_algorithm, key_size_bits, signature_algorithm, extended_key_usage,
    key_usage, chain_complete, chain_trusted, pqc_vulnerable, risk_score, risk_flags,
    grade, renewal_status, source, raw_cert_b64
)
VALUES (
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '1001',
    'CN=ci-seed.example.com,O=Kryptkeeper CI,C=US',
    'ci-seed.example.com',
    '{ci-seed.example.com,www.ci-seed.example.com}',
    'CN=CI Seed Root CA,O=Kryptkeeper CI,C=US',
    'CI Seed Root CA',
    '00000000-0000-0000-0000-000000000107',
    '00000000-0000-0000-0000-000000000106',
    '00000000-0000-0000-0000-000000000102',
    '2026-01-01T00:00:00Z',
    '2027-01-01T00:00:00Z',
    'RSA',
    2048,
    'SHA256-RSA',
    '{serverAuth}',
    '{digitalSignature,keyEncipherment}',
    TRUE,
    TRUE,
    TRUE,
    5,
    '{PQC_VULNERABLE}',
    'A',
    'active',
    'api',
    'Q0ktU0VFRC1DRVJUX0JBU0U2NA=='
)
ON CONFLICT (fingerprint_sha256) DO NOTHING;

UPDATE certificate_authorities
   SET certificate_fingerprint_sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
 WHERE id = '00000000-0000-0000-0000-000000000107';

INSERT INTO scan_jobs (id, type, connector, scope, status, results_summary, created_by)
VALUES (
    '00000000-0000-0000-0000-000000000108',
    'network',
    'ci-seed-network',
    '{"cidr": "10.10.0.0/24"}',
    'complete',
    '{"endpoints_scanned": 1, "certs_found": 1, "new_certs": 1, "changed_certs": 0}',
    '00000000-0000-0000-0000-000000000103'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO endpoints (
    id, ip_address, hostname, port, protocol, tls_versions, cipher_suites,
    sni_name, is_default_cert, last_scan_job_id, last_scanned, tags
)
VALUES (
    '00000000-0000-0000-0000-000000000109',
    '10.10.0.10',
    'ci-seed.example.com',
    443,
    'tls',
    '{TLSv1.2,TLSv1.3}',
    '{TLS_AES_256_GCM_SHA384}',
    'ci-seed.example.com',
    TRUE,
    '00000000-0000-0000-0000-000000000108',
    NOW(),
    '{ci-seed}'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO certificate_endpoints (certificate_fingerprint, endpoint_id, currently_active)
VALUES (
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '00000000-0000-0000-0000-000000000109',
    TRUE
)
ON CONFLICT (certificate_fingerprint, endpoint_id) DO NOTHING;

INSERT INTO scan_results (id, scan_job_id, result_type, target, certificate_fingerprint, data)
VALUES (
    '00000000-0000-0000-0000-000000000110',
    '00000000-0000-0000-0000-000000000108',
    'endpoint_cert',
    '10.10.0.10:443',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '{"hostname": "ci-seed.example.com", "port": 443}'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO audit_log (
    timestamp, action, actor_type, actor_id, actor_email,
    resource_type, resource_id, trace_id, details, outcome
)
VALUES (
    NOW(),
    'seed.bootstrap',
    'system',
    'system',
    'system@kryptkeeper.local',
    'migration',
    '000007_seed_baseline_data',
    'seed-trace-0001',
    '{"seed": "ci-seed", "wave": "W7"}',
    'success'
);

COMMIT;
