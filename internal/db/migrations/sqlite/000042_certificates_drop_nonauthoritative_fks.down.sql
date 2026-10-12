-- Wave S rollback (SQLite)
-- Paired with: 000042_certificates_drop_nonauthoritative_fks.up.sql
--
-- Restores the original template_id/team_id FK constraints. Unlike
-- Postgres's ADD CONSTRAINT (which validates every existing row and aborts
-- on a violation), this rebuild's data copy runs with foreign_keys=OFF, so
-- SQLite does not retroactively validate rows that already violate the
-- restored FK -- it only declares the constraint going forward. Rolling
-- back after a real, non-authoritative value has been written leaves that
-- row in place, unvalidated, rather than failing the rollback -- the same
-- assumption every other down.sql in this tree makes about reversing
-- cleanly (see 000033_discovery_schema_realign.down.sql), just with a
-- different failure mode on this engine than on Postgres.
--
-- legacy_alter_table=ON works around the same SQLite behavior documented in
-- the up.sql's comment: "ALTER TABLE ... RENAME TO" recompiles every
-- trigger in the schema to rewrite table references, and
-- certificate_authorities' trg_ca_certificate_fingerprint_fk_ins/upd query
-- "certificates" in their WHEN clause, which fails while the table is
-- transiently absent mid-rebuild. Restored to OFF afterward.

PRAGMA foreign_keys=OFF;
PRAGMA legacy_alter_table=ON;

BEGIN;

CREATE TABLE certificates_new (
    fingerprint_sha256        TEXT PRIMARY KEY,
    serial_number             TEXT NOT NULL,
    subject_dn                TEXT NOT NULL,
    common_name               TEXT,
    subject_alt_names         TEXT,
    issuer_dn                 TEXT NOT NULL,
    issuer_cn                 TEXT,
    ca_id                     TEXT REFERENCES certificate_authorities(id),
    template_id               TEXT REFERENCES certificate_templates(id),
    team_id                   TEXT REFERENCES teams(id),
    valid_from                TEXT NOT NULL,
    valid_until               TEXT NOT NULL,
    public_key_algorithm      TEXT NOT NULL CHECK (public_key_algorithm IN ('RSA', 'ECDSA', 'Ed25519', 'ML-DSA')),
    key_size_bits             INTEGER,
    signature_algorithm       TEXT NOT NULL,
    extended_key_usage        TEXT,
    key_usage                 TEXT,
    chain_complete            INTEGER NOT NULL DEFAULT 0 CHECK (chain_complete IN (0,1)),
    chain_trusted             INTEGER NOT NULL DEFAULT 0 CHECK (chain_trusted IN (0,1)),
    pqc_vulnerable            INTEGER NOT NULL DEFAULT 0 CHECK (pqc_vulnerable IN (0,1)),
    risk_score                INTEGER NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_flags                TEXT NOT NULL DEFAULT '[]',
    grade                     TEXT NOT NULL DEFAULT 'A' CHECK (grade IN ('A', 'B', 'C', 'D', 'F')),
    renewal_method            TEXT CHECK (renewal_method IN ('acme', 'est', 'scep', 'api', 'manual') OR renewal_method IS NULL),
    renewal_status            TEXT DEFAULT 'active' CHECK (renewal_status IN ('active', 'renewed', 'expired', 'revoked')),
    predecessor_fingerprint   TEXT REFERENCES certificates(fingerprint_sha256),
    successor_fingerprint     TEXT REFERENCES certificates(fingerprint_sha256),
    revoked_at                TEXT,
    revocation_reason         INTEGER,
    source                    TEXT NOT NULL DEFAULT 'api'
                              CHECK (source IN ('api', 'acme', 'est', 'scep', 'discovery_network',
                                               'discovery_ssh', 'discovery_winrm', 'discovery_agent',
                                               'discovery_cloud', 'discovery_k8s', 'ct_log', 'import')),
    raw_cert_b64              TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    owner_email               TEXT,
    owner_team                TEXT,
    service_name              TEXT,
    labels                    TEXT DEFAULT '[]'
);

INSERT INTO certificates_new (
    fingerprint_sha256, serial_number, subject_dn, common_name, subject_alt_names,
    issuer_dn, issuer_cn, ca_id, template_id, team_id,
    valid_from, valid_until, public_key_algorithm, key_size_bits,
    signature_algorithm, extended_key_usage, key_usage,
    chain_complete, chain_trusted, pqc_vulnerable,
    risk_score, risk_flags, grade, renewal_method, renewal_status,
    predecessor_fingerprint, successor_fingerprint, revoked_at, revocation_reason,
    source, raw_cert_b64, created_at, updated_at,
    owner_email, owner_team, service_name, labels
)
SELECT
    fingerprint_sha256, serial_number, subject_dn, common_name, subject_alt_names,
    issuer_dn, issuer_cn, ca_id, template_id, team_id,
    valid_from, valid_until, public_key_algorithm, key_size_bits,
    signature_algorithm, extended_key_usage, key_usage,
    chain_complete, chain_trusted, pqc_vulnerable,
    risk_score, risk_flags, grade, renewal_method, renewal_status,
    predecessor_fingerprint, successor_fingerprint, revoked_at, revocation_reason,
    source, raw_cert_b64, created_at, updated_at,
    owner_email, owner_team, service_name, labels
FROM certificates;

DROP TABLE certificates;
ALTER TABLE certificates_new RENAME TO certificates;

CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_serial_ca ON certificates(serial_number, ca_id);
CREATE INDEX IF NOT EXISTS idx_cert_valid_until ON certificates(valid_until);
CREATE INDEX IF NOT EXISTS idx_cert_risk_score ON certificates(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_cert_grade ON certificates(grade);
CREATE INDEX IF NOT EXISTS idx_cert_renewal_status ON certificates(renewal_status);
CREATE INDEX IF NOT EXISTS idx_cert_team ON certificates(team_id);
CREATE INDEX IF NOT EXISTS idx_cert_ca ON certificates(ca_id);
CREATE INDEX IF NOT EXISTS idx_cert_common_name ON certificates(common_name);
CREATE INDEX IF NOT EXISTS idx_cert_revoked_at ON certificates(revoked_at);
CREATE INDEX IF NOT EXISTS idx_cert_subject_dn ON certificates(subject_dn);
CREATE INDEX IF NOT EXISTS idx_cert_valid_window ON certificates(valid_from, valid_until);
CREATE INDEX IF NOT EXISTS idx_certs_owner_email ON certificates(owner_email) WHERE owner_email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certs_owner_team  ON certificates(owner_team)  WHERE owner_team  IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certs_service     ON certificates(service_name) WHERE service_name IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS trg_certificates_set_updated_at
AFTER UPDATE ON certificates
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE certificates
       SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE fingerprint_sha256 = NEW.fingerprint_sha256;
END;

COMMIT;

PRAGMA legacy_alter_table=OFF;
PRAGMA foreign_keys=ON;
