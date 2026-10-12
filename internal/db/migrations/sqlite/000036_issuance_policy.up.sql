-- W5-05 (D-046/FR-P8): data-driven issuance policies. rules is a JSON
-- document (allowed_algorithms, min_rsa_bits, max_validity_days,
-- allow_ca_certs); ca_id '' applies the policy to every CA.
CREATE TABLE IF NOT EXISTS issuance_policies (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    ca_id      TEXT NOT NULL DEFAULT '',
    rules      TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_issuance_policies_ca ON issuance_policies(ca_id, enabled);
