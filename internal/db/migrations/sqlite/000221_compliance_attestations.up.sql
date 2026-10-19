CREATE TABLE IF NOT EXISTS compliance_attestations (
    id            TEXT PRIMARY KEY,
    control_id    TEXT NOT NULL,
    attester_name TEXT NOT NULL,
    attested_by   TEXT NOT NULL,
    note          TEXT NOT NULL DEFAULT '',
    attested_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_compliance_attestations_control ON compliance_attestations(control_id, attested_at);
