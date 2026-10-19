-- W22-29: persisted dedup identity for findings (funnel stage 2).
-- Semantics identical to postgres. tenant is part of the identity.
CREATE TABLE IF NOT EXISTS finding_identities (
    id           TEXT PRIMARY KEY,
    tenant       TEXT NOT NULL DEFAULT '',
    target_type  TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    finding_code TEXT NOT NULL,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_identities_target ON finding_identities(tenant, target_type, target_id);
