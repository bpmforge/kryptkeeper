-- (postgres) Issuance policy version history (W22-15): every applied change to a
-- policy appends a gap-free per-policy version, so any prior state can be
-- restored (a restore that would loosen still needs a second approver).
CREATE TABLE IF NOT EXISTS issuance_policy_versions (
    policy_id   TEXT NOT NULL,
    version     INTEGER NOT NULL,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL,
    ca_id       TEXT NOT NULL DEFAULT '',
    rules       TEXT NOT NULL,
    changed_by  TEXT NOT NULL,
    change_kind TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (policy_id, version)
);
