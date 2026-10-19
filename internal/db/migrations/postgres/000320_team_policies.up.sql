-- W33-20: per-team issuance allowance (allowed CAs/templates/DNS names, max
-- validity, monthly quota). Timestamps are RFC3339 TEXT; list columns are JSON arrays.
CREATE TABLE IF NOT EXISTS team_policies (
    tenant               TEXT NOT NULL DEFAULT 'default',
    team                 TEXT NOT NULL,
    allowed_cas          TEXT NOT NULL DEFAULT '[]',
    allowed_templates    TEXT NOT NULL DEFAULT '[]',
    allowed_dns_suffixes TEXT NOT NULL DEFAULT '[]',
    allowed_dns_names    TEXT NOT NULL DEFAULT '[]',
    max_validity_days    INTEGER NOT NULL DEFAULT 0,
    monthly_quota        INTEGER NOT NULL DEFAULT 0,
    version              INTEGER NOT NULL DEFAULT 1,
    updated_by           TEXT NOT NULL DEFAULT '',
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    PRIMARY KEY (tenant, team)
);
CREATE INDEX IF NOT EXISTS idx_team_policies_tenant ON team_policies(tenant);
