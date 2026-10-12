-- Wave W20 (SQLite) (W20-16, D-121): one-time SCEP enrollment challenges.
-- Each row is minted through the authenticated API for one device's names
-- and consumed once by PKIOperation. Only the challenge's SHA-256 is stored.
-- Times are fixed-width UTC text (2006-01-02T15:04:05Z) so they compare as text.
-- Rollback pair: 000066_scep_challenges.down.sql

CREATE TABLE IF NOT EXISTS scep_challenges (
    id                TEXT PRIMARY KEY,
    challenge_sha256  TEXT NOT NULL UNIQUE,
    ca_id             TEXT NOT NULL,
    common_name       TEXT NOT NULL,
    dns_names         TEXT NOT NULL DEFAULT '[]',
    created_by        TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    used_at           TEXT
);

CREATE INDEX IF NOT EXISTS idx_scep_challenges_created ON scep_challenges(created_at);
