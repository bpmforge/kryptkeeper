-- W9-09 (D-087/FR-P49): per-key lifecycle policy — owner/ACL beyond the
-- global admin gate, max-age auto-rotation schedule, compromise stamp.
CREATE TABLE IF NOT EXISTS key_lifecycle (
    key_id         TEXT PRIMARY KEY,
    owner          TEXT NOT NULL,
    acl            TEXT NOT NULL DEFAULT '[]',
    max_age_days   INTEGER NOT NULL DEFAULT 0
                   CHECK (max_age_days >= 0),
    rotated_at     TEXT NOT NULL,
    compromised_at TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
