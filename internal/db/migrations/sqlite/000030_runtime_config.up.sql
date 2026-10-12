CREATE TABLE IF NOT EXISTS runtime_config (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    envelope    TEXT,
    updated_at  TEXT NOT NULL,
    updated_by  TEXT
);
