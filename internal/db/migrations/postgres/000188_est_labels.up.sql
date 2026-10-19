-- Wave W26 (W26-06): named EST endpoints /.well-known/est/<label>/, each bound
-- to one certificate template. Times are fixed-width UTC text.
-- Rollback pair: 000188_est_labels.down.sql

CREATE TABLE IF NOT EXISTS est_labels (
    label       TEXT PRIMARY KEY,
    template_id TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
