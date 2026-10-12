-- Wave W2 (SQLite)
-- Purpose: accepted-risk exception primitive (W2-06, D-031/R-D1, FR-R10 phase 1)
-- Depends on: none
-- Rollback pair: 000022_finding_exceptions.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS finding_exceptions (
    id                  TEXT PRIMARY KEY,
    target_type         TEXT NOT NULL
                          CHECK (target_type IN ('certificate', 'ca')),
    target_id           TEXT NOT NULL,
    finding_code        TEXT NOT NULL,
    justification_code  TEXT NOT NULL
                          CHECK (justification_code IN (
                              'risk_accepted', 'compensating_control',
                              'false_positive', 'planned_remediation', 'not_applicable'
                          )),
    justification_note  TEXT,
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_exceptions_target ON finding_exceptions(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_finding_exceptions_expires ON finding_exceptions(expires_at);

COMMIT;
