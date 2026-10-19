-- Purpose: W34 (FR-R10). Accepted-risk exceptions can be filed against one
-- discovered file (a Tomcat keystore owned by root, say), so
-- finding_exceptions.target_type admits 'target_file'; target_id is the
-- discovered_files.id. SQLite cannot alter a CHECK, so the table is rebuilt
-- with its 000022 columns and indexes. finding_exception_tenants and
-- finding_exception_events key on the exception id and are untouched.
-- Depends on: 000022, 000342
-- Rollback pair: 000347_finding_exceptions_target_file.down.sql

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE finding_exceptions_new (
    id                  TEXT PRIMARY KEY,
    target_type         TEXT NOT NULL
                          CHECK (target_type IN ('certificate', 'ca', 'target_file')),
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

INSERT INTO finding_exceptions_new
    (id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at)
SELECT
     id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at
FROM finding_exceptions;

DROP TABLE finding_exceptions;

ALTER TABLE finding_exceptions_new RENAME TO finding_exceptions;

CREATE INDEX IF NOT EXISTS idx_finding_exceptions_target ON finding_exceptions(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_finding_exceptions_expires ON finding_exceptions(expires_at);

COMMIT;

PRAGMA foreign_keys=ON;
