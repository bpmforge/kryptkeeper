-- Rollback pair of 000347. Exceptions on files go first: the narrower CHECK
-- cannot hold them. Their tenant stamps and lifecycle events are removed too.
DELETE FROM finding_exception_tenants WHERE exception_id IN (SELECT id FROM finding_exceptions WHERE target_type = 'target_file');
DELETE FROM finding_exception_events WHERE exception_id IN (SELECT id FROM finding_exceptions WHERE target_type = 'target_file');
DELETE FROM finding_exceptions WHERE target_type = 'target_file';

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE finding_exceptions_old (
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

INSERT INTO finding_exceptions_old
    (id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at)
SELECT
     id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at
FROM finding_exceptions;

DROP TABLE finding_exceptions;

ALTER TABLE finding_exceptions_old RENAME TO finding_exceptions;

CREATE INDEX IF NOT EXISTS idx_finding_exceptions_target ON finding_exceptions(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_finding_exceptions_expires ON finding_exceptions(expires_at);

COMMIT;

PRAGMA foreign_keys=ON;
