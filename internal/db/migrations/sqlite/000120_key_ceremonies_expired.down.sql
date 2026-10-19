-- Rollback pair of 000120. Expired ceremonies become aborted (same terminal
-- outcome) before the CHECK narrows; reminder_sent_at is dropped.

PRAGMA foreign_keys=OFF;

BEGIN;

UPDATE key_ceremonies SET status = 'aborted' WHERE status = 'expired';

CREATE TABLE key_ceremonies_old (
    id            TEXT PRIMARY KEY,
    ca_id         TEXT NOT NULL,
    ca_name       TEXT NOT NULL,
    common_name   TEXT NOT NULL,
    algorithm     TEXT NOT NULL,
    validity_days INTEGER NOT NULL CHECK (validity_days > 0),
    initiator     TEXT NOT NULL,
    approvers     TEXT NOT NULL,
    quorum        INTEGER NOT NULL CHECK (quorum >= 2),
    approvals     TEXT NOT NULL DEFAULT '[]',
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'completed', 'aborted')),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

INSERT INTO key_ceremonies_old (id, ca_id, ca_name, common_name, algorithm, validity_days,
    initiator, approvers, quorum, approvals, status, created_at, updated_at)
SELECT id, ca_id, ca_name, common_name, algorithm, validity_days,
    initiator, approvers, quorum, approvals, status, created_at, updated_at
FROM key_ceremonies;

DROP TABLE key_ceremonies;
ALTER TABLE key_ceremonies_old RENAME TO key_ceremonies;

COMMIT;

PRAGMA foreign_keys=ON;
