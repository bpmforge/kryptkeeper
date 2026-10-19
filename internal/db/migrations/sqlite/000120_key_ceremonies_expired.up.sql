-- W23-07 (D-084/FR-P46): widen key_ceremonies.status with `expired` and add
-- reminder_sent_at. SQLite cannot alter a CHECK, so the table is rebuilt.

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE key_ceremonies_new (
    id               TEXT PRIMARY KEY,
    ca_id            TEXT NOT NULL,
    ca_name          TEXT NOT NULL,
    common_name      TEXT NOT NULL,
    algorithm        TEXT NOT NULL,
    validity_days    INTEGER NOT NULL CHECK (validity_days > 0),
    initiator        TEXT NOT NULL,
    approvers        TEXT NOT NULL,
    quorum           INTEGER NOT NULL CHECK (quorum >= 2),
    approvals        TEXT NOT NULL DEFAULT '[]',
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'completed', 'aborted', 'expired')),
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    reminder_sent_at TEXT
);

INSERT INTO key_ceremonies_new (id, ca_id, ca_name, common_name, algorithm, validity_days,
    initiator, approvers, quorum, approvals, status, created_at, updated_at)
SELECT id, ca_id, ca_name, common_name, algorithm, validity_days,
    initiator, approvers, quorum, approvals, status, created_at, updated_at
FROM key_ceremonies;

DROP TABLE key_ceremonies;
ALTER TABLE key_ceremonies_new RENAME TO key_ceremonies;

COMMIT;

PRAGMA foreign_keys=ON;
