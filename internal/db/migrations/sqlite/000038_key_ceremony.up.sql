-- W9-06 (D-084/G-41/FR-P46): M-of-N root-CA key ceremonies. The CA is born
-- pending_ceremony and only reaches active when `quorum` distinct approvers
-- from the `approvers` set have approved.
CREATE TABLE IF NOT EXISTS key_ceremonies (
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
