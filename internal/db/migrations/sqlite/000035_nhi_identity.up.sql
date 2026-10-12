-- W7-02 (D-056/NFR-P2): non-human identities (AI agents, service
-- accounts, workflows) with approval-governed issuance. Scopes are
-- authorization data resolved by SPIFFE ID at request time — never
-- baked into certificates.
CREATE TABLE IF NOT EXISTS nhi_identities (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    spiffe_id   TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '[]',
    status      TEXT NOT NULL DEFAULT 'pending',
    created_by  TEXT NOT NULL,
    decided_by  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    decided_at  TEXT NOT NULL DEFAULT '',
    UNIQUE (name, kind)
);
