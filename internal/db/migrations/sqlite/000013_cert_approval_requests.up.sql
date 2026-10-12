CREATE TABLE IF NOT EXISTS cert_approval_requests (
    id               TEXT PRIMARY KEY,
    template_id      TEXT NOT NULL,
    ca_id            TEXT NOT NULL,
    requester        TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    csr_pem          TEXT NOT NULL,
    team_id          TEXT,
    requested_at     TEXT NOT NULL,
    decided_at       TEXT,
    decided_by       TEXT,
    reject_reason    TEXT,
    issued_fingerprint TEXT
);

CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON cert_approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_approval_requests_template ON cert_approval_requests(template_id);
CREATE INDEX IF NOT EXISTS idx_approval_requests_requester ON cert_approval_requests(requester);
