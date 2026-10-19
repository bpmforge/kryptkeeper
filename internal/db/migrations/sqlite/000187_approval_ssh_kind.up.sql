-- W26-31: SSH certificate issuance honours template require_approval. SSH
-- requests reuse cert_approval_requests; kind says which issuer completes the
-- approval, request_json holds the SSH issue request, tenant scopes the row
-- (an SSH request has no CA to derive a tenant from).
-- Rollback pair: 000187_approval_ssh_kind.down.sql
ALTER TABLE cert_approval_requests ADD COLUMN kind TEXT NOT NULL DEFAULT 'x509';
ALTER TABLE cert_approval_requests ADD COLUMN request_json TEXT;
ALTER TABLE cert_approval_requests ADD COLUMN tenant TEXT;
