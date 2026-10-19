ALTER TABLE cert_approval_requests DROP COLUMN IF EXISTS tenant;
ALTER TABLE cert_approval_requests DROP COLUMN IF EXISTS request_json;
ALTER TABLE cert_approval_requests DROP COLUMN IF EXISTS kind;
