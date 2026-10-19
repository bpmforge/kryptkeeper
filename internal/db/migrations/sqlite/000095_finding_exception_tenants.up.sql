-- (sqlite) Accepted-risk exception tenant stamp (W22-28): the tenant of the
-- principal whose proposal created the exception. A side table so the
-- finding_exceptions rows and their readers stay untouched; a missing stamp
-- means the exception predates tenancy and belongs to the default tenant.
CREATE TABLE IF NOT EXISTS finding_exception_tenants (
    exception_id TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL
);
