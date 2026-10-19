-- (sqlite) Approver delegation (W22-11): one active delegation per delegator per
-- tenant, RFC3339 UTC bounds, at most 30 days (enforced in the API). The
-- primary key includes tenant because principal ids are free text and two
-- tenants may reuse one; a delegation must never cross that boundary.
CREATE TABLE IF NOT EXISTS approval_delegations (
    delegator TEXT NOT NULL, tenant TEXT NOT NULL DEFAULT 'default', delegate TEXT NOT NULL,
    starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY (delegator, tenant));
