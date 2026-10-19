-- W33-23: a delegate files a certificate request on behalf of another
-- principal's team. requester stays the delegate; on_behalf_of is the
-- delegator (also the row's team_id).
-- Rollback pair: 000322_approval_on_behalf_of.down.sql
ALTER TABLE cert_approval_requests ADD COLUMN IF NOT EXISTS on_behalf_of TEXT;
