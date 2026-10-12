-- RC1-A-01: who armed hub-side key egress on this target. Set only by the
-- target handlers, and only for a principal holding certificate.renew; the
-- renewal scheduler skips an auto_renew target where it is empty. Existing rows
-- are deliberately NOT backfilled: re-save auto_renew as an authorized
-- principal to re-arm them.
ALTER TABLE managed_targets ADD COLUMN auto_renew_set_by TEXT;
