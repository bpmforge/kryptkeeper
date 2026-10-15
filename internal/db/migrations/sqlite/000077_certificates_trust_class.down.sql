-- (SQLite) rollback of 000077. Served-chain CA rows lose their marker and
-- re-enter the leaf inventory; they are discovery-owned and re-marked by the
-- next scan.
ALTER TABLE certificates DROP COLUMN is_ca;
ALTER TABLE certificates DROP COLUMN trust_class;
