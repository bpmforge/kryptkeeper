-- W40-02 (D-317): operator-managed inventory of device permanent identifiers
-- that ACME device-attest-01 may issue to. Attestation proves the hardware;
-- this table proves the hub's owner expects it. identifier is the order value
-- verbatim (case-sensitive) and unique across the hub so two tenants cannot
-- both claim one device; tenant_id is '' for the default tenant.
CREATE TABLE IF NOT EXISTS acme_device_allowlist (
  identifier TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL DEFAULT '',
  label TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_acme_device_allowlist_tenant ON acme_device_allowlist (tenant_id);
