-- W20-23 (D-327): named SCEP endpoints /scep/<label>. Today the only challenge mode is 'intune': the hub
-- validates each device's challenge through the Intune SCEP validation API with the Entra app named here.
-- credential_ref points into the outbound credential store; the app's secret or certificate is never a column.
-- Times are fixed-width UTC text.
-- Rollback pair: 000388_scep_labels.down.sql

CREATE TABLE IF NOT EXISTS scep_labels (
    label             TEXT PRIMARY KEY,
    mode              TEXT NOT NULL CHECK (mode IN ('intune')),
    template_id       TEXT NOT NULL,
    intune_tenant_id  TEXT NOT NULL,
    intune_client_id  TEXT NOT NULL,
    credential_ref    TEXT NOT NULL,
    issuing_authority TEXT NOT NULL DEFAULT '',
    description       TEXT NOT NULL DEFAULT '',
    created_by        TEXT NOT NULL,
    created_at        TEXT NOT NULL
);
