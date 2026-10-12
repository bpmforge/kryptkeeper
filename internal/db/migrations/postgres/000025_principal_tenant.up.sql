-- Wave W3 (PostgreSQL)
-- Purpose: FK ca_tenants/template_tenants -> tenants (W3-01 acceptance #3)
-- Depends on: W2 (tenants, ca_tenants, template_tenants)
-- Rollback pair: 000025_principal_tenant.down.sql

BEGIN;

ALTER TABLE ca_tenants
    ADD CONSTRAINT fk_ca_tenants_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE template_tenants
    ADD CONSTRAINT fk_template_tenants_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

COMMIT;
