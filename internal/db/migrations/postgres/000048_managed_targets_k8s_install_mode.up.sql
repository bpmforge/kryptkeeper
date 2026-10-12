-- Wave W17 (PostgreSQL)
-- Purpose: allow install_mode 'k8s' on managed_targets (W17-11).
--
-- renewal_executor.go has routed and pushed install_mode 'k8s' since W5-04
-- (the Istio / ingress-gateway serving-cert path), but 000028's CHECK never
-- listed it. No k8s target could ever be persisted, so that push branch was
-- unreachable in practice -- a data-layer orphan of the same class the W17
-- wave cleared at the package level. Found while wiring W17-07.
-- Depends on: 000028
-- Rollback pair: 000048_managed_targets_k8s_install_mode.down.sql

BEGIN;

ALTER TABLE managed_targets
    DROP CONSTRAINT IF EXISTS managed_targets_install_mode_check;

ALTER TABLE managed_targets
    ADD CONSTRAINT managed_targets_install_mode_check
    CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'cloud', 'acme'));

COMMIT;
