-- =============================================================================
-- chora-identity : 0014_platform_operator_role.down.sql
--
-- Reverses 0014_platform_operator_role.up.sql — drops the role_catalog table
-- and, by implication, the PLATFORM_OPERATOR canonical role entry. Use this
-- only if ADR-165 escalates to REJECTED + the corresponding chora-payments
-- WithRLSBypass(ctx) helper is also removed.
--
-- Cross-DB queries forbidden — chora-identity touches only chora_identity.
-- =============================================================================

BEGIN;

DROP TABLE IF EXISTS role_catalog;

COMMIT;
