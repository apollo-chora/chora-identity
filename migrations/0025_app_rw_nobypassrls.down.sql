-- =============================================================================
-- chora-identity : 0025_app_rw_nobypassrls.down.sql
--
-- Intentional NO-OP. Rolling back would mean re-adding the `BYPASSRLS` role
-- attribute to `chora_identity_app_rw`, which re-opens the cross-tenant RLS
-- hole 0025 closes (chora-tenancy 0013 precedent). The role's default,
-- correct posture is already NOBYPASSRLS, so there is nothing safe to revert
-- to — leaving it NOBYPASSRLS is the only secure state.
-- =============================================================================
SELECT 1;
