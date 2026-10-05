-- =============================================================================
-- chora-identity : 0042_local_credentials.down.sql
--
-- Reverse of 0042_local_credentials.up.sql. DESTRUCTIVE: drops the credentials
-- table + the local tenant registry + the login-time membership helper. The
-- `password` value added to identity_provider is intentionally NOT removed —
-- PostgreSQL cannot drop a single ENUM value, and dropping/recreating the type
-- would rewrite every users row. Roll forward instead.
-- =============================================================================

BEGIN;

DROP FUNCTION IF EXISTS identity_active_memberships_for_gcid(uuid);
DROP TABLE IF EXISTS local_credentials;
DROP TABLE IF EXISTS tenants;

COMMIT;
