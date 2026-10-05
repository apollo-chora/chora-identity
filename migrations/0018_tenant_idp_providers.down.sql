-- =============================================================================
-- chora-identity : 0018_tenant_idp_providers.down.sql
--
-- Reverse the Setup Wizard step 3 (CHO-1682) tenant IdP storage. Drops the
-- table, the partial unique index, the RLS policy (implicit via table drop),
-- and the dedicated ENUM. The shared identity_set_updated_at trigger
-- function (from 0001_initial) is NOT dropped — other tables still use it.
-- =============================================================================

BEGIN;

DROP TRIGGER IF EXISTS trg_tenant_idp_providers_updated_at ON tenant_idp_providers;
DROP TABLE IF EXISTS tenant_idp_providers;
DROP TYPE  IF EXISTS tenant_idp_provider_type;

COMMIT;
