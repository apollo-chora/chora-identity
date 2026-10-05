-- =============================================================================
-- chora-identity : 0019_rls_tenant_id_nullif_safe.down.sql
-- Revert 0019 — restore the original 0003 tenant_isolation policies (bare
-- ::uuid cast). NOTE: this reintroduces the latent 22P02-on-empty-GUC bug;
-- prefer rolling forward. DROP/CREATE POLICY only (no row deletes).
-- =============================================================================

BEGIN;

DROP POLICY IF EXISTS tenant_isolation ON mana_subsidy_allocations;
CREATE POLICY tenant_isolation ON mana_subsidy_allocations
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation ON user_subscriptions;
CREATE POLICY tenant_isolation ON user_subscriptions
    FOR ALL USING (
        tenant_id IS NULL
        OR tenant_id = current_setting('chora.tenant_id', true)::uuid
    );

COMMIT;
