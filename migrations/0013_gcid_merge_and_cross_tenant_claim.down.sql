-- =============================================================================
-- chora-identity : 0013_gcid_merge_and_cross_tenant_claim.down.sql
-- =============================================================================

BEGIN;

DROP TRIGGER IF EXISTS trg_cross_tenant_claim_no_delete ON cross_tenant_claim;
DROP TRIGGER IF EXISTS trg_cross_tenant_claim_no_update ON cross_tenant_claim;
DROP FUNCTION IF EXISTS reject_cross_tenant_claim_mutation();
DROP TABLE IF EXISTS cross_tenant_claim;

DROP TRIGGER IF EXISTS trg_gcid_merge_no_delete ON gcid_merge;
DROP TRIGGER IF EXISTS trg_gcid_merge_no_update ON gcid_merge;
DROP FUNCTION IF EXISTS reject_gcid_merge_mutation();
DROP TABLE IF EXISTS gcid_merge;

COMMIT;
