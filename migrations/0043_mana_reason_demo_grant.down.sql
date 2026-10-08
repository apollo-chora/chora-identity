-- =============================================================================
-- chora-identity : 0043_mana_reason_demo_grant.down.sql
--
-- Best-effort reverse of 0043. PostgreSQL cannot remove an ENUM value:
-- 'demo_grant' STAYS on mana_reason (harmless — no row can reference it once
-- the demo grant is disabled, and the value is additive metadata, not a
-- constraint). The SECURITY DEFINER helper IS dropped: it exists only to
-- serve the demo-grant budget axis, and leaving a definer function behind
-- after the feature is rolled back would be an unjustified privilege.
--
-- Cross-DB queries forbidden — chora-identity touches only chora_identity.
-- =============================================================================

BEGIN;

DROP FUNCTION IF EXISTS mana_demo_grant_total_units();

COMMIT;
