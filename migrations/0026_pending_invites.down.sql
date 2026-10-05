-- =============================================================================
-- chora-identity : 0026_pending_invites.down.sql  (WS3 / CHO-1873, ADR-194 D2)
-- =============================================================================
BEGIN;
DROP FUNCTION IF EXISTS match_pending_invites_by_email(text);
DROP TABLE IF EXISTS pending_invites;
DROP TYPE IF EXISTS pending_invite_status;
COMMIT;
