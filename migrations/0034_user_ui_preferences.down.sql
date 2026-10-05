-- =============================================================================
-- chora-identity : 0034_user_ui_preferences.down.sql
-- Reverses 0034 — drops the ui_preferences JSONB slice from users.
-- =============================================================================

BEGIN;

ALTER TABLE users
    DROP COLUMN IF EXISTS ui_preferences;

COMMIT;
