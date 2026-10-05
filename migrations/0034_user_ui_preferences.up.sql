-- =============================================================================
-- chora-identity : 0034_user_ui_preferences.up.sql
--
-- Domain        : Identity (supporting/platform)
-- Database      : chora_identity
-- Story         : SP2.9 — A+ dashboard-as-hub layout persistence
--
-- Adds a GCID-scoped ui_preferences JSONB slice to the User profile aggregate
-- (users). The first UI preference is the A+ dashboard layout — the learner's
-- ordered set of draggable card-group "wrapper" keys + an FE Last-Write-Wins
-- timestamp:
--
--   {"dashboard_layout": {"order": ["map","cast","courses"],
--                         "updated_at": "2026-07-06T12:00:00Z"}}
--
-- The layout is a GCID-scoped account preference (portable across tenants like
-- the GCID itself) — it belongs on the identity-scoped users row, NOT a tenant-
-- scoped table. users carries NO RLS policy (identity-scoped; the service-side
-- policy is "only the GCID owner may read/write"); the repository scopes every
-- read/write by gcid = the authenticated caller. This is NOT a new RLS-bypass
-- surface.
--
-- JSONB (not a typed column) so future UI preferences append a key without a
-- migration. NOT NULL DEFAULT '{}' so existing rows read back an empty object.
-- =============================================================================

BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS ui_preferences JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN users.ui_preferences IS
    'GCID-scoped UI preferences (SP2.9). Keys: dashboard_layout {order[],updated_at}. JSONB for schema-free extension.';

COMMIT;
