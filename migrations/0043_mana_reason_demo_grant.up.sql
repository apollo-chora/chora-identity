-- =============================================================================
-- chora-identity : 0043_mana_reason_demo_grant.up.sql
--
-- Domain        : Identity (supporting/platform)
-- Database      : chora_identity
-- Author        : agent A-Demo-Mana-Grant (demo-mode mana top-up)
-- Date          : 2026-05-18
--
-- Purpose:
--   Demo mode needs a free, server-side mana grant so a demo never has to run
--   a real payment/top-up flow. Two schema effects, both ADDITIVE:
--
--     1. a dedicated `demo_grant` value on the `mana_reason` ENUM. It is a
--        DISTINCT reason from `topup`: `topup` means a PAID purchase (the
--        retired Stripe /me/mana/topup route), while `demo_grant` is a free,
--        server-issued, ledger-backed mint. Reusing `topup` would mislabel a
--        free grant as revenue-bearing in every downstream revenue report.
--
--     2. a SECURITY DEFINER helper `mana_demo_grant_total_units()` returning
--        the total units recorded under `demo_grant` across ALL GCIDs. The
--        demo-grant endpoint enforces a platform-wide budget, but
--        `mana_ledger` carries the `user_isolation` RLS policy (migration
--        0003) and the runtime role `chora_identity_app_rw` is NOBYPASSRLS
--        (migration 0025), so a plain SELECT can only ever see the caller's
--        own rows. The function runs as its owner (the migration role, which
--        owns the table) and is granted EXECUTE only to the app roles — the
--        same controlled-bypass pattern as
--        identity_active_memberships_for_gcid() in 0042_local_credentials.
--
--   The per-GCID grant cap needs NO helper: it is a count over the caller's
--   own rows, which the RLS policy already exposes.
--
-- Idempotency: `ALTER TYPE ... ADD VALUE IF NOT EXISTS` is a no-op once
-- applied; `CREATE OR REPLACE FUNCTION` replaces in place.
--
-- HARD RULE: cross-database queries forbidden. This touches only chora_identity.
-- =============================================================================

-- 1. The demo_grant reason. ALTER TYPE ... ADD VALUE runs OUTSIDE the
-- transactional block below because a freshly-added enum value cannot be
-- referenced inside the transaction that adds it.
ALTER TYPE mana_reason ADD VALUE IF NOT EXISTS 'demo_grant';

BEGIN;

-- 2. Platform-wide demo-grant budget axis (controlled RLS bypass via
-- ownership). STABLE: it only reads.
CREATE OR REPLACE FUNCTION mana_demo_grant_total_units()
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT COALESCE(sum(units), 0)::bigint
      FROM mana_ledger
     WHERE reason = 'demo_grant'::mana_reason;
$$;

REVOKE ALL ON FUNCTION mana_demo_grant_total_units() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mana_demo_grant_total_units()
    TO chora_identity_app_rw, chora_identity_app_ro;

COMMIT;

-- =============================================================================
-- VERIFICATION (run manually after apply, with the migrate DSN):
--   SELECT unnest(enum_range(NULL::mana_reason))::text;
--   -- expect: ... 'demo_grant' ...
--   SELECT mana_demo_grant_total_units();  -- expect: 0
-- =============================================================================
