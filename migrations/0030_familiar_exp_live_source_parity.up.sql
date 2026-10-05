-- =============================================================================
-- chora-identity : 0030_familiar_exp_live_source_parity.up.sql
--
-- ADR             : ADR-218 D6 — Familiar Growth & Grimoire: the live in-code
--                   EXP source map (chora-consumption growth/curve.go) unifies
--                   onto identity's ExpRuleResolver (migration 0027 schema).
-- Related         : ADR-201 §5 (ExpRuleResolver) · ADR-203 §12 / L16 (verified-EXP)
-- Jira            : CHO-2012 (P0 — Familiar Growth & Grimoire CR)
-- Domain          : Identity (supporting)  /  Database : chora_identity
-- Source of truth : chora-consumption internal/domain/growth/curve.go
--                   (LIVE award vocabulary + values, verified 2026-07-03)
-- Date            : 2026-07-03
--
-- Purpose:
--   Migration 0027 seeded the ADR-203 §12 *aspirational* EXP catalogue. The LIVE
--   familiar growth path (chora-consumption growth/curve.go) awards EXP off a
--   DIFFERENT, smaller source vocabulary with different values. ADR-218 D6 unifies
--   the two: chora-consumption will call ExpRuleService.ResolveExpRule instead of
--   its in-code map (which remains ONLY as the fail-loud-logged fallback when the
--   resolver is unreachable). This migration parity-seeds exp_source_def with the
--   LIVE vocabulary + values so resolution returns EXACTLY today's live behaviour.
--
--   (a) INSERT 10 NEW live-token sources (idempotent, ON CONFLICT DO NOTHING).
--   (b) UPDATE the shared atom_authored row from ADR-203's aspirational 30/150 to
--       the LIVE 20/40 (idempotent — a SET to a fixed value).
--   (c) DEPRECATE the 7 ADR-203 rows superseded by a live token (idempotent —
--       deprecated_at = COALESCE(deprecated_at, now())), so the catalogue keeps
--       ONE live registry row per real source. A deprecated source resolves to
--       ErrUnknownSource; nothing feeds these today. The other 15 aspirational
--       rows (certification_issued, cluster_mastered, …) STAY for future wiring.
--
--   PARITY CONTRACT (ADR-218 D6): the 11 live values below (10 inserts + the
--   atom_authored 20/40) are the mirror of chora-consumption growth/curve.go.
--   Consumption pins the same literals in its own parity test; if the two drift,
--   resolution stops matching the live in-code fallback and the D6 unification is
--   broken. Do NOT change a value here without changing curve.go (and vice versa).
--
--   INVARIANT (ADR-203 L16 — verified-EXP anti-gaming): every source is a
--   Chora-verified system event; this migration only registers / tunes / retires
--   catalogue rows — it can never mint a self-declare source.
--
--   HARD INVARIANT: idempotent + revertable. Applied in lex order (psql -f);
--   every statement is guarded (ON CONFLICT DO NOTHING / COALESCE / a fixed-value
--   SET). GRANTs are delegated to 9999_grant_app_roles.sql. Cross-database queries
--   forbidden — exp_source_def is local to chora_identity. Do NOT apply manually
--   — migrations auto-apply at deploy.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- (a) 10 NEW live-token sources — the chora-consumption growth/curve.go award
--     vocabulary (source_code, display_name, tier, default_exp_value,
--     default_daily_cap, enabled). Idempotent: ON CONFLICT (source_code) DO
--     NOTHING. Behaviour-neutral: no exp_rule_plan / exp_rule rows are seeded, so
--     resolution falls straight to these catalogue defaults (migration 0027).
-- -----------------------------------------------------------------------------
INSERT INTO exp_source_def
    (source_code, display_name, tier, default_exp_value, default_daily_cap, enabled)
VALUES
    ('atom_session',      'Atom session answered (live token)',                'B', 3,  30, TRUE),
    ('ebbinghaus_review', 'Due spaced-repetition review completed (live token)','B', 5,  15, TRUE),
    ('hex_expand',        'KG hexagon expanded (live token)',                  'C', 4,  12, TRUE),
    ('conv_turn',         'Familiar conversational turn (live token)',         'D', 2,  10, TRUE),
    ('daily_dose_open',   'Daily dose opened (live token)',                    'B', 2,  2,  TRUE),
    ('social_share',      'Milestone/post shared (live token)',                'E', 8,  16, TRUE),
    ('social_reaction',   'Reaction received on your post (live token)',       'E', 1,  10, TRUE),
    ('junction_accepted', 'Rare KG junction accepted (live token)',            'C', 15, 15, TRUE),
    ('admin_grant',       'Operator EXP grant (explicit delta, audit)',        'S', 0,  0,  TRUE),
    ('hatch_roll',        'Hatch roll audit event (no EXP)',                   'D', 0,  0,  TRUE)
ON CONFLICT (source_code) DO NOTHING;

-- -----------------------------------------------------------------------------
-- (b) atom_authored — the ONE source code shared across both vocabularies. The
--     LIVE curve.go awards 20 (cap 40/day), not ADR-203's aspirational 30 (cap
--     150). Re-point the catalogue default to the live value. Idempotent (a SET
--     to a fixed value re-applies cleanly).
-- -----------------------------------------------------------------------------
UPDATE exp_source_def
   SET default_exp_value = 20,
       default_daily_cap = 40,
       updated_at        = now()
 WHERE source_code = 'atom_authored';

-- -----------------------------------------------------------------------------
-- (c) Deprecate the 7 ADR-203 rows superseded by a live token — one registry row
--     per real source. Idempotent: deprecated_at = COALESCE(deprecated_at, now())
--     (once set, re-apply keeps the original timestamp). Each maps to its live
--     replacement. A deprecated source resolves to ErrUnknownSource; nothing
--     feeds these today, so no live award is affected.
-- -----------------------------------------------------------------------------
UPDATE exp_source_def
   SET deprecated_at = COALESCE(deprecated_at, now()), updated_at = now()
 WHERE source_code = 'atom_correct';         -- superseded by atom_session (live)
UPDATE exp_source_def
   SET deprecated_at = COALESCE(deprecated_at, now()), updated_at = now()
 WHERE source_code = 'atom_attempt';         -- superseded by atom_session (incorrect answer)
UPDATE exp_source_def
   SET deprecated_at = COALESCE(deprecated_at, now()), updated_at = now()
 WHERE source_code = 'on_time_review';       -- superseded by ebbinghaus_review (live)
UPDATE exp_source_def
   SET deprecated_at = COALESCE(deprecated_at, now()), updated_at = now()
 WHERE source_code = 'chat_turn';            -- superseded by conv_turn (live)
UPDATE exp_source_def
   SET deprecated_at = COALESCE(deprecated_at, now()), updated_at = now()
 WHERE source_code = 'kg_hexagon_expanded';  -- superseded by hex_expand (live)
UPDATE exp_source_def
   SET deprecated_at = COALESCE(deprecated_at, now()), updated_at = now()
 WHERE source_code = 'daily_dose_completed'; -- superseded by daily_dose_open (live)
UPDATE exp_source_def
   SET deprecated_at = COALESCE(deprecated_at, now()), updated_at = now()
 WHERE source_code = 'post_shared';          -- superseded by social_share (live)

COMMIT;

-- =============================================================================
-- VERIFICATION (run manually after apply):
--
--   -- 10 new live tokens present with live values
--   SELECT source_code, default_exp_value, default_daily_cap FROM exp_source_def
--    WHERE source_code IN ('atom_session','ebbinghaus_review','hex_expand',
--          'conv_turn','daily_dose_open','social_share','social_reaction',
--          'junction_accepted','admin_grant','hatch_roll')
--    ORDER BY source_code;
--
--   -- atom_authored re-pointed to the live 20/40
--   SELECT default_exp_value, default_daily_cap FROM exp_source_def
--    WHERE source_code = 'atom_authored';                 -- => 20 | 40
--
--   -- the 7 superseded rows are deprecated (resolve to ErrUnknownSource)
--   SELECT source_code FROM exp_source_def
--    WHERE deprecated_at IS NOT NULL ORDER BY source_code; -- => the 7 codes
-- =============================================================================
