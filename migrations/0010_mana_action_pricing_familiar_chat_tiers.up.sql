-- =============================================================================
-- chora-identity : 0010_mana_action_pricing_familiar_chat_tiers.up.sql
--
-- ADR             : ADR-154 — Familiar conversational chat surface
-- Design doc      : docs/architecture/adrs/adr-154-familiar-chat-surface.md §D3
-- Plan            : ~/.claude/plans/golden-hopping-owl.md (D3 — per-turn mana)
-- Domain          : Identity (supporting)
-- Database        : chora_identity
-- Author          : ADR-154 — Familiar chat surface
-- Date            : 2026-05-15
-- Architecture    : Architecture Review locked 2026-05-07
--
-- Purpose:
--   Seeds 3 new mana_action_pricing rows for the Familiar conversational
--   chat surface. Per ADR-154 D3 the cost is tier-aware per ADR-142 +
--   ADR-149 model mapping:
--
--     - familiar_chat_turn_basic     →  5 mana  (gemini-2.5-flash-lite)
--     - familiar_chat_turn_standard  → 15 mana  (gemini-3-flash-preview)
--     - familiar_chat_turn_premium   → 30 mana  (gemini-3.1-pro-preview)
--
--   Replaces the single `familiar_chat` (20 mana) action that the legacy
--   in-memory canonicalCostMap (chora-consumption cost_map.go) defined
--   pre-ADR-154 — the legacy code remains for safety as a fallback.
--
--   Idempotent — ON CONFLICT (action_code, effective_from) DO NOTHING.
--   See services/chora-identity/migrations/0002_user_economy.sql §240 for
--   the PK shape.
-- =============================================================================

BEGIN;

INSERT INTO mana_action_pricing (action_code, mana_cost, description) VALUES
    ('familiar_chat_turn_basic',     5,
        'One conversational chat turn with a Familiar at Basic tier (gemini-2.5-flash-lite)'),
    ('familiar_chat_turn_standard', 15,
        'One conversational chat turn with a Familiar at Standard tier (gemini-3-flash-preview)'),
    ('familiar_chat_turn_premium',  30,
        'One conversational chat turn with a Familiar at Premium tier (gemini-3.1-pro-preview)')
ON CONFLICT (action_code, effective_from) DO NOTHING;

COMMIT;
