-- =============================================================================
-- chora-identity : 0038_mana_action_pricing_duel_agents.down.sql
-- Reverses 0038_mana_action_pricing_duel_agents.up.sql.
--
-- Drops the three duel-agent action codes from all three pricing layers.
-- Non-refundable codes with no ledger rows referencing them (the gateway
-- debits synchronously; a down-migrate after production use would leave
-- orphaned ledger rows — acceptable for a rollback in pre-prod).
-- =============================================================================

BEGIN;

DELETE FROM mana_price_rule
 WHERE action_code IN ('profile_conjurer', 'duel_atom_smith', 'duel_atom_smith_web_research');

DELETE FROM mana_action_def
 WHERE action_code IN ('profile_conjurer', 'duel_atom_smith', 'duel_atom_smith_web_research');

DELETE FROM mana_action_pricing
 WHERE action_code IN ('profile_conjurer', 'duel_atom_smith', 'duel_atom_smith_web_research');

COMMIT;
