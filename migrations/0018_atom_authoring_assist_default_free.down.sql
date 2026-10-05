-- =============================================================================
-- chora-identity : 0018_atom_authoring_assist_default_free.down.sql
--
-- No-op revert. 0018 adds a single ADDITIVE, PRICE-NEUTRAL platform-default rule
-- (atom_authoring_assist = 0 = free). It changes no existing price and is
-- idempotent. Leaving the 0-cost rule in place on rollback is harmless — the
-- crew stays free either way (with the rule it resolves to 0; without it the
-- action is unpriced and the chora-creation debit fails open to free). Removing
-- the seeded config rule is intentionally NOT done here to keep rollback safe +
-- to respect the soft-delete domain-table policy. mana_action_def.atom_authoring_assist
-- was seeded by 0017 and is likewise left untouched.
-- =============================================================================

BEGIN;
-- intentionally empty (see header)
SELECT 1;
COMMIT;
