-- chora-identity : 0039_companion_action_pricing_twins.down.sql
-- Reverts 0039: removes the companion_* twins (rules first, then defs, then
-- prices) and narrows the category CHECK back. The familiar_* rows were never
-- touched by 0039. Roll the gateway image back first (it meters
-- companion_chat_turn_* fail-closed; with the rows gone those turns are
-- un-metered, not blocked).
BEGIN;

DELETE FROM mana_price_rule
 WHERE action_code LIKE 'companion%'
   AND note LIKE '%(0039%';

DELETE FROM mana_action_def
 WHERE action_code LIKE 'companion%'
   AND replace(CASE WHEN action_code = 'companion_skill_kg_explore' THEN 'familiar_skill_fog_scout' ELSE action_code END,
               'companion', 'familiar') IN (SELECT action_code FROM mana_action_def);

DELETE FROM mana_action_pricing
 WHERE action_code LIKE 'companion%'
   AND replace(CASE WHEN action_code = 'companion_skill_kg_explore' THEN 'familiar_skill_fog_scout' ELSE action_code END,
               'companion', 'familiar') IN (SELECT action_code FROM mana_action_pricing);

DO $$
DECLARE
    cname text;
BEGIN
    SELECT conname INTO cname
      FROM pg_constraint
     WHERE conrelid = 'mana_action_def'::regclass
       AND contype = 'c'
       AND pg_get_constraintdef(oid) ILIKE '%category%';
    IF cname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE mana_action_def DROP CONSTRAINT %I', cname);
    END IF;
    ALTER TABLE mana_action_def
        ADD CONSTRAINT mana_action_def_category_check
        CHECK (category IN ('authoring','familiar','consumption','grading','free'));
END$$;

COMMIT;
