-- =============================================================================
-- chora-identity : 0027_familiar_exp_rules_layer.up.sql
--
-- ADR             : ADR-201 §5 — Familiar mana + EXP administration (H+);
--                   the NEW ExpRuleResolver (third instance of the ADR-178
--                   PricePlanResolver / ADR-197 PromptResolver pattern).
-- Sources         : ADR-203 §12 — verified-EXP gain list (catalogue defaults).
-- Workstream      : WS4 of the Familiar Holistic Redesign
--                   (docs/FAMILIAR-HOLISTIC-REDESIGN-2026-06-28.md §6, §12).
-- Domain          : Identity (supporting)
-- Database        : chora_identity
-- Date            : 2026-06-28
--
-- Purpose:
--   Introduce the configurable per-source familiar-EXP rules layer that lets an
--   H+ super-admin tune EXP value / daily cap / eligibility / enabled WITHOUT a
--   code deploy, resolving (source_code, tenant) → rule via the precedence
--   ladder (tenant override > platform plan > catalogue default) — exactly the
--   shape ADR-178 proved for mana pricing.
--
--   Three new tables (all in chora_identity):
--     1. exp_source_def — catalogue of VERIFIED EXP sources + default value /
--                         daily cap / tier (global config, NO RLS).
--     2. exp_rule_plan  — named, versioned, platform-or-tenant-scoped plans (RLS).
--     3. exp_rule       — the per-(plan, source) value / cap / eligibility (RLS).
--
--   INVARIANT (ADR-203 L16 — verified-EXP anti-gaming): the EXP source is ALWAYS
--   a Chora-verified system event and is NON-CONFIGURABLE. This layer tunes the
--   VALUE / cap / eligibility / enabled of KNOWN sources; it can NEVER add a
--   self-declare source. Enforced structurally: exp_rule.source_code is a FK to
--   exp_source_def, so an override row can only exist for a catalogued verified
--   source. The catalogue (exp_source_def) is the sole registry of sources.
--
--   Behaviour-neutral on rollout: NO plan rows are seeded. With no exp_rule_plan
--   / exp_rule rows, the resolver falls straight through to the exp_source_def
--   catalogue default (the ADR-203 §12 values seeded below), so the EXP economy
--   behaves exactly as its documented defaults until an admin authors a plan.
--
--   RLS: exp_rule_plan + exp_rule carry the tenant axis (via the plan). A tenant
--   admin can read/write ONLY their own tenant's plans; the platform plan
--   (scope='platform', tenant_id IS NULL) is world-readable so every tenant
--   resolves against it as the plan-default fallback. exp_source_def carries NO
--   RLS (global config, like mana_action_def). The tenant cast is NULLIF-safe
--   (per migration 0019) so the placeholder '' / unset chora.tenant_id reset
--   value yields NULL (no tenant rows) instead of a 22P02 cast error.
--
--   RLS GUC convention (LOCKED, per 0003_user_economy_rls.sql):
--     SET LOCAL chora.tenant_id = '<uuid>';
--     SET LOCAL chora.role      = '<learner|instructor|admin|auditor>';
--
--   HARD INVARIANT: idempotent + revertable. Applied in lex order (psql -f);
--   every statement is guarded (IF NOT EXISTS / DO ... duplicate_object /
--   ON CONFLICT DO NOTHING) for re-apply safety. GRANTs are delegated to
--   9999_grant_app_roles.sql (ALTER DEFAULT PRIVILEGES picks up these tables).
--
--   HARD RULE: cross-database queries forbidden. These tables are local to
--   chora_identity. H+ (chora-tenancy host) reaches them via gRPC/events only.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. exp_source_def — the catalogue of VERIFIED EXP sources (the registry +
-- default value/cap axis). Global config (NO RLS), like mana_action_def. One
-- row per canonical verified-event source. `tier` is the ADR-203 §12 S..F
-- classification (descriptive, not a resolution selector). deprecated_at retires
-- a source without deleting it (a deprecated source resolves to ErrUnknownSource).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exp_source_def (
    source_code       VARCHAR(64)  PRIMARY KEY,
    display_name      TEXT         NOT NULL,
    tier              VARCHAR(2)   NOT NULL,                  -- S|A|B|C|D|E|F (ADR-203 §12)
    default_exp_value BIGINT       NOT NULL CHECK (default_exp_value >= 0),
    default_daily_cap INTEGER      NOT NULL DEFAULT 0 CHECK (default_daily_cap >= 0), -- 0 = uncapped (max EXP/day)
    enabled           BOOLEAN      NOT NULL DEFAULT TRUE,
    deprecated_at     TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CHECK (tier IN ('S','A','B','C','D','E','F'))
);

CREATE INDEX IF NOT EXISTS idx_exp_source_def_active
    ON exp_source_def (tier) WHERE deprecated_at IS NULL;

-- -----------------------------------------------------------------------------
-- 2. exp_rule_plan — the plan axis (platform + tenant scope). A named, versioned
-- set of EXP rules. The platform owns the canonical plan; a tenant may own a
-- plan that overrides selected sources. Precedence is encoded by scope +
-- tenant_id. Mirrors mana_price_plan (0017).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exp_rule_plan (
    plan_id        UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_code      VARCHAR(64)  NOT NULL,
    scope          VARCHAR(16)  NOT NULL,                  -- platform|tenant
    tenant_id      UUID,                                   -- NULL when scope='platform'
    status         VARCHAR(16)  NOT NULL DEFAULT 'draft',  -- draft|active|archived
    effective_from TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_by     UUID,                                   -- admin GCID (audit)
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CHECK (scope  IN ('platform','tenant')),
    CHECK (status IN ('draft','active','archived')),
    CHECK ((scope = 'platform' AND tenant_id IS NULL)
        OR (scope = 'tenant'   AND tenant_id IS NOT NULL))
);

-- Exactly one ACTIVE platform plan, and at most one ACTIVE plan per tenant.
CREATE UNIQUE INDEX IF NOT EXISTS uq_exp_plan_active_platform
    ON exp_rule_plan (scope) WHERE status = 'active' AND scope = 'platform';
CREATE UNIQUE INDEX IF NOT EXISTS uq_exp_plan_active_tenant
    ON exp_rule_plan (tenant_id) WHERE status = 'active' AND scope = 'tenant';

-- -----------------------------------------------------------------------------
-- 3. exp_rule — the value axis (the actual numbers H+ edits). One row per
-- (plan, source). exp_value = EXP per occurrence; daily_cap = max EXP/day
-- (0 = uncapped); eligibility = advisory growth_stage / goal-scope hint
-- ('' = always); enabled toggles the source off without deleting the rule.
-- source_code FK to exp_source_def ENFORCES the non-configurable-source
-- invariant (ADR-203 L16) — no rule for an unknown source can exist.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exp_rule (
    rule_id     UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id     UUID         NOT NULL REFERENCES exp_rule_plan(plan_id) ON DELETE CASCADE,
    source_code VARCHAR(64)  NOT NULL REFERENCES exp_source_def(source_code),
    exp_value   BIGINT       NOT NULL CHECK (exp_value >= 0),
    daily_cap   INTEGER      NOT NULL DEFAULT 0 CHECK (daily_cap >= 0),  -- 0 = uncapped
    eligibility TEXT         NOT NULL DEFAULT '',                        -- '' = always eligible
    enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
    note        TEXT         NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- A plan prices each source at most once.
CREATE UNIQUE INDEX IF NOT EXISTS uq_exp_rule_plan_source
    ON exp_rule (plan_id, source_code);
CREATE INDEX IF NOT EXISTS idx_exp_rule_lookup
    ON exp_rule (source_code);

-- -----------------------------------------------------------------------------
-- RLS — exp_rule_plan + exp_rule (tenant axis via the plan).
--
-- A tenant admin can read/write ONLY their own tenant's plans; the platform
-- plan (scope='platform') is world-readable so every tenant resolves against it
-- as the plan-default fallback. admin-role escape for O+ auditor + cross-tenant
-- platform operators. ENABLE + FORCE so the policy applies even to the table
-- owner (defence in depth; app traffic uses NOBYPASSRLS app_rw/app_ro per 0025).
--
-- exp_rule has no tenant_id column — it inherits scope through its plan, so its
-- policy is a subquery against exp_rule_plan. The tenant cast is NULLIF-safe
-- (per 0019): the placeholder '' / unset chora.tenant_id resolves to NULL (no
-- tenant rows) instead of a 22P02 invalid-uuid error.
-- -----------------------------------------------------------------------------

ALTER TABLE exp_rule_plan ENABLE ROW LEVEL SECURITY;
ALTER TABLE exp_rule_plan FORCE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY exp_plan_scope_isolation ON exp_rule_plan
        FOR ALL USING (
            scope = 'platform'
            OR tenant_id = NULLIF(current_setting('chora.tenant_id', true), '')::uuid
            OR current_setting('chora.role', true) = 'admin'
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

ALTER TABLE exp_rule ENABLE ROW LEVEL SECURITY;
ALTER TABLE exp_rule FORCE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY exp_rule_scope_isolation ON exp_rule
        FOR ALL USING (
            current_setting('chora.role', true) = 'admin'
            OR EXISTS (
                SELECT 1 FROM exp_rule_plan pp
                 WHERE pp.plan_id = exp_rule.plan_id
                   AND ( pp.scope = 'platform'
                      OR pp.tenant_id = NULLIF(current_setting('chora.tenant_id', true), '')::uuid )
            )
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- -----------------------------------------------------------------------------
-- 4. Seed exp_source_def — the ADR-203 §12 verified-EXP gain list as catalogue
-- defaults. default_exp_value is a single pick from the table's range;
-- default_daily_cap is the max-EXP-per-day ceiling (0 = uncapped; '1/day' rows
-- cap at the single-event value). These become editor-tunable via exp_rule
-- overrides; the catalogue is the behaviour-neutral floor.
--
-- Idempotent: ON CONFLICT (source_code) DO NOTHING. NO plan rows are seeded
-- (behaviour-neutral rollout — resolution falls to these defaults).
-- -----------------------------------------------------------------------------
INSERT INTO exp_source_def
    (source_code, display_name, tier, default_exp_value, default_daily_cap, enabled)
VALUES
    -- S — goals / milestones (high EXP, uncapped)
    ('certification_issued',  'Chora certification earned',        'S', 2000, 0,   TRUE),
    ('course_completed',      'Course completed',                  'S', 1000, 0,   TRUE),
    ('path_completed',        'Learning path completed',           'S', 1000, 0,   TRUE),
    ('familiar_goal_achieved','FamiliarGoal achieved (bonus)',     'S', 500,  0,   TRUE),
    ('path_milestone',        'Path milestone (25/50/75%)',        'S', 100,  0,   TRUE),
    -- A — assessment
    ('assessment_passed',     'Assessment or exam passed',         'A', 200,  0,   TRUE),
    ('first_attempt_mastery', 'First-attempt mastery (no hints)',  'A', 100,  0,   TRUE),
    ('assessment_attempted',  'Assessment attempted (effort)',     'A', 20,   60,  TRUE),
    -- B — core loop
    ('concept_mastered',      'Concept mastered',                  'B', 50,   0,   TRUE),
    ('weakness_recovered',    'Growth edge recovered',             'B', 100,  0,   TRUE),
    ('atom_correct',          'Atom answered correct',             'B', 3,    30,  TRUE),
    ('atom_attempt',          'Atom answered (attempt)',           'B', 1,    20,  TRUE),
    ('daily_dose_completed',  'Daily dose completed',              'B', 10,   10,  TRUE),
    ('on_time_review',        'On-time spaced-repetition review',  'B', 2,    40,  TRUE),
    -- C — discovery / KG
    ('kg_hexagon_expanded',   'KG hexagon expanded',               'C', 4,    40,  TRUE),
    ('cluster_mastered',      'Cluster mastered',                  'C', 50,   0,   TRUE),
    -- D — engagement (small, capped)
    ('streak_day',            'Daily practice streak day',         'D', 5,    5,   TRUE),
    ('streak_milestone',      'Streak milestone (7/30/100)',       'D', 50,   0,   TRUE),
    ('chat_turn',             'Familiar chat meaningful session',  'D', 1,    10,  TRUE),
    -- E — social (capped)
    ('duel_won',              'Duel won',                          'E', 30,   90,  TRUE),
    ('referral_converted',    'Refer-a-friend converted',          'E', 100,  0,   TRUE),
    ('post_shared',           'Post or atom shared',               'E', 1,    5,   TRUE),
    -- F — creation (capped)
    ('atom_authored',         'Atom authored and approved',        'F', 30,   150, TRUE)
ON CONFLICT (source_code) DO NOTHING;

COMMIT;

-- =============================================================================
-- VERIFICATION (run manually after apply):
--
--   -- all 23 ADR-203 §12 verified sources seeded
--   SELECT count(*) FROM exp_source_def;                 -- => 23
--
--   -- no plan rows (behaviour-neutral rollout — resolver falls to catalogue)
--   SELECT count(*) FROM exp_rule_plan;                  -- => 0
--   SELECT count(*) FROM exp_rule;                       -- => 0
--
--   -- the non-configurable-source invariant holds (FK rejects unknown source):
--   --   INSERT INTO exp_rule (plan_id, source_code, exp_value)
--   --     VALUES (gen_random_uuid(), 'i_passed_the_real_pmp', 9999);
--   --   => ERROR: insert or update on table "exp_rule" violates foreign key
--   --            constraint (source_code not in exp_source_def)
-- =============================================================================
