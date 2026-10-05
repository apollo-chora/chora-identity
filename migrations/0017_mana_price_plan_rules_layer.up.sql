-- =============================================================================
-- chora-identity : 0017_mana_price_plan_rules_layer.up.sql
--
-- ADR             : ADR-178 — Configurable mana price-plan rules layer (H+)
-- Design doc      : docs/design/mana_price_plan_rules_layer.md §1 + §4
-- Jira            : CHO-1661
-- Domain          : Identity (supporting)
-- Database        : chora_identity
-- Date            : 2026-06-05
-- Architecture    : Architecture Review locked 2026-05-07 + ADR-142 §4
--
-- Purpose:
--   Supersede the flat `action_code → units` lookup (mana_action_pricing)
--   with a configurable rules layer resolving
--     (action_code, tenant, tier) → {units, refundable, per_item, meter_home}
--   via a precedence ladder (tenant override > plan default > catalogue
--   fallback). The existing `mana_action_pricing` table is LEFT UNTOUCHED and
--   becomes the bottom-of-precedence catalogue fallback (zero migration risk).
--
--   Three new tables (all in chora_identity):
--     1. mana_action_def     — action registry (granularity + semantics flags)
--     2. mana_price_plan      — named, versioned, platform-or-tenant-scoped plans
--     3. mana_price_rule      — the actual numbers, optionally tier-keyed
--
--   Migration is purely ADDITIVE + idempotent + changes NO current price:
--   every active `mana_action_pricing` row is back-filled as a NULL-tier rule
--   in the platform `default` plan with the EXACT same cost, so resolution is
--   a no-op on prices on rollout (Migration_preserves_every_catalogue_price).
--
--   RLS: mana_price_plan + mana_price_rule carry a tenant axis (via the plan).
--   Tenant-scoped plans are protected so a tenant admin cannot read/write
--   another tenant's plan; the platform `default` plan is world-readable (every
--   tenant resolves against it as fallback). mana_action_def is global config
--   (RLS axis NONE — like mana_action_pricing today).
--
--   RLS GUC convention (LOCKED, per 0003_user_economy_rls.sql):
--     SET LOCAL chora.tenant_id = '<uuid>';
--     SET LOCAL chora.role      = '<learner|instructor|admin|auditor>';
--
--   HARD INVARIANT: idempotent + revertable. Apply via
--   `migrate -database <DSN> -path migrations up`. Do NOT apply manually until
--   the build orchestrator schedules it.
--
--   HARD RULE: cross-database queries forbidden. These tables are local to
--   chora_identity. H+ (chora-tenancy host) reaches them via gRPC/events only.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. mana_action_def — action registry (the granularity + semantics axis).
--
-- Declares WHAT an action is + its semantics flags (refundable / per_item),
-- orthogonal to WHAT it costs. One row per canonical action_code. A tenant
-- override changes price, never whether a batch is per-item — so these flags
-- live on the action def, not on a price rule.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mana_action_def (
    action_code   VARCHAR(64)  PRIMARY KEY,
    display_name  TEXT         NOT NULL,
    category      VARCHAR(32)  NOT NULL,                 -- authoring|familiar|consumption|grading|free
    refundable    BOOLEAN      NOT NULL DEFAULT FALSE,   -- caller MAY wire refund-on-failure (advisory)
    per_item      BOOLEAN      NOT NULL DEFAULT FALSE,   -- price is multiplied by context.item_count
    meter_home    VARCHAR(16)  NOT NULL DEFAULT 'gateway', -- gateway|creation|consumption (who debits; FU-4 lever)
    tier_aware    BOOLEAN      NOT NULL DEFAULT FALSE,   -- BACKLOG: honour context.tier when resolving a rule
    deprecated_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CHECK (category   IN ('authoring','familiar','consumption','grading','free')),
    CHECK (meter_home IN ('gateway','creation','consumption'))
);

CREATE INDEX IF NOT EXISTS idx_mana_action_def_active
    ON mana_action_def (category) WHERE deprecated_at IS NULL;

-- -----------------------------------------------------------------------------
-- 2. mana_price_plan — the plan-default axis (platform + tenant scope).
--
-- A price plan is a named, versioned set of price rules. The platform owns the
-- canonical default plan (`default`); a tenant may own a plan that overrides
-- selected actions. Precedence is encoded by scope + tenant_id.
--
-- plan_id is UUID DEFAULT gen_random_uuid() in SQL; app code mints UUIDv7 for
-- new tables (the back-fill below uses gen_random_uuid for the seed default
-- plan — a one-off platform row, not an app-minted aggregate).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mana_price_plan (
    plan_id        UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_code      VARCHAR(64)  NOT NULL,
    scope          VARCHAR(16)  NOT NULL,                -- platform|tenant
    tenant_id      UUID,                                 -- NULL when scope='platform'
    status         VARCHAR(16)  NOT NULL DEFAULT 'draft',-- draft|active|archived
    effective_from TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_by     UUID,                                 -- admin GCID (audit)
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CHECK (scope  IN ('platform','tenant')),
    CHECK (status IN ('draft','active','archived')),
    CHECK ((scope = 'platform' AND tenant_id IS NULL)
        OR (scope = 'tenant'   AND tenant_id IS NOT NULL))
);

-- Exactly one ACTIVE platform plan, and at most one ACTIVE plan per tenant.
CREATE UNIQUE INDEX IF NOT EXISTS uq_mana_plan_active_platform
    ON mana_price_plan (scope) WHERE status = 'active' AND scope = 'platform';
CREATE UNIQUE INDEX IF NOT EXISTS uq_mana_plan_active_tenant
    ON mana_price_plan (tenant_id) WHERE status = 'active' AND scope = 'tenant';

-- -----------------------------------------------------------------------------
-- 3. mana_price_rule — the price axis (the actual numbers, optionally tier-keyed).
--
-- One row per (plan, action_code, tier). tier is NULLABLE — NULL means "applies
-- to all tiers" (today's behaviour); a non-null tier is the BACKLOG high/low
-- axis. This is the table H+ edits.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mana_price_rule (
    rule_id     UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id     UUID         NOT NULL REFERENCES mana_price_plan(plan_id) ON DELETE CASCADE,
    action_code VARCHAR(64)  NOT NULL REFERENCES mana_action_def(action_code),
    tier        VARCHAR(16),                             -- NULL = all tiers; 'low'|'high' = BACKLOG axis
    mana_cost   BIGINT       NOT NULL CHECK (mana_cost >= 0),
    note        TEXT         NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CHECK (tier IS NULL OR tier IN ('low','high'))
);

-- A plan prices each (action, tier) at most once. NULLS NOT DISTINCT (PG15+)
-- so a second NULL-tier rule for the same action collides (one default price).
CREATE UNIQUE INDEX IF NOT EXISTS uq_mana_price_rule_plan_action_tier
    ON mana_price_rule (plan_id, action_code, tier) NULLS NOT DISTINCT;
CREATE INDEX IF NOT EXISTS idx_mana_price_rule_lookup
    ON mana_price_rule (action_code, tier);

-- -----------------------------------------------------------------------------
-- RLS — mana_price_plan + mana_price_rule (tenant axis via the plan).
--
-- A tenant admin can read/write ONLY their own tenant's plans; the platform
-- `default` plan (scope='platform', tenant_id IS NULL) is world-readable so
-- every tenant resolves against it as the plan-default fallback. admin role
-- bypass for O+ auditor + cross-tenant platform operators.
--
-- mana_price_rule has no tenant_id column — it inherits scope through its
-- plan, so its policy is a subquery against mana_price_plan. (RLS subqueries
-- re-apply the parent policy, so a tenant only sees rules of plans it can see.)
-- mana_action_def carries NO RLS (global config, like mana_action_pricing).
-- -----------------------------------------------------------------------------

ALTER TABLE mana_price_plan ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY plan_scope_isolation ON mana_price_plan
        FOR ALL USING (
            scope = 'platform'
            OR tenant_id = current_setting('chora.tenant_id', true)::uuid
            OR current_setting('chora.role', true) = 'admin'
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

ALTER TABLE mana_price_rule ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY rule_scope_isolation ON mana_price_rule
        FOR ALL USING (
            current_setting('chora.role', true) = 'admin'
            OR EXISTS (
                SELECT 1 FROM mana_price_plan pp
                 WHERE pp.plan_id = mana_price_rule.plan_id
                   AND ( pp.scope = 'platform'
                      OR pp.tenant_id = current_setting('chora.tenant_id', true)::uuid )
            )
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- -----------------------------------------------------------------------------
-- 4. Seed mana_action_def — the union of all known action codes (0002/0009/0010),
-- stamping refundable / per_item / meter_home. refundable=true is set ONLY for
-- the authoring codes chora-creation already refunds today (descriptive of
-- existing behaviour, NOT a new behaviour).
-- -----------------------------------------------------------------------------
INSERT INTO mana_action_def (action_code, display_name, category, refundable, per_item, meter_home, tier_aware) VALUES
    ('summon_familiar',                  'Summon Familiar',                'free',        FALSE, FALSE, 'gateway',     FALSE),
    ('daily_dose_deterministic',         'Daily Dose (deterministic)',     'free',        FALSE, FALSE, 'gateway',     FALSE),
    ('daily_dose_coach',                 'Daily Dose Coach',               'consumption', FALSE, FALSE, 'gateway',     FALSE),
    ('atom_authoring_assist',            'Atom Authoring Assist',          'authoring',   FALSE, FALSE, 'gateway',     FALSE),
    ('question_generation',              'Question Generation (coarse)',   'authoring',   FALSE, FALSE, 'creation',    FALSE),
    ('familiar_chat',                    'Familiar Chat (legacy)',         'familiar',    FALSE, FALSE, 'consumption', FALSE),
    ('knowledge_graph_traverse',         'Knowledge Graph Traverse',       'consumption', FALSE, FALSE, 'gateway',     FALSE),
    ('boss_challenge_atom_gen',          'Boss Challenge Atom Gen',        'consumption', FALSE, FALSE, 'gateway',     FALSE),
    ('coach_session_full',               'Full Coach Session',             'consumption', FALSE, FALSE, 'gateway',     FALSE),
    ('question_authoring_model_answer',  'Question Authoring: Model Answer', 'authoring', TRUE,  FALSE, 'creation',    FALSE),
    ('question_authoring_ai_draft',      'Question Authoring: AI Draft',   'authoring',   TRUE,  FALSE, 'creation',    FALSE),
    ('question_authoring_batch_parse',   'Question Authoring: Batch Parse','authoring',   TRUE,  FALSE, 'creation',    FALSE),
    ('question_authoring_batch_per_item','Question Authoring: Batch Per-Item','authoring',TRUE,  TRUE,  'creation',    FALSE),
    ('familiar_chat_turn_basic',         'Familiar Chat Turn (Basic)',     'familiar',    FALSE, FALSE, 'consumption', FALSE),
    ('familiar_chat_turn_standard',      'Familiar Chat Turn (Standard)',  'familiar',    FALSE, FALSE, 'consumption', FALSE),
    ('familiar_chat_turn_premium',       'Familiar Chat Turn (Premium)',   'familiar',    FALSE, FALSE, 'consumption', FALSE)
ON CONFLICT (action_code) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 5. Create the platform `default` plan (exactly one ACTIVE platform plan) and
-- back-fill one NULL-tier rule per active mana_action_pricing row with the
-- EXACT same mana_cost. Because step 5 mirrors every catalogue price into the
-- default plan, resolution is identical whether it stops at the plan default
-- or falls through to the catalogue → NO-OP on prices.
--
-- Idempotent: the platform-plan INSERT is conditional on no active platform
-- plan already existing; the rule back-fill is ON CONFLICT DO NOTHING.
-- -----------------------------------------------------------------------------
INSERT INTO mana_price_plan (plan_code, scope, tenant_id, status)
SELECT 'default', 'platform', NULL, 'active'
 WHERE NOT EXISTS (
     SELECT 1 FROM mana_price_plan
      WHERE scope = 'platform' AND status = 'active'
 );

INSERT INTO mana_price_rule (plan_id, action_code, tier, mana_cost, note)
SELECT dp.plan_id, p.action_code, NULL, p.mana_cost,
       'migrated from mana_action_pricing 0002/0009/0010'
  FROM (
      SELECT plan_id FROM mana_price_plan
       WHERE plan_code = 'default' AND scope = 'platform' AND status = 'active'
       LIMIT 1
  ) dp
  CROSS JOIN (
      -- The active catalogue price per action (latest effective_from wins),
      -- restricted to codes registered in mana_action_def.
      SELECT DISTINCT ON (action_code) action_code, mana_cost
        FROM mana_action_pricing
       WHERE deprecated_at IS NULL
         AND effective_from <= now()
         AND action_code IN (SELECT action_code FROM mana_action_def)
       ORDER BY action_code, effective_from DESC
  ) p
ON CONFLICT (plan_id, action_code, tier) DO NOTHING;

COMMIT;

-- =============================================================================
-- VERIFICATION (run manually after apply):
--
--   -- exactly one active platform plan
--   SELECT count(*) FROM mana_price_plan WHERE scope='platform' AND status='active';
--   -- => 1
--
--   -- every active catalogue price mirrored at the same cost
--   SELECT p.action_code, p.mana_cost AS catalogue, r.mana_cost AS rule
--     FROM (SELECT DISTINCT ON (action_code) action_code, mana_cost
--             FROM mana_action_pricing
--            WHERE deprecated_at IS NULL AND effective_from <= now()
--            ORDER BY action_code, effective_from DESC) p
--     JOIN mana_price_rule r ON r.action_code = p.action_code AND r.tier IS NULL
--     JOIN mana_price_plan pl ON pl.plan_id = r.plan_id
--          AND pl.scope='platform' AND pl.status='active'
--    WHERE p.mana_cost <> r.mana_cost;
--   -- => 0 rows (no price drift)
-- =============================================================================
