-- =============================================================================
-- chora-identity : 0002_user_economy.sql
--
-- Domain        : Identity (supporting/platform)
-- Database      : chora_identity
-- Author        : agent-ace64673342d4a161 (BE-USR-1, ADR-142)
-- Date          : 2026-05-09
-- Architecture  : Architecture Review locked 2026-05-07 (Tier 1 D1) + ADR-142
--                 (per-user Familiar mana economy + KYC pricing)
--
-- Adds:
--   - user_subscriptions       — per-user Familiar plan aggregate (3 tiers)
--   - user_mana                — per-GCID wallet snapshot (one row per gcid)
--   - mana_ledger              — append-only ledger (month-partitioned)
--   - mana_action_pricing      — config table for action_code → mana_cost
--   - kyc_verifications        — KYCVerification aggregate + audit log JSONB
--   - users.kyc_*              — KYC summary projection on User (ADR-142)
--
-- All migrations are idempotent: guarded with `DO $$ BEGIN IF NOT EXISTS ... `
-- patterns or `IF NOT EXISTS` clauses so re-running is safe.
--
-- HARD INVARIANT: cross-database queries forbidden — these tables are local
-- to chora_identity. Cross-domain reads (e.g., TenantManaPool source in
-- chora_tenancy) flow exclusively via Pub/Sub events.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- ENUMs (idempotent guards)
-- -----------------------------------------------------------------------------
DO $$ BEGIN
    CREATE TYPE subscription_status AS ENUM (
        'pending_activation', 'active', 'paused', 'cancelled', 'expired', 'grace'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE billing_period AS ENUM ('monthly', 'annually');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE familiar_tier AS ENUM (
        'familiar_basic', 'familiar_standard', 'familiar_premium'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE mana_direction AS ENUM (
        'credit', 'debit', 'mint', 'refund', 'rollover'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE mana_reason AS ENUM (
        'subscription_grant', 'familiar_action', 'refund',
        'account_closure', 'promo', 'tenant_subsidy', 'topup', 'rollover'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE kyc_method AS ENUM ('singpass', 'skillsfuture', 'manual_doc');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE kyc_status AS ENUM (
        'pending', 'submitted', 'verified', 'rejected', 'expired'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE verification_status AS ENUM (
        'unverified', 'pending', 'verified', 'rejected', 'expired'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- -----------------------------------------------------------------------------
-- users — extend with KYC summary projection (ADR-142 fast-path)
-- -----------------------------------------------------------------------------
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS kyc_method          kyc_method,
    ADD COLUMN IF NOT EXISTS kyc_verified_at     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS verification_status verification_status NOT NULL DEFAULT 'unverified';

CREATE INDEX IF NOT EXISTS idx_users_verification_status
    ON users (verification_status) WHERE deleted_at IS NULL;

-- -----------------------------------------------------------------------------
-- user_subscriptions — per-user Familiar plan aggregate
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_subscriptions (
    subscription_id          UUID                   PRIMARY KEY,
    gcid                     UUID                   NOT NULL REFERENCES users(gcid) ON DELETE RESTRICT,
    tenant_id                UUID,                                     -- nullable: cross-tenant subscriptions
    plan_code                VARCHAR(64)            NOT NULL,
    tier                     familiar_tier          NOT NULL,
    status                   subscription_status    NOT NULL DEFAULT 'pending_activation',
    billing_period           billing_period         NOT NULL,
    mana_monthly_units       BIGINT                 NOT NULL CHECK (mana_monthly_units >= 0),
    onboarding_bonus_units   BIGINT                 NOT NULL DEFAULT 0 CHECK (onboarding_bonus_units >= 0),
    stripe_subscription_id   VARCHAR(128),
    current_period_start     TIMESTAMPTZ            NOT NULL,
    current_period_end       TIMESTAMPTZ            NOT NULL,
    prior_plan_code          VARCHAR(64),
    cancellation_reason      TEXT,
    cancelled_at             TIMESTAMPTZ,
    cancelled_by_gcid        UUID,
    version                  BIGINT                 NOT NULL DEFAULT 1,    -- OCC
    created_at               TIMESTAMPTZ            NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ            NOT NULL DEFAULT now(),
    deleted_at               TIMESTAMPTZ,
    CHECK (current_period_end >= current_period_start),
    CHECK (lower(gcid::text) NOT LIKE '0197a%')
);

CREATE INDEX IF NOT EXISTS idx_user_subscriptions_gcid
    ON user_subscriptions (gcid) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_status
    ON user_subscriptions (status) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_stripe
    ON user_subscriptions (stripe_subscription_id) WHERE stripe_subscription_id IS NOT NULL;

DO $$ BEGIN
    CREATE TRIGGER trg_user_subscriptions_updated_at
        BEFORE UPDATE ON user_subscriptions
        FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- -----------------------------------------------------------------------------
-- user_mana — one row per gcid; OCC version on every write
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_mana (
    gcid               UUID         PRIMARY KEY REFERENCES users(gcid) ON DELETE RESTRICT,
    balance_units      BIGINT       NOT NULL DEFAULT 0 CHECK (balance_units >= 0),
    lifetime_earned    BIGINT       NOT NULL DEFAULT 0 CHECK (lifetime_earned >= 0),
    lifetime_spent     BIGINT       NOT NULL DEFAULT 0 CHECK (lifetime_spent >= 0),
    last_credited_at   TIMESTAMPTZ,
    version            BIGINT       NOT NULL DEFAULT 1,                  -- OCC int8
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_mana_updated_at
    ON user_mana (updated_at);

DO $$ BEGIN
    CREATE TRIGGER trg_user_mana_updated_at
        BEFORE UPDATE ON user_mana
        FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- -----------------------------------------------------------------------------
-- mana_ledger — append-only audit trail; partitioned by month for time-range
-- queries + retention. Default partition created at migration time covers the
-- current month; ops scripts add subsequent partitions.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mana_ledger (
    entry_id                 UUID            NOT NULL,
    gcid                     UUID            NOT NULL,
    direction                mana_direction  NOT NULL,
    units                    BIGINT          NOT NULL CHECK (units > 0),
    reason                   mana_reason     NOT NULL,
    source_subscription_id   UUID,
    source_action_id         VARCHAR(128),
    source_allocation_id     UUID,
    source_topup_id          UUID,
    balance_after_units      BIGINT          NOT NULL,
    idempotency_key          VARCHAR(128)    NOT NULL,
    request_id               VARCHAR(128),
    reverses_entry_id        UUID,
    recorded_at              TIMESTAMPTZ     NOT NULL DEFAULT now(),
    PRIMARY KEY (entry_id, recorded_at)
) PARTITION BY RANGE (recorded_at);

-- Default partition covers the current month — production ops bootstraps the
-- next 12 months at migration time and rotates monthly via a Cloud Scheduler job.
DO $$
DECLARE
    start_of_month DATE := date_trunc('month', now())::DATE;
    next_month     DATE := (date_trunc('month', now()) + INTERVAL '1 month')::DATE;
    pname          TEXT := 'mana_ledger_' || to_char(start_of_month, 'YYYY_MM');
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class WHERE relname = pname
    ) THEN
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF mana_ledger FOR VALUES FROM (%L) TO (%L)',
            pname, start_of_month, next_month
        );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_mana_ledger_gcid_recorded_at
    ON mana_ledger (gcid, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_mana_ledger_idempotency
    ON mana_ledger (gcid, idempotency_key);
CREATE INDEX IF NOT EXISTS idx_mana_ledger_action_code
    ON mana_ledger (source_action_id) WHERE source_action_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mana_ledger_allocation
    ON mana_ledger (source_allocation_id) WHERE source_allocation_id IS NOT NULL;

-- mana_ledger is APPEND-ONLY — block UPDATE / DELETE at the trigger layer.
CREATE OR REPLACE FUNCTION enforce_mana_ledger_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'mana_ledger is append-only: % rejected', TG_OP;
END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
    CREATE TRIGGER trg_mana_ledger_no_update
        BEFORE UPDATE ON mana_ledger
        FOR EACH ROW EXECUTE FUNCTION enforce_mana_ledger_append_only();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TRIGGER trg_mana_ledger_no_delete
        BEFORE DELETE ON mana_ledger
        FOR EACH ROW EXECUTE FUNCTION enforce_mana_ledger_append_only();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- -----------------------------------------------------------------------------
-- mana_action_pricing — config table mapping action_code → mana_cost. Editable
-- via admin tooling; effective_from supports rollouts and historical price
-- audits.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mana_action_pricing (
    action_code      VARCHAR(64)   NOT NULL,
    mana_cost        BIGINT        NOT NULL CHECK (mana_cost >= 0),
    description      TEXT          NOT NULL DEFAULT '',
    effective_from   TIMESTAMPTZ   NOT NULL DEFAULT now(),
    deprecated_at    TIMESTAMPTZ,
    PRIMARY KEY (action_code, effective_from)
);

CREATE INDEX IF NOT EXISTS idx_mana_action_pricing_active
    ON mana_action_pricing (action_code) WHERE deprecated_at IS NULL;

-- Seed the ADR-142 default pricing schedule. INSERT ... ON CONFLICT DO NOTHING
-- to keep migration idempotent.
INSERT INTO mana_action_pricing (action_code, mana_cost, description) VALUES
    ('summon_familiar',          0,    'Pure game mechanic — no cost'),
    ('daily_dose_deterministic', 0,    'SM-2 spaced repetition — no LLM'),
    ('daily_dose_coach',         10,   'Daily Dose with LLM-backed coach'),
    ('atom_authoring_assist',    25,   'Single LLM call for atom authoring'),
    ('question_generation',      50,   'Instructor question generation + validation'),
    ('familiar_chat',            20,   'Familiar feedback / comments / chat per turn'),
    ('knowledge_graph_traverse', 100,  'RAG-assisted knowledge graph traversal'),
    ('boss_challenge_atom_gen',  200,  'Multi-step boss challenge atom generation'),
    ('coach_session_full',       500,  'Full multi-turn exam-prep coach session')
ON CONFLICT (action_code, effective_from) DO NOTHING;

-- -----------------------------------------------------------------------------
-- mana_subsidy_allocations — local projection of TenantManaAllocation sourced
-- from chora.tenancy.tenant_mana_allocation.granted.v1 (cross-domain via
-- Pub/Sub). The source-of-truth is in chora_tenancy; we keep a denormalised
-- copy here so the FIFO Spend Order can run inside chora_identity without
-- crossing the database boundary.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mana_subsidy_allocations (
    allocation_id    UUID         PRIMARY KEY,
    gcid             UUID         NOT NULL REFERENCES users(gcid) ON DELETE RESTRICT,
    tenant_id        UUID         NOT NULL,
    remaining_units  BIGINT       NOT NULL CHECK (remaining_units >= 0),
    expires_at       TIMESTAMPTZ,
    allocated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mana_subsidy_alloc_gcid_expiry
    ON mana_subsidy_allocations (gcid, expires_at NULLS LAST, allocated_at);

-- -----------------------------------------------------------------------------
-- kyc_verifications — KYCVerification aggregate
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kyc_verifications (
    verification_id              UUID         PRIMARY KEY,
    gcid                         UUID         NOT NULL REFERENCES users(gcid) ON DELETE RESTRICT,
    method                       kyc_method   NOT NULL,
    status                       kyc_status   NOT NULL DEFAULT 'pending',
    provider                     VARCHAR(64)  NOT NULL DEFAULT '',
    document_uri                 TEXT,                                          -- GCS opaque path
    verified_at                  TIMESTAMPTZ,
    rejected_at                  TIMESTAMPTZ,
    rejection_code               VARCHAR(64),
    rejection_notes              TEXT,
    retry_allowed                BOOLEAN      NOT NULL DEFAULT TRUE,
    fee_charged_cents            BIGINT,
    currency                     CHAR(3),
    skillsfuture_scope_granted   BOOLEAN      NOT NULL DEFAULT FALSE,
    expires_at                   TIMESTAMPTZ,
    audit_log                    JSONB        NOT NULL DEFAULT '[]'::jsonb,
    version                      BIGINT       NOT NULL DEFAULT 1,
    created_at                   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at                   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at                   TIMESTAMPTZ,
    CHECK (lower(gcid::text) NOT LIKE '0197a%')
);

CREATE INDEX IF NOT EXISTS idx_kyc_verifications_gcid
    ON kyc_verifications (gcid) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_kyc_verifications_status
    ON kyc_verifications (status) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_kyc_verifications_method
    ON kyc_verifications (method) WHERE deleted_at IS NULL;

DO $$ BEGIN
    CREATE TRIGGER trg_kyc_verifications_updated_at
        BEFORE UPDATE ON kyc_verifications
        FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

COMMIT;
