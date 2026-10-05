-- =============================================================================
-- chora-identity : 0013_gcid_merge_and_cross_tenant_claim.up.sql
--
-- Domain        : Identity (7 supporting)
-- Database      : chora_identity
-- Author        : ADR-133 (GCID identity portability + cross-tenant claim protocol)
-- Architecture  : docs/architecture/adrs/adr-133-gcid-identity-portability.md
--                 docs/references/ddd-aggregate-map.md §3.6 + §10 (audit A2)
-- Audit reference: ~/.claude/plans/transient-hugging-dewdrop.md §4.1 A2 + §16.2 I.2
--
-- Purpose:
--   Author the two chora_identity tables that ADR-133 commits but earlier audits
--   flagged as missing. gcid_merge is the append-only audit of duplicate-unification
--   events (one GCID becomes the primary; the other becomes a retired alias).
--   cross_tenant_claim is the claim-protocol audit of cross-tenant identity
--   portability events (a learner moving from tenant A to tenant B via the
--   four-step claim protocol).
--
--   OrgUnit (the per-tenant org hierarchy: HQ / franchise / branch / campus /
--   department) lives in chora_tenancy, not chora_identity — see the parallel
--   chora-tenancy migration 0015_org_unit.up.sql for the OrgUnit DDL.
--
--   Sub-tenant linkage already exists as `tenants.parent_tenant_id` in
--   chora_tenancy.0001_initial.sql line 12 — no separate sub_tenant_link table
--   is required (audit re-confirmed 2026-05-23).
--
-- Append-only on both tables per .claude/rules/ddd-enforcement.md §4.
-- RLS-enabled — composes with multi-tenant-rls skill.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- gcid_merge — append-only audit of GCID duplicate unification events
--
-- When two GCIDs are determined to identify the same human (Singpass NRIC
-- match, OIDC email match, WebAuthn match, or admin manual review), one
-- becomes the primary (surviving) and the other becomes the alias (retired).
-- The merge record is immutable post-write per ADR-133 §"GCIDMerge".
--
-- Cross-domain references: primary_gcid + merged_gcid + verified_by_gcid all
-- reference users(gcid) within chora_identity (intra-DB FK allowed).
-- -----------------------------------------------------------------------------
CREATE TABLE gcid_merge (
    merge_id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),

    primary_gcid          UUID         NOT NULL,
    merged_gcid           UUID         NOT NULL,

    verification_method   TEXT         NOT NULL
        CHECK (verification_method IN (
            'webauthn_match',
            'oidc_email_match',
            'admin_manual',
            'singpass_nric_match'
        )),
    verified_by_gcid      UUID,
    evidence              JSONB        NOT NULL DEFAULT '{}'::jsonb,
    merge_reason          TEXT,

    merged_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CHECK (primary_gcid <> merged_gcid)
);

CREATE INDEX idx_gcid_merge_primary
    ON gcid_merge (primary_gcid, merged_at DESC);

CREATE INDEX idx_gcid_merge_merged_alias
    ON gcid_merge (merged_gcid);

CREATE UNIQUE INDEX idx_gcid_merge_alias_unique
    ON gcid_merge (merged_gcid);

-- Append-only enforcement.
CREATE OR REPLACE FUNCTION reject_gcid_merge_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'gcid_merge is append-only (ADR-133 §GCIDMerge — immutable audit)';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_gcid_merge_no_update
    BEFORE UPDATE ON gcid_merge
    FOR EACH ROW EXECUTE FUNCTION reject_gcid_merge_mutation();

CREATE TRIGGER trg_gcid_merge_no_delete
    BEFORE DELETE ON gcid_merge
    FOR EACH ROW EXECUTE FUNCTION reject_gcid_merge_mutation();

-- gcid_merge is platform-wide rather than tenant-scoped (a merge transcends
-- tenant boundaries since the GCID is cross-tenant portable). No RLS policy
-- is applied; access is gated at the application layer per the admin-only
-- merge-authority pattern in ADR-133.

-- -----------------------------------------------------------------------------
-- cross_tenant_claim — claim-protocol audit for GCID portability
--
-- ADR-133 defines a four-step claim protocol for a GCID moving from tenant A
-- to tenant B:
--   1. claim_initiated     (target tenant raises the claim)
--   2. proof_submitted     (claimant provides proof — Singpass / WebAuthn / etc.)
--   3. proof_verified      (verification authority signs off)
--   4. claim_completed     (TenantMembership granted in target tenant)
--
-- Each transition is recorded as an append-only row. The claim_id correlates
-- all four rows of a single claim.
-- -----------------------------------------------------------------------------
CREATE TABLE cross_tenant_claim (
    claim_event_id        UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id              UUID         NOT NULL,

    gcid                  UUID         NOT NULL,
    source_tenant_id      UUID,
    target_tenant_id      UUID         NOT NULL,

    transition            TEXT         NOT NULL
        CHECK (transition IN (
            'claim_initiated',
            'proof_submitted',
            'proof_verified',
            'claim_completed',
            'claim_rejected',
            'claim_expired'
        )),
    proof_method          TEXT
        CHECK (proof_method IS NULL OR proof_method IN (
            'singpass_nric',
            'webauthn',
            'oidc_email',
            'admin_manual'
        )),
    actor_gcid            UUID,
    evidence              JSONB        NOT NULL DEFAULT '{}'::jsonb,

    occurred_at           TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_cross_tenant_claim_claim_id
    ON cross_tenant_claim (claim_id, occurred_at);

CREATE INDEX idx_cross_tenant_claim_gcid
    ON cross_tenant_claim (gcid, occurred_at DESC);

CREATE INDEX idx_cross_tenant_claim_target_tenant
    ON cross_tenant_claim (target_tenant_id, occurred_at DESC);

-- Append-only enforcement.
CREATE OR REPLACE FUNCTION reject_cross_tenant_claim_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'cross_tenant_claim is append-only (ADR-133 §cross-tenant claim protocol audit)';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_cross_tenant_claim_no_update
    BEFORE UPDATE ON cross_tenant_claim
    FOR EACH ROW EXECUTE FUNCTION reject_cross_tenant_claim_mutation();

CREATE TRIGGER trg_cross_tenant_claim_no_delete
    BEFORE DELETE ON cross_tenant_claim
    FOR EACH ROW EXECUTE FUNCTION reject_cross_tenant_claim_mutation();

-- RLS scoping: a claim row references two tenants (source + target). The
-- access pattern uses target_tenant_id as the read scope (target tenant
-- admins audit incoming claims). Source tenant audit is via the claim_id
-- correlation rather than direct RLS.
ALTER TABLE cross_tenant_claim ENABLE ROW LEVEL SECURITY;
ALTER TABLE cross_tenant_claim FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON cross_tenant_claim
    FOR ALL USING (
        target_tenant_id = current_setting('chora.tenant_id', true)::uuid
        OR (source_tenant_id IS NOT NULL AND source_tenant_id = current_setting('chora.tenant_id', true)::uuid)
    );

-- -----------------------------------------------------------------------------
-- Grants handled by services/chora-identity/migrations/9999_grant_app_roles.sql.

COMMIT;
