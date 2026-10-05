-- =============================================================================
-- chora-identity : 0026_pending_invites.up.sql
--
-- WS3 / CHO-1873 (ADR-194 D2) — cold-invite / pending-membership.
--
-- A pending_invite is keyed by EMAIL, not gcid: the invitee may never have
-- logged in, so there is NO gcid (and therefore NO users(gcid) FK) until the
-- invite is accepted at first resolve. `accepted_gcid` is filled in then.
--
-- Admin CRUD is tenant-scoped via the `tenant_isolation` RLS policy
-- (RunInTenantTx). The resolve-time cross-tenant email match runs through the
-- SECURITY DEFINER `match_pending_invites_by_email()` function below (mirroring
-- chora-tenancy 0011) — surgically scoped to a READ; the membership writes that
-- follow run RLS-scoped via RunInTenantTx (ADR-194 D2: SECURITY DEFINER is the
-- read-only matcher only, never a membership write under definer rights).
--
-- HARD RULE: cross-database queries forbidden. chora_identity-local only.
-- =============================================================================

BEGIN;

CREATE TYPE pending_invite_status AS ENUM ('pending', 'accepted', 'revoked', 'expired');

CREATE TABLE pending_invites (
    invite_id        UUID                  PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID                  NOT NULL,
    email            VARCHAR(320)          NOT NULL,
    roles            TEXT[]                NOT NULL,
    invited_by_gcid  UUID                  NOT NULL,
    token            UUID                  NOT NULL,
    status           pending_invite_status NOT NULL DEFAULT 'pending',
    expires_at       TIMESTAMPTZ           NOT NULL,
    accepted_at      TIMESTAMPTZ           NULL,
    accepted_gcid    UUID                  NULL,
    created_at       TIMESTAMPTZ           NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ           NOT NULL DEFAULT now(),
    CHECK (array_length(roles, 1) >= 1)
);

-- At most ONE live pending invite per (tenant, email). A revoked / accepted /
-- expired invite does NOT block a fresh re-invite (partial index).
CREATE UNIQUE INDEX uq_pending_invites_tenant_email_pending
    ON pending_invites (tenant_id, lower(email))
    WHERE status = 'pending';

-- Resolve-time cross-tenant probe goes by lower(email).
CREATE INDEX idx_pending_invites_email  ON pending_invites (lower(email));
CREATE INDEX idx_pending_invites_tenant ON pending_invites (tenant_id);
CREATE INDEX idx_pending_invites_token  ON pending_invites (token);

CREATE TRIGGER trg_pending_invites_updated_at
    BEFORE UPDATE ON pending_invites
    FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();

ALTER TABLE pending_invites ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pending_invites
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON pending_invites TO chora_identity_app_rw;
GRANT SELECT ON pending_invites TO chora_identity_app_ro;

-- Cross-tenant email matcher (mirrors chora-tenancy 0011). app_rw is
-- NOBYPASSRLS (0025) and the resolve seam sets no tenant GUC, so it cannot see
-- invites across tenants under tenant_isolation; this owner-privileged function
-- with row_security off is the surgically-scoped read for exactly that lookup.
CREATE OR REPLACE FUNCTION match_pending_invites_by_email(p_email text)
RETURNS TABLE (
    invite_id  uuid,
    tenant_id  uuid,
    roles      text[],
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET row_security = off
SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
        SELECT pi.invite_id, pi.tenant_id, pi.roles, pi.expires_at
        FROM   pending_invites pi
        WHERE  lower(pi.email) = lower(p_email)
          AND  pi.status = 'pending'::pending_invite_status
          AND  pi.expires_at > now()
        ORDER BY pi.created_at ASC;
END;
$$;

GRANT EXECUTE ON FUNCTION match_pending_invites_by_email(text) TO chora_identity_app_rw;

COMMIT;

-- =============================================================================
-- VERIFICATION (manual, after apply):
--   -- one live pending per (tenant,email):
--   INSERT INTO pending_invites (tenant_id,email,roles,invited_by_gcid,token,expires_at)
--     VALUES ('<t>','a@b.sg','{instructor}','<g>',gen_random_uuid(),now()+interval '14 days');
--   -- a second pending for the same (tenant,email) must violate the partial UNIQUE.
--   -- matcher returns it across tenants with no GUC set:
--   SELECT * FROM match_pending_invites_by_email('a@b.sg');
-- =============================================================================
