-- =============================================================================
-- chora-identity : 0035_proctor_role.up.sql
--
-- ADR-191 — `PROCTOR` becomes a canonical role in the platform-wide role
-- vocabulary. Unlike AUTHOR (0020), PROCTOR is a JWT-EXTENSION role: it is
-- asserted via the chora-session JWT `roles` claim + propagated on
-- `x-mesh-user-roles` (like TRAINING_ADMIN / TENANT_ADMIN / PLATFORM_OPERATOR),
-- so:
--   * NO `ALTER TYPE membership_role` — the base ENUM stays clean (ADR-191 D1,
--     Alternative D rejected). PROCTOR is add-on-gated (`exam_administration`)
--     and bound per-sitting via ExamInvigilator(tenant_id, sitting_id,
--     invigilator_gcid), NOT a `tenant_memberships` row.
--   * NO `tenant_memberships` UNIQUE-index change (0020 needed one for AUTHOR
--     because AUTHOR is a stored multi-role membership; PROCTOR is not stored).
--
-- The ONLY schema effect is the single-row idempotent role_catalog seed
-- (mirrors 0014 PLATFORM_OPERATOR + 0020 AUTHOR: the 0014-lockstep rule —
-- new roles land BOTH in domain/identity/membership.go::CanonicalRoles AND
-- role_catalog). is_tenant_scoped=TRUE — PLATFORM_OPERATOR remains the sole
-- cross-tenant role (ADR-191 D1, Alternative B rejected).
-- =============================================================================

INSERT INTO role_catalog (canonical_label, is_tenant_scoped, seeded_in, notes) VALUES
    ('PROCTOR', TRUE, '0035_proctor_role',
     'ADR-191 — exam sitting invigilation (logistics only: check-in / open / close / view roster / file incident). JWT-extension + x-mesh-user-roles; add-on-gated (exam_administration); NOT in the membership_role ENUM; bound per-sitting via ExamInvigilator. Content-embargoed: a PROCTOR-claimed caller is excluded from learning_atoms / atom_revisions content by a RESTRICTIVE RLS policy in chora_creation (mig 0028) + a 403 EXAM_CONTENT_EMBARGO_VIOLATION at the content boundary. Tenant-scoped — PLATFORM_OPERATOR remains the sole cross-tenant role.')
ON CONFLICT (canonical_label) DO NOTHING;
