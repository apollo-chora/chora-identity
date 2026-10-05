-- =============================================================================
-- chora-identity : 0035_proctor_role.down.sql
--
-- Best-effort reverse of 0035. role_catalog is append-only by design (mirrors
-- 0020.down): mark the note rather than DELETE the row, so any historically
-- issued PROCTOR JWTs are visibly flagged as no-longer-asserted rather than
-- silently vanishing from the registry. No ENUM / index changes were made by
-- 0035.up (PROCTOR is a JWT-extension role), so none are reversed here.
-- =============================================================================

UPDATE role_catalog
SET    notes = notes || ' [ROLLED BACK by 0035.down — do not assert on JWTs]'
WHERE  canonical_label = 'PROCTOR';
