package kyc

import "context"

// Subject-gcid request context — carries the GCID whose verification an
// operation acts on, so a persistence adapter can scope its per-user RLS.
//
// GetLatestByGcid + Save receive the gcid directly (a method arg / the
// aggregate's Gcid). GetByID takes only a verification_id, yet the durable
// (pg) adapter still needs a gcid to satisfy the `user_isolation` RLS policy on
// kyc_verifications (migration 0003 — `gcid = current_setting('chora.user_gcid')`).
// The one GetByID call site (the Singpass callback in the http adapter) knows
// the owning gcid from the consumed state token and threads it here, keeping
// the read least-privilege — scoped to exactly that person, never an admin
// bypass. The in-memory adapter ignores the value.
type subjectGcidKey struct{}

// WithSubjectGcid returns a context carrying the GCID whose verification the
// operation acts on. Empty gcid is stored as-is; adapters that require it fail
// loud rather than silently widening scope.
func WithSubjectGcid(ctx context.Context, gcid string) context.Context {
	return context.WithValue(ctx, subjectGcidKey{}, gcid)
}

// SubjectGcidFromContext returns the subject GCID set by WithSubjectGcid, or ""
// when unset.
func SubjectGcidFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(subjectGcidKey{}).(string); ok {
		return v
	}
	return ""
}
