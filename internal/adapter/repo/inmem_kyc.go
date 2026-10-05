// In-memory adapter for kyc.Repository.
package repo

import (
	"context"
	"sort"
	"sync"

	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// InMemKycRepo is the in-memory implementation of kyc.Repository.
type InMemKycRepo struct {
	mu    sync.RWMutex
	store map[string]*kyc.Verification // keyed by verification_id
}

// NewInMemKycRepo constructs an empty repo.
func NewInMemKycRepo() *InMemKycRepo {
	return &InMemKycRepo{store: make(map[string]*kyc.Verification)}
}

// Save upserts.
func (r *InMemKycRepo) Save(_ context.Context, v *kyc.Verification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *v
	if v.VerifiedAt != nil {
		t := *v.VerifiedAt
		clone.VerifiedAt = &t
	}
	if v.RejectedAt != nil {
		t := *v.RejectedAt
		clone.RejectedAt = &t
	}
	if v.DeletedAt != nil {
		t := *v.DeletedAt
		clone.DeletedAt = &t
	}
	if v.ExpiresAt != nil {
		t := *v.ExpiresAt
		clone.ExpiresAt = &t
	}
	clone.AuditLog = append([]kyc.AuditEntry(nil), v.AuditLog...)
	r.store[v.VerificationID] = &clone
	return nil
}

// GetByID returns by verification_id, or ErrNotFound.
func (r *InMemKycRepo) GetByID(_ context.Context, id string) (*kyc.Verification, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.store[id]
	if !ok || v.DeletedAt != nil {
		return nil, kyc.ErrNotFound
	}
	clone := *v
	clone.AuditLog = append([]kyc.AuditEntry(nil), v.AuditLog...)
	return &clone, nil
}

// GetLatestByGcid returns the most recently updated live verification for the gcid.
func (r *InMemKycRepo) GetLatestByGcid(_ context.Context, gcid string) (*kyc.Verification, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	candidates := make([]*kyc.Verification, 0)
	for _, v := range r.store {
		if v.Gcid != gcid || v.DeletedAt != nil {
			continue
		}
		candidates = append(candidates, v)
	}
	if len(candidates) == 0 {
		return nil, kyc.ErrNotFound
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].UpdatedAt.After(candidates[j].UpdatedAt)
	})
	clone := *candidates[0]
	clone.AuditLog = append([]kyc.AuditEntry(nil), candidates[0].AuditLog...)
	return &clone, nil
}

// Compile-time guard.
var _ kyc.Repository = (*InMemKycRepo)(nil)
