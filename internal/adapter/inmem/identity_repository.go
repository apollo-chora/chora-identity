// Package inmem is the in-memory implementation of the Identity domain
// repository ports. Used for tests + the M10 skeleton; Cloud SQL is deferred
// to Tier 2 (chora_identity database).
package inmem

import (
	"context"
	"sort"
	"sync"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// User repository
// -----------------------------------------------------------------------------

type UserRepository struct {
	mu    sync.RWMutex
	users map[string]*identity.User // keyed by gcid
}

func NewUserRepository() *UserRepository {
	return &UserRepository{users: make(map[string]*identity.User)}
}

func (r *UserRepository) Save(_ context.Context, u *identity.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *u
	r.users[u.Gcid] = &clone
	return nil
}

func (r *UserRepository) GetByGcid(_ context.Context, gcid string) (*identity.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.users[gcid]
	if !ok {
		return nil, identity.ErrUserNotFound
	}
	clone := *u
	return &clone, nil
}

// FindByFederatedSubject returns the User whose FederatedSubject matches sub,
// or (nil, false) if none. Used by the Identity Platform Blocking Function
// handler for idempotency on beforeCreate retries + beforeSignIn lookups.
//
// O(n) scan — acceptable for the in-memory MVP. Production wires a unique
// index on (federated_subject, identity_provider) in chora_identity.users.
func (r *UserRepository) FindByFederatedSubject(sub string) (*identity.User, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if u.FederatedSubject == sub {
			clone := *u
			return &clone, true
		}
	}
	return nil, false
}

// AllForTest returns a defensive copy of all users for assertions in tests.
// NOT used in production code paths — naming is explicit.
func (r *UserRepository) AllForTest() []*identity.User {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*identity.User, 0, len(r.users))
	for _, u := range r.users {
		clone := *u
		out = append(out, &clone)
	}
	return out
}

// -----------------------------------------------------------------------------
// Membership repository
// -----------------------------------------------------------------------------

type MembershipRepository struct {
	mu          sync.RWMutex
	memberships map[string]*identity.TenantMembership // keyed by membership_id
	// Composite key (gcid|tenant_id) -> membership_id, for duplicate detection.
	pairs map[string]string
}

func NewMembershipRepository() *MembershipRepository {
	return &MembershipRepository{
		memberships: make(map[string]*identity.TenantMembership),
		pairs:       make(map[string]string),
	}
}

func (r *MembershipRepository) AddMembership(_ context.Context, m *identity.TenantMembership) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	pairKey := m.Gcid + "|" + m.TenantID
	if _, exists := r.pairs[pairKey]; exists {
		return identity.ErrMembershipExists
	}
	clone := *m
	clone.AuditTrail = append([]identity.RoleAuditEntry(nil), m.AuditTrail...)
	r.memberships[m.MembershipID] = &clone
	r.pairs[pairKey] = m.MembershipID
	return nil
}

func (r *MembershipRepository) GetByID(_ context.Context, id string) (*identity.TenantMembership, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.memberships[id]
	if !ok {
		return nil, identity.ErrMembershipNotFound
	}
	clone := *m
	clone.AuditTrail = append([]identity.RoleAuditEntry(nil), m.AuditTrail...)
	return &clone, nil
}

func (r *MembershipRepository) List(_ context.Context, f identity.MembershipFilter) ([]*identity.TenantMembership, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*identity.TenantMembership, 0, len(r.memberships))
	for _, m := range r.memberships {
		if f.TenantID != "" && m.TenantID != f.TenantID {
			continue
		}
		if f.Gcid != "" && m.Gcid != f.Gcid {
			continue
		}
		clone := *m
		clone.AuditTrail = append([]identity.RoleAuditEntry(nil), m.AuditTrail...)
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (r *MembershipRepository) UpdateRole(_ context.Context, m *identity.TenantMembership) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.memberships[m.MembershipID]; !ok {
		return identity.ErrMembershipNotFound
	}
	clone := *m
	clone.AuditTrail = append([]identity.RoleAuditEntry(nil), m.AuditTrail...)
	r.memberships[m.MembershipID] = &clone
	return nil
}

// -----------------------------------------------------------------------------
// Snapshot repository — append-only
// -----------------------------------------------------------------------------

type SnapshotRepository struct {
	mu        sync.RWMutex
	snapshots map[string]*identity.PortableSnapshot // keyed by snapshot_id
}

func NewSnapshotRepository() *SnapshotRepository {
	return &SnapshotRepository{snapshots: make(map[string]*identity.PortableSnapshot)}
}

func (r *SnapshotRepository) Append(_ context.Context, s *identity.PortableSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.snapshots[s.SnapshotID]; exists {
		// Append-only invariant: same SnapshotID cannot be re-appended.
		return identity.ErrSnapshotImmutable
	}
	clone := *s
	r.snapshots[s.SnapshotID] = &clone
	return nil
}

func (r *SnapshotRepository) List(_ context.Context, gcid string) ([]*identity.PortableSnapshot, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*identity.PortableSnapshot, 0)
	for _, s := range r.snapshots {
		if s.Gcid != gcid {
			continue
		}
		clone := *s
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Sequence < out[j].Sequence
	})
	return out, nil
}

func (r *SnapshotRepository) NextSequence(_ context.Context, gcid string) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	max := 0
	for _, s := range r.snapshots {
		if s.Gcid != gcid {
			continue
		}
		if s.Sequence > max {
			max = s.Sequence
		}
	}
	return max + 1, nil
}
