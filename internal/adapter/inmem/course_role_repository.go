// In-memory implementation of identity.CourseRoleRepository plus comic-seed
// fixtures used by tests + dev. Production wiring will replace this with a
// pgx adapter against a denormalised projection in the chora_identity DB
// (refreshed via Pub/Sub from chora.delivery.* events; deferred to Tier 2).
package inmem

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// CourseRoleRepository — in-memory store keyed by (gcid|course_id).
// -----------------------------------------------------------------------------

type CourseRoleRepository struct {
	mu          sync.RWMutex
	assignments map[string]identity.CourseRoleAssignment
}

func NewCourseRoleRepository() *CourseRoleRepository {
	return &CourseRoleRepository{
		assignments: make(map[string]identity.CourseRoleAssignment),
	}
}

func key(gcid, courseID string) string {
	return strings.ToLower(gcid) + "|" + strings.ToLower(courseID)
}

// Assign registers (or replaces) an assignment. Used by seed fixtures + tests.
func (r *CourseRoleRepository) Assign(a identity.CourseRoleAssignment) error {
	if strings.TrimSpace(a.Gcid) == "" {
		return errors.New("gcid is required")
	}
	if strings.TrimSpace(a.CourseID) == "" {
		return errors.New("course_id is required")
	}
	if !a.Role.Valid() || a.Role == identity.CourseRoleNone {
		return errors.New("invalid or absent role")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.assignments[key(a.Gcid, a.CourseID)] = a
	return nil
}

// GetAssignment implements identity.CourseRoleRepository.
func (r *CourseRoleRepository) GetAssignment(_ context.Context, gcid, courseID string) (*identity.CourseRoleAssignment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.assignments[key(gcid, courseID)]
	if !ok {
		return nil, identity.ErrCourseRoleNotFound
	}
	clone := a
	return &clone, nil
}

// Upsert implements identity.CourseRoleWriter.
//
// Returns inserted=true when a new (gcid, course_id) row was created, false
// when an existing row was overwritten.
func (r *CourseRoleRepository) Upsert(_ context.Context, a identity.CourseRoleAssignment) (bool, error) {
	if strings.TrimSpace(a.Gcid) == "" {
		return false, errors.New("gcid is required")
	}
	if strings.TrimSpace(a.CourseID) == "" {
		return false, errors.New("course_id is required")
	}
	if !a.Role.Valid() || a.Role == identity.CourseRoleNone {
		return false, errors.New("invalid or absent role")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := key(a.Gcid, a.CourseID)
	_, exists := r.assignments[k]
	r.assignments[k] = a
	return !exists, nil
}

// -----------------------------------------------------------------------------
// Comic Ch4 P8 seed — used by handler tests + dev defaults in main.
//
// Phyllis Tan         01935b5a-9bcf-7000-8000-000000000001
// Mr. Chen            01935b5a-9bcf-7000-8000-000000000002
// Course CSPO         01935b5a-9bcf-7000-8000-000000000099 (Phyllis = instructor)
// Course CSM          01935b5a-9bcf-7000-8000-000000000098 (Phyllis = learner; Chen = instructor)
// Tenant MightyMind   01935b5a-9bcf-7000-8000-000000000010
// -----------------------------------------------------------------------------

const (
	ComicGcidPhyllis    = "01935b5a-9bcf-7000-8000-000000000001"
	ComicGcidChen       = "01935b5a-9bcf-7000-8000-000000000002"
	ComicCourseCSPO     = "01935b5a-9bcf-7000-8000-000000000099"
	ComicCourseCSM      = "01935b5a-9bcf-7000-8000-000000000098"
	ComicTenantMightyMS = "01935b5a-9bcf-7000-8000-000000000010"
)

// SeedComicFixtures inserts Phyllis Tan + Mr. Chen as Users and wires the
// Comic Ch4 P8 per-course role assignments into the provided repositories.
// Returns the first error encountered; otherwise nil.
//
// NOTE: We pre-mint identity.User records with the FIXED Comic GCIDs (not
// freshly-issued ones) so handler tests can reproduce Comic invariants
// deterministically.
func SeedComicFixtures(users *UserRepository, roles *CourseRoleRepository) error {
	now := time.Now().UTC()
	phyllis := &identity.User{
		Gcid:             ComicGcidPhyllis,
		Email:            "phyllis@mightymind.sg",
		DisplayName:      "Phyllis Tan",
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "google|phyllis-001",
		Status:           identity.UserStatusActive,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	chen := &identity.User{
		Gcid:             ComicGcidChen,
		Email:            "chen@mightymind.sg",
		DisplayName:      "Mr. Chen",
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "google|chen-001",
		Status:           identity.UserStatusActive,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := users.Save(context.Background(), phyllis); err != nil {
		return err
	}
	if err := users.Save(context.Background(), chen); err != nil {
		return err
	}

	for _, a := range []identity.CourseRoleAssignment{
		{Gcid: ComicGcidPhyllis, CourseID: ComicCourseCSPO, TenantID: ComicTenantMightyMS, Role: identity.CourseRoleInstructor},
		{Gcid: ComicGcidPhyllis, CourseID: ComicCourseCSM, TenantID: ComicTenantMightyMS, Role: identity.CourseRoleLearner},
		{Gcid: ComicGcidChen, CourseID: ComicCourseCSM, TenantID: ComicTenantMightyMS, Role: identity.CourseRoleInstructor},
	} {
		if err := roles.Assign(a); err != nil {
			return err
		}
	}
	return nil
}
