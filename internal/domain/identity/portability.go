// PortableSnapshot — append-only cross-tenant data export per BP-01
// (Learner Ownership). A snapshot is constructed once and never mutated: the
// repository only supports Save (append) + List, NEVER Update or Delete.
package identity

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PortableSnapshot is an immutable, append-only export envelope. The actual
// payload (atoms, sessions, social graph, etc.) is referenced by hash; the
// payload itself is stored in GCS (deferred — adapters/storage in Tier 2).
type PortableSnapshot struct {
	SnapshotID  string    `json:"snapshot_id"`
	Gcid        string    `json:"gcid"`
	Sequence    int       `json:"sequence"`
	PayloadHash string    `json:"payload_hash"`
	GeneratedAt time.Time `json:"generated_at"`
}

// NewPortableSnapshotParams is the constructor input.
type NewPortableSnapshotParams struct {
	Gcid        string
	Sequence    int
	PayloadHash string
}

// NewPortableSnapshot constructs a fresh, immutable snapshot envelope.
func NewPortableSnapshot(p NewPortableSnapshotParams) (*PortableSnapshot, error) {
	if p.Gcid == "" {
		return nil, errors.New("gcid is required")
	}
	if p.Sequence < 1 {
		return nil, fmt.Errorf("sequence must be >= 1; got %d", p.Sequence)
	}
	if p.PayloadHash == "" {
		return nil, errors.New("payload_hash is required")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7: %w", err)
	}
	return &PortableSnapshot{
		SnapshotID:  id.String(),
		Gcid:        p.Gcid,
		Sequence:    p.Sequence,
		PayloadHash: p.PayloadHash,
		GeneratedAt: time.Now().UTC(),
	}, nil
}

// AppendOnlyMarker is a no-op method that exists solely as a documentation
// guard: any new mutator added to PortableSnapshot is a code-review violation
// because the type is append-only by aggregate invariant.
func (s *PortableSnapshot) AppendOnlyMarker() {}
