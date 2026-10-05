// Repository port for the kyc aggregate. Hexagonal: adapters implement;
// domain never imports adapters.
package kyc

import (
	"context"
	"errors"
)

// ErrNotFound — sentinel for missing verifications.
var ErrNotFound = errors.New("kyc: verification not found")

// Repository is the persistence port.
type Repository interface {
	Save(ctx context.Context, v *Verification) error
	GetByID(ctx context.Context, verificationID string) (*Verification, error)
	GetLatestByGcid(ctx context.Context, gcid string) (*Verification, error)
}
