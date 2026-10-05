// In-memory adapter for user_mana.Store — re-exports the domain's
// in-memory store under the adapter package for symmetry with the other
// repos. Production pgx-backed adapter arrives at M12+.
package repo

import (
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// InMemManaStore is a thin wrapper over mana.InMemoryStore so the cmd/server
// wiring imports a single repo package for all per-user aggregates.
type InMemManaStore = mana.InMemoryStore

// NewInMemManaStore returns a fresh in-memory mana store.
func NewInMemManaStore() *InMemManaStore { return mana.NewInMemoryStore() }
