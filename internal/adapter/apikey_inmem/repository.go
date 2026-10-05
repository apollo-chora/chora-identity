// Package apikey_inmem is the in-memory implementation of
// internal/domain/apikey.Repository.
//
// Used in tests + the M10 skeleton; Cloud SQL (chora_identity.api_keys table)
// is deferred to Tier 2 — the schema is in migrations/0006_api_keys.sql.
//
// Hexagonal: ADAPTER. Imports domain (apikey package) only; no other adapter
// dependencies. Tests use this directly; production wiring (M12+) swaps in
// the pg.Repository.
package apikey_inmem

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/apikey"
)

// Repository is the in-memory Repository implementation.
type Repository struct {
	mu   sync.RWMutex
	keys map[string]*apikey.APIKey // keyed by key ID
}

// NewRepository constructs an empty Repository.
func NewRepository() *Repository {
	return &Repository{keys: make(map[string]*apikey.APIKey)}
}

// ListByGcid returns all API keys owned by the GCID (active + revoked).
// Results are sorted by CreatedAt ASC for deterministic test assertions.
func (r *Repository) ListByGcid(_ context.Context, gcid string) ([]apikey.APIKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]apikey.APIKey, 0, len(r.keys))
	for _, k := range r.keys {
		if k.Gcid != gcid {
			continue
		}
		clone := *k
		clone.Scopes = append([]string(nil), k.Scopes...)
		out = append(out, clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// Save upserts the API key.
func (r *Repository) Save(_ context.Context, k *apikey.APIKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *k
	clone.Scopes = append([]string(nil), k.Scopes...)
	r.keys[k.ID] = &clone
	return nil
}

// Revoke marks the API key as revoked (sets RevokedAt = now).
// Returns apikey.ErrNotFound if the ID is unknown.
func (r *Repository) Revoke(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k, ok := r.keys[id]
	if !ok {
		return apikey.ErrNotFound
	}
	now := time.Now().UTC()
	k.RevokedAt = &now
	return nil
}
