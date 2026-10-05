// Append-only ManaLedger entries — the audit-grade trail of every mana
// movement. Idempotency: (gcid, idempotency_key) tuple is unique.
package user_mana

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Direction is the sign of the ledger movement.
type Direction string

const (
	DirectionCredit   Direction = "credit"
	DirectionDebit    Direction = "debit"
	DirectionMint     Direction = "mint"
	DirectionRefund   Direction = "refund"
	DirectionRollover Direction = "rollover"
)

// Valid reports whether the direction is one of the known 5.
func (d Direction) Valid() bool {
	switch d {
	case DirectionCredit, DirectionDebit, DirectionMint, DirectionRefund, DirectionRollover:
		return true
	}
	return false
}

// Reason is the audit-grade reason on each ledger movement.
type Reason string

const (
	ReasonSubscriptionGrant Reason = "subscription_grant"
	ReasonFamiliarAction    Reason = "familiar_action"
	ReasonRefund            Reason = "refund"
	ReasonAccountClosure    Reason = "account_closure"
	ReasonPromo             Reason = "promo"
	ReasonTenantSubsidy     Reason = "tenant_subsidy"
	ReasonTopup             Reason = "topup"
	ReasonRollover          Reason = "rollover"
)

// Valid reports whether the reason is one of the known 8.
func (r Reason) Valid() bool {
	switch r {
	case ReasonSubscriptionGrant, ReasonFamiliarAction, ReasonRefund, ReasonAccountClosure,
		ReasonPromo, ReasonTenantSubsidy, ReasonTopup, ReasonRollover:
		return true
	}
	return false
}

// LedgerEntry is one append-only ledger row.
type LedgerEntry struct {
	EntryID              string
	Gcid                 string
	Direction            Direction
	Units                int64
	Reason               Reason
	SourceSubscriptionID string
	SourceActionID       string
	SourceAllocationID   string
	SourceTopupID        string
	BalanceAfterUnits    int64
	IdempotencyKey       string
	RequestID            string
	ReversesEntryID      string
	RecordedAt           time.Time
}

// NewLedgerParams is the constructor input.
type NewLedgerParams struct {
	Gcid                 string
	Direction            Direction
	Units                int64
	Reason               Reason
	SourceSubscriptionID string
	SourceActionID       string
	SourceAllocationID   string
	SourceTopupID        string
	IdempotencyKey       string
	RequestID            string
	ReversesEntryID      string
	BalanceAfterUnits    int64
}

// NewLedgerEntry constructs a fresh LedgerEntry. Validates invariants.
func NewLedgerEntry(p NewLedgerParams) (*LedgerEntry, error) {
	if err := validateGcid(p.Gcid); err != nil {
		return nil, err
	}
	if err := validateUnits(p.Units); err != nil {
		return nil, err
	}
	if !p.Direction.Valid() {
		return nil, fmt.Errorf("user_mana: invalid direction %q", p.Direction)
	}
	if !p.Reason.Valid() {
		return nil, fmt.Errorf("user_mana: invalid reason %q", p.Reason)
	}
	return &LedgerEntry{
		EntryID:              newUUIDv7(),
		Gcid:                 p.Gcid,
		Direction:            p.Direction,
		Units:                p.Units,
		Reason:               p.Reason,
		SourceSubscriptionID: p.SourceSubscriptionID,
		SourceActionID:       p.SourceActionID,
		SourceAllocationID:   p.SourceAllocationID,
		SourceTopupID:        p.SourceTopupID,
		IdempotencyKey:       p.IdempotencyKey,
		RequestID:            p.RequestID,
		ReversesEntryID:      p.ReversesEntryID,
		BalanceAfterUnits:    p.BalanceAfterUnits,
		RecordedAt:           time.Now().UTC(),
	}, nil
}

// LedgerFilter — query parameters for listing entries.
type LedgerFilter struct {
	Gcid      string
	From      *time.Time
	To        *time.Time
	Direction *Direction
	Reason    *Reason
	Cursor    string
	PageSize  int
}

// ErrInvalidFilter — sentinel for malformed filter.
var ErrInvalidFilter = errors.New("user_mana: invalid ledger filter")

// EncodeLedgerCursor produces an opaque keyset cursor for paginating the ledger:
// base64url(recorded_at RFC3339Nano "|" entry_id). The next page selects rows
// strictly older than this (recorded_at, entry_id) tuple. Returns "" for a nil
// entry (the first page carries no cursor). CHO-1883.
func EncodeLedgerCursor(e *LedgerEntry) string {
	if e == nil {
		return ""
	}
	raw := e.RecordedAt.UTC().Format(time.RFC3339Nano) + "|" + e.EntryID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeLedgerCursor parses a cursor back into its (recorded_at, entry_id)
// keyset components. An empty cursor decodes to the zero value (first page); a
// malformed cursor returns ErrInvalidFilter so the caller can 400.
func DecodeLedgerCursor(cursor string) (time.Time, string, error) {
	if cursor == "" {
		return time.Time{}, "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", ErrInvalidFilter
	}
	at, id, ok := strings.Cut(string(b), "|")
	if !ok || id == "" {
		return time.Time{}, "", ErrInvalidFilter
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return time.Time{}, "", ErrInvalidFilter
	}
	return t.UTC(), id, nil
}
