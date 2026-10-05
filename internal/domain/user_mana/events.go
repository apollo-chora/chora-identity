// Domain events for user_mana / mana_ledger. JSON-shaped for the
// events.Publisher port; the Pub/Sub adapter handles full Protobuf
// marshalling at M12+.
package user_mana

import "time"

// EventType — name within the topic.
type EventType string

const (
	EventCredited      EventType = "credited"
	EventDebited       EventType = "debited"
	EventRefunded      EventType = "refunded"
	EventSnapshotTaken EventType = "snapshot_taken"
)

// TopicName returns the canonical Pub/Sub topic.
func TopicName(evt EventType) string {
	return "chora.identity.user_mana." + string(evt) + ".v1"
}

// LedgerEntryPayload — canonical JSON shape for credited/debited/refunded events.
type LedgerEntryPayload struct {
	EntryID              string    `json:"entry_id"`
	Gcid                 string    `json:"gcid"`
	Direction            string    `json:"direction"`
	Units                int64     `json:"units"`
	Reason               string    `json:"reason"`
	SourceSubscriptionID string    `json:"source_subscription_id,omitempty"`
	SourceTopupID        string    `json:"source_topup_id,omitempty"`
	SourceAllocationID   string    `json:"source_allocation_id,omitempty"`
	SourceActionID       string    `json:"source_action_id,omitempty"`
	BalanceAfterUnits    int64     `json:"balance_after_units"`
	RecordedAt           time.Time `json:"recorded_at"`
}

// LedgerEntryPayloadFrom builds a payload from a LedgerEntry.
func LedgerEntryPayloadFrom(e *LedgerEntry) LedgerEntryPayload {
	return LedgerEntryPayload{
		EntryID:              e.EntryID,
		Gcid:                 e.Gcid,
		Direction:            string(e.Direction),
		Units:                e.Units,
		Reason:               string(e.Reason),
		SourceSubscriptionID: e.SourceSubscriptionID,
		SourceTopupID:        e.SourceTopupID,
		SourceAllocationID:   e.SourceAllocationID,
		SourceActionID:       e.SourceActionID,
		BalanceAfterUnits:    e.BalanceAfterUnits,
		RecordedAt:           e.RecordedAt,
	}
}

// SnapshotPayload — canonical JSON shape for snapshot_taken.v1.
type SnapshotPayload struct {
	Gcid           string    `json:"gcid"`
	BalanceUnits   int64     `json:"balance_units"`
	LifetimeEarned int64     `json:"lifetime_earned"`
	LifetimeSpent  int64     `json:"lifetime_spent"`
	SnapshotReason string    `json:"snapshot_reason"`
	SnapshotAt     time.Time `json:"snapshot_at"`
}
