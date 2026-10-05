// Domain events for the KYCVerification aggregate. JSON-shaped for the
// events.Publisher port; the Pub/Sub adapter handles full Protobuf
// marshalling at M12+.
package kyc

import "time"

// EventType — name within the topic.
type EventType string

const (
	EventSubmitted EventType = "submitted"
	EventVerified  EventType = "verified"
	EventRejected  EventType = "rejected"
)

// TopicName returns the canonical Pub/Sub topic.
func TopicName(evt EventType) string {
	return "chora.identity.kyc." + string(evt) + ".v1"
}

// SubmittedPayload — canonical JSON shape for kyc.submitted.v1.
type SubmittedPayload struct {
	VerificationID  string    `json:"verification_id"`
	Gcid            string    `json:"gcid"`
	Method          string    `json:"method"`
	Provider        string    `json:"provider"`
	DocumentURI     string    `json:"document_uri,omitempty"`
	FeeChargedCents int64     `json:"fee_charged_cents"`
	Currency        string    `json:"currency,omitempty"`
	SubmittedAt     time.Time `json:"submitted_at"`
}

// SubmittedFrom builds a SubmittedPayload from a Verification aggregate.
func SubmittedFrom(v *Verification) SubmittedPayload {
	return SubmittedPayload{
		VerificationID:  v.VerificationID,
		Gcid:            v.Gcid,
		Method:          string(v.Method),
		Provider:        v.Provider,
		DocumentURI:     v.DocumentURI,
		FeeChargedCents: v.FeeChargedCents,
		Currency:        v.Currency,
		SubmittedAt:     v.UpdatedAt,
	}
}

// VerifiedPayload — canonical JSON shape for kyc.verified.v1.
type VerifiedPayload struct {
	VerificationID           string    `json:"verification_id"`
	Gcid                     string    `json:"gcid"`
	Method                   string    `json:"method"`
	Provider                 string    `json:"provider"`
	VerifiedByGcid           string    `json:"verified_by_gcid,omitempty"`
	SkillsfutureScopeGranted bool      `json:"skillsfuture_scope_granted"`
	VerifiedAt               time.Time `json:"verified_at"`
}

// VerifiedFrom builds a VerifiedPayload from a Verification aggregate.
func VerifiedFrom(v *Verification) VerifiedPayload {
	verifiedAt := time.Time{}
	if v.VerifiedAt != nil {
		verifiedAt = *v.VerifiedAt
	}
	verifiedBy := ""
	for i := len(v.AuditLog) - 1; i >= 0; i-- {
		if v.AuditLog[i].Event == "verified" {
			verifiedBy = v.AuditLog[i].ActorGcid
			break
		}
	}
	return VerifiedPayload{
		VerificationID:           v.VerificationID,
		Gcid:                     v.Gcid,
		Method:                   string(v.Method),
		Provider:                 v.Provider,
		VerifiedByGcid:           verifiedBy,
		SkillsfutureScopeGranted: v.SkillsfutureScopeGranted,
		VerifiedAt:               verifiedAt,
	}
}

// RejectedPayload — canonical JSON shape for kyc.rejected.v1.
type RejectedPayload struct {
	VerificationID string    `json:"verification_id"`
	Gcid           string    `json:"gcid"`
	Method         string    `json:"method"`
	Provider       string    `json:"provider"`
	RejectionCode  string    `json:"rejection_code"`
	RejectionNotes string    `json:"rejection_notes"`
	RetryAllowed   bool      `json:"retry_allowed"`
	RejectedAt     time.Time `json:"rejected_at"`
}

// RejectedFrom builds a RejectedPayload from a Verification aggregate.
func RejectedFrom(v *Verification) RejectedPayload {
	rejectedAt := time.Time{}
	if v.RejectedAt != nil {
		rejectedAt = *v.RejectedAt
	}
	return RejectedPayload{
		VerificationID: v.VerificationID,
		Gcid:           v.Gcid,
		Method:         string(v.Method),
		Provider:       v.Provider,
		RejectionCode:  v.RejectionCode,
		RejectionNotes: v.RejectionNotes,
		RetryAllowed:   v.RetryAllowed,
		RejectedAt:     rejectedAt,
	}
}
