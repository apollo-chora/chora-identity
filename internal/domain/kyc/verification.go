// Package kyc is the KYCVerification aggregate for the Identity supporting
// domain (chora_identity database, Team 3 / Platform). Owns verification
// lifecycle for Singpass / SkillsFuture / manual document upload per ADR-142.
//
// State machine:
//
//	pending  → submitted → verified | rejected | expired
//
// Pricing (per ADR-142): singpass / skillsfuture = $0; manual_doc = $9.99
// (configurable). Manual review SLA ~24h.
package kyc

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// Method
// -----------------------------------------------------------------------------

// Method identifies the verification provider.
type Method string

const (
	MethodSingpass     Method = "singpass"
	MethodSkillsFuture Method = "skillsfuture"
	MethodManualDoc    Method = "manual_doc"
)

// Valid reports whether the method is one of the known 3.
func (m Method) Valid() bool {
	switch m {
	case MethodSingpass, MethodSkillsFuture, MethodManualDoc:
		return true
	}
	return false
}

// DefaultFeeCents returns the default one-time fee for a given method per
// ADR-142. Singpass + SkillsFuture are $0; manual_doc is $9.99.
func DefaultFeeCents(m Method) int64 {
	switch m {
	case MethodSingpass, MethodSkillsFuture:
		return 0
	case MethodManualDoc:
		return 999
	}
	return 0
}

// -----------------------------------------------------------------------------
// Status — lifecycle
// -----------------------------------------------------------------------------

// Status of the KYC verification.
type Status string

const (
	StatusPending   Status = "pending"
	StatusSubmitted Status = "submitted"
	StatusVerified  Status = "verified"
	StatusRejected  Status = "rejected"
	StatusExpired   Status = "expired"
)

// -----------------------------------------------------------------------------
// AuditEntry — immutable audit trail row
// -----------------------------------------------------------------------------

// AuditEntry is one immutable audit-trail row for a KYCVerification.
type AuditEntry struct {
	Event      string
	ActorGcid  string
	Notes      string
	OccurredAt time.Time
}

// -----------------------------------------------------------------------------
// Verification aggregate root
// -----------------------------------------------------------------------------

// Verification is the KYC aggregate root.
//
// SingpassSub (Path A, ADR follow-up 2026-05-10): the OIDC `sub` claim from
// the Singpass NDI ID token (UUID) is the ONLY Singpass-derived attribute
// Chora persists. NRIC/FIN, name, DOB, nationality, address, family, and all
// other MyInfo fields are explicitly NOT stored — the upstream singpass
// adapter discards them on receipt. Idempotency is enforced via the partial
// unique index on kyc_verifications.singpass_sub (migration 0004), and the
// closure saga zeroes the field on SoftDelete.
type Verification struct {
	VerificationID           string
	Gcid                     string
	Method                   Method
	Status                   Status
	Provider                 string
	DocumentURI              string
	SingpassSub              string
	VerifiedAt               *time.Time
	RejectedAt               *time.Time
	RejectionCode            string
	RejectionNotes           string
	RetryAllowed             bool
	FeeChargedCents          int64
	Currency                 string
	SkillsfutureScopeGranted bool
	ExpiresAt                *time.Time
	AuditLog                 []AuditEntry

	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// NewParams is the constructor input.
type NewParams struct {
	Gcid     string
	Method   Method
	Provider string
}

// NewVerification constructs a fresh verification in `pending` state +
// records the initiating audit entry.
func NewVerification(p NewParams) (*Verification, error) {
	if strings.TrimSpace(p.Gcid) == "" {
		return nil, errors.New("kyc: gcid required")
	}
	if !p.Method.Valid() {
		return nil, fmt.Errorf("kyc: invalid method %q", p.Method)
	}
	now := time.Now().UTC()
	return &Verification{
		VerificationID: newUUIDv7(),
		Gcid:           p.Gcid,
		Method:         p.Method,
		Status:         StatusPending,
		Provider:       p.Provider,
		AuditLog: []AuditEntry{
			{Event: "initiated", OccurredAt: now},
		},
		Version:   1,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// Submit transitions pending → submitted (e.g., manual_doc upload posted,
// Singpass redirect URL handed back).
func (v *Verification) Submit(documentURI string, feeCents int64, currency string) error {
	if v.Status != StatusPending {
		return fmt.Errorf("kyc: cannot submit from %q", v.Status)
	}
	v.DocumentURI = documentURI
	v.FeeChargedCents = feeCents
	v.Currency = currency
	v.appendAudit("submitted", "", "")
	v.setStatus(StatusSubmitted)
	return nil
}

// AttachPendingDocument records the uploaded manual-doc URI while the
// verification is still pending. Used by the fee-gated manual_doc flow
// (ADR-142 + ADR-164 Stage A.5): the document is captured at submission
// time, but the verification only enters the review queue (Submit →
// submitted) once chora-payments confirms the $9.99 fee is captured via
// chora.payments.identity_kyc_fee.payment_captured.v1. Charging at
// submission gates the manual-review effort behind payment; Singpass /
// SkillsFutures learners skip the fee entirely (DefaultFeeCents == 0).
//
// Idempotent on the same URI; only valid while pending.
func (v *Verification) AttachPendingDocument(uri string) error {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return errors.New("kyc: document uri required")
	}
	if v.Status != StatusPending {
		return fmt.Errorf("kyc: cannot attach document from %q", v.Status)
	}
	if v.DocumentURI == uri {
		return nil
	}
	v.DocumentURI = uri
	v.appendAudit("document_attached", "", "")
	v.touch()
	return nil
}

// Verify transitions submitted → verified.
func (v *Verification) Verify(verifiedByGcid string, skillsfutureScope bool) error {
	if v.Status != StatusSubmitted {
		return fmt.Errorf("kyc: cannot verify from %q", v.Status)
	}
	now := time.Now().UTC()
	v.VerifiedAt = &now
	v.SkillsfutureScopeGranted = skillsfutureScope
	v.appendAudit("verified", verifiedByGcid, "")
	v.setStatus(StatusVerified)
	return nil
}

// Reject transitions submitted → rejected.
func (v *Verification) Reject(code, notes string, retryAllowed bool) error {
	if v.Status != StatusSubmitted {
		return fmt.Errorf("kyc: cannot reject from %q", v.Status)
	}
	now := time.Now().UTC()
	v.RejectedAt = &now
	v.RejectionCode = code
	v.RejectionNotes = notes
	v.RetryAllowed = retryAllowed
	v.appendAudit("rejected", "", notes)
	v.setStatus(StatusRejected)
	return nil
}

// MarkExpired transitions any non-terminal status → expired (e.g., document
// validity window passed).
func (v *Verification) MarkExpired() error {
	if v.Status == StatusExpired {
		return nil
	}
	v.appendAudit("expired", "", "")
	v.setStatus(StatusExpired)
	return nil
}

// BindSingpassSub records the Singpass NDI OIDC `sub` UUID against this
// verification (Path A, SP-2). The sub is the only Singpass-derived attribute
// Chora persists — name, NRIC, DOB, etc. are discarded by the singpass
// adapter on receipt and never reach this aggregate.
//
// Idempotent on the same sub. Re-binding to a different sub is rejected
// (the upstream uniqueness anchor in chora_identity must hold one Singpass
// account → one verification).
func (v *Verification) BindSingpassSub(sub string) error {
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return errors.New("kyc: singpass sub required")
	}
	if v.SingpassSub != "" && v.SingpassSub != sub {
		return fmt.Errorf("kyc: singpass sub already bound to a different value")
	}
	if v.SingpassSub == sub {
		return nil
	}
	v.SingpassSub = sub
	// Audit trail must NOT contain the sub itself — the field already holds
	// it, and audit entries are a privacy surface (closure tokenises the
	// field, not the audit log).
	v.appendAudit("singpass_sub_bound", "", "")
	v.touch()
	return nil
}

// SoftDelete marks the row pseudonymised — preserves audit trail per ADR-142
// closure semantics. Per migration 0004 + PII_Closure_Map.yaml the
// SingpassSub field is dropped (strategy: drop) so the federated saga's
// crypto-shred terminal step has nothing left to recover.
func (v *Verification) SoftDelete() {
	if v.DeletedAt != nil {
		return
	}
	now := time.Now().UTC()
	v.DeletedAt = &now
	v.SingpassSub = ""
	v.touch()
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func (v *Verification) appendAudit(event, actor, notes string) {
	v.AuditLog = append(v.AuditLog, AuditEntry{
		Event:      event,
		ActorGcid:  actor,
		Notes:      notes,
		OccurredAt: time.Now().UTC(),
	})
}

func (v *Verification) setStatus(next Status) {
	v.Status = next
	v.touch()
}

func (v *Verification) touch() {
	v.UpdatedAt = time.Now().UTC()
	v.Version++
}

// newUUIDv7 — RFC 9562 §5.7. Inline to keep this domain dependency-free.
func newUUIDv7() string {
	const buflen = 16
	var b [buflen]byte
	now := uint64(time.Now().UnixMilli())
	b[0] = byte(now >> 40)
	b[1] = byte(now >> 32)
	b[2] = byte(now >> 24)
	b[3] = byte(now >> 16)
	b[4] = byte(now >> 8)
	b[5] = byte(now)
	var randTail [10]byte
	_, _ = rand.Read(randTail[:])
	copy(b[6:], randTail[:])
	b[6] = (b[6] & 0x0f) | 0x70
	b[8] = (b[8] & 0x3f) | 0x80
	hexstr := hex.EncodeToString(b[:])
	return hexstr[0:8] + "-" + hexstr[8:12] + "-" + hexstr[12:16] + "-" + hexstr[16:20] + "-" + hexstr[20:32]
}
