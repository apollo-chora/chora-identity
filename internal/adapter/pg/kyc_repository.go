// kyc_repository.go — pgx-backed implementation of kyc.Repository (the durable
// KYCVerification aggregate store).
//
// The W4 Exam BC candidate-admission gate (ADR-190 D2) refuses to admit unless
// chora-identity reports the candidate's GCID as VERIFIED. That claim is read
// via GET /internal/v1/identity/verification-status → kyc.Repository
// .GetLatestByGcid. With the in-memory repo the store is empty on every pod
// start, so the gate refuses ALL candidates. This adapter makes the claim
// durable against the existing kyc_verifications table (migrations 0002/0004;
// the `user_isolation` RLS policy, migration 0003).
//
// RLS axis: kyc_verifications carries `user_isolation` keyed on
// chora.user_gcid (migration 0003 — `gcid = current_setting('chora.user_gcid')
// OR chora.role = 'admin'`). KYC is identity-personal, NOT tenant-scoped — a
// verification claim follows the GCID across tenants. Every method therefore
// runs inside RunInUserTx scoped to the OWNING gcid: Save uses the aggregate's
// Gcid, GetLatestByGcid its gcid argument, and GetByID the subject gcid threaded
// through the request context (kyc.WithSubjectGcid) by the one caller that has
// only a verification_id (the Singpass callback). No admin bypass is used.
//
// Semantics mirror the in-memory adapter it replaces: last-write-wins upsert
// keyed on verification_id; reads filter `deleted_at IS NULL`; ErrNoRows maps
// to kyc.ErrNotFound.
//
// Cross-DB queries forbidden — chora-identity reads only chora_identity.
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// KycRepository is the pgx-backed kyc.Repository.
type KycRepository struct {
	txr UserTxQuerier
}

// NewKycRepository wraps a UserTxQuerier (production: *PgxPoolQuerier).
func NewKycRepository(txr UserTxQuerier) *KycRepository {
	return &KycRepository{txr: txr}
}

// Compile-time check.
var _ kyc.Repository = (*KycRepository)(nil)

// kycSelectColumns is the column order shared by GetByID + GetLatestByGcid and
// consumed by scanVerification. Keep the SELECT list, the scan dest order, and
// the adapter test's 21-dest expectation in lockstep.
const kycSelectColumns = `verification_id, gcid, method, status, provider,
	document_uri, singpass_sub, verified_at, rejected_at, rejection_code,
	rejection_notes, retry_allowed, fee_charged_cents, currency,
	skillsfuture_scope_granted, expires_at, audit_log, version,
	created_at, updated_at, deleted_at`

// auditEntryDTO is the stable on-disk (jsonb) shape of a kyc.AuditEntry. Snake
// case keys so the audit_log column is legible to O+ compliance surfaces.
type auditEntryDTO struct {
	Event      string    `json:"event"`
	ActorGcid  string    `json:"actor_gcid"`
	Notes      string    `json:"notes"`
	OccurredAt time.Time `json:"occurred_at"`
}

// Save upserts the verification, scoped to its owning gcid so the per-user RLS
// policy permits the write. Last-write-wins on verification_id (parity with the
// in-memory adapter — the kyc.Repository port defines no OCC contract).
func (r *KycRepository) Save(ctx context.Context, v *kyc.Verification) error {
	if v == nil {
		return errors.New("pg.KycRepository.Save: nil verification")
	}
	auditRaw, err := marshalAuditLog(v.AuditLog)
	if err != nil {
		return fmt.Errorf("pg.KycRepository.Save: marshal audit_log: %w", err)
	}
	return r.txr.RunInUserTx(ctx, v.Gcid, "", func(ctx context.Context, tx Tx) error {
		return tx.Exec(ctx, `
			INSERT INTO kyc_verifications
			    (verification_id, gcid, method, status, provider,
			     document_uri, singpass_sub, verified_at, rejected_at, rejection_code,
			     rejection_notes, retry_allowed, fee_charged_cents, currency,
			     skillsfuture_scope_granted, expires_at, audit_log, version,
			     created_at, updated_at, deleted_at)
			VALUES ($1, $2, $3::kyc_method, $4::kyc_status, $5,
			        $6, $7, $8, $9, $10,
			        $11, $12, $13, $14,
			        $15, $16, $17, $18,
			        $19, $20, $21)
			ON CONFLICT (verification_id) DO UPDATE SET
			    status                     = EXCLUDED.status,
			    provider                   = EXCLUDED.provider,
			    document_uri               = EXCLUDED.document_uri,
			    singpass_sub               = EXCLUDED.singpass_sub,
			    verified_at                = EXCLUDED.verified_at,
			    rejected_at                = EXCLUDED.rejected_at,
			    rejection_code             = EXCLUDED.rejection_code,
			    rejection_notes            = EXCLUDED.rejection_notes,
			    retry_allowed              = EXCLUDED.retry_allowed,
			    fee_charged_cents          = EXCLUDED.fee_charged_cents,
			    currency                   = EXCLUDED.currency,
			    skillsfuture_scope_granted = EXCLUDED.skillsfuture_scope_granted,
			    expires_at                 = EXCLUDED.expires_at,
			    audit_log                  = EXCLUDED.audit_log,
			    version                    = EXCLUDED.version,
			    updated_at                 = EXCLUDED.updated_at,
			    deleted_at                 = EXCLUDED.deleted_at`,
			v.VerificationID, v.Gcid, string(v.Method), string(v.Status), v.Provider,
			nullText(v.DocumentURI), nullUUID(v.SingpassSub), v.VerifiedAt, v.RejectedAt, nullText(v.RejectionCode),
			nullText(v.RejectionNotes), v.RetryAllowed, v.FeeChargedCents, nullText(v.Currency),
			v.SkillsfutureScopeGranted, v.ExpiresAt, auditRaw, v.Version,
			v.CreatedAt, v.UpdatedAt, v.DeletedAt)
	})
}

// GetByID returns a live verification by its id, scoped to the subject gcid
// carried in ctx (kyc.WithSubjectGcid). Fails loud when no subject gcid is
// present — a missing RLS scope must never masquerade as ErrNotFound, which
// would false-negative the admission gate.
func (r *KycRepository) GetByID(ctx context.Context, verificationID string) (*kyc.Verification, error) {
	subject := kyc.SubjectGcidFromContext(ctx)
	if subject == "" {
		return nil, fmt.Errorf("pg.KycRepository.GetByID: subject gcid required in context for RLS scope (verification_id=%s)", verificationID)
	}
	var out *kyc.Verification
	err := r.txr.RunInUserTx(ctx, subject, "", func(ctx context.Context, tx Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+kycSelectColumns+`
			  FROM kyc_verifications
			 WHERE verification_id = $1 AND deleted_at IS NULL`, verificationID)
		v, err := scanVerification(row)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// GetLatestByGcid returns the most-recently-updated live verification for a
// gcid, or kyc.ErrNotFound.
func (r *KycRepository) GetLatestByGcid(ctx context.Context, gcid string) (*kyc.Verification, error) {
	var out *kyc.Verification
	err := r.txr.RunInUserTx(ctx, gcid, "", func(ctx context.Context, tx Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+kycSelectColumns+`
			  FROM kyc_verifications
			 WHERE gcid = $1 AND deleted_at IS NULL
			 ORDER BY updated_at DESC
			 LIMIT 1`, gcid)
		v, err := scanVerification(row)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// scanVerification maps one kyc_verifications row (kycSelectColumns order) into
// the aggregate, mapping ErrNoRows → kyc.ErrNotFound and nullable columns back
// to their zero values.
func scanVerification(row Row) (*kyc.Verification, error) {
	var (
		v              kyc.Verification
		method, status string
		documentURI    *string
		singpassSub    *string
		verifiedAt     *time.Time
		rejectedAt     *time.Time
		rejectionCode  *string
		rejectionNotes *string
		feeCents       *int64
		currency       *string
		expiresAt      *time.Time
		auditRaw       []byte
		deletedAt      *time.Time
	)
	if err := row.Scan(
		&v.VerificationID, &v.Gcid, &method, &status, &v.Provider,
		&documentURI, &singpassSub, &verifiedAt, &rejectedAt, &rejectionCode,
		&rejectionNotes, &v.RetryAllowed, &feeCents, &currency, &v.SkillsfutureScopeGranted,
		&expiresAt, &auditRaw, &v.Version, &v.CreatedAt, &v.UpdatedAt, &deletedAt,
	); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, kyc.ErrNotFound
		}
		return nil, fmt.Errorf("pg.KycRepository: scan verification: %w", err)
	}
	v.Method = kyc.Method(method)
	v.Status = kyc.Status(status)
	v.DocumentURI = deref(documentURI)
	v.SingpassSub = deref(singpassSub)
	v.VerifiedAt = verifiedAt
	v.RejectedAt = rejectedAt
	v.RejectionCode = deref(rejectionCode)
	v.RejectionNotes = deref(rejectionNotes)
	if feeCents != nil {
		v.FeeChargedCents = *feeCents
	}
	v.Currency = deref(currency)
	v.ExpiresAt = expiresAt
	v.DeletedAt = deletedAt
	audit, err := unmarshalAuditLog(auditRaw)
	if err != nil {
		return nil, fmt.Errorf("pg.KycRepository: unmarshal audit_log (verification_id=%s): %w", v.VerificationID, err)
	}
	v.AuditLog = audit
	return &v, nil
}

func marshalAuditLog(entries []kyc.AuditEntry) ([]byte, error) {
	dtos := make([]auditEntryDTO, len(entries))
	for i, e := range entries {
		dtos[i] = auditEntryDTO{Event: e.Event, ActorGcid: e.ActorGcid, Notes: e.Notes, OccurredAt: e.OccurredAt}
	}
	return json.Marshal(dtos)
}

func unmarshalAuditLog(raw []byte) ([]kyc.AuditEntry, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var dtos []auditEntryDTO
	if err := json.Unmarshal(raw, &dtos); err != nil {
		return nil, err
	}
	if len(dtos) == 0 {
		return nil, nil
	}
	out := make([]kyc.AuditEntry, len(dtos))
	for i, d := range dtos {
		out[i] = kyc.AuditEntry{Event: d.Event, ActorGcid: d.ActorGcid, Notes: d.Notes, OccurredAt: d.OccurredAt}
	}
	return out, nil
}
