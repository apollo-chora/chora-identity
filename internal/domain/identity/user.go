// Package identity is the Identity supporting domain (one of 6 supporting/
// platform domains per the locked architecture).
//
// Owns: IAM, GCID portability (cross-tenant), OIDC + WebAuthn registration,
// TenantMembership graph, and PortableSnapshot append-only export.
//
// AGID-vs-GCID distinction (CLAUDE.md §1 §3, ddd-enforcement aggregate
// invariant #10): GCID is the global learner / human identity (UUIDv7);
// AGID is a separate agent identity. Agents CANNOT hold TenantMembership.
//
// This package is dependency-free w.r.t. infrastructure (hexagonal: domain
// at the centre, adapters depend on domain, never the reverse).
package identity

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// -----------------------------------------------------------------------------
// IdentityProvider — the authoritative IdP for a user. Identity Platform
// federates Microsoft / Google / Singpass / generic OIDC + SAML + WebAuthn
// per CLAUDE.md §1 + Tier 1 B-items.
// -----------------------------------------------------------------------------

type IdentityProvider string

const (
	ProviderOIDC     IdentityProvider = "oidc"
	ProviderSAML     IdentityProvider = "saml"
	ProviderWebAuthn IdentityProvider = "webauthn"
	// ProviderPassword is a locally-authenticated identity (username/password
	// with an Argon2id credential in local_credentials). Added with the local
	// login provider (migration 0042).
	ProviderPassword IdentityProvider = "password"
)

func (p IdentityProvider) Valid() bool {
	switch p {
	case ProviderOIDC, ProviderSAML, ProviderWebAuthn, ProviderPassword:
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// UserStatus
// -----------------------------------------------------------------------------

type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusClosed    UserStatus = "closed"
)

// -----------------------------------------------------------------------------
// VerificationStatus — KYC fast-path projection on the User aggregate.
//
// The full KYCVerification aggregate lives in package kyc; this enum is a
// denormalised summary cached on User for fast role-gate decisions per ADR-142.
// -----------------------------------------------------------------------------

type VerificationStatus string

const (
	VerificationStatusUnverified VerificationStatus = "unverified"
	VerificationStatusPending    VerificationStatus = "pending"
	VerificationStatusVerified   VerificationStatus = "verified"
	VerificationStatusRejected   VerificationStatus = "rejected"
	VerificationStatusExpired    VerificationStatus = "expired"
)

// Valid reports whether the status is one of the known 5.
func (s VerificationStatus) Valid() bool {
	switch s {
	case VerificationStatusUnverified, VerificationStatusPending,
		VerificationStatusVerified, VerificationStatusRejected, VerificationStatusExpired:
		return true
	}
	return false
}

// KycMethod — Singpass / SkillsFuture / manual_doc per ADR-142. String form
// (free-form here for forward-compat with provider additions; the canonical
// enum lives in package kyc).
type KycMethod string

// -----------------------------------------------------------------------------
// User aggregate root — represents a global Chora identity (GCID).
// -----------------------------------------------------------------------------

// User is the Identity domain's primary aggregate root. The Gcid field is the
// opaque, cross-tenant-portable UUIDv7 identifier per CLAUDE.md §1.
type User struct {
	Gcid             string           `json:"gcid"`
	Email            string           `json:"email"`
	DisplayName      string           `json:"display_name,omitempty"`
	IdentityProvider IdentityProvider `json:"identity_provider"`
	FederatedSubject string           `json:"federated_subject"` // SUB claim from IdP
	Status           UserStatus       `json:"status"`

	// KYC summary fast-path projection per ADR-142. The authoritative
	// audit trail lives in the kyc.Verification aggregate.
	KycMethod          KycMethod          `json:"kyc_method,omitempty"`
	KycVerifiedAt      *time.Time         `json:"kyc_verified_at,omitempty"`
	VerificationStatus VerificationStatus `json:"verification_status"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// DeletedAt is the soft-delete marker (ddd-enforcement #5). Setting it
	// frees the partial unique email index in chora_identity
	// (idx_users_email ... WHERE deleted_at IS NULL) so the SAME email can
	// re-register with a FRESH GCID after closure (CHO-1719 / ADR-181 D5).
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// NewUserParams is the constructor input for NewUser.
type NewUserParams struct {
	Email            string
	DisplayName      string
	IdentityProvider IdentityProvider
	FederatedSubject string
}

// NewUser constructs a fresh User. Returns an error if invariants are violated.
func NewUser(p NewUserParams) (*User, error) {
	email := strings.TrimSpace(p.Email)
	if email == "" {
		return nil, errors.New("email is required")
	}
	if !LooseValidEmail(email) {
		return nil, fmt.Errorf("invalid email: %q", email)
	}
	if !p.IdentityProvider.Valid() {
		return nil, fmt.Errorf("invalid identity_provider: %q", string(p.IdentityProvider))
	}
	subject := strings.TrimSpace(p.FederatedSubject)
	if subject == "" {
		return nil, errors.New("federated_subject is required")
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7: %w", err)
	}

	now := time.Now().UTC()
	return &User{
		Gcid:               id.String(),
		Email:              email,
		DisplayName:        strings.TrimSpace(p.DisplayName),
		IdentityProvider:   p.IdentityProvider,
		FederatedSubject:   subject,
		Status:             UserStatusActive,
		VerificationStatus: VerificationStatusUnverified,
		CreatedAt:          now,
		UpdatedAt:          now,
	}, nil
}

// MarkKycVerified sets KYC summary fields atomically. Idempotent on already-
// verified state with the same method.
func (u *User) MarkKycVerified(method KycMethod, verifiedAt time.Time) {
	if u.VerificationStatus == VerificationStatusVerified && u.KycMethod == method {
		return
	}
	u.KycMethod = method
	t := verifiedAt.UTC()
	u.KycVerifiedAt = &t
	u.VerificationStatus = VerificationStatusVerified
	u.UpdatedAt = time.Now().UTC()
}

// MarkKycPending flags the User as having a pending KYC verification.
func (u *User) MarkKycPending(method KycMethod) {
	if u.VerificationStatus == VerificationStatusPending && u.KycMethod == method {
		return
	}
	u.KycMethod = method
	u.VerificationStatus = VerificationStatusPending
	u.UpdatedAt = time.Now().UTC()
}

// MarkKycRejected flips status without touching VerifiedAt.
func (u *User) MarkKycRejected() {
	if u.VerificationStatus == VerificationStatusRejected {
		return
	}
	u.VerificationStatus = VerificationStatusRejected
	u.UpdatedAt = time.Now().UTC()
}

// Suspend transitions the user to suspended status.
func (u *User) Suspend() {
	if u.Status == UserStatusSuspended {
		return
	}
	u.Status = UserStatusSuspended
	u.UpdatedAt = time.Now().UTC()
}

// Close transitions the user to closed status. Idempotent.
//
// NOTE: This is a status flip only — full account closure is the federated
// Closure Saga (per Tier 3 D11), which is owned by the Closure Orchestrator
// service in chora-local. The skeleton here only sets the Identity-domain
// state; downstream pseudonymisation flows via Pub/Sub events (deferred).
func (u *User) Close() {
	if u.Status == UserStatusClosed {
		return
	}
	u.Status = UserStatusClosed
	u.UpdatedAt = time.Now().UTC()
}

// Pseudonymise applies the identity-domain terminal closure step (Tier 3
// D11, CHO-1719): tombstone the PII columns + soft-delete the row while
// PRESERVING the GCID (FK integrity across all 13 domain DBs depends on
// it — NEVER hard-delete).
//
//   - Email → tombstoneEmail (e.g. "user-{hash}@redacted.invalid" per
//     config/PII_Closure_Map.yaml users.email). Combined with DeletedAt,
//     this frees the partial unique email index so the same email can
//     re-register and mint a FRESH GCID.
//   - DisplayName → tombstoneName (e.g. "Former member").
//   - FederatedSubject → "shredded:{gcid}" so the UNIQUE
//     (identity_provider, federated_subject) pair can never resurrect the
//     closed account when the IdP re-issues the same SUB.
//   - Status → closed; DeletedAt set (soft delete).
//
// Idempotent: a user that is already closed AND soft-deleted is left
// untouched (DeletedAt must not move on saga redelivery).
func (u *User) Pseudonymise(tombstoneEmail, tombstoneName string) {
	if u.Status == UserStatusClosed && u.DeletedAt != nil {
		return
	}
	now := time.Now().UTC()
	u.Email = tombstoneEmail
	u.DisplayName = tombstoneName
	u.FederatedSubject = "shredded:" + u.Gcid
	u.Status = UserStatusClosed
	u.DeletedAt = &now
	u.UpdatedAt = now
}

// LooseValidEmail performs a minimal sanity check: at least one local-part char,
// exactly one '@', and a non-empty domain that contains a '.'. We do NOT use a
// strict RFC 5322 validator because the IdP is the source of truth for email
// validity; this guard simply rejects obviously-malformed input.
func LooseValidEmail(email string) bool {
	if email == "" {
		return false
	}
	at := strings.IndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return false
	}
	// Reject any further '@'.
	if strings.Count(email, "@") != 1 {
		return false
	}
	domain := email[at+1:]
	if !strings.Contains(domain, ".") {
		return false
	}
	return true
}

// -----------------------------------------------------------------------------
// AGID detection — agents CANNOT hold TenantMembership.
// -----------------------------------------------------------------------------

// IsAGID reports whether the given identifier is in the AGID (agent identity)
// shape. Per CLAUDE.md §1 §3 + ddd-enforcement aggregate invariant #10, the
// skeleton heuristic is "AGIDs start with '0197A' (case-insensitive)". The
// production implementation will defer to a registry lookup, but the shape
// guard catches the obvious cases at the API boundary.
func IsAGID(id string) bool {
	if id == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(id), "0197a")
}
