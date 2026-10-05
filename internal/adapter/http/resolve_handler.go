// resolve_handler.go — POST /v1/identity/resolve
//
// Called by chora-gateway during POST /api/v1/auth/session/mint AFTER the
// upstream ID token has been signature-validated. Returns the user's GCID
// + the full list of tenant memberships they hold.
//
// Per the user-stated arch invariant (Bucket 2, 2026-05-14): one GCID, many
// tenants, many roles per tenant. A user can be learner + author at tenant
// A AND instructor + admin at tenant B simultaneously.
//
// Flow:
//
//  1. Validate body shape (non-empty email + firebase_uid)
//  2. Lookup-or-create the GlobalChoraIdentity row by (email, firebase_uid)
//     via the UserRepository
//  3. gRPC call to chora-tenancy's ListMembershipsByGCID over Cloud Service
//     Mesh mTLS — chora-identity MUST NOT query chora_tenancy directly per
//     ddd-enforcement HARD RULE
//  4. Apply active_tenant_id hint when present + valid; else use
//     server-derived default_tenant_id from the gRPC response
//  5. Emit chora.identity.gcid.resolved.v1 (idempotent on
//     sha256(email+firebase_uid)) for the audit trail
//  6. 200 with canonical envelope
//
// Trust model: NO Authorization check here — chora-gateway is the upstream
// trust boundary that gates the upstream ID token. The endpoint is mesh-
// internal only; production binds it to SVC_IDENTITY_URL.
//
// WIRE-COMPAT (history): the request/response field `firebase_uid` (Go field
// FirebaseUID) is a RETAINED legacy wire name from the pre-migration
// chora-contracts schema. The login provider is now local username/password
// (POST /v1/auth/verify-credentials); this field carries the generic
// federated subject and is kept verbatim so existing callers keep decoding.
// It is not an infrastructure dependency and carries no Google Cloud import.
package httpadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// TenantMembership is the JSON shape carried on the response envelope.
// Mirrors the OpenAPI schema and the gRPC TenantMembership.
type TenantMembership struct {
	TenantID   string   `json:"tenant_id"`
	TenantSlug string   `json:"tenant_slug"`
	Roles      []string `json:"roles"`
	Surfaces   []string `json:"surfaces"`
	IsDefault  bool     `json:"is_default"`
}

// MembershipsResolution is what the chora-tenancy gRPC client returns.
// Adapter-port shape — translated from the proto TenantMembership.
type MembershipsResolution struct {
	Memberships     []TenantMembership
	DefaultTenantID string
}

// TenancyClient is the minimal port the resolve handler needs against
// chora-tenancy. Implemented in production by a gRPC client adapter
// (services/chora-identity/internal/adapter/grpc/tenancy_client.go).
type TenancyClient interface {
	ListMembershipsByGCID(ctx context.Context, gcid string) (*MembershipsResolution, error)
}

// PublicTenantEnroller enrols a GCID into the public chora-master tenant
// (ADR-182 D2: every GCID is auto-enrolled learner+author at first
// resolve — "tenantless" users don't exist). Implemented in production
// by the tenancy UpsertMembership gRPC adapter; idempotent by
// construction (the authoritative store upserts ON CONFLICT DO NOTHING).
type PublicTenantEnroller interface {
	EnsurePublicMembership(ctx context.Context, gcid string) error
}

// EmittedEvent is the bundle the chora.identity.gcid.resolved.v1 publisher
// receives. Keeps the resolve handler decoupled from the events package
// Envelope shape (handler does not know about JSON-formatted Pub/Sub).
type EmittedEvent struct {
	GCID             string
	TenantID         string
	Email            string
	FirebaseUID      string
	IdempotencyKey   string
	MembershipsCount int
}

// EventPublisher is the minimal port for emitting the resolved event.
type EventPublisher interface {
	PublishGCIDResolved(ctx context.Context, ev EmittedEvent) error
}

// ResolveIdentityRequest is the on-wire body shape.
type ResolveIdentityRequest struct {
	Email          string `json:"email"`
	FirebaseUID    string `json:"firebase_uid"`
	ActiveTenantID string `json:"active_tenant_id,omitempty"`
}

// ResolveIdentityResponse is the canonical 200-OK envelope.
type ResolveIdentityResponse struct {
	GCID            string             `json:"gcid"`
	Memberships     []TenantMembership `json:"memberships"`
	DefaultTenantID string             `json:"default_tenant_id"`
	Email           string             `json:"email"`
	FirebaseUID     string             `json:"firebase_uid"`
}

// InviteApplier applies cold pending-invites for a freshly-resolved email
// (WS3 / ADR-194 D2), returning the tenant IDs applied. Optional — nil disables
// cold-invite apply (dev / no pending-invite store).
type InviteApplier interface {
	ApplyByEmail(ctx context.Context, gcid, email string) ([]string, error)
}

// ResolveHandler implements POST /v1/identity/resolve.
type ResolveHandler struct {
	users         identity.UserRepository
	tenancy       TenancyClient
	events        EventPublisher
	enroller      PublicTenantEnroller
	inviteApplier InviteApplier
	sourceProject string
}

// ResolveHandlerConfig is the constructor input.
type ResolveHandlerConfig struct {
	Users   identity.UserRepository
	Tenancy TenancyClient
	Events  EventPublisher
	// Enroller is the ADR-182 public-tenant auto-enrolment port. Optional:
	// when nil the zero-membership case keeps the legacy 200-with-empty
	// contract (dev mode without a tenancy conn).
	Enroller PublicTenantEnroller
	// InviteApplier applies cold pending-invites for the resolved email AFTER
	// the ADR-182 auto-enrol (WS3 / ADR-194 D2). Optional — nil disables it.
	InviteApplier InviteApplier
	// SourceProject is stamped on emitted events. Defaults to "chora-local"
	// when empty (the canonical platform host project).
	SourceProject string
}

// NewResolveHandler constructs the handler. Returns nil if any required dep
// is missing — fail-loud at boot.
func NewResolveHandler(cfg ResolveHandlerConfig) *ResolveHandler {
	if cfg.Users == nil || cfg.Tenancy == nil {
		return nil
	}
	if cfg.SourceProject == "" {
		cfg.SourceProject = "chora-local"
	}
	return &ResolveHandler{
		users:         cfg.Users,
		tenancy:       cfg.Tenancy,
		events:        cfg.Events,
		enroller:      cfg.Enroller,
		inviteApplier: cfg.InviteApplier,
		sourceProject: cfg.SourceProject,
	}
}

// ServeHTTP dispatches POST /v1/identity/resolve. Other methods get 405.
func (h *ResolveHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "IDENTITY_METHOD_NOT_ALLOWED",
			"only POST supported on /v1/identity/resolve")
		return
	}

	// 1. Decode body.
	var req ResolveIdentityRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_BAD_REQUEST",
			"invalid JSON body: "+err.Error())
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	fedSubject := strings.TrimSpace(req.FirebaseUID)
	if email == "" {
		writeError(w, http.StatusBadRequest, "IDENTITY_BAD_REQUEST", "email required")
		return
	}
	if fedSubject == "" {
		writeError(w, http.StatusBadRequest, "IDENTITY_BAD_REQUEST", "firebase_uid required")
		return
	}

	// 2. Lookup-or-create the GlobalChoraIdentity.
	user, err := h.lookupOrCreateUser(r.Context(), email, fedSubject)
	if err != nil {
		log.Printf("resolve_handler: lookup-or-create: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR",
			"failed to persist user")
		return
	}

	// 3. gRPC to chora-tenancy.
	resolution, err := h.tenancy.ListMembershipsByGCID(r.Context(), user.Gcid)
	if err != nil {
		log.Printf("resolve_handler: tenancy unavailable: %v", err)
		writeError(w, http.StatusServiceUnavailable, "IDENTITY_TENANCY_UNAVAILABLE",
			"chora-tenancy gRPC failed: "+err.Error())
		return
	}

	// 3b. ADR-182 auto-enrol: zero memberships at first resolve → enrol
	//     the GCID into the public chora-master tenant (learner+author)
	//     then re-list, so the mint downstream always has a tenant.
	//     "Tenantless" users don't exist post-ADR-182; the gateway treats
	//     an empty list as an upstream inconsistency.
	if len(resolution.Memberships) == 0 && h.enroller != nil {
		if err := h.enroller.EnsurePublicMembership(r.Context(), user.Gcid); err != nil {
			log.Printf("resolve_handler: public-tenant enrol failed: %v", err)
			writeError(w, http.StatusServiceUnavailable, "IDENTITY_ENROL_FAILED",
				"public tenant enrolment failed: "+err.Error())
			return
		}
		resolution, err = h.tenancy.ListMembershipsByGCID(r.Context(), user.Gcid)
		if err != nil {
			log.Printf("resolve_handler: tenancy unavailable (post-enrol re-list): %v", err)
			writeError(w, http.StatusServiceUnavailable, "IDENTITY_TENANCY_UNAVAILABLE",
				"chora-tenancy gRPC failed: "+err.Error())
			return
		}
	}

	// 3c. WS3 (ADR-194 D2) — cold-invite apply: match live pending invites for
	//     this resolved email and apply each (authoritative chora_tenancy +
	//     identity mirror). Runs on EVERY resolve (a returning user may have a
	//     fresh invite to a new tenant); a no-match is a no-op. Best-effort: an
	//     apply error must never block sign-in (the invite stays pending and
	//     re-applies next resolve). On a successful apply, re-list so the new
	//     memberships are in the response.
	var invitedTenantID string
	if h.inviteApplier != nil {
		applied, aerr := h.inviteApplier.ApplyByEmail(r.Context(), user.Gcid, user.Email)
		if aerr != nil {
			log.Printf("resolve_handler: pending-invite apply (non-fatal): %v", aerr)
		}
		if len(applied) > 0 {
			invitedTenantID = applied[0]
			if relisted, rerr := h.tenancy.ListMembershipsByGCID(r.Context(), user.Gcid); rerr == nil {
				resolution = relisted
			} else {
				log.Printf("resolve_handler: re-list after invite apply (non-fatal): %v", rerr)
			}
		}
	}

	// 4. Default active tenant. Precedence: an explicit valid active_tenant_id
	//    hint wins; else a freshly cold-invited tenant (so the invitee lands in
	//    the tenant they were invited to, not chora-master); else the
	//    tenancy-resolved default.
	activeTenantID := strings.TrimSpace(req.ActiveTenantID)
	defaultTenantID := resolution.DefaultTenantID
	if invitedTenantID != "" && isMemberOf(resolution.Memberships, invitedTenantID) {
		defaultTenantID = invitedTenantID
	}
	if activeTenantID != "" && isMemberOf(resolution.Memberships, activeTenantID) {
		defaultTenantID = activeTenantID
	}

	// 5. Empty memberships is no longer a 404 — return 200 with
	//    Memberships: [] so chora-gateway can mint a "bootstrap-mode"
	//    Chora session JWT (tenant_id="" + roles=[]) that the FE H+
	//    Setup-Tenant form (CHO-1642) uses to call
	//    POST /api/v1/tenants/bootstrap. Without this, the user is
	//    stuck in a circular dependency: the mint requires a tenant
	//    that the bootstrap endpoint creates, but the bootstrap
	//    endpoint needs the JWT mint accepted. See CHO-1648 for the
	//    full incident write-up.
	//
	//    Pre-CHO-1648 behaviour (for context): the 404 with body code
	//    IDENTITY_NO_TENANT_MEMBERSHIP was translated by chora-gateway
	//    into a 403 AUTH_NO_TENANT_MEMBERSHIP, blocking sign-in
	//    completely. The error text directed users at the H+
	//    Setup-Tenant wizard — but the wizard wasn't reachable from
	//    behind the gate. Phases 1-4 made the wizard work; Phase 5
	//    (this change) opens the gate so users can use it.

	// 6. Emit chora.identity.gcid.resolved.v1 — outbox-safe via the
	//    injected publisher. Idempotency key = sha256(email+firebase_uid)
	//    so retries dedupe cleanly downstream.
	if h.events != nil {
		idem := idempotencyKey(email, fedSubject)
		ev := EmittedEvent{
			GCID:             user.Gcid,
			TenantID:         defaultTenantID,
			Email:            email,
			FirebaseUID:      fedSubject,
			IdempotencyKey:   idem,
			MembershipsCount: len(resolution.Memberships),
		}
		if perr := h.events.PublishGCIDResolved(r.Context(), ev); perr != nil {
			// Event publish failure is NOT fatal — handler still returns
			// 200 so the caller can mint the session. The publisher
			// implementation is the canonical outbox so a transient
			// failure shows up at the dispatcher level.
			log.Printf("resolve_handler: event publish failed (non-fatal): %v", perr)
		}
	}

	writeJSON(w, http.StatusOK, ResolveIdentityResponse{
		GCID:            user.Gcid,
		Memberships:     resolution.Memberships,
		DefaultTenantID: defaultTenantID,
		Email:           user.Email,
		FirebaseUID:     fedSubject,
	})
}

// lookupOrCreateUser is the idempotent-on-(email, firebase_uid) lookup
// path. New users get a fresh UUIDv7 GCID stamped via NewUser; existing
// users are returned as-is.
//
// The injected UserRepository port (identity.UserRepository) is the minimal
// Save + GetByGcid contract — it does NOT declare a federated-subject
// lookup. The concrete adapters DO expose one, but with DIFFERENT shapes:
//
//   - pg.UserRepository:    FindByFederatedSubject(ctx, sub) (*User, bool, error)
//   - inmem.UserRepository: FindByFederatedSubject(sub)      (*User, bool)
//
// Both must be recognised. If the handler only matches one signature, the
// other wiring silently mints a FRESH random GCID for a user that already
// exists — and that fresh GCID carries zero tenant memberships, so
// chora-tenancy returns an empty list and this handler emits a spurious
// 404 IDENTITY_NO_TENANT_MEMBERSHIP (surfaced as 403 AUTH_NO_TENANT_
// MEMBERSHIP at chora-gateway). That was the D0.1c demo-login blocker.
//
// lookupExistingUser below probes for every known signature before
// falling through to create.
func (h *ResolveHandler) lookupOrCreateUser(ctx context.Context, email, fedSubject string) (*identity.User, error) {
	if existing, found, err := h.lookupExistingUser(ctx, email, fedSubject); err != nil {
		return nil, err
	} else if found {
		return existing, nil
	}

	// New user — mint a fresh GCID + persist.
	created, err := identity.NewUser(identity.NewUserParams{
		Email:            email,
		DisplayName:      "", // not known at resolve time; populated later by /me PATCH
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: fedSubject,
	})
	if err != nil {
		return nil, err
	}
	if err := h.users.Save(ctx, created); err != nil {
		return nil, err
	}
	return created, nil
}

// lookupExistingUser probes the wired UserRepository for an existing row
// matching fedSubject (preferred — it is the IdP-stable key) or email,
// across every concrete adapter signature. Returns (user, true, nil) on
// hit, (nil, false, nil) on a clean miss, (nil, false, err) on a backing-
// store error.
//
// Probe order: federated-subject first (ctx-carrying pg shape, then the
// legacy inmem 2-value shape), then email (ctx-carrying then 2-value),
// so a user is never re-created merely because the wired repo speaks a
// different method shape than the one the handler happened to try first.
func (h *ResolveHandler) lookupExistingUser(ctx context.Context, email, fedSubject string) (*identity.User, bool, error) {
	// --- federated-subject lookup (ctx-carrying — pg.UserRepository) ---
	if finder, ok := h.users.(interface {
		FindByFederatedSubject(ctx context.Context, sub string) (*identity.User, bool, error)
	}); ok {
		got, found, err := finder.FindByFederatedSubject(ctx, fedSubject)
		if err != nil {
			return nil, false, err
		}
		if found {
			return got, true, nil
		}
	}

	// --- federated-subject lookup (legacy 2-value — inmem.UserRepository) ---
	if finder, ok := h.users.(interface {
		FindByFederatedSubject(sub string) (*identity.User, bool)
	}); ok {
		if got, found := finder.FindByFederatedSubject(fedSubject); found {
			return got, true, nil
		}
	}

	// --- by-email lookup (ctx-carrying) ---
	if finder, ok := h.users.(interface {
		FindByEmail(ctx context.Context, email string) (*identity.User, bool, error)
	}); ok {
		got, found, err := finder.FindByEmail(ctx, email)
		if err != nil {
			return nil, false, err
		}
		if found {
			return got, true, nil
		}
	}

	// --- by-email lookup (legacy 2-value) ---
	if finder, ok := h.users.(interface {
		FindByEmail(email string) (*identity.User, bool)
	}); ok {
		if got, found := finder.FindByEmail(email); found {
			return got, true, nil
		}
	}

	return nil, false, nil
}

// isMemberOf reports whether the supplied tenant_id matches any
// membership in the resolution.
func isMemberOf(memberships []TenantMembership, tenantID string) bool {
	for _, m := range memberships {
		if m.TenantID == tenantID {
			return true
		}
	}
	return false
}

// idempotencyKey derives a deterministic key from (email, firebase_uid)
// per the Bucket 2 contract.
func idempotencyKey(email, fedSubject string) string {
	sum := sha256.Sum256([]byte("resolve:" + email + ":" + fedSubject))
	return hex.EncodeToString(sum[:])
}

// ErrTenancyUnavailable is exposed for callers that need to react to a
// degraded gRPC client beyond simply translating to 503.
var ErrTenancyUnavailable = errors.New("identity.resolve: tenancy unavailable")
