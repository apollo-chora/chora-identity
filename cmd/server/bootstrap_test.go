// bootstrap_test.go — composition-root wiring tests.
//
// B2 systemic bug (2026-05-15) — the chora-identity composition root used
// to construct two parallel users-repo bindings:
//
//	users     := inmem.NewUserRepository()   // legacy router path
//	pgUsers   := pg.NewUserRepository(...)   // resolve handler ONLY (D0.1c)
//
// The legacy `handler` (mounted at /me + /api/users/{gcid} +
// /api/users/{gcid}/portability/*) was wired with the *inmem* repo, so
// the bearer-auth middleware + MeHandler.getMe never saw the canonical
// Phyllis gcid `00000000-0000-7000-8000-000000001999` that lives in
// chora_identity.users — every authed call to /api/me returned
// `401 IDENTITY_UNKNOWN_GCID`.
//
// Same `_ = wired later` debt class as A7 (chora-tenancy /api/* stores) +
// D0.1c (chora-identity resolve UserRepository) + #27 (chora-creation
// AtomRepository RLS-blind reads). Documented in
// `docs/m14/RESUME_PROMPT_BACKEND_DEMO_2026-05-14_CLOSE.md` §3.
//
// The fix introduces `selectUserRepository(pgUsers, fallbackUsers, env)`
// at the composition root. Production wiring (CHORA_ENV=prod) MUST bind
// the pgx-backed repo for /me; missing pool fails LOUD per
// `feedback_no_stubs_real_wiring`. Dev mode (CHORA_ENV unset) falls back
// to the in-memory comic seed.
package main

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// fakeUserRepo is a minimal identity.UserRepository stand-in for the
// "pgx-backed" pool — exercised here without spinning up a real DB. The
// only invariant we assert: it ISN'T the same instance as the inmem
// fallback. (Production swaps in *pg.UserRepository; test swaps in
// *fakeUserRepo. Both satisfy identity.UserRepository.)
type fakeUserRepo struct {
	users map[string]*identity.User
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{users: make(map[string]*identity.User)}
}

func (r *fakeUserRepo) Save(_ context.Context, u *identity.User) error {
	r.users[u.Gcid] = u
	return nil
}

func (r *fakeUserRepo) GetByGcid(_ context.Context, gcid string) (*identity.User, error) {
	u, ok := r.users[gcid]
	if !ok {
		return nil, identity.ErrUserNotFound
	}
	return u, nil
}

// -----------------------------------------------------------------------------
// selectUserRepository — composition-root wiring helper (B2 fix)
// -----------------------------------------------------------------------------

// TestSelectUserRepository_PrefersPgxWhenAvailable asserts that when the
// pgx-backed pool is wired, the production code path returns the pgx repo —
// NOT the in-memory fallback. This is the canonical B2 bug class:
// `_ = pgUsers // wired later` shadowed the pgx adapter and the legacy
// router bound to the inmem stub instead.
func TestSelectUserRepository_PrefersPgxWhenAvailable(t *testing.T) {
	t.Parallel()

	pgUsers := newFakeUserRepo()
	fallback := inmem.NewUserRepository()

	got, err := selectUserRepository(pgUsers, fallback, "prod")
	if err != nil {
		t.Fatalf("selectUserRepository: unexpected error %v", err)
	}
	// The pgx-backed repo MUST be returned — identity comparison via
	// any-interface unwrap is the cleanest assertion that the wiring isn't
	// quietly substituting a stub.
	if got != identity.UserRepository(pgUsers) {
		t.Fatalf("selectUserRepository returned the wrong repo — bug class _=wired-later strikes again. got=%T pgUsers=%T", got, pgUsers)
	}
}

// TestSelectUserRepository_FailsLoudInProductionWhenPgxUnavailable —
// per feedback_no_stubs_real_wiring: when CHORA_ENV=prod, the helper
// MUST refuse to fall back to in-memory (which would mint spurious
// behaviour for canonical users and 401 every real session).
func TestSelectUserRepository_FailsLoudInProductionWhenPgxUnavailable(t *testing.T) {
	t.Parallel()

	fallback := inmem.NewUserRepository()

	_, err := selectUserRepository(nil, fallback, "prod")
	if err == nil {
		t.Fatalf("selectUserRepository(nil, fallback, prod) must return error — the inmem fallback is dev-only")
	}
	if !errors.Is(err, errPgxUserRepoRequired) {
		t.Errorf("selectUserRepository returned wrong error type — want errPgxUserRepoRequired got %v", err)
	}
}

// TestSelectUserRepository_FallsBackInDevelopment — dev / test mode
// honours the in-memory fallback so local servers + the comic-seed
// fixtures keep working without a Cloud SQL instance.
func TestSelectUserRepository_FallsBackInDevelopment(t *testing.T) {
	t.Parallel()

	fallback := inmem.NewUserRepository()

	got, err := selectUserRepository(nil, fallback, "")
	if err != nil {
		t.Fatalf("selectUserRepository(nil, fallback, dev) unexpected error: %v", err)
	}
	if got != identity.UserRepository(fallback) {
		t.Fatalf("selectUserRepository in dev should return fallback inmem repo; got %T", got)
	}
}

// TestSelectUserRepository_FallsBackOnNonProdEnv — explicit env names
// other than "prod" / "production" route to dev fallback.
func TestSelectUserRepository_FallsBackOnNonProdEnv(t *testing.T) {
	t.Parallel()

	fallback := inmem.NewUserRepository()

	for _, env := range []string{"dev", "test", "staging", "local"} {
		env := env
		t.Run(env, func(t *testing.T) {
			t.Parallel()
			got, err := selectUserRepository(nil, fallback, env)
			if err != nil {
				t.Fatalf("env=%q: unexpected error %v", env, err)
			}
			if got != identity.UserRepository(fallback) {
				t.Errorf("env=%q: want fallback got %T", env, got)
			}
		})
	}
}

// TestSelectUserRepository_ProductionAcceptsCaseInsensitiveEnv —
// mirrors the existing CHORA_ENV handling in main.go (resolveUsers
// wiring uses strings.EqualFold for both "prod" / "production").
func TestSelectUserRepository_ProductionAcceptsCaseInsensitiveEnv(t *testing.T) {
	t.Parallel()

	fallback := inmem.NewUserRepository()

	for _, env := range []string{"prod", "PROD", "Production", "production"} {
		env := env
		t.Run(env, func(t *testing.T) {
			t.Parallel()
			_, err := selectUserRepository(nil, fallback, env)
			if err == nil {
				t.Errorf("env=%q: want error (prod must fail loud) got nil", env)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// selectPasskeyBackend — passkey durability decision (CHO-2198)
// -----------------------------------------------------------------------------
//
// Passkeys are WebAuthn AUTH CREDENTIALS. The pre-fix composition root stored
// them in-memory even with a healthy chora_identity pool, because the durable
// pgx adapter was opt-in behind CHORA_IDENTITY_PASSKEY_BACKEND=pg — an UNSET
// env silently selected the volatile in-memory store, so a pod restart dropped
// every registered passkey. These tests lock the corrected contract:
// durable-by-default on a healthy pool, in-memory only as an explicit,
// loudly-announced dev override, and FAIL LOUD rather than run a credential
// store on volatile memory.

// TestSelectPasskeyBackend_HealthyPoolUnsetEnvDefaultsToPg is the CHO-2198 RED:
// a healthy pool with the env UNSET must select the DURABLE pgx store. Before
// the fix this returned memory (the durability bug).
func TestSelectPasskeyBackend_HealthyPoolUnsetEnvDefaultsToPg(t *testing.T) {
	t.Parallel()

	got, err := selectPasskeyBackend(true, "")
	if err != nil {
		t.Fatalf("healthy pool + unset env: unexpected error %v", err)
	}
	if got != passkeyBackendPg {
		t.Fatalf("healthy pool + unset env MUST default to durable pg (CHO-2198); got %q — passkeys would be silently volatile", got)
	}
}

// TestSelectPasskeyBackend_HealthyPoolExplicitPg — explicit pg with a pool is
// the production path (unchanged behaviour, locked here).
func TestSelectPasskeyBackend_HealthyPoolExplicitPg(t *testing.T) {
	t.Parallel()

	got, err := selectPasskeyBackend(true, "pg")
	if err != nil || got != passkeyBackendPg {
		t.Fatalf("healthy pool + pg: want (pg,nil); got (%q,%v)", got, err)
	}
}

// TestSelectPasskeyBackend_PgRequestedWithoutPoolFailsLoud — pg explicitly
// requested but no pool: refuse. Never silently degrade a credential store to
// volatile memory.
func TestSelectPasskeyBackend_PgRequestedWithoutPoolFailsLoud(t *testing.T) {
	t.Parallel()

	got, err := selectPasskeyBackend(false, "pg")
	if err == nil {
		t.Fatalf("pg requested + no pool MUST fail loud; got backend=%q, nil error", got)
	}
	if !errors.Is(err, errPasskeyPgPoolRequired) {
		t.Errorf("want errPasskeyPgPoolRequired; got %v", err)
	}
	if got != "" {
		t.Errorf("fail-loud path must not return a backend; got %q", got)
	}
}

// TestSelectPasskeyBackend_UnsetWithoutPoolFailsLoud — after the fix, unset
// MEANS durable-by-default; with no pool we cannot be durable, and a credential
// store must never silently run on volatile memory. Dev without a DB opts in
// explicitly via =memory.
func TestSelectPasskeyBackend_UnsetWithoutPoolFailsLoud(t *testing.T) {
	t.Parallel()

	got, err := selectPasskeyBackend(false, "")
	if err == nil {
		t.Fatalf("unset + no pool MUST fail loud (no silent volatile credential store); got backend=%q, nil error", got)
	}
	if !errors.Is(err, errPasskeyPgPoolRequired) {
		t.Errorf("want errPasskeyPgPoolRequired; got %v", err)
	}
}

// TestSelectPasskeyBackend_ExplicitMemoryOverride — the dev escape hatch:
// CHORA_IDENTITY_PASSKEY_BACKEND=memory (or =inmem) selects the volatile store
// even when a healthy pool exists; the caller emits a loud WARNING. Accepts a
// couple of spellings + surrounding whitespace + case.
func TestSelectPasskeyBackend_ExplicitMemoryOverride(t *testing.T) {
	t.Parallel()

	for _, env := range []string{"memory", "MEMORY", "inmem", " InMem "} {
		env := env
		t.Run(env, func(t *testing.T) {
			t.Parallel()
			got, err := selectPasskeyBackend(true, env) // even WITH a healthy pool, the explicit override wins
			if err != nil {
				t.Fatalf("explicit memory override %q: unexpected error %v", env, err)
			}
			if got != passkeyBackendMemory {
				t.Fatalf("explicit %q must select memory; got %q", env, got)
			}
		})
	}
}

// TestSelectPasskeyBackend_UnknownValueFailsLoud — a typo'd backend value must
// not silently pick either store; refuse loudly.
func TestSelectPasskeyBackend_UnknownValueFailsLoud(t *testing.T) {
	t.Parallel()

	got, err := selectPasskeyBackend(true, "redis")
	if err == nil {
		t.Fatalf("unknown backend MUST fail loud (no silent selection); got backend=%q, nil error", got)
	}
	if !errors.Is(err, errPasskeyBackendUnknown) {
		t.Errorf("want errPasskeyBackendUnknown; got %v", err)
	}
}
