package main

import (
	"context"
	"log"
	"os"
	"strings"

	cgcsecrets "github.com/apollo-chora/chora-common/secrets"
	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/redisstate"
)

// singpassStateRepoFromEnv returns the Memorystore-backed Singpass OIDC state
// store when CHORA_REDIS_ADDR is set, and the in-memory one otherwise.
//
// Why this is not in-memory in production. The state token bridges the Singpass
// redirect and the callback, and chora-identity's HPA allows up to 5 replicas.
// With a per-pod map the callback can land on a pod that never saw the
// redirect, and the KYC flow fails with no obvious cause under exactly the load
// that makes it hardest to diagnose. Redis is shared across replicas AND can
// enforce single use through GETDEL, which is why neither session affinity nor
// a stateless signed state parameter is sufficient: neither can make a token
// one-use.
//
// ⚠ A MISSING STORE MUST NOT FAIL THE BOOT. cost-pause DELETES the Memorystore
// instance and cost-resume recreates it, so the endpoint legitimately vanishes
// between restarts. The adapter dials lazily and never pings here, so an absent
// instance surfaces as a denied callback (fail-closed, correct) rather than a
// crash-looping identity service (not correct). Losing in-flight five-minute
// OAuth state across a pause is acceptable; refusing to start is not.
//
// Secret resolution follows chora-user-event-stream against the same instance:
// prefer the *_SECRET_ID form, fall back to the direct value for local dev.
func singpassStateRepoFromEnv(ctx context.Context) httpadapter.SingpassStateRepository {
	addr := strings.TrimSpace(os.Getenv("CHORA_REDIS_ADDR"))
	if addr == "" {
		log.Printf("identity: CHORA_REDIS_ADDR unset, Singpass OIDC state is IN-MEMORY " +
			"(single-replica-correct only; a callback on a second replica will fail)")
		return httpadapter.NewInMemSingpassStateRepository()
	}

	password := resolveRedisSecret(ctx, "CHORA_REDIS_PASSWORD_SECRET_ID", "CHORA_REDIS_PASSWORD")
	caCert := resolveRedisSecret(ctx, "CHORA_REDIS_CA_CERT_SECRET_ID", "CHORA_REDIS_CA_CERT")

	store, err := redisstate.NewStore(redisstate.Config{
		Addr:      addr,
		Password:  password,
		CACertPEM: caCert,
	})
	if err != nil {
		// Only a malformed CA reaches here; a dial failure does not, because
		// the adapter does not dial. A bad CA is a config error the operator
		// must see, and falling back to in-memory would hide it, so this is
		// the one case that fails loud.
		log.Fatalf("identity: Singpass state store config invalid (fail-loud): %v", err)
	}
	log.Printf("identity: Singpass OIDC state store is Memorystore-backed at %s "+
		"(shared across replicas, single-use via GETDEL, fail-closed)", addr)
	return store
}

// resolveRedisSecret reads secretEnv as a Secret Manager resource id, falling
// back to plainEnv. A fetch failure returns empty rather than aborting: the
// caller then dials without that material and the connection fails at use,
// which keeps a secret outage out of the boot path for the same reason the
// missing-instance case does.
func resolveRedisSecret(ctx context.Context, secretEnv, plainEnv string) string {
	if v := strings.TrimSpace(os.Getenv(plainEnv)); v != "" {
		return v
	}
	id := strings.TrimSpace(os.Getenv(secretEnv))
	if id == "" {
		return ""
	}
	project := strings.TrimSpace(os.Getenv("CHORA_REDIS_SECRET_PROJECT"))
	if project == "" {
		project = strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_PROJECT"))
	}
	c, err := cgcsecrets.NewClient(ctx, project)
	if err != nil {
		log.Printf("identity: secret manager init failed for %s: %v", secretEnv, err)
		return ""
	}
	defer func() { _ = c.Close() }()
	v, err := c.GetSecret(ctx, id)
	if err != nil {
		log.Printf("identity: could not read %s (%s): %v", secretEnv, id, err)
		return ""
	}
	return v
}
