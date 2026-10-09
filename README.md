# chora-identity

## About

chora-identity is the Identity service for Chora. It manages GCIDs and tenant membership data, local username/password authentication, WebAuthn passkeys, KYC, per-user mana and subscriptions, API keys, user preferences, and identity-related event publishing. The service exposes HTTP and gRPC interfaces and uses PostgreSQL for durable identity data, with NATS JetStream for local event delivery.

## Quick start

### Prerequisites

- Docker with Docker Compose
- Go 1.26.1 or newer for local development outside Docker

### Run the local stack

From the repository root:

```sh
cp .env.example .env
docker compose up --build
```

The default Compose stack starts:

- chora-identity
- PostgreSQL 18
- NATS JetStream
- NATS stream initialization

The HTTP service is available at `http://localhost:8080`. gRPC listens on port `9090`.

The checked-in `.env.example` contains local development defaults. The `.env` file is ignored by Git.

To seed a local admin after PostgreSQL is available, run the seed command with the required environment variables:

```sh
CHORA_DB_DSN='postgres://chora:chora@localhost:5432/chora_identity?sslmode=disable' \
CHORA_SEED_TENANT_ID='22222222-2222-7222-8222-222222222222' \
CHORA_SEED_TENANT_SLUG='chora-local' \
CHORA_SEED_ADMIN_USERNAME='admin' \
CHORA_SEED_ADMIN_EMAIL='admin@example.com' \
CHORA_SEED_ADMIN_PASSWORD='change-me' \
go run ./cmd/seed
```

The seed job is idempotent. It upserts the tenant, user, local Argon2id credential, and active admin membership in one transaction.

Two more users can be seeded alongside the admin: set `CHORA_SEED_INSTRUCTOR_USERNAME` (role `instructor`) and/or `CHORA_SEED_STUDENT_USERNAME` — the matching `_EMAIL` and `_PASSWORD` variables then become required. The student account is stored with membership_role `learner`; the stored role vocabulary has no `student` value. PLATFORM_OPERATOR is intentionally not seedable here (ADR-165: cross-tenant role with no membership row).

### One-off demo mana seed grant

`cmd/seed-demo-mana` credits the demo mana balance (default `1000000000`) to an explicit list of **existing** GCIDs. It exists because the full seed job above also upserts the tenant, user rows, credentials and memberships, so running it on a live deployment merely to add balances can mutate identity data. This command writes only `user_mana` + `mana_ledger`, through the same transactional primitive `cmd/seed` uses. A GCID with no `users` row is reported as `unknown-gcid` and **not** created.

It is idempotent: the idempotency key is deterministic (`demo-seed:v1:<gcid>`), so a re-run replays and credits nothing, and a balance the account has since spent is never reset. Each GCID is granted in its own transaction with `SET LOCAL chora.user_gcid` applied, so the wallet/ledger RLS policy scopes the write to that account.

Both modes refuse to run unless `CHORA_DEMO_MANA_TOPUP_ENABLED=true` and `CHORA_DEMO_MODE=true`, and refuse outright when `CHORA_ENV` is `prod` or `production`.

```sh
# Dry run — reads the wallet and ledger state and reports what WOULD happen; writes nothing.
CHORA_ENV=local \
CHORA_DEMO_MODE=true \
CHORA_DEMO_MANA_TOPUP_ENABLED=true \
CHORA_DB_DSN='postgres://chora_identity_app_rw:...@localhost:5432/chora_identity?sslmode=disable' \
go run ./cmd/seed-demo-mana -gcids=<gcid>,<gcid> -dry-run

# Real run — the same invocation without -dry-run.
CHORA_ENV=local \
CHORA_DEMO_MODE=true \
CHORA_DEMO_MANA_TOPUP_ENABLED=true \
CHORA_DB_DSN='postgres://chora_identity_app_rw:...@localhost:5432/chora_identity?sslmode=disable' \
go run ./cmd/seed-demo-mana -gcids=<gcid>,<gcid>
```

GCIDs may also be given as repeated `-gcid=<gcid>` flags or as `CHORA_DEMO_MANA_GCIDS`; the amount via `-amount` or `CHORA_DEMO_MANA_GRANT_UNITS`. Every run prints an audit line per GCID (`applied` / `replayed` / `unknown-gcid` / `would-apply` / `would-replay` / `conflict`) and a batch summary. The exit status is non-zero when any GCID was not granted.

## Usage

### Health and readiness

```sh
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

`GET /healthz`, `GET /health`, and `GET /readyz` are public. The root endpoint returns service metadata.

### Local username/password authentication

When a PostgreSQL pool is configured, the service exposes:

```http
POST /v1/auth/verify-credentials
Content-Type: application/json

{"username":"admin","password":"change-me"}
```

A successful response contains the GCID, email, authoritative active tenant, roles, and all active tenant memberships. Invalid credentials return `401`; an inactive account returns `403`.

### WebAuthn passkeys

The passkey ceremony is exposed through:

```http
POST /v1/auth/passkey/challenge
POST /v1/auth/passkey/register
POST /v1/auth/passkey/verify
```

`RP_ID` controls the WebAuthn relying-party ID and defaults to `chora.site`. The challenge TTL is five minutes.

Passkey verification returns the verified GCID and email. Session JWT creation is handled by chora-gateway, not by this service.

By default, passkey credentials use the PostgreSQL-backed repositories when the identity database is available. `CHORA_IDENTITY_PASSKEY_BACKEND=memory` explicitly selects the non-durable in-memory backend for development.

### Identity resolution

```http
POST /v1/identity/resolve
Content-Type: application/json

{"email":"admin@example.com","firebase_uid":"subject","active_tenant_id":"<optional-tenant-uuid>"}
```

This endpoint resolves or creates a GCID and obtains tenant memberships through the chora-tenancy gRPC client. `SVC_TENANCY_GRPC_URL` is required for this path in production.

### Profile and membership HTTP APIs

The service also exposes:

```http
GET  /me
GET  /me/roles

POST /api/users
GET  /api/users/{gcid}

POST /api/memberships
GET  /api/memberships?tenant_id=&gcid=
PATCH /api/memberships/{id}/role

POST /api/users/{gcid}/portability/export
GET  /api/users/{gcid}/portability/snapshots
```

Protected `/api/*` requests require `X-Tenant-Id` and either `gcid` or `X-Chora-GCID` headers. The `/me` routes use bearer authentication instead.

Additional HTTP surfaces include API keys, tenant IdP provider configuration, tenant member administration, tenant invites, KYC, user preferences, subscriptions, mana, marketplace plans, and the public JWKS endpoint:

```http
GET /.well-known/jwks.json
```

The JWKS response uses an ETag and public cache headers.

### gRPC

The gRPC server defaults to port `9090`. It registers the standard gRPC health service plus Chora identity services including:

- `chora.services.identity.v1.Identity`
- `chora.services.identity.v1.ManaService`
- `chora.services.identity.v1.ExpRuleService` when the PostgreSQL pool is configured
- `chora.services.identity.v1.KycService`

The Identity gRPC surface currently implements `GetMe`, which resolves a GCID to its email and display name.

### Configuration

The main local configuration is in `.env.example`.

Common variables include:

| Variable | Purpose | Default |
| --- | --- | --- |
| `CHORA_ENV` | Environment name | `local` |
| `PORT` | HTTP listen port | `8080` |
| `CHORA_GRPC_PORT` | Compose-exposed gRPC port | `9090` |
| `GRPC_PORT` | Process gRPC listen port | `9090` |
| `CHORA_DB_DSN` | PostgreSQL runtime DSN | local Compose DSN |
| `CHORA_OUTBOX_DSN` | Transactional outbox DSN | same PostgreSQL database |
| `NATS_URL` | NATS JetStream URL | `nats://nats:4222` |
| `CHORA_LOCAL_KEK` | Base64-encoded 32-byte AES-256 master KEK | dev key in `.env.example` |
| `SVC_TENANCY_GRPC_URL` | chora-tenancy gRPC target | unset locally |
| `CHORA_PAYMENTS_GRPC_ADDR` | chora-payments gRPC target | unset locally |
| `RP_ID` | WebAuthn relying-party ID | `chora.site` |
| `CHORA_IDENTITY_PASSKEY_BACKEND` | Passkey backend | PostgreSQL when available |

`CHORA_LOCAL_KEK` is required at process startup. The value in `.env.example` is for development only; generate a real 32-byte key for a deployment.

PostgreSQL is also used for the transactional outbox when `CHORA_OUTBOX_DSN` is configured. NATS JetStream is used when `NATS_URL` is set; otherwise the service falls back to an in-memory event bus.

## Development

### Build and test

Build the server and seed binaries directly with Go:

```sh
go build ./cmd/server
go build ./cmd/seed
go build ./cmd/seed-demo-mana
```

Run the test suite:

```sh
go test ./...
```

Build the production container from the repository root:

```sh
docker build -t chora-identity:local .
```

The Dockerfile builds `./cmd/server`, `./cmd/seed` and `./cmd/seed-demo-mana` and produces a small Alpine-based runtime image.

### Project layout

```text
cmd/
  server/        service entrypoint and composition root
  seed/          idempotent local-admin provisioning job
  seed-demo-mana/ one-off demo mana seed grant for explicit existing GCIDs

internal/
  adapter/      HTTP, gRPC, PostgreSQL, event, crypto, and integration adapters
  domain/       identity, authentication, KYC, mana, API key, and related domain logic
  observability/ tracing and HTTP instrumentation

migrations/     PostgreSQL schema migrations
config/         runtime configuration data, including the PII closure map
compose.yaml    local PostgreSQL, NATS, and service stack
Dockerfile      multi-stage container build
go.mod          Go module definition
```

Database schema changes are stored in `migrations/`. Forward migrations are the `*.up.sql` files and are applied in filename order by the platform migration runner.

For local development, the Compose stack provisions the `CHORA_EVENTS` and `CHORA_DLQ` JetStream streams expected by the service.