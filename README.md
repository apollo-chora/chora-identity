# chora-identity

Identity service for Chora: GCID (global Chora identity) lifecycle, tenant
membership mirror, roles, KYC, per-user mana, API keys, WebAuthn passkeys, and
local username/password authentication.

The service is designed to run locally with Docker Compose and uses environment
variables for configuration. No cloud account or managed services (managed SQL,
message broker, secret manager, identity provider, or CI/CD) are required.

## Local stack

The default Compose stack contains:

- **chora-identity** — HTTP and gRPC service
- **PostgreSQL 18** — identity data, durable outbox, and subscriber idempotency
- **NATS JetStream** — local event publishing and subscriptions (streams provisioned by `nats-init`)

## Requirements

- Docker with Docker Compose

## Configuration

Create the local environment file:

```sh
cp .env.example .env
```

The checked-in `.env.example` contains the complete local defaults. The actual
`.env` file is ignored by Git.

Important variables:

| Variable | Purpose | Local default |
| --- | --- | --- |
| `PORT` | HTTP port | `8080` |
| `CHORA_GRPC_PORT` | gRPC port | `9090` |
| `CHORA_DB_DSN` | PostgreSQL connection string | Compose PostgreSQL |
| `CHORA_OUTBOX_DSN` | Durable outbox database | Same PostgreSQL instance |
| `NATS_URL` | NATS JetStream event bus | `nats://nats:4222` |
| `CHORA_LOCAL_KEK` | Base64 32-byte master KEK for DEK envelope encryption (required) | dev value in `.env.example` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/gRPC trace endpoint | `http://otel-collector:4317` |

## Run locally

From the repository root:

```sh
docker compose up --build
```

HTTP is exposed on `http://localhost:8080`; gRPC is exposed on port `9090` by
default.

## Database

PostgreSQL is the durable backing store. The same database is also used for the
transactional outbox and the subscriber idempotency store. Schema changes live
in `migrations/`.

The migrations are applied by the platform migration runner (`scripts/migrate.sh`
in the orchestrator repository), which mounts this repository's `migrations/`
directory. Every forward migration is a `*.sql` file that is not a `*.down.sql`.

## Event bus

Local messaging uses NATS JetStream. The event taxonomy
(`chora.{domain}.{aggregate}.{event_type}.v{N}`) is unchanged, and the transport
is brokered by `github.com/apollo-chora/chora-common/eventbus`.

`nats-init` provisions two streams: `CHORA_EVENTS` (subjects `chora.>`) and
`CHORA_DLQ` (subjects `_dlq.>`, the dead-letter convention). Consumers are
durable and created on demand by the service. If `NATS_URL` is unset the
application falls back to its in-memory event bus (publish-only; not durable).

## Authentication

Login is local username/password. Credentials are stored in
`chora_identity.local_credentials` as Argon2id PHC strings
(`$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>`), with a globally-unique
normalised username.

```text
POST /v1/auth/verify-credentials
{"username":"admin","password":"..."}
```

A successful response carries the authoritative active tenant:

```json
{
  "gcid": "<uuid>",
  "email": "<string>",
  "active_tenant_id": "<uuid>",
  "active_tenant_roles": ["<role>"],
  "memberships": [{"tenant_id": "<uuid>", "roles": ["<role>"]}]
}
```

`401 INVALID_CREDENTIALS` is returned for an unknown username, a wrong password,
or a user with no active tenant membership. `403 ACCOUNT_DISABLED` is returned
for a non-active user.

### Seeding a local admin

`cmd/seed` is an idempotent job that upserts a tenant, a user, the credential,
and an active admin membership from environment variables. Re-running is a
no-op; the stored Argon2id hash is only rewritten when it no longer verifies
against `CHORA_SEED_ADMIN_PASSWORD`.

```env
CHORA_SEED_TENANT_ID=<uuid>
CHORA_SEED_TENANT_SLUG=chora-local
CHORA_SEED_ADMIN_USERNAME=admin
CHORA_SEED_ADMIN_EMAIL=admin@example.com
CHORA_SEED_ADMIN_PASSWORD=<password>
```

## Envelope encryption

Per-user data encryption keys (DEKs) are wrapped with a local master KEK
(`CHORA_LOCAL_KEK`, base64 of 32 bytes) using AES-256-GCM. Only the wrapped form
is persisted (`chora_identity.user_dek_wrap`); crypto-shred tombstones the row.
A missing or malformed KEK is a hard boot error — envelope encryption is never
silently disabled.

## Migrations

Forward migrations are applied in filename order. New credentials/membership
tables are added by `migrations/0042_local_credentials.up.sql`.
