# chora-identity

> The identity service: local credentials, WebAuthn passkeys, session minting, account
> resolution, tenant memberships, and the per-user data-encryption-key envelope the rest
> of the platform's privacy guarantees rest on.

Go, HTTP/JSON plus gRPC. PostgreSQL for durable state, NATS JetStream for events, and a
local KEK that wraps every user's data-encryption key.

## What it is

Every authenticated action in Chora traces back here. The service owns:

- **Local credentials** — username and password, with the seeded accounts the stack
  creates.
- **Passkeys** — WebAuthn registration and assertion, with durable credential storage.
- **Sessions** — minting the signed session JWT the gateway validates, plus refresh.
- **Resolution** — mapping an incoming identity to a GCID and its tenant memberships,
  which is what every downstream service trusts.
- **The DEK envelope** — a 32-byte data-encryption key per user, wrapped by a local KEK
  with AES-256-GCM. This is the mechanism behind crypto-shredding: destroy the wrapped
  key and the user's encrypted data becomes unreadable.
- **Mana** — the per-user wallet and its pricing events.
- **Demo grants** — an off-by-default path to top up mana for demonstrations.

It serves HTTP on `PORT` (default `8080`) and gRPC on **`GRPC_PORT`** (default `9090`).
In the stack both are `expose`d and neither is published — the comment in `compose.yml`
says it plainly: identity is reached by the gateway, never by the browser.

Note the variable name, because it is easy to get wrong: `compose.yml` sets
`CHORA_GRPC_PORT`, but this service reads **`GRPC_PORT`**. The values agree (both 9090),
so nothing breaks today — but changing `CHORA_GRPC_PORT` will not move identity's gRPC
listener.

### The envelope is the point

`CHORA_LOCAL_KEK` wraps each user's DEK, and the wrapped key is persisted in
`user_dek_wrap`. The live log confirms both halves of that:

```text
identity: DEK wrapped-key store = pgx durable (user_dek_wrap, migration 0021)
identity: DEK manager = LocalKEKKeyManager (AES-256-GCM envelope encryption, ADR-186)
```

Two consequences follow, and neither is obvious from a deployment command:

1. **The KEK is not a convenience secret.** Lose or change it and every previously
   wrapped DEK becomes undecryptable — the data is not lost, but it is unreachable
   through this service forever.
2. **The service refuses to run without a valid one.** A missing or malformed KEK is a
   hard boot failure, by design: it will not serve identity without envelope encryption.

### Demo mana is off, and refuses to be half-on

`CHORA_DEMO_MODE` and `CHORA_DEMO_MANA_TOPUP_ENABLED` are both `false` in the stack.
Turning the grant on requires **both** flags *and* a non-empty
`CHORA_DEMO_MANA_ALLOWED_GCIDS`; with the flags set and the allowlist empty, identity
refuses to boot rather than opening grants to everyone. That guard is deliberate — do not
"fix" a boot failure here by unsetting the allowlist.

## Prerequisites

| Route | What you need |
| --- | --- |
| In the stack | A working `chora-stack` deployment. PostgreSQL and NATS come from it, and `identity-seed` creates the tenant and the three accounts. |
| Standalone (durable) | Go **1.26.1 or newer**, PostgreSQL with this repository's schema, NATS JetStream, and a valid KEK. |
| Either | A 32-byte KEK and a ≥32-byte session signer. The service will not start without both. |
| Passkeys | A browser origin and RP ID matching the deployment; WebAuthn will not work over a mismatched origin. |

## Credentials

This service holds **two locally generated secrets** and no provider credentials. Both
are mandatory, both are validated at boot, and both are shared with another service.

| Value | Generate with | Variable | Shared with |
| --- | --- | --- | --- |
| **Local KEK** | `openssl rand -base64 32` | `CHORA_LOCAL_KEK` | only this service and `identity-seed` |
| **Session signer** | `openssl rand -hex 32` | `CHORA_SESSION_SIGNER` | `chora-gateway` — must match exactly |
| PostgreSQL password | `openssl rand -hex 16` | inside `CHORA_DB_DSN` | every service |
| Seeded account passwords | your choice | `CHORA_SEED_ADMIN_PASSWORD`, `CHORA_SEED_INSTRUCTOR_PASSWORD`, `CHORA_SEED_STUDENT_PASSWORD` | the stack's logins |

**The KEK must decode to exactly 32 bytes.** `openssl rand -base64 32` produces the
44-character base64 string that does; a 32-character hex string does not, and produces:

```text
identity: DEK manager init failed (fail-loud — envelope encryption is required): cryptolocal: invalid KEK: decoded length 19, want 32
```

or, for a non-base64 value, `CHORA_LOCAL_KEK is not valid base64`. Both are boot failures,
not warnings. Keep the same KEK across restarts and redeploys: `identity-seed` wraps with
it too, and rotating it orphans every DEK created before the rotation.

**The session signer must be at least 32 bytes**, and the gateway validates sessions
against the same value. A mismatch is the classic symptom: minting succeeds and every
protected route returns `401`.

There are **no provider credentials** here — identity calls no model and no search API.
Where the stack's shared values come from, and how to obtain the provider keys that
*other* services need, is documented once in
[`chora-stack/README.md`](../chora-stack/README.md#credentials).

## Run it in the stack

`compose.yml` does four things:

1. Builds the image from the sibling checkout at `../chora-identity`.
2. Runs `identity-migrate` to apply the schema, then `identity-seed` — the same image
   with `entrypoint: ["/seed"]` — which creates the local tenant and the admin,
   instructor and student accounts.
3. Starts the service only after `postgres` and `nats` are healthy, `nats-init` has
   completed, and `identity-seed` completed successfully.
4. Publishes no host port; it `expose`s `8080` and `9090` only.

```sh
cd chora-stack
docker compose up -d identity
docker compose ps identity identity-seed
docker compose logs identity-seed | tail -3
```

The seed log is the useful one: it names every account it created and the roles attached
to each. `identity` cannot start until the seed exits 0, so a stuck `identity` container
almost always means the seed failed.

What Compose sets:

| Variable | Stack value | Note |
| --- | --- | --- |
| `CHORA_DB_DSN` | `chora_identity` as `chora_identity_app_rw` | the only DSN — see the outbox note below |
| `CHORA_LOCAL_KEK` | from the stack `.env` | the envelope key |
| `CHORA_SESSION_SIGNER` | from the stack `.env` | required; must match the gateway |
| `CHORA_SESSION_ISSUER`, `CHORA_SESSION_AUDIENCE` | `https://api.chora.local`, `chora-local` | must match the gateway's |
| `CHORA_SESSION_TTL_SECONDS`, `CHORA_REFRESH_TTL_SECONDS` | `3600`, `604800` | 1 hour access, 7 day refresh |
| `SVC_TENANCY_GRPC_URL` | `tenancy:9090` | membership lookups |
| `NATS_URL`, `CHORA_SOURCE_PROJECT` | NATS and `chora-local` | event bus |
| `CHORA_DEMO_*` | all off | the demo-grant guard described above |

Compose does **not** set `CHORA_OUTBOX_DSN`, and that has a consequence worth stating:
`bootstrapOutboxDB` returns no database when neither `CHORA_OUTBOX_DSN` nor
`CHORA_OUTBOX_DSN_SECRET_ID` is set, so the service wires the **in-memory** outbox store.
Events still publish — the live log shows `outbox_published ...
topic=chora.identity.user_mana.debited.v1` — but the outbox is not durable: queued rows
do not survive a restart and are lost when the process stops. `CHORA_DB_DSN` alone does
not make it persistent.

Probe it from inside the network:

```sh
docker compose exec -T nats wget -qO- http://identity:8080/readyz
```

## Run it standalone

```sh
git clone https://github.com/apollo-chora/chora-identity.git
cd chora-identity
cp .env.example .env
set -a; . ./.env; set +a       # the binary does not read .env itself
go run ./cmd/server
```

`.env.example` carries the Compose hostnames (`postgres`, `nats`), so change them for a
host-side run, and set a real KEK and signer before anything will boot. Apply the
migrations first — the service does not migrate itself.

To create the local accounts, run the seed binary with the same environment:

```sh
go run ./cmd/seed
```

It needs `CHORA_DB_DSN`, `CHORA_SEED_TENANT_ID`, `CHORA_SEED_TENANT_SLUG`,
`CHORA_SEED_ADMIN_USERNAME`, `CHORA_SEED_ADMIN_EMAIL` and `CHORA_SEED_ADMIN_PASSWORD`.

The instructor and student accounts are **optional**: each is created only when its
`*_USERNAME` is set, and setting a username also requires that account's matching email
and password. `.env.example` supplies all of them, which is why the stack's seed produces
three accounts — a standalone seed that sets only the admin inputs produces one.

Build and test:

```sh
go build ./cmd/server
go test ./...
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | HTTP listen port |
| `GRPC_PORT` | `9090` | gRPC listen port — **not** `CHORA_GRPC_PORT`, which Compose sets but this service never reads |
| `CHORA_DB_DSN` | — | PostgreSQL DSN (required for durable operation) |
| `CHORA_OUTBOX_DSN` | falls back to `CHORA_DB_DSN` | outbox DSN; the stack leaves it unset |
| `CHORA_OUTBOX_WORKER_ID` | `HOSTNAME` or a local fallback | outbox dispatcher identity |
| `CHORA_LOCAL_KEK` | — | **required**; base64 of exactly 32 bytes |
| `CHORA_SESSION_SIGNER` | — | **required**; ≥32 bytes, shared with the gateway |
| `CHORA_SESSION_ISSUER` | — | session `iss`; must match the gateway |
| `CHORA_SESSION_AUDIENCE` | — | session `aud`; must match the gateway |
| `CHORA_SESSION_TTL_SECONDS` | `3600` | access-session lifetime |
| `CHORA_REFRESH_TTL_SECONDS` | `604800` | refresh-session lifetime |
| `NATS_URL` | — | NATS JetStream |
| `CHORA_SOURCE_PROJECT` | — | event envelope source project |
| `SVC_TENANCY_GRPC_URL` | — | tenancy gRPC target for memberships |
| `CHORA_DEMO_MODE` | `false` | demo-mode master switch |
| `CHORA_DEMO_MANA_TOPUP_ENABLED` | `false` | the grant itself |
| `CHORA_DEMO_MANA_ALLOWED_GCIDS` | empty | **must be non-empty when the grant is enabled** |
| `CHORA_DEMO_MANA_GRANT_UNITS` | `1000000` | units per grant |
| `CHORA_DEMO_MANA_GRANT_MAX_PER_GCID` | `10` | per-user cap |
| `CHORA_DEMO_MANA_GRANT_TOTAL_BUDGET` | `1000000000` | global cap |
| `CHORA_SEED_TENANT_ID`, `CHORA_SEED_TENANT_SLUG` | the seeded local tenant | seed inputs |
| `CHORA_SEED_ADMIN_*`, `CHORA_SEED_INSTRUCTOR_*`, `CHORA_SEED_STUDENT_*` | `admin`, `instructor`, `student` | seed account inputs |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | OTLP/gRPC trace endpoint |

The four session variables are a matched set: identity mints, the gateway validates, and
both must agree on signer, issuer and audience. Changing one side alone produces `401`s
that look like a credentials problem and are not.

## Verify it works

### It is up

```sh
docker compose exec -T nats wget -qO- http://identity:8080/healthz
docker compose exec -T nats wget -qO- http://identity:8080/readyz
```

```json
{"status":"ok","time":"..."}
{"status":"ready"}
```

`readyz` is bare — it does not prove the database or the envelope are usable.

### Its envelope is live

```sh
docker compose logs identity | grep -E 'DEK|KEK' | tail -3
```

Two lines should appear:

```text
identity: DEK wrapped-key store = pgx durable (user_dek_wrap, migration 0021)
identity: DEK manager = LocalKEKKeyManager (AES-256-GCM envelope encryption, ADR-186)
```

A `DEK manager init failed` line instead means the KEK is malformed and the process is
crash-looping.

### Its migrations landed

```sh
docker compose exec -T postgres psql -U chora_identity_migrate -d chora_identity \
  -c "select count(*) from schema_migrations;"
```

Expect a count at or just under the 49 forward files listed under
[Migrations](#migrations).

### The seeded accounts exist

```sh
docker compose logs identity-seed | grep 'seed: ok'
```

The final line names the tenant, its slug and the three accounts with their roles.

### Login works end to end

The cleanest check is through the gateway, because it exercises minting and validation
together:

```sh
curl -s -X POST http://localhost:8093/api/v1/auth/session/mint \
  -H 'Content-Type: application/json' \
  -d '{"username":"instructor","password":"instructor"}'
```

A session JWT is the pass. `401` means the credentials do not match what the seed
created; a `503` means the gateway cannot reach identity.

## Troubleshooting

- **`DEK manager init failed ... invalid KEK: decoded length N, want 32`** — the KEK is
  not base64 of exactly 32 bytes. Generate one with `openssl rand -base64 32`.
- **`CHORA_LOCAL_KEK is not valid base64`** — the value contains characters outside the
  base64 alphabet, usually because a hex string was used.
- **`CHORA_SESSION_SIGNER must be ≥32 bytes (got N)`** — the signer is too short; note
  this failure appears on the *gateway*, not here.
- **Sessions mint here but every downstream route returns `401`** — the signer, issuer or
  audience disagrees between identity and the gateway. All three must match.
- **`identity` stays in `Created`** — `identity-seed` did not exit 0. Read
  `docker compose logs identity-seed`; it is the gate.
- **Previously encrypted data cannot be decrypted** — the KEK changed. Every wrapped DEK
  was sealed under the old value; there is no re-wrap path. Restore the original KEK.
- **Identity refuses to boot after enabling demo grants** — `CHORA_DEMO_MANA_ALLOWED_GCIDS`
  is empty. That is the guard working; populate the allowlist rather than unsetting it.
- **A passkey cannot be registered** — WebAuthn is origin-bound. The browser origin and
  the RP ID must match the deployment; a `localhost` registration will not assert against
  a different host.
- **Events queued while the service was down never arrive** — the outbox is in-memory
  because neither `CHORA_OUTBOX_DSN` nor `CHORA_OUTBOX_DSN_SECRET_ID` is set. Publishing
  works while the process runs; nothing queued survives a restart. Set
  `CHORA_OUTBOX_DSN` for durability.
- **No event leaves the service at all** — check `NATS_URL`.
- **Traces never reach Tempo** — every service in this stack logs
  `invalid target address http://otel-collector:4317 ... too many colons in address`.
  Observed in the running stack; only tracing is affected.

## API surface

Identity serves its own `/v1/auth/*` and `/api/*` paths, and the browser never reaches
them directly. The gateway's `POST /api/v1/auth/session/mint` calls identity's
`/v1/auth/verify-credentials` and mints the session itself — so a `404` for the mint path
against `identity:8080` is expected, because it is not an identity route.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz`, `/readyz` | liveness and readiness |
| `POST` | `/v1/auth/verify-credentials` | check a username/password pair; the gateway's mint calls this |
| `POST` | `/v1/auth/passkey/challenge` | issue a WebAuthn challenge |
| `POST` | `/v1/auth/passkey/register` | register a passkey |
| `POST` | `/v1/auth/passkey/verify` | assert a passkey |
| `POST` | `/v1/identity/resolve` | resolve a caller to a GCID and memberships |
| `GET` | `/api/v1/me/mana`, `/api/v1/me/mana/ledger` | the caller's wallet and ledger |
| `POST` | `/api/v1/me/mana/topup`, `/api/v1/me/mana/demo-grant` | top up; the demo grant |
| `GET` | `/api/v1/me/mana/ledger/export` | export the ledger |
| `GET` | `/api/v1/me/preferences` | preferences and dashboard/home layout |
| `GET` | `/api/v1/me/subscriptions` | subscriptions |
| `GET` | `/api/v1/me/kyc/status`, `POST` `/api/v1/me/kyc/manual` | KYC |
| `GET` | `/api/identity/api-keys` | API keys |
| `GET` | `/api/users`, `/api/memberships` | user and membership administration |
| `POST` | `/api/users/{id}/portability/export` | a user's data export — `POST`, not `GET`; the snapshots view is `GET /api/users/{id}/portability/snapshots` |
| `GET` | `/api/v1/admin/tenant-members`, `/api/v1/admin/tenant-memberships` | membership administration |
| `GET` | `/api/v1/admin/tenant-invites` | invites |
| `GET` | `/api/v1/admin/kyc/*` | KYC administration |
| `POST` | `/api/v1/admin/directory/backfill` | directory backfill |

gRPC on `CHORA_GRPC_PORT` serves the identity contract used by the gateway, tenancy,
consumption and payments.

Paths marked `*` are grouped for readability; the exact sub-paths are in the handlers
under `internal/adapter/http`.

## Architecture

```text
cmd/server/                 entrypoint and wiring
cmd/seed/                   the identity-seed one-shot
internal/domain/            users, memberships, DEKs, mana, passkeys, consents
internal/adapter/http/      REST handlers and middleware
internal/adapter/grpc/      identity gRPC adapter
internal/adapter/pg/        PostgreSQL repositories, including user_dek_wrap
internal/adapter/crypto/    local KEK manager (AES-256-GCM envelope)
internal/adapter/events/    event publishers and the outbox
config/                     runtime configuration
migrations/                 PostgreSQL schema
```

The crypto boundary is the part to understand before operating this service: the KEK
lives in the environment, the wrapped DEKs live in `user_dek_wrap`, and nothing else
holds a copy. Compromise the KEK and you can unwrap every DEK; lose it and you can unwrap
none.

## Events

Events are published to NATS JetStream, but the outbox behind them is **in-memory in this
stack**: `bootstrapOutboxDB` returns no database when neither `CHORA_OUTBOX_DSN` nor
`CHORA_OUTBOX_DSN_SECRET_ID` is set, and Compose sets neither. The live logs confirm
publishing works (`outbox_published ... topic=chora.identity.user_mana.debited.v1`), but
that does not make the outbox durable — queued rows die with the process.

Set `CHORA_OUTBOX_DSN` — the same database works — if you need replay across a restart.

Observed subjects include the mana lifecycle (`chora.identity.user_mana.debited.v1`) and
user/tenant lifecycle events. Streams are the platform standard: `CHORA_EVENTS` for
normal subjects, `CHORA_DLQ` for dead letters, both provisioned by `nats-init`, which
this service depends on.

## Migrations

**49 forward migration files**, applied by the stack's `scripts/migrate.sh` in the
`identity-migrate` one-shot against `chora_identity`. The runner is not part of this
repository.

The set runs from `0001_initial.sql` through `0044_demo_grant_budget.up.sql`, plus two
unusually named files at the end:

- **`9999_grant_app_roles.sql`** — the `_app_rw` grants.
- **`9999z_demo_grant_least_privilege.up.sql`** — a second pass that narrows the demo
  grant's privileges. The `z` suffix is deliberate: it sorts after `9999`, so the
  tightening applies after the broad grant rather than before it.

Two other files carry requirements worth knowing: `0021_user_dek_wrap` creates the table
the envelope store reports at boot, and `0040_uuidv7_pk_defaults` switches primary-key
defaults to PostgreSQL 18's native `uuidv7()` — an older server fails the migrate
one-shot.

The `.down.sql` siblings are destructive rollbacks and are never applied: the runner
takes every `*.sql` except `*.down.sql`, records a SHA-256 checksum per file in
`schema_migrations`, and refuses a file whose contents changed after application. Because
identity's schema is the one everything else references, a partially applied run here is
worth resolving before starting anything downstream.
