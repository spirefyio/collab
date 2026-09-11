# collab/server

Relay broker + team service for spirefyio/collab. Written in Go.

## Components

- **chi** — HTTP router and middleware
- **jwtauth** — JWT auth middleware (`internal/auth/jwt.go`, mounted in `internal/api/router.go`)
- **casbin** — RBAC enforcement (`internal/acl/enforcer.go`, `RequireAccess` middleware)
- **gorilla/websocket** — opaque relay broker (`internal/relay/hub.go`)
- **pgx** — Postgres driver (runtime pool + migration driver)
- **golang-migrate** — schema migrations, applied at boot and operable via `cmd/collab-migrate` (see [migrations/README.md](migrations/README.md))
- **OAuth2** — Google + GitHub identity — **not built yet**; nothing in the tree imports `oauth2`

## Quick start — local Go

```bash
make build      # → bin/collab-server and bin/collab-migrate
make test       # go test ./...
make run        # builds then runs against localhost defaults
```

Boots zero-config (no DB, no auth) and exposes:

```
GET  /              service banner
GET  /health        liveness probe
GET  /health/ready  readiness (db ping + relay status)
GET  /relay/ws      opaque WebSocket relay broker
```

`GET /me` and `GET /teams/{teamID}/probe` are mounted **only** when
`COLLAB_JWT_SECRET` is set. Without it the protected group is never
registered, so a zero-config boot answers `/me` with a plain 404 — not a 401.
A 404 there means "no auth configured", not "wrong path".

## Quick start — Docker (server + Postgres)

```bash
docker compose up --build
curl http://localhost:8443/health
curl http://localhost:8443/health/ready
docker compose down            # stops; data persists in volume
docker compose down --volumes  # nukes data too
```

If port 5432 or 8443 is already in use (e.g. another Postgres on the
host), remap host ports without touching the compose file:

```bash
POSTGRES_HOST_PORT=15432 SERVER_HOST_PORT=18443 docker compose up
```

Override defaults by exporting before compose:

```bash
COLLAB_JWT_SECRET=$(openssl rand -hex 32) \
COLLAB_OAUTH_GOOGLE_CLIENT_ID=... \
  docker compose up --build
```

Self-host with external Postgres — point `COLLAB_DATABASE_URL` at the managed
instance. `--no-deps` is load-bearing: the `server` service declares
`depends_on: postgres`, so without it compose starts and health-waits on the
local Postgres too — the very container this recipe exists to avoid, and the
one that collides on port 5432 above.

```bash
COLLAB_DATABASE_URL=postgres://user:pass@db.example.com/collab \
  docker compose up --no-deps server
```

## Configuration

All knobs are environment variables, prefixed `COLLAB_`. See
`.env.example` for the full list. The skeleton requires no env vars for
local dev. Production must set `COLLAB_PRODUCTION=1`, which then enforces:

- `COLLAB_JWT_SECRET` — must be >= 32 bytes
- `COLLAB_DATABASE_URL` — Postgres connection string
- `COLLAB_OAUTH_REDIRECT_BASE_URL` — public URL for OAuth callbacks

## Database migrations

The server migrates itself at boot: with `COLLAB_DATABASE_URL` set,
`cmd/relay` applies every pending migration before opening the runtime pool,
and it is a no-op when already at head. Deploying a build migrates the
database.

`cmd/collab-migrate` is the operator CLI for everything boot cannot do:

```bash
make db-start                    # compose Postgres, waits for pg_isready
make db-version                  # applied version, dirty flag, head, pending
make db-up                       # apply pending (ahead of a deploy)
make db-down N=1 CONFIRM=yes      # roll back one migration
make db-goto V=1                 # migrate to exactly version 1 (CONFIRM=yes if descending)
make db-new NAME=add_sessions    # scaffold the next up/down pair
make db-reset CONFIRM=yes        # down to empty, back up to head
make db-force V=1 CONFIRM=yes    # recover a dirty schema (runs no SQL)
make db-stop / make db-destroy   # stop the compose Postgres / also drop its volume
make test-integration            # run the suite against a real Postgres
```

Every verb that can destroy data — `down`, `down-all`, `force`, `goto 0`, and
any `goto` that descends — refuses without `-yes`, and the `make` wrappers
require `CONFIRM=yes` to supply it.

CORRECTION (2026-09-10): this paragraph previously said "destructive verbs are
gated twice" without qualification. That was false for two of them. `down n`
and a descending `goto v` had **no** gate at either layer, and since `Steps`
treats over-stepping as success, `make db-down N=99` on a one-migration set
emptied the schema exactly like `down-all` — which did require confirmation.
Both are now gated, and because `goto 1` is a forward migration on an empty
schema and a rollback on a schema at version 2, its gate is decided from the
applied version at execution time rather than from the command line.

Two things the confirmation does **not** tell you, so the CLI prints them:

- **Which database.** `CONFIRM=yes` and `-yes` both confirm "be destructive";
  neither confirms "against this one". `COLLAB_DATABASE_URL` decides that
  silently, so every destructive verb names its resolved target — credentials
  stripped — in both the refusal and the run.
- **That the CLI has no default URL at all**, because a default is how an
  operator migrates the wrong database.

Conventions for writing a migration, the advisory-lock behaviour under
replica contention, and the dirty-schema runbook are in
[migrations/README.md](migrations/README.md).

## Architecture

See [../README.md](../README.md) for the overall multi-channel CRDT
architecture. This server hosts two surfaces:

1. **Relay broker** (`/relay/ws`) — opaque WebSocket forwarding. Never
   decrypts CRDT payloads. Used by both ad-hoc Share/Join sessions and
   team-mode workspaces.
2. **REST API** — team management. Auth is JWT issued after OAuth login,
   RBAC via casbin.

   CORRECTION (2026-09-10): this list previously read
   ``/auth`, `/teams`, `/workspaces`, `/invites``, none of which exist.
   The mounted routes are exactly `/`, `/health`, `/health/ready`,
   `/relay/ws`, `/me`, and `/teams/{teamID}/probe` — and the last is
   explicitly a placeholder proving the JWT + casbin pipe
   (`internal/api/teams.go`). The schema those tables live in *is* real
   (`migrations/0001_init.up.sql`); the handlers over it are not. See Status
   for what that leaves owed.

## Status

Pre-1.0 — landing in stages.

Working today: the relay broker, JWT issuance and verification, casbin
enforcement, the Postgres pool, and the migration surface above.

Owed: the team / workspace / invite store and handlers — `internal/store/`
does not exist (it is absent, not empty; an earlier draft of this file said
"empty", which sends a reader to `ls` a directory that is not there) — and
OAuth login, with no `oauth2` import anywhere in the tree.

Not covered by CI: nothing in this repo's automation builds, vets, or tests
`server/` on a push. The workflow that exists is Zig-only and manual
(`workflow_dispatch`). `.github/workflows/go.yml` adds that for the Go server;
until it has run at least once, treat green as "someone ran `make test`".
