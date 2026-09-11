# collab/server

Relay broker + team service for spirefyio/collab. Written in Go.

## Components

- **chi** — HTTP router and middleware
- **jwtauth** — JWT auth middleware (added in a follow-up commit)
- **casbin** — RBAC enforcement (added in a follow-up commit)
- **gorilla/websocket** — opaque relay broker (added in a follow-up commit)
- **pgx** — Postgres driver (runtime pool + migration driver)
- **golang-migrate** — schema migrations, applied at boot and operable via `cmd/collab-migrate` (see [migrations/README.md](migrations/README.md))
- **OAuth2** — Google + GitHub identity (added in a follow-up commit)

## Quick start — local Go

```bash
make build      # → bin/collab-server
make test       # go test ./...
make run        # builds then runs against localhost defaults
```

Skeleton boots zero-config (no DB, no auth) and exposes:

```
GET  /              service banner
GET  /health        liveness probe
GET  /health/ready  readiness (db ping + relay status)
GET  /me            JWT-protected (when COLLAB_JWT_SECRET is set)
GET  /relay/ws      opaque WebSocket relay broker
```

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

Self-host with external Postgres — start only the server and point
COLLAB_DATABASE_URL at the managed instance:

```bash
COLLAB_DATABASE_URL=postgres://user:pass@db.example.com/collab \
  docker compose up server
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
make db-down N=1                 # roll back one migration
make db-goto V=1                 # migrate to exactly version 1
make db-new NAME=add_sessions    # scaffold the next up/down pair
make db-reset CONFIRM=yes        # down to empty, back up to head
make db-force V=1 CONFIRM=yes    # recover a dirty schema (runs no SQL)
make test-integration            # run the suite against a real Postgres
```

Destructive verbs are gated twice — `CONFIRM=yes` at the Makefile and `-yes`
at the CLI — and the CLI has no default database URL, because a default is
how an operator migrates the wrong database. Conventions for writing a
migration, and the dirty-schema runbook, are in
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
   (`internal/api/teams.go`). `internal/store/` is empty and nothing
   references `oauth2`, so the CRUD, the Postgres store, and the OAuth login
   this section describes are all still owed. The schema those tables live in
   *is* real (`migrations/0001_init.up.sql`); the handlers over it are not.

## Status

Pre-1.0 — landing in stages. Working today: the relay broker, JWT issuance
and verification, casbin enforcement, the Postgres pool, and the full
migration surface above. Owed: the team/workspace/invite store and handlers
(`internal/store/` is empty), and OAuth login (no `oauth2` consumer yet).
