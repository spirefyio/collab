# collab/server

Relay broker + team service for spirefyio/collab. Written in Go.

## Components

- **chi** — HTTP router and middleware
- **jwtauth** — JWT auth middleware (added in a follow-up commit)
- **casbin** — RBAC enforcement (added in a follow-up commit)
- **gorilla/websocket** — opaque relay broker (added in a follow-up commit)
- **pgx** — Postgres driver (added in a follow-up commit)
- **golang-migrate** — schema migrations (added in a follow-up commit)
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

## Architecture

See [../README.md](../README.md) for the overall multi-channel CRDT
architecture. This server hosts two surfaces:

1. **Relay broker** (`/relay/ws`) — opaque WebSocket forwarding. Never
   decrypts CRDT payloads. Used by both ad-hoc Share/Join sessions and
   team-mode workspaces.
2. **REST API** (`/auth`, `/teams`, `/workspaces`, `/invites`) — team
   management. Auth is JWT issued after OAuth login. RBAC via casbin.

## Status

Pre-1.0 — skeleton landing in stages. See commits on
`kevin/phase-0c-server-skeleton`.
