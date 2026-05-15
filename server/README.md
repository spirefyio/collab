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

## Quick start

```bash
make build      # → bin/collab-server
make test       # go test ./...
make run        # builds then runs against localhost defaults
```

Skeleton boots zero-config and exposes:

```
GET /         service banner
GET /health   liveness probe
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
