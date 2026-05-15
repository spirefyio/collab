# collab

A real-time collaboration library for Zig, with a multi-channel CRDT
runtime, end-to-end encryption (AEAD, suite-negotiated), and per-operation
Ed25519 signing. Ships with a Go relay + team service that brokers
WebSocket sessions, manages accounts and workspaces, and persists
encrypted snapshots — without ever decrypting payloads.

## Components

- **Zig library** (`src/collab/`) — embed into desktop / CLI / server
  apps. Multi-channel CRDT runtime (LWW-Map today; Text + Blob CRDTs
  in progress), AEAD-encrypted wire protocol (pv:4), Ed25519 per-op
  signing, file-backed keystore.
- **Go server** (`server/`) — relay broker (opaque WebSocket
  forwarding, never decrypts) + REST API for accounts, teams,
  workspaces, invites, and audit log. Auth via JWT + OAuth (Google,
  GitHub). RBAC via Casbin. Postgres via pgx.
- **Docker setup** (`docker-compose.yml`) — one-command local dev with
  Postgres. Server + DB are both wireable to external instances via
  environment variables, so a company can self-host the server on
  static-IP infrastructure and back it with their own managed Postgres.

## Transport modes

- **Ad-hoc Share/Join** — one desktop hosts, others join via
  `ws://peer:port`. No server required. Per-session ephemeral identity.
- **Team mode** — desktop clients connect to `wss://collab.example.com`
  brokered by the Go server. Persistent OAuth identity, persistent
  workspaces, role-based ACL, audit log.

## Status

Pre-1.0. Library being extracted from `spirefyio/desktop`; server
scaffolding in progress. See `docs/` for the detailed architecture.

## License

MIT — see [LICENSE](LICENSE).
