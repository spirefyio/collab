# desktop/src/collab — collab transport layer

This directory is the **transport layer** for Spirefy's real-time collaboration feature. It is purely generic plumbing — it knows nothing about `UnifiedModel`, OpenAPI, or any other domain concept.

## Files

- `manager.zig` — `CollabManager`: room lifecycle, peer connections, broadcast/receive plumbing.
- `websocket.zig` — TLS WebSocket transport.
- `crypto.zig` — room-key encryption (the shared symmetric key used by all peers in a room).
- `crdt.zig` — LWW-Map CRDT primitives (registers keyed by namespaced path; merge rule: higher Lamport timestamp wins, tie → higher peer_id).
- `protocol.zig` — wire-format message types (join, leave, sync_state, op, etc.).
- `session.zig` — per-peer connection state.
- `bridge_handlers.zig` — bridge endpoints exposed to studio (and any other consumer).
- `host_functions.zig` — host fns the plugin engine routes for plugin-side use.
- `lib.zig` — module entry point.

## Layering

This module is **generic** in the same sense as the rest of `desktop/`. It transports CRDT ops without knowing what those ops mean. The translation between `UnifiedModel` mutations and CRDT field paths lives in `studio/src/model/crdt_bridge.zig` (Phase B.6, not yet built). Studio consumes this transport; future apps that want collab on a different domain model (a future native GUI, a headless service) consume it the same way and ship their own bridge.

## What this directory does NOT define

- **The merge semantics from a user's perspective** (last-writer-wins, the Lamport surprise, the structural-op limitation, the "trust all peers" v1 posture). All of that lives in `docs/architecture/crdt-collaboration-explained.md`.
- **The `UnifiedModel` ↔ CRDT-path mapping**. That's `studio/src/model/crdt_bridge.zig` (B.6).
- **The plugin-author rules** (don't reflexively submit derived batches from `origin_kind=crdt` events, etc.). That's `plugins/docs/plugin-authoring/collab-considerations.md`.

If you are debugging a *transport* bug (peer can't connect, sync_state never arrives, message decryption fails), you are in the right directory. If you are debugging a *user-visible* bug ("my edit disappeared," "the operation I deleted came back"), start with the canonical explainer.
