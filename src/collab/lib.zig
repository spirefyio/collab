//! collab — a real-time collaboration library for Zig.
//!
//! Multi-channel CRDT runtime with end-to-end encryption (AEAD,
//! suite-negotiated) and per-operation Ed25519 signing. Embed into
//! desktop / CLI / server apps.
//!
//! Public surface lands during Phase 0b extraction from
//! `spirefyio/desktop`.

const std = @import("std");

test "scaffolding present" {
    try std.testing.expect(true);
}
