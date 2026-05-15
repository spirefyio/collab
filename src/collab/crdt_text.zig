//! TextCrdt — sequence CRDT stub for editor pair programming.
//!
//! ## Status: STUB (not yet implemented)
//!
//! Phase A registered the multi-channel architecture; this file is the
//! roadmap-anchor for the eventual real implementation. The struct
//! exists and compiles; every vtable method returns
//! `error.NotImplemented`. The TextCrdt is NOT registered with
//! `CollabManager.registerDefaultChannels()` — it ships in a future
//! commit when the implementation lands.
//!
//! ## Algorithm choice (open — to be locked at impl time)
//!
//! Three families are realistic for a Zig 0.16 implementation:
//!
//! 1. **Yata** (Y.js underlying CRDT) — operations carry char-id =
//!    (siteId, lamportClock). Insert ops reference a `left` and
//!    `right` char-id; conflict resolution prefers higher siteId at
//!    the same position. Yata is what Yjs ships in production and is
//!    well-studied. Tradeoff: ops are bigger (left/right refs),
//!    storage grows with edit history (garbage collection is
//!    non-trivial).
//!
//! 2. **RGA (Replicated Growable Array)** — each char carries
//!    (timestamp, charId, deleted-flag). Insert ops carry the char
//!    plus a reference to the char-id immediately to the left. RGA
//!    is simpler to implement than Yata but has weaker concurrent-
//!    insert intent preservation (multiple users typing at the same
//!    position can interleave in ways that surprise UX). Storage
//!    similarly grows.
//!
//! 3. **Y.Text-inspired with delete-set GC** — Yata semantics but
//!    with a per-doc deleted-id set so deleted chars can be eagerly
//!    GC'd once all peers ACK. Adds anti-entropy plumbing that v1
//!    doesn't have ("trust all peers" + no per-peer ACK), so this
//!    is realistically a v2 option.
//!
//! Estimated effort: 1500-2500 LOC for the chosen algorithm + a
//! 200-line EditorTextBridge in studio + UI plumbing in the editor
//! plugin. Per the plan, this is 2-3 dedicated sessions of focused
//! work (the foundation is done; this fills the gap).
//!
//! ## Op shape sketch (illustrative — not normative)
//!
//! For Yata-family:
//! ```json
//! {"k":"i", "id":[siteId, clock], "left":[siteId, clock], "right":[siteId, clock], "ch":"a"}
//! {"k":"d", "id":[siteId, clock]}
//! ```
//!
//! Snapshot = full character list serialized in document order +
//! delete-set for tombstones the receiver hasn't seen.
//!
//! ## Threading + ownership
//!
//! Same `CrdtInterface` contract as `crdt_lww_map.zig` —
//! `CollabManager` always holds its mutex before calling into the
//! vtable; the CRDT MUST NOT re-enter the manager. peer_id (site_id
//! in text-CRDT speak) is set at init time via the constructor;
//! there is no post-init setter (the LWW-Map's experience showed
//! that's a foot-gun for any Lamport-tiebroken CRDT).
//!
//! ## Reference
//! - `desktop/docs/collab/adding-a-crdt-type.md` — walkthrough
//!   guide using THIS stub as the worked example.
//! - `desktop/docs/collab/architecture.md` — multi-channel context.

const std = @import("std");
const crdt_interface = @import("crdt_interface.zig");
const CrdtInterface = crdt_interface.CrdtInterface;
const OpBytes = crdt_interface.OpBytes;
const SnapshotBytes = crdt_interface.SnapshotBytes;

/// Stub for the editor-text sequence CRDT. Compiles + implements the
/// vtable surface so it can register with `ChannelRegistry` once the
/// algorithm is implemented; all methods currently return
/// `error.NotImplemented`.
pub const TextCrdt = struct {
    allocator: std.mem.Allocator,
    site_id: [16]u8,
    // ↑ The Lamport tiebreaker. Set at init; NEVER mutated.
    //
    // ↓ Future: storage for the char-list, delete-set, clock, etc.
    //   Leaving fields out until the algorithm is picked so the stub
    //   doesn't pretend to be more than it is.

    pub fn initWithSiteId(allocator: std.mem.Allocator, site_id: [16]u8) TextCrdt {
        return .{ .allocator = allocator, .site_id = site_id };
    }

    pub fn deinit(self: *TextCrdt) void {
        _ = self;
    }

    // -------------------------------------------------------------------------
    // CrdtInterface vtable
    //
    // Returns `error.NotImplemented` everywhere. Once the real algorithm
    // lands these get filled in; the bridge (EditorTextBridge in studio)
    // routes ops through the registered channel.
    // -------------------------------------------------------------------------

    fn vtableApplyLocal(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        input: []const u8,
    ) anyerror!OpBytes {
        _ = ptr;
        _ = allocator;
        _ = input;
        return error.NotImplemented;
    }
    fn vtableApplyRemote(ptr: *anyopaque, op_bytes: OpBytes) anyerror!bool {
        _ = ptr;
        _ = op_bytes;
        return error.NotImplemented;
    }
    fn vtableSnapshot(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!SnapshotBytes {
        _ = ptr;
        _ = allocator;
        return error.NotImplemented;
    }
    fn vtableLoadSnapshot(ptr: *anyopaque, bytes: SnapshotBytes) anyerror!void {
        _ = ptr;
        _ = bytes;
        return error.NotImplemented;
    }
    fn vtableDeinit(ptr: *anyopaque, allocator: std.mem.Allocator) void {
        const self: *TextCrdt = @ptrCast(@alignCast(ptr));
        _ = allocator;
        self.deinit();
    }

    const vtable_inst: CrdtInterface.VTable = .{
        .applyLocal = vtableApplyLocal,
        .applyRemote = vtableApplyRemote,
        .snapshot = vtableSnapshot,
        .loadSnapshot = vtableLoadSnapshot,
        .deinit = vtableDeinit,
    };

    pub fn interface(self: *TextCrdt) CrdtInterface {
        return .{ .ptr = self, .vtable = &vtable_inst };
    }
};

// =============================================================================
// Tests — confirm the stub conforms to the vtable surface so future
// implementation work can replace internals without API churn.
// =============================================================================

const testing = std.testing;

test "TextCrdt: vtable methods return NotImplemented" {
    var doc = TextCrdt.initWithSiteId(testing.allocator, [_]u8{0xAB} ** 16);
    defer doc.deinit();
    const iface = doc.interface();

    try testing.expectError(error.NotImplemented, iface.applyLocal(testing.allocator, "ignored"));
    try testing.expectError(error.NotImplemented, iface.applyRemote("ignored"));
    try testing.expectError(error.NotImplemented, iface.snapshot(testing.allocator));
    try testing.expectError(error.NotImplemented, iface.loadSnapshot("ignored"));
}

test "TextCrdt: deinit via vtable is safe (no double-free)" {
    var doc = TextCrdt.initWithSiteId(testing.allocator, [_]u8{0xCD} ** 16);
    const iface = doc.interface();
    iface.deinit(testing.allocator);
    // Calling deinit a second time on the same stub is also a no-op.
    doc.deinit();
}
