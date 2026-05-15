//! BlobCrdt — content-addressed binary CRDT stub.
//!
//! ## Status: STUB (not yet implemented)
//!
//! Same posture as `crdt_text.zig`: registers compile-time, every
//! vtable method returns `error.NotImplemented`. NOT registered with
//! `CollabManager.registerDefaultChannels()`.
//!
//! ## Use cases
//!
//! - Binary attachments (images, PDFs, zip files) inside a shared
//!   workflow — currently impossible because LWW-Map's `value` field
//!   is a JSON string.
//! - Recorder sessions (the recorder-pro plugin captures binary
//!   `.spfr` blobs; sharing them peer-to-peer needs a binary CRDT).
//! - Future canvas / graph CRDT might reuse the blob storage layer
//!   for image nodes.
//!
//! ## Algorithm choice (open — to be locked at impl time)
//!
//! 1. **LWW-on-whole-blob (v1 simple path)** — same semantics as
//!    `crdt_lww_map` but values are binary slices, not JSON strings.
//!    Cheap to implement (~300 LOC), but every write replaces the
//!    whole blob — terrible for large files. v1 acceptable for
//!    small attachments (< 1 MiB).
//!
//! 2. **Content-addressed dedup** — hash the blob, store
//!    `content_id → bytes` in a side table; the CRDT layer only
//!    sees `content_id` (32-byte hash). LWW on the content-id is
//!    natural. Dedup happens at write time across peers. Tradeoff:
//!    side-table sync needs anti-entropy (Tier 2).
//!
//! 3. **Rsync-style delta** — for blobs that change incrementally
//!    (e.g., a recorder session being edited live), send only the
//!    diff. Implementation is significantly more complex.
//!
//! Recommendation: ship (1) for v1 of the editor's attachment
//! support, plan (2) for v2 once anti-entropy lands.
//!
//! ## Op shape sketch (illustrative — not normative)
//!
//! For LWW-on-whole-blob:
//! ```json
//! {"k":"set", "path":"attachments.<id>", "blob":"<base64>", "ts":N, "p":"<peer>"}
//! ```
//!
//! For content-addressed dedup:
//! ```json
//! {"k":"set", "path":"attachments.<id>", "content_id":"<sha256-hex>", "ts":N, "p":"<peer>"}
//! ```
//! plus a separate `blob-store` channel for the content-id → bytes
//! mapping.
//!
//! ## Snapshot
//!
//! Whole-blob snapshot can get LARGE. The protocol's
//! `MAX_SNAPSHOT_BYTES = 16 MiB` cap is the absolute ceiling — when
//! the blob CRDT lands, the impl must either chunk large blobs into
//! multiple snapshot envelopes (streaming-snapshot — system-architect
//! MED follow-up from Phase A panel) or refuse to host blobs over
//! the limit.
//!
//! ## Reference
//! - `desktop/docs/collab/adding-a-crdt-type.md`
//! - `desktop/docs/collab/architecture.md`

const std = @import("std");
const crdt_interface = @import("crdt_interface.zig");
const CrdtInterface = crdt_interface.CrdtInterface;
const OpBytes = crdt_interface.OpBytes;
const SnapshotBytes = crdt_interface.SnapshotBytes;

/// Stub for the binary blob CRDT. Vtable returns NotImplemented.
pub const BlobCrdt = struct {
    allocator: std.mem.Allocator,
    peer_id: [16]u8,

    pub fn initWithPeerId(allocator: std.mem.Allocator, peer_id: [16]u8) BlobCrdt {
        return .{ .allocator = allocator, .peer_id = peer_id };
    }

    pub fn deinit(self: *BlobCrdt) void {
        _ = self;
    }

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
        const self: *BlobCrdt = @ptrCast(@alignCast(ptr));
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

    pub fn interface(self: *BlobCrdt) CrdtInterface {
        return .{ .ptr = self, .vtable = &vtable_inst };
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "BlobCrdt: vtable methods return NotImplemented" {
    var doc = BlobCrdt.initWithPeerId(testing.allocator, [_]u8{0xEF} ** 16);
    defer doc.deinit();
    const iface = doc.interface();

    try testing.expectError(error.NotImplemented, iface.applyLocal(testing.allocator, "ignored"));
    try testing.expectError(error.NotImplemented, iface.applyRemote("ignored"));
    try testing.expectError(error.NotImplemented, iface.snapshot(testing.allocator));
    try testing.expectError(error.NotImplemented, iface.loadSnapshot("ignored"));
}
