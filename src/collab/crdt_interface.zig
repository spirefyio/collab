//! CrdtInterface — vtable for pluggable CRDT types within the collab module.
//!
//! This is the Zig-platform-level extension point that lets the collab
//! transport host arbitrary CRDT types in parallel. The collab transport
//! treats CRDT op payloads as OPAQUE BYTES; each CRDT defines its own
//! op + snapshot serialization. `CollabManager` dispatches inbound
//! op-frames to the channel whose name matches the envelope's `ch` field.
//!
//! Pluggability is Zig-only. WASM plugins do NOT register CRDT types —
//! they consume channels via existing bridge handlers (e.g. `collab.mutate`)
//! with optional per-plugin allowlist enforcement on the channel.
//!
//! v1 ships ONE concrete implementation:
//!   - `crdt_lww_map.CrdtDoc` — LWW-Map (last-writer-wins over flat path
//!     space) used by the studio's `unified-model` channel.
//!
//! Future implementations (already scaffolded in `crdt_text.zig` / `crdt_blob.zig`):
//!   - `TextCrdt`  — sequence CRDT for editor pair programming (Yata/RGA family)
//!   - `BlobCrdt`  — content-addressed blob sync for binary attachments
//!
//! Memory ownership convention (matches `studio/src/util/clock.zig` and
//! `studio/src/config.zig`): callers pass an allocator to slice-returning
//! methods; the CRDT allocates with that allocator; the caller frees with
//! the same allocator. No `free_op_bytes` / `free_snapshot` vtable hooks —
//! the codebase precedent is "same allocator in, same allocator out."
//!
//! Threading contract (CRITICAL — enforced by `CollabManager`):
//!   - A CrdtInterface method MUST NOT call back into any other
//!     CrdtInterface or CollabManager method (no re-entrancy).
//!   - CollabManager always acquires its mutex BEFORE calling
//!     CrdtInterface methods.
//!   - Channel CRDTs MUST NOT acquire CollabManager.mutex from their vtable.
//!   - Lock order: CollabManager.mutex → CRDT internal mutex (if any).
//!   - `applyLocal` MUST NOT be called before peer_id is set at init time.
//!     There is NO post-init `set_peer_id` setter — see `crdt_lww_map.zig`
//!     for why (zero peer_id silently loses every concurrent edit via the
//!     Lamport tiebreaker).
//!
//! Idempotency contract:
//!   - `applyRemote(op)` MUST be idempotent — replaying the same op_bytes
//!     after it has already been merged returns `false` (no state change)
//!     without erroring. LWW-Map satisfies this by tombstone-comparing
//!     timestamps; future CRDTs must document how they achieve it.

const std = @import("std");

/// Opaque transport payload — each CRDT defines its own op serialization.
/// CollabManager treats these as bytes (base64-encoded over the wire).
pub const OpBytes = []const u8;

/// Opaque snapshot bytes — used for join-time bootstrap. Each CRDT defines
/// its own snapshot encoding; CollabManager only routes them.
pub const SnapshotBytes = []const u8;

/// Generic CRDT interface. A `Channel` holds one of these and routes ops
/// to it via name lookup in `ChannelRegistry`.
pub const CrdtInterface = struct {
    /// Type-erased pointer to the concrete CRDT instance (e.g. `*CrdtDoc`).
    ptr: *anyopaque,

    /// Dispatch table. Const so the same vtable instance can be shared
    /// across multiple CRDT instances of the same concrete type.
    vtable: *const VTable,

    pub const VTable = struct {
        /// Apply a local change. `input` is CRDT-specific (e.g. for
        /// LWW-Map: `{"path":"...","value":"..."}` JSON). Returns
        /// op_bytes to broadcast. CALLER owns returned slice; free with
        /// the same allocator passed in.
        ///
        /// Must NOT be called before the CRDT's peer_id has been set
        /// (constructor argument; no setter exists).
        applyLocal: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            input: []const u8,
        ) anyerror!OpBytes,

        /// Apply a remote op. Returns `true` if state changed (idempotent
        /// when called with an op already merged: returns `false`).
        /// `op_bytes` is BORROWED for the call duration only —
        /// implementations must copy if retaining beyond return.
        applyRemote: *const fn (ptr: *anyopaque, op_bytes: OpBytes) anyerror!bool,

        /// Produce full snapshot for join-time sync. CALLER owns returned
        /// slice; free with the same allocator passed in.
        snapshot: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
        ) anyerror!SnapshotBytes,

        /// Restore from snapshot (replaces current state). `snapshot_bytes`
        /// BORROWED for the call duration only.
        loadSnapshot: *const fn (ptr: *anyopaque, snapshot_bytes: SnapshotBytes) anyerror!void,

        /// Tear down the CRDT instance. Allocator must match the one used
        /// at construction. The caller (ChannelRegistry) invokes this
        /// once per channel during `deinit()`, AFTER networking has been
        /// stopped (so no thread is mid-dispatch).
        deinit: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) void,
    };

    // -------------------------------------------------------------------------
    // Convenience wrappers — dispatch through the vtable.
    // -------------------------------------------------------------------------

    pub inline fn applyLocal(
        self: CrdtInterface,
        allocator: std.mem.Allocator,
        input: []const u8,
    ) !OpBytes {
        return self.vtable.applyLocal(self.ptr, allocator, input);
    }

    pub inline fn applyRemote(self: CrdtInterface, op_bytes: OpBytes) !bool {
        return self.vtable.applyRemote(self.ptr, op_bytes);
    }

    pub inline fn snapshot(
        self: CrdtInterface,
        allocator: std.mem.Allocator,
    ) !SnapshotBytes {
        return self.vtable.snapshot(self.ptr, allocator);
    }

    pub inline fn loadSnapshot(self: CrdtInterface, bytes: SnapshotBytes) !void {
        return self.vtable.loadSnapshot(self.ptr, bytes);
    }

    pub inline fn deinit(self: CrdtInterface, allocator: std.mem.Allocator) void {
        self.vtable.deinit(self.ptr, allocator);
    }
};

// =============================================================================
// Tests — pure vtable plumbing. Concrete CRDTs (LWW-Map, Text, Blob) have
// their own test suites that validate dispatch + idempotency + threading.
// =============================================================================

const testing = std.testing;

test "CrdtInterface: vtable dispatches to ptr-owned methods" {
    const MockCrdt = struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        apply_local_calls: usize = 0,
        apply_remote_calls: usize = 0,
        snapshot_calls: usize = 0,
        load_snapshot_calls: usize = 0,
        deinit_called: bool = false,
        last_remote_op_len: usize = 0,

        fn applyLocal(ptr: *anyopaque, allocator: std.mem.Allocator, input: []const u8) anyerror!OpBytes {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.apply_local_calls += 1;
            return allocator.dupe(u8, input);
        }
        fn applyRemote(ptr: *anyopaque, op_bytes: OpBytes) anyerror!bool {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.apply_remote_calls += 1;
            self.last_remote_op_len = op_bytes.len;
            return true;
        }
        fn snapshot(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror!SnapshotBytes {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.snapshot_calls += 1;
            return allocator.dupe(u8, "{}");
        }
        fn loadSnapshot(ptr: *anyopaque, bytes: SnapshotBytes) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            _ = bytes;
            self.load_snapshot_calls += 1;
        }
        fn deinitFn(ptr: *anyopaque, allocator: std.mem.Allocator) void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            _ = allocator;
            self.deinit_called = true;
        }

        const vtable_inst: CrdtInterface.VTable = .{
            .applyLocal = applyLocal,
            .applyRemote = applyRemote,
            .snapshot = snapshot,
            .loadSnapshot = loadSnapshot,
            .deinit = deinitFn,
        };

        fn interface(self: *Self) CrdtInterface {
            return .{ .ptr = self, .vtable = &vtable_inst };
        }
    };

    var mock = MockCrdt{ .allocator = testing.allocator };
    const iface = mock.interface();

    const op = try iface.applyLocal(testing.allocator, "hello");
    defer testing.allocator.free(op);
    try testing.expectEqualStrings("hello", op);
    try testing.expectEqual(@as(usize, 1), mock.apply_local_calls);

    const changed = try iface.applyRemote("world");
    try testing.expect(changed);
    try testing.expectEqual(@as(usize, 1), mock.apply_remote_calls);
    try testing.expectEqual(@as(usize, 5), mock.last_remote_op_len);

    const snap = try iface.snapshot(testing.allocator);
    defer testing.allocator.free(snap);
    try testing.expectEqualStrings("{}", snap);
    try testing.expectEqual(@as(usize, 1), mock.snapshot_calls);

    try iface.loadSnapshot("{}");
    try testing.expectEqual(@as(usize, 1), mock.load_snapshot_calls);

    iface.deinit(testing.allocator);
    try testing.expect(mock.deinit_called);
}
