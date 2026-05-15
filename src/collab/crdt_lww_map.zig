//! LWW-Map CRDT (Last-Writer-Wins Map)
//!
//! Every field is tracked as a register: {value, timestamp, peer_id}.
//! Merge rule (deterministic, commutative):
//!   1. Higher Lamport timestamp wins
//!   2. If timestamps equal, higher peer_id wins (lexicographic)
//!   Result: ALL peers always converge to the SAME state.
//!
//! Uses a namespaced path system so any plugin can share state:
//!   "model.nodes.<id>.x"                → node X position
//!   "plugin.<plugin-id>.<anything>"      → plugin-specific state
//!
//! Delete operations use a tombstone: value = "" (empty), which means "deleted."
//!
//! ## Role in the multi-channel collab architecture
//!
//! `CrdtDoc` implements `CrdtInterface` (see `crdt_interface.zig`) via
//! the `interface()` method. `CollabManager` registers ONE instance as
//! the `unified-model` channel; future CRDT types (text, blob) register
//! their own channel names and share the same transport.

const std = @import("std");
const compat = @import("compat");
const crdt_interface = @import("crdt_interface.zig");
const CrdtInterface = crdt_interface.CrdtInterface;
const OpBytes = crdt_interface.OpBytes;
const SnapshotBytes = crdt_interface.SnapshotBytes;

/// A single CRDT field: value + causal metadata.
pub const CrdtField = struct {
    /// JSON-encoded value. Empty string means tombstone (deleted).
    value: []const u8,
    /// Lamport logical timestamp (increments on every mutation).
    timestamp: u64,
    /// Peer that last wrote this field.
    peer_id: [16]u8,
};

/// A single mutation request (path + value).
pub const Mutation = struct {
    path: []const u8,
    value: []const u8,
};

/// A CRDT operation — the unit of replication sent over the wire.
pub const CrdtOp = struct {
    path: []const u8,
    value: []const u8,
    timestamp: u64,
    peer_id: [16]u8,
};

/// LWW-Map CRDT document.
/// Thread safety: callers must synchronize access externally.
pub const CrdtDoc = struct {
    allocator: std.mem.Allocator,
    fields: std.StringHashMap(CrdtField),
    clock: u64,
    peer_id: [16]u8,

    pub fn init(allocator: std.mem.Allocator) CrdtDoc {
        var peer_id: [16]u8 = undefined;
        compat.io().random(&peer_id);
        return .{
            .allocator = allocator,
            .fields = std.StringHashMap(CrdtField).init(allocator),
            .clock = 0,
            .peer_id = peer_id,
        };
    }

    pub fn initWithPeerId(allocator: std.mem.Allocator, peer_id: [16]u8) CrdtDoc {
        return .{
            .allocator = allocator,
            .fields = std.StringHashMap(CrdtField).init(allocator),
            .clock = 0,
            .peer_id = peer_id,
        };
    }

    pub fn deinit(self: *CrdtDoc) void {
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.value);
        }
        self.fields.deinit();
    }

    /// Apply a local mutation. Returns the CrdtOp to broadcast to peers.
    pub fn mutate(self: *CrdtDoc, path: []const u8, value: []const u8) !CrdtOp {
        self.clock += 1;

        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);

        const field = CrdtField{
            .value = owned_value,
            .timestamp = self.clock,
            .peer_id = self.peer_id,
        };

        if (self.fields.getPtr(path)) |existing| {
            // Path exists — replace value in-place
            self.allocator.free(existing.value);
            existing.* = field;
        } else {
            // New path — allocate key
            const owned_path = try self.allocator.dupe(u8, path);
            errdefer self.allocator.free(owned_path);
            try self.fields.put(owned_path, field);
        }

        return CrdtOp{
            .path = path,
            .value = value,
            .timestamp = self.clock,
            .peer_id = self.peer_id,
        };
    }

    /// Apply a batch of local mutations atomically. Returns ops to broadcast.
    pub fn mutateBatch(self: *CrdtDoc, mutations: []const Mutation) ![]CrdtOp {
        var ops = try self.allocator.alloc(CrdtOp, mutations.len);
        for (mutations, 0..) |m, i| {
            ops[i] = try self.mutate(m.path, m.value);
        }
        return ops;
    }

    /// Merge a remote operation. Returns true if local state changed.
    /// Implements LWW: higher timestamp wins; tie-break by peer_id (lexicographic).
    pub fn applyRemoteOp(self: *CrdtDoc, op: CrdtOp) !bool {
        // Advance Lamport clock: max(local, remote) + 1
        self.clock = @max(self.clock, op.timestamp) + 1;

        if (self.fields.getPtr(op.path)) |existing| {
            if (!shouldReplace(existing.*, op)) {
                return false; // Local value wins, no change
            }
            // Replace value in-place (key stays the same, it's the same path)
            self.allocator.free(existing.value);
            existing.* = CrdtField{
                .value = try self.allocator.dupe(u8, op.value),
                .timestamp = op.timestamp,
                .peer_id = op.peer_id,
            };
            return true;
        }

        // New path — allocate key and value
        const owned_path = try self.allocator.dupe(u8, op.path);
        errdefer self.allocator.free(owned_path);
        const owned_value = try self.allocator.dupe(u8, op.value);
        errdefer self.allocator.free(owned_value);

        try self.fields.put(owned_path, CrdtField{
            .value = owned_value,
            .timestamp = op.timestamp,
            .peer_id = op.peer_id,
        });

        return true;
    }

    /// LWW comparison: should the incoming op replace the existing field?
    fn shouldReplace(existing: CrdtField, incoming: CrdtOp) bool {
        if (incoming.timestamp > existing.timestamp) return true;
        if (incoming.timestamp < existing.timestamp) return false;
        // Tie-break: higher peer_id wins (lexicographic)
        return std.mem.order(u8, &incoming.peer_id, &existing.peer_id) == .gt;
    }

    /// Serialize the full CRDT state for syncing a new peer.
    /// Format: JSON object mapping path → {v, ts, p (hex)}.
    pub fn snapshot(self: *const CrdtDoc) ![]const u8 {
        var buf: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer buf.deinit();
        const w = &buf.writer;

        try w.writeByte('{');
        var first = true;
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            if (!first) try w.writeByte(',');
            first = false;

            // "path":{"v":"value","ts":123,"p":"hex"}
            try w.writeByte('"');
            try writeJsonEscaped(w, entry.key_ptr.*);
            try w.writeAll("\":{\"v\":");
            try w.writeByte('"');
            try writeJsonEscaped(w, entry.value_ptr.value);
            try w.writeAll("\",\"ts\":");
            try w.print("{d}", .{entry.value_ptr.timestamp});
            try w.writeAll(",\"p\":\"");
            try writeHex(w, &entry.value_ptr.peer_id);
            try w.writeAll("\"}");
        }
        try w.writeByte('}');

        return buf.toOwnedSlice();
    }

    /// Load a full CRDT snapshot (received from host peer).
    /// Replaces all local state.
    pub fn loadSnapshot(self: *CrdtDoc, data: []const u8) !void {
        // Clear existing state
        self.clearAll();

        // Parse the snapshot JSON
        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, data, .{});
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => return error.InvalidSnapshot,
        };

        var it = obj.iterator();
        while (it.next()) |entry| {
            const path = entry.key_ptr.*;
            const field_obj = switch (entry.value_ptr.*) {
                .object => |o| o,
                else => continue,
            };

            const v_val = field_obj.get("v") orelse continue;
            const ts_val = field_obj.get("ts") orelse continue;
            const p_val = field_obj.get("p") orelse continue;

            const value = switch (v_val) {
                .string => |s| s,
                else => continue,
            };
            const ts: u64 = switch (ts_val) {
                .integer => |i| @intCast(i),
                else => continue,
            };
            const peer_hex = switch (p_val) {
                .string => |s| s,
                else => continue,
            };

            var peer_id: [16]u8 = undefined;
            _ = std.fmt.hexToBytes(&peer_id, peer_hex) catch continue;

            const owned_path = try self.allocator.dupe(u8, path);
            errdefer self.allocator.free(owned_path);
            const owned_value = try self.allocator.dupe(u8, value);
            errdefer self.allocator.free(owned_value);

            try self.fields.put(owned_path, CrdtField{
                .value = owned_value,
                .timestamp = ts,
                .peer_id = peer_id,
            });

            // Advance clock past any timestamp in the snapshot
            self.clock = @max(self.clock, ts);
        }
    }

    /// Export the merged CRDT state as a flat JSON object: {"path": "value", ...}
    /// Tombstones (empty value) are omitted.
    pub fn toModelJson(self: *const CrdtDoc) ![]const u8 {
        var buf: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer buf.deinit();
        const w = &buf.writer;

        try w.writeByte('{');
        var first = true;
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            // Skip tombstones
            if (entry.value_ptr.value.len == 0) continue;

            if (!first) try w.writeByte(',');
            first = false;

            try w.writeByte('"');
            try writeJsonEscaped(w, entry.key_ptr.*);
            try w.writeAll("\":");

            // Value is already JSON-encoded, write it raw
            try w.writeAll(entry.value_ptr.value);
        }
        try w.writeByte('}');

        return buf.toOwnedSlice();
    }

    /// Get the value at a path, or null if not present / tombstoned.
    pub fn get(self: *const CrdtDoc, path: []const u8) ?[]const u8 {
        const field = self.fields.get(path) orelse return null;
        if (field.value.len == 0) return null; // tombstone
        return field.value;
    }

    /// Number of non-tombstone fields.
    /// Iterate every (path, value, peer_id, timestamp) entry currently
    /// in the CRDT doc. Used by `manager.processMessage(.sync)` so the
    /// joiner can replay the host's existing state through the bridge
    /// into its local UnifiedModel — without this, a joiner that
    /// connects AFTER the host has imported sees the data only in the
    /// CRDT layer, never in the actor / UI.
    pub fn iterateFields(
        self: *const CrdtDoc,
        ctx: *anyopaque,
        callback: *const fn (ctx: *anyopaque, path: []const u8, value: []const u8, peer_id: [16]u8) void,
    ) void {
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            callback(ctx, entry.key_ptr.*, entry.value_ptr.value, entry.value_ptr.peer_id);
        }
    }

    pub fn fieldCount(self: *const CrdtDoc) usize {
        var count: usize = 0;
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.value.len > 0) count += 1;
        }
        return count;
    }

    fn clearAll(self: *CrdtDoc) void {
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.value);
        }
        self.fields.clearAndFree();
    }

    // =========================================================================
    // CrdtInterface adapter
    //
    // The vtable wrappers below let `CollabManager` route ops to this
    // CRDT via the same dispatch path used by future CRDT types (text,
    // blob). The wire-side `op_bytes` encoding is the same JSON shape
    // the old `protocol.encode(.op = CrdtOp{...})` produced — the field
    // names `path`/`v`/`ts`/`p` are preserved so a 2-instance smoke
    // run from the previous tree is on-the-wire identical.
    // =========================================================================

    /// Caller-facing input to `applyLocal` via the vtable:
    /// `{"path":"...","value":"..."}`.
    /// We use `value` (long form) on the inbound path to mirror the
    /// existing `bridge_handlers.collab.mutate` JSON shape; the on-the-
    /// wire short form (`v`) is emitted inside `encodeOpBytes` below.
    fn vtableApplyLocal(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        input: []const u8,
    ) anyerror!OpBytes {
        const self: *CrdtDoc = @ptrCast(@alignCast(ptr));
        const parsed = try std.json.parseFromSlice(struct {
            path: []const u8,
            value: []const u8,
        }, allocator, input, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const op = try self.mutate(parsed.value.path, parsed.value.value);
        return try encodeOpBytes(allocator, op);
    }

    fn vtableApplyRemote(ptr: *anyopaque, op_bytes: OpBytes) anyerror!bool {
        const self: *CrdtDoc = @ptrCast(@alignCast(ptr));
        const op = try decodeOpBytes(self.allocator, op_bytes);
        // `decodeOpBytes` returns owned `path` + `value` strings; the
        // CRDT dupes them again into its own storage during
        // `applyRemoteOp`, so the transient copies must be freed here.
        defer self.allocator.free(op.path);
        defer self.allocator.free(op.value);
        return try self.applyRemoteOp(op);
    }

    fn vtableSnapshot(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!SnapshotBytes {
        const self: *CrdtDoc = @ptrCast(@alignCast(ptr));
        // `snapshot()` already uses `self.allocator`; for v1 the manager
        // and the CRDT share an allocator, so this is fine. If they ever
        // diverge, dup into `allocator` here.
        if (self.allocator.ptr != allocator.ptr) {
            const native = try self.snapshot();
            defer self.allocator.free(native);
            return try allocator.dupe(u8, native);
        }
        return try self.snapshot();
    }

    fn vtableLoadSnapshot(ptr: *anyopaque, bytes: SnapshotBytes) anyerror!void {
        const self: *CrdtDoc = @ptrCast(@alignCast(ptr));
        try self.loadSnapshot(bytes);
    }

    fn vtableDeinit(ptr: *anyopaque, allocator: std.mem.Allocator) void {
        const self: *CrdtDoc = @ptrCast(@alignCast(ptr));
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

    /// Type-erase `self` for `Channel.crdt`. The returned interface holds
    /// `self` by pointer; `self` must outlive the channel registration.
    pub fn interface(self: *CrdtDoc) CrdtInterface {
        return .{ .ptr = self, .vtable = &vtable_inst };
    }
};

// =============================================================================
// LWW-Map op wire encoding (used by the CrdtInterface adapter)
// =============================================================================

/// Encode one CrdtOp to opaque bytes: `{"path":"...","v":"...","ts":N,"p":"hex"}`.
/// Caller owns the returned slice; free with the same `allocator`.
pub fn encodeOpBytes(allocator: std.mem.Allocator, op: CrdtOp) ![]u8 {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    const w = &buf.writer;

    try w.writeAll("{\"path\":\"");
    try json_util.writeJsonEscaped(w, op.path);
    try w.writeAll("\",\"v\":\"");
    try json_util.writeJsonEscaped(w, op.value);
    try w.writeAll("\",\"ts\":");
    try w.print("{d}", .{op.timestamp});
    try w.writeAll(",\"p\":\"");
    try json_util.writeHex(w, &op.peer_id);
    try w.writeAll("\"}");

    return buf.toOwnedSlice();
}

/// Decode opaque bytes back into a CrdtOp. The op's `path` + `value`
/// fields point into a heap-allocated `std.json.Parsed` buffer — the
/// caller must consume the op (e.g. by calling `applyRemoteOp` which
/// dupes any retained strings into the CRDT's own storage) before
/// the underlying buffer is freed.
///
/// For the vtable's `applyRemote` path, the CRDT's `applyRemoteOp`
/// dupes both `path` and `value` into the doc's storage, so the
/// transient buffer is safe to discard immediately after the call.
pub fn decodeOpBytes(allocator: std.mem.Allocator, bytes: []const u8) !CrdtOp {
    // Parse into a private arena so the JSON allocations don't leak
    // even if `applyRemoteOp` is interrupted by an OOM in the doc.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, aa, bytes, .{});

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidOpBytes,
    };
    const path_val = obj.get("path") orelse return error.InvalidOpBytes;
    const v_val = obj.get("v") orelse return error.InvalidOpBytes;
    const ts_val = obj.get("ts") orelse return error.InvalidOpBytes;
    const p_val = obj.get("p") orelse return error.InvalidOpBytes;

    const path_s = switch (path_val) {
        .string => |s| s,
        else => return error.InvalidOpBytes,
    };
    const v_s = switch (v_val) {
        .string => |s| s,
        else => return error.InvalidOpBytes,
    };
    const ts: u64 = switch (ts_val) {
        .integer => |i| if (i < 0) return error.InvalidOpBytes else @intCast(i),
        else => return error.InvalidOpBytes,
    };
    const p_hex = switch (p_val) {
        .string => |s| s,
        else => return error.InvalidOpBytes,
    };
    var peer_id: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&peer_id, p_hex) catch return error.InvalidOpBytes;

    // Dup the borrowed strings into the caller's allocator so they
    // outlive the arena. `applyRemoteOp` will dupe them again into its
    // own storage; the temporary duplication is acceptable for v1 and
    // can be elided in a future tightness pass.
    const path_owned = try allocator.dupe(u8, path_s);
    errdefer allocator.free(path_owned);
    const v_owned = try allocator.dupe(u8, v_s);
    errdefer allocator.free(v_owned);

    return .{
        .path = path_owned,
        .value = v_owned,
        .timestamp = ts,
        .peer_id = peer_id,
    };
}

// =============================================================================
// Helpers — delegated to shared utility
// =============================================================================

const json_util = @import("util_json");
const writeJsonEscaped = json_util.writeJsonEscaped;
const writeHex = json_util.writeHex;

// =============================================================================
// Tests
// =============================================================================

test "CrdtDoc: basic mutate and get" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    const op = try doc.mutate("model.nodes.A.x", "100");
    try std.testing.expectEqualStrings("model.nodes.A.x", op.path);
    try std.testing.expectEqualStrings("100", op.value);
    try std.testing.expectEqual(@as(u64, 1), op.timestamp);

    const val = doc.get("model.nodes.A.x");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("100", val.?);
}

test "CrdtDoc: mutate overwrites previous value" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    _ = try doc.mutate("x", "1");
    _ = try doc.mutate("x", "2");
    try std.testing.expectEqualStrings("2", doc.get("x").?);
    try std.testing.expectEqual(@as(u64, 2), doc.clock);
}

test "CrdtDoc: applyRemoteOp merges correctly" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    // Apply remote op to empty doc
    const changed = try doc.applyRemoteOp(.{
        .path = "model.nodes.A.x",
        .value = "42",
        .timestamp = 5,
        .peer_id = [_]u8{0xFF} ** 16,
    });
    try std.testing.expect(changed);
    try std.testing.expectEqualStrings("42", doc.get("model.nodes.A.x").?);
}

test "CrdtDoc: LWW higher timestamp wins" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    // Set local value at ts=1
    _ = try doc.mutate("x", "local");

    // Remote op with higher timestamp should win
    const changed = try doc.applyRemoteOp(.{
        .path = "x",
        .value = "remote",
        .timestamp = 10,
        .peer_id = [_]u8{0x01} ** 16,
    });
    try std.testing.expect(changed);
    try std.testing.expectEqualStrings("remote", doc.get("x").?);
}

test "CrdtDoc: LWW lower timestamp loses" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    // Set local value at ts=1
    _ = try doc.mutate("x", "local");

    // Manually set a high timestamp field
    const key = try allocator.dupe(u8, "y");
    const val = try allocator.dupe(u8, "high");
    try doc.fields.put(key, .{
        .value = val,
        .timestamp = 100,
        .peer_id = doc.peer_id,
    });

    // Remote op with lower timestamp should lose
    const changed = try doc.applyRemoteOp(.{
        .path = "y",
        .value = "low",
        .timestamp = 5,
        .peer_id = [_]u8{0xFF} ** 16,
    });
    try std.testing.expect(!changed);
    try std.testing.expectEqualStrings("high", doc.get("y").?);
}

test "CrdtDoc: LWW timestamp tie breaks by peer_id" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.initWithPeerId(allocator, [_]u8{0x01} ** 16);
    defer doc.deinit();

    // Set value
    _ = try doc.mutate("x", "low_peer");

    // Remote op with same timestamp but higher peer_id should win
    const changed = try doc.applyRemoteOp(.{
        .path = "x",
        .value = "high_peer",
        .timestamp = 1, // same as local
        .peer_id = [_]u8{0xFF} ** 16, // higher than 0x01
    });
    try std.testing.expect(changed);
    try std.testing.expectEqualStrings("high_peer", doc.get("x").?);
}

test "CrdtDoc: snapshot and loadSnapshot round-trip" {
    const allocator = std.testing.allocator;

    // Create doc with some state
    var doc1 = CrdtDoc.init(allocator);
    defer doc1.deinit();
    _ = try doc1.mutate("a", "1");
    _ = try doc1.mutate("b", "2");
    _ = try doc1.mutate("c", "3");

    // Snapshot
    const snap = try doc1.snapshot();
    defer allocator.free(snap);

    // Load into fresh doc
    var doc2 = CrdtDoc.init(allocator);
    defer doc2.deinit();
    try doc2.loadSnapshot(snap);

    // Verify all fields match
    try std.testing.expectEqualStrings("1", doc2.get("a").?);
    try std.testing.expectEqualStrings("2", doc2.get("b").?);
    try std.testing.expectEqualStrings("3", doc2.get("c").?);
}

test "CrdtDoc: toModelJson excludes tombstones" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    _ = try doc.mutate("alive", "\"yes\"");
    _ = try doc.mutate("dead", ""); // tombstone

    const json = try doc.toModelJson();
    defer allocator.free(json);

    // Should contain "alive" but not "dead"
    try std.testing.expect(std.mem.indexOf(u8, json, "alive") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "dead") == null);
}

test "CrdtDoc: Lamport clock advances on remote ops" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    _ = try doc.applyRemoteOp(.{
        .path = "x",
        .value = "1",
        .timestamp = 50,
        .peer_id = [_]u8{0xAA} ** 16,
    });

    // Clock should be max(0, 50) + 1 = 51
    try std.testing.expectEqual(@as(u64, 51), doc.clock);

    // Next local mutation should use clock=52
    const op = try doc.mutate("y", "2");
    try std.testing.expectEqual(@as(u64, 52), op.timestamp);
}

test "CrdtDoc: concurrent non-conflicting edits merge cleanly" {
    const allocator = std.testing.allocator;

    var doc_a = CrdtDoc.initWithPeerId(allocator, [_]u8{0xAA} ** 16);
    defer doc_a.deinit();
    var doc_b = CrdtDoc.initWithPeerId(allocator, [_]u8{0xBB} ** 16);
    defer doc_b.deinit();

    // Alice edits path "x", Bob edits path "y" — no conflict
    const op_a = try doc_a.mutate("x", "100");
    const op_b = try doc_b.mutate("y", "200");

    // Cross-apply
    _ = try doc_a.applyRemoteOp(op_b);
    _ = try doc_b.applyRemoteOp(op_a);

    // Both docs should have both values
    try std.testing.expectEqualStrings("100", doc_a.get("x").?);
    try std.testing.expectEqualStrings("200", doc_a.get("y").?);
    try std.testing.expectEqualStrings("100", doc_b.get("x").?);
    try std.testing.expectEqualStrings("200", doc_b.get("y").?);
}

test "CrdtDoc: convergence on same-field conflict" {
    const allocator = std.testing.allocator;

    var doc_a = CrdtDoc.initWithPeerId(allocator, [_]u8{0xAA} ** 16);
    defer doc_a.deinit();
    var doc_b = CrdtDoc.initWithPeerId(allocator, [_]u8{0xBB} ** 16);
    defer doc_b.deinit();

    // Both edit the same path concurrently (ts=1 for both)
    const op_a = try doc_a.mutate("x", "alice");
    const op_b = try doc_b.mutate("x", "bob");

    // Cross-apply
    _ = try doc_a.applyRemoteOp(op_b);
    _ = try doc_b.applyRemoteOp(op_a);

    // Both should converge to the same value (BB > AA, so Bob wins)
    try std.testing.expectEqualStrings(doc_a.get("x").?, doc_b.get("x").?);
    try std.testing.expectEqualStrings("bob", doc_a.get("x").?);
}
