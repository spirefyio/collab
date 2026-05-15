//! Collaboration Bridge Handlers
//!
//! These handlers enable direct JS ↔ Zig communication for collaboration
//! without going through WASM. They follow the zora Bridge handler contract:
//!   fn(allocator: Allocator, json_args: []const u8) anyerror![]const u8
//!
//! Registration with the zora Bridge requires adding custom handler support
//! to DesktopConfig (one-time zora modification). Until then, collaboration
//! is fully functional via host functions (WASM plugins call collab_* host
//! functions, results pushed to JS via view_push).
//!
//! 7 handlers:
//!   collab.create        — Create session, return room code
//!   collab.join          — Join session with room code
//!   collab.mutate        — Apply mutation: {path, value, channel?} → CRDT op → broadcast
//!   collab.mutate_batch  — Apply multiple mutations atomically
//!   collab.leave         — Leave session
//!   collab.peers         — Query connected peers
//!   collab.channels      — List registered channels + per-plugin writability
//!
//! ## Multi-channel routing (Phase A)
//!
//! `collab.mutate` and `collab.mutate_batch` accept an optional `channel`
//! field. If omitted, ops route to the `unified-model` channel (back-compat
//! with the studio's existing flow). Future text/blob/etc. channels are
//! addressed by name.
//!
//! ## Per-plugin ACL (Phase A, security-engineer H-4)
//!
//! The bridge layer knows the calling plugin's id from the zora Bridge
//! contract (currently a TODO — see the comment in `handleMutate` below).
//! Once that wiring lands, `channel.allowed_plugin_ids` is checked here
//! BEFORE the mutation is forwarded to the CRDT. The `unified-model`
//! channel has an empty allowlist + special-case bypass (any plugin can
//! mutate it; v1 back-compat). New channels declare the specific plugins
//! they trust.

const std = @import("std");
const CollabManager = @import("manager.zig").CollabManager;
const crdt_lww_map = @import("crdt_lww_map.zig");
const crypto_mod = @import("crypto.zig");
const Mutation = crdt_lww_map.Mutation;
const channel_mod = @import("channel.zig");

/// Generic handler function type. Compatible with the zora Bridge handler
/// contract but decoupled from the Bridge struct to avoid cross-module deps.
pub const HandlerFn = *const fn (allocator: std.mem.Allocator, json_args: []const u8) anyerror![]const u8;

pub const HandlerDef = struct {
    name: []const u8,
    handler: HandlerFn,
};

var global_manager: ?*CollabManager = null;

/// Set the global collab manager reference.
pub fn setGlobalManager(manager: *CollabManager) void {
    global_manager = manager;
}

/// Get all 7 bridge handler definitions.
pub fn getHandlerDefs() [7]HandlerDef {
    return .{
        .{ .name = "collab.create", .handler = &handleCreate },
        .{ .name = "collab.join", .handler = &handleJoin },
        .{ .name = "collab.mutate", .handler = &handleMutate },
        .{ .name = "collab.mutate_batch", .handler = &handleMutateBatch },
        .{ .name = "collab.leave", .handler = &handleLeave },
        .{ .name = "collab.peers", .handler = &handlePeers },
        .{ .name = "collab.channels", .handler = &handleChannels },
    };
}

/// Default channel for back-compat: ops without a `channel` field route
/// to "unified-model" (the studio's only v1 channel).
const DEFAULT_CHANNEL = "unified-model";

// =============================================================================
// Handler Implementations
// =============================================================================

fn handleCreate(allocator: std.mem.Allocator, json_args: []const u8) anyerror![]const u8 {
    const manager = global_manager orelse
        return try allocator.dupe(u8, "{\"error\":\"Collab not initialized\"}");

    const parsed = std.json.parseFromSlice(struct {
        room: []const u8 = "",
        name: []const u8 = "Anonymous",
        port: u16 = 8080,
        /// Optional AEAD suite override. Default `.aes_gcm_v1` matches A1
        /// behavior; pass `"chacha-v1"` for ChaCha-only sessions. Unknown
        /// values fall back to AES-GCM (no scary error in the JSON path
        /// — the host log records the override).
        suite: []const u8 = "",
    }, allocator, json_args, .{ .ignore_unknown_fields = true }) catch {
        return try allocator.dupe(u8, "{\"error\":\"Invalid JSON\"}");
    };
    defer parsed.deinit();

    const requested: ?[]const u8 = if (parsed.value.room.len == 0) null else parsed.value.room;
    const suite: crypto_mod.Suite = if (parsed.value.suite.len == 0)
        .aes_gcm_v1
    else
        crypto_mod.Suite.fromName(parsed.value.suite) orelse .aes_gcm_v1;
    const room_code = manager.createSession(parsed.value.name, parsed.value.port, requested, suite) catch |err| {
        // Idempotency: if a session is already active and the caller asked
        // for the *same* room, treat as success and echo the current room.
        // This protects against double-fire bugs in the JS dispatch layer
        // and also makes the UX forgiving of click-bouncing on the Share
        // button. A *different* requested room is still rejected — that
        // means a second user has a real semantic conflict.
        if (err == error.SessionActive) {
            if (manager.currentRoomMatches(requested)) {
                return try std.fmt.allocPrint(allocator, "{{\"room\":\"{s}\"}}", .{manager.currentRoom()});
            }
        }
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
    };

    return try std.fmt.allocPrint(allocator, "{{\"room\":\"{s}\"}}", .{room_code});
}

fn handleJoin(allocator: std.mem.Allocator, json_args: []const u8) anyerror![]const u8 {
    const manager = global_manager orelse
        return try allocator.dupe(u8, "{\"error\":\"Collab not initialized\"}");

    const parsed = std.json.parseFromSlice(struct {
        room: []const u8,
        relay: []const u8,
        name: []const u8 = "Anonymous",
    }, allocator, json_args, .{ .ignore_unknown_fields = true }) catch {
        return try allocator.dupe(u8, "{\"error\":\"Invalid JSON\"}");
    };
    defer parsed.deinit();

    manager.joinSession(parsed.value.room, parsed.value.relay, parsed.value.name) catch |err| {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
    };

    return try allocator.dupe(u8, "{\"ok\":true}");
}

fn handleMutate(allocator: std.mem.Allocator, json_args: []const u8) anyerror![]const u8 {
    const manager = global_manager orelse
        return try allocator.dupe(u8, "{\"error\":\"Collab not initialized\"}");

    const parsed = std.json.parseFromSlice(struct {
        path: []const u8,
        value: []const u8,
        channel: ?[]const u8 = null,
    }, allocator, json_args, .{ .ignore_unknown_fields = true }) catch {
        return try allocator.dupe(u8, "{\"error\":\"Invalid JSON\"}");
    };
    defer parsed.deinit();

    const ch_name = parsed.value.channel orelse DEFAULT_CHANNEL;

    // TODO(security H-4 plumbing): once the zora Bridge contract surfaces
    // the calling plugin_id to handlers, add the per-plugin ACL check
    // here via `channel_mod.isPluginAllowedToWrite(ch, calling_plugin)`.
    // For Phase A, the back-compat path (unified-model is open to all
    // plugins per the channel.isPluginAllowedToWrite default) keeps
    // existing flows working; new channels MUST register an explicit
    // allowlist AND wait for the plumbing to land before exposing
    // a public mutate path.

    if (std.mem.eql(u8, ch_name, DEFAULT_CHANNEL)) {
        // Fast path for the v1 LWW channel — directly dispatch through
        // the legacy `mutate(path, value)` API which is the channel-aware
        // back-compat wrapper inside CollabManager.
        manager.mutate(parsed.value.path, parsed.value.value) catch |err| {
            return try std.fmt.allocPrint(allocator, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
        };
    } else {
        // Generic path for future channels: build the channel's input
        // JSON and route through `applyLocalToChannel`. The LWW input
        // shape `{"path":...,"value":...}` is established here; other
        // CRDT types define their own input shape.
        var input_buf: std.Io.Writer.Allocating = .init(allocator);
        defer input_buf.deinit();
        const w = &input_buf.writer;
        w.writeAll("{\"path\":\"") catch return try allocator.dupe(u8, "{\"error\":\"alloc\"}");
        writeEscaped(w, parsed.value.path) catch return try allocator.dupe(u8, "{\"error\":\"alloc\"}");
        w.writeAll("\",\"value\":\"") catch return try allocator.dupe(u8, "{\"error\":\"alloc\"}");
        writeEscaped(w, parsed.value.value) catch return try allocator.dupe(u8, "{\"error\":\"alloc\"}");
        w.writeAll("\"}") catch return try allocator.dupe(u8, "{\"error\":\"alloc\"}");
        manager.applyLocalToChannel(ch_name, input_buf.written()) catch |err| {
            return try std.fmt.allocPrint(allocator, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
        };
    }

    return try allocator.dupe(u8, "{\"ok\":true}");
}

fn handleChannels(allocator: std.mem.Allocator, _: []const u8) anyerror![]const u8 {
    const manager = global_manager orelse
        return try allocator.dupe(u8, "{\"error\":\"Collab not initialized\"}");

    manager.mutex.lockUncancelable(compat_io());
    defer manager.mutex.unlock(compat_io());

    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    const w = &buf.writer;

    try w.writeAll("{\"channels\":[");
    var first = true;
    for (manager.channels.slots.items) |ch| {
        if (!first) try w.writeByte(',');
        first = false;
        try w.writeAll("{\"name\":\"");
        try writeEscaped(w, ch.name);
        try w.writeAll("\",\"writable_by_local\":");
        try w.writeAll(if (ch.writable_by_local) "true" else "false");
        try w.writeAll(",\"writable_by_peers\":");
        try w.writeAll(if (ch.writable_by_peers) "true" else "false");
        try w.writeByte('}');
    }
    try w.writeAll("]}");
    return try buf.toOwnedSlice();
}

fn compat_io() std.Io {
    // Pull through `compat.io()` indirectly to avoid an extra import here.
    return @import("compat").io();
}

fn writeEscaped(w: *std.Io.Writer, s: []const u8) !void {
    const json_util = @import("util_json");
    return json_util.writeJsonEscaped(w, s);
}

fn handleMutateBatch(allocator: std.mem.Allocator, json_args: []const u8) anyerror![]const u8 {
    const manager = global_manager orelse
        return try allocator.dupe(u8, "{\"error\":\"Collab not initialized\"}");

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_args, .{}) catch {
        return try allocator.dupe(u8, "{\"error\":\"Invalid JSON\"}");
    };
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return try allocator.dupe(u8, "{\"error\":\"Expected object\"}"),
    };

    // Channel routing: optional `channel` field at batch level.
    // For Phase A only the LWW back-compat path is exposed (batch ops
    // on non-LWW channels are deferred to channel-specific bridges).
    const ch_name: []const u8 = if (obj.get("channel")) |ch_val| switch (ch_val) {
        .string => |s| s,
        else => return try allocator.dupe(u8, "{\"error\":\"Invalid channel\"}"),
    } else DEFAULT_CHANNEL;
    if (!std.mem.eql(u8, ch_name, DEFAULT_CHANNEL)) {
        return try allocator.dupe(u8, "{\"error\":\"Batch mutate on non-unified-model channels not supported in Phase A\"}");
    }

    const mutations_val = obj.get("mutations") orelse
        return try allocator.dupe(u8, "{\"error\":\"Missing mutations\"}");
    const mutations_arr = switch (mutations_val) {
        .array => |a| a,
        else => return try allocator.dupe(u8, "{\"error\":\"Expected array\"}"),
    };

    const mutations = try allocator.alloc(Mutation, mutations_arr.items.len);
    defer allocator.free(mutations);

    for (mutations_arr.items, 0..) |item, i| {
        const item_obj = switch (item) {
            .object => |o| o,
            else => return try allocator.dupe(u8, "{\"error\":\"Invalid mutation\"}"),
        };
        const path = switch (item_obj.get("path") orelse
            return try allocator.dupe(u8, "{\"error\":\"Missing path\"}")) {
            .string => |s| s,
            else => return try allocator.dupe(u8, "{\"error\":\"Invalid path\"}"),
        };
        const value = switch (item_obj.get("value") orelse
            return try allocator.dupe(u8, "{\"error\":\"Missing value\"}")) {
            .string => |s| s,
            else => return try allocator.dupe(u8, "{\"error\":\"Invalid value\"}"),
        };
        mutations[i] = .{ .path = path, .value = value };
    }

    manager.mutateBatch(mutations) catch |err| {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"{s}\"}}", .{@errorName(err)});
    };

    return try allocator.dupe(u8, "{\"ok\":true}");
}

fn handleLeave(allocator: std.mem.Allocator, _: []const u8) anyerror![]const u8 {
    const manager = global_manager orelse
        return try allocator.dupe(u8, "{\"error\":\"Collab not initialized\"}");
    manager.leaveSession();
    return try allocator.dupe(u8, "{\"ok\":true}");
}

fn handlePeers(allocator: std.mem.Allocator, _: []const u8) anyerror![]const u8 {
    const manager = global_manager orelse
        return try allocator.dupe(u8, "{\"error\":\"Collab not initialized\"}");

    return manager.getPeersJson() catch
        try allocator.dupe(u8, "{\"error\":\"Serialization error\"}");
}
