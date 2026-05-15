//! Collaboration Host Functions for Zora Plugin Engine
//!
//! Exposes the CollabManager to WASM plugins via CustomHostFunction.
//! 7 host functions in the "spirefy" module:
//!   collab_create_session  — Start hosting, returns room code
//!   collab_join_session    — Join room by code
//!   collab_mutate          — Apply a local mutation to CRDT + broadcast
//!   collab_mutate_batch    — Apply multiple mutations atomically
//!   collab_get_peers       — List connected peers
//!   collab_get_session_info — Get session state
//!   collab_leave_session   — Disconnect from session

const std = @import("std");
const zora = @import("zora");
const CollabManager = @import("manager.zig").CollabManager;
const Mutation = @import("crdt_lww_map.zig").Mutation;
const crypto_mod = @import("crypto.zig");

var global_allocator: ?std.mem.Allocator = null;
var global_manager: ?*CollabManager = null;

/// Set the global collab context. Must be called before engine starts.
pub fn setGlobalContext(allocator: std.mem.Allocator, manager: *CollabManager) void {
    global_allocator = allocator;
    global_manager = manager;
}

/// Get the 7 host function definitions for registration with the engine.
pub fn getHostFunctionDefs() [7]zora.pe.host.CustomHostFunction {
    return .{
        .{
            .name = "collab_create_session",
            .handler = &hostCreateSession,
            .description = "Create a collaboration session (host mode)",
        },
        .{
            .name = "collab_join_session",
            .handler = &hostJoinSession,
            .description = "Join a collaboration session by room code",
        },
        .{
            .name = "collab_mutate",
            .handler = &hostMutate,
            .description = "Apply a local CRDT mutation and broadcast",
        },
        .{
            .name = "collab_mutate_batch",
            .handler = &hostMutateBatch,
            .description = "Apply multiple CRDT mutations atomically",
        },
        .{
            .name = "collab_get_peers",
            .handler = &hostGetPeers,
            .description = "List connected collaboration peers",
        },
        .{
            .name = "collab_get_session_info",
            .handler = &hostGetSessionInfo,
            .description = "Get current collaboration session info",
        },
        .{
            .name = "collab_leave_session",
            .handler = &hostLeaveSession,
            .description = "Leave the current collaboration session",
        },
    };
}

// =============================================================================
// Host Function Implementations
// =============================================================================

/// Create session. Input: {"name":"Alice","port":8080}
/// Returns: {"room":"ABCD-1234"} or {"error":"..."}
fn hostCreateSession(
    data_ptr: [*c]const u8,
    data_len: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    const allocator = global_allocator orelse return errorResponse(out_len, "Collab not initialized");
    const manager = global_manager orelse return errorResponse(out_len, "Collab manager not available");

    if (data_len == 0) return errorResponse(out_len, "Empty input");
    const input = data_ptr[0..data_len];

    const parsed = std.json.parseFromSlice(struct {
        room: []const u8 = "",
        name: []const u8 = "Anonymous",
        port: u16 = 8080,
        /// Optional AEAD suite override. Default `.aes_gcm_v1` matches A1
        /// behavior; pass `"chacha-v1"` for ChaCha-only sessions.
        suite: []const u8 = "",
    }, allocator, input, .{ .ignore_unknown_fields = true }) catch {
        return errorResponse(out_len, "Invalid JSON input");
    };
    defer parsed.deinit();

    const requested: ?[]const u8 = if (parsed.value.room.len == 0) null else parsed.value.room;
    const suite: crypto_mod.Suite = if (parsed.value.suite.len == 0)
        .aes_gcm_v1
    else
        crypto_mod.Suite.fromName(parsed.value.suite) orelse .aes_gcm_v1;
    const room_code = manager.createSession(parsed.value.name, parsed.value.port, requested, suite) catch |err| {
        return errorResponse(out_len, @errorName(err));
    };

    const json = std.fmt.allocPrint(allocator, "{{\"room\":\"{s}\"}}", .{room_code}) catch {
        return errorResponse(out_len, "Serialization error");
    };
    out_len.* = json.len;
    return json.ptr;
}

/// Join session. Input: {"room":"ABCD-1234","relay":"ws://...","name":"Bob"}
/// Returns: {"ok":true} or {"error":"..."}
fn hostJoinSession(
    data_ptr: [*c]const u8,
    data_len: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    const allocator = global_allocator orelse return errorResponse(out_len, "Collab not initialized");
    const manager = global_manager orelse return errorResponse(out_len, "Collab manager not available");

    if (data_len == 0) return errorResponse(out_len, "Empty input");
    const input = data_ptr[0..data_len];

    const parsed = std.json.parseFromSlice(struct {
        room: []const u8,
        relay: []const u8,
        name: []const u8 = "Anonymous",
    }, allocator, input, .{ .ignore_unknown_fields = true }) catch {
        return errorResponse(out_len, "Invalid JSON input");
    };
    defer parsed.deinit();

    manager.joinSession(parsed.value.room, parsed.value.relay, parsed.value.name) catch |err| {
        return errorResponse(out_len, @errorName(err));
    };

    return okResponse(out_len);
}

/// Mutate. Input: {"path":"model.nodes.A.x","value":"100"}
/// Returns: {"ok":true} or {"error":"..."}
fn hostMutate(
    data_ptr: [*c]const u8,
    data_len: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    const allocator = global_allocator orelse return errorResponse(out_len, "Collab not initialized");
    const manager = global_manager orelse return errorResponse(out_len, "Collab manager not available");

    if (data_len == 0) return errorResponse(out_len, "Empty input");
    const input = data_ptr[0..data_len];

    const parsed = std.json.parseFromSlice(struct {
        path: []const u8,
        value: []const u8,
    }, allocator, input, .{ .ignore_unknown_fields = true }) catch {
        return errorResponse(out_len, "Invalid JSON input");
    };
    defer parsed.deinit();

    manager.mutate(parsed.value.path, parsed.value.value) catch |err| {
        return errorResponse(out_len, @errorName(err));
    };

    return okResponse(out_len);
}

/// Batch mutate. Input: {"mutations":[{"path":"...","value":"..."},...]}}
/// Returns: {"ok":true} or {"error":"..."}
fn hostMutateBatch(
    data_ptr: [*c]const u8,
    data_len: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    const allocator = global_allocator orelse return errorResponse(out_len, "Collab not initialized");
    const manager = global_manager orelse return errorResponse(out_len, "Collab manager not available");

    if (data_len == 0) return errorResponse(out_len, "Empty input");
    const input = data_ptr[0..data_len];

    // Parse with dynamic JSON since we need an array of objects
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, input, .{}) catch {
        return errorResponse(out_len, "Invalid JSON input");
    };
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return errorResponse(out_len, "Expected JSON object"),
    };

    const mutations_val = obj.get("mutations") orelse return errorResponse(out_len, "Missing 'mutations' field");
    const mutations_arr = switch (mutations_val) {
        .array => |a| a,
        else => return errorResponse(out_len, "Expected 'mutations' to be an array"),
    };

    // Build mutation slice
    const mutations = allocator.alloc(Mutation, mutations_arr.items.len) catch {
        return errorResponse(out_len, "Allocation error");
    };
    defer allocator.free(mutations);

    for (mutations_arr.items, 0..) |item, i| {
        const item_obj = switch (item) {
            .object => |o| o,
            else => return errorResponse(out_len, "Invalid mutation entry"),
        };
        const path = switch (item_obj.get("path") orelse return errorResponse(out_len, "Missing 'path'")) {
            .string => |s| s,
            else => return errorResponse(out_len, "Invalid 'path'"),
        };
        const value = switch (item_obj.get("value") orelse return errorResponse(out_len, "Missing 'value'")) {
            .string => |s| s,
            else => return errorResponse(out_len, "Invalid 'value'"),
        };
        mutations[i] = .{ .path = path, .value = value };
    }

    manager.mutateBatch(mutations) catch |err| {
        return errorResponse(out_len, @errorName(err));
    };

    return okResponse(out_len);
}

/// Get peers. Input: ignored. Returns: {"peers":[{"id":"...","name":"..."},...]}}
fn hostGetPeers(
    _: [*c]const u8,
    _: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    const allocator = global_allocator orelse return errorResponse(out_len, "Collab not initialized");
    const manager = global_manager orelse return errorResponse(out_len, "Collab manager not available");

    const json = manager.getPeersJson() catch {
        return errorResponse(out_len, "Serialization error");
    };
    defer allocator.free(json);
    return dupeToC(allocator, json, out_len);
}

/// Get session info. Input: ignored. Returns session state JSON.
fn hostGetSessionInfo(
    _: [*c]const u8,
    _: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    const allocator = global_allocator orelse return errorResponse(out_len, "Collab not initialized");
    const manager = global_manager orelse return errorResponse(out_len, "Collab manager not available");

    const json = manager.getSessionInfoJson() catch {
        return errorResponse(out_len, "Serialization error");
    };
    defer allocator.free(json);
    return dupeToC(allocator, json, out_len);
}

/// Leave session. Input: ignored. Returns: {"ok":true}
fn hostLeaveSession(
    _: [*c]const u8,
    _: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    const manager = global_manager orelse return errorResponse(out_len, "Collab manager not available");
    manager.leaveSession();
    return okResponse(out_len);
}

// =============================================================================
// Helpers
// =============================================================================

fn dupeToC(allocator: std.mem.Allocator, data: []const u8, out_len: *usize) [*c]u8 {
    const buf = allocator.alloc(u8, data.len) catch return null;
    @memcpy(buf, data);
    out_len.* = buf.len;
    return buf.ptr;
}

fn okResponse(out_len: *usize) [*c]u8 {
    const allocator = global_allocator orelse {
        out_len.* = 0;
        return null;
    };
    const json = allocator.dupe(u8, "{\"ok\":true}") catch {
        out_len.* = 0;
        return null;
    };
    out_len.* = json.len;
    return json.ptr;
}

fn errorResponse(out_len: *usize, msg: []const u8) [*c]u8 {
    const allocator = global_allocator orelse {
        out_len.* = 0;
        return null;
    };
    const json = std.fmt.allocPrint(allocator, "{{\"error\":\"{s}\"}}", .{msg}) catch {
        out_len.* = 0;
        return null;
    };
    out_len.* = json.len;
    return json.ptr;
}
