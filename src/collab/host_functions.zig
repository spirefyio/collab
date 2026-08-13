//! Collaboration Host Functions for Zora Plugin Engine
//!
//! Exposes the CollabManager to WASM plugins via CustomHostFunction.
//! 7 host functions:
//!   collab_create_session  — Start hosting, returns room code
//!   collab_join_session    — Join room by code
//!   collab_mutate          — Apply a local mutation to CRDT + broadcast
//!   collab_mutate_batch    — Apply multiple mutations atomically
//!   collab_get_peers       — List connected peers
//!   collab_get_session_info — Get session state
//!   collab_leave_session   — Disconnect from session
//!
//! ## Every one of these is a network operation, so every one carries a subject
//!
//! Until #112 these seven registered with BOTH `capability` and `caller_handler`
//! null. That combination is not "two defaults" — it is two separate gates
//! switched off:
//!
//!   * `capability = null` ⇒ the engine's trampoline gate is
//!     `if (ctx.capability) |cap| {…}`, so a null capability SKIPS it entirely.
//!     No grant was required to call these.
//!   * `caller_handler = null` ⇒ `decideCustomDispatch` returns the identity-free
//!     `.handler`, so the code that opened a socket never learned WHO asked.
//!
//! The consequence was a plugin declaring the import getting outbound TCP to a
//! host of its choosing — `collab_join_session` takes the relay URL straight from
//! guest JSON — with no capability grant, no manifest ACL, no consent and no audit
//! entry, because there was no subject to attribute any of those to.
//!
//! Both are closed here, and the shape is deliberate:
//!
//!   1. `capability = "network.websocket"` on all seven. A node that already
//!      exists in zora's capability tree (`types/capability.zig`), so a plugin
//!      granted `network.*` or `network.websocket` satisfies it and nothing else
//!      does. Checked BEFORE any guest memory is read.
//!   2. `caller_handler` on all seven. The engine resolves the calling plugin id
//!      from the store's `instance_context` — host-set and unforgeable — and
//!      denies fail-closed when it cannot. That id is the subject.
//!   3. `handler` — required by the registration type, and the entry any
//!      non-trampoline caller would reach — is a REFUSAL for all seven. It is the
//!      path with no subject, and there is no collab operation that should run
//!      without one.
//!   4. `collab_join_session` additionally asks the app's `EgressGate` whether
//!      THIS plugin may reach THAT host, which is the same manifest allow-list
//!      the one-shot and streaming HTTP paths enforce.
//!
//! ## What is still open
//!
//! `bridge_handlers.zig` exposes the same six operations to the WebView lane, and
//! its handler type (`fn(allocator, json_args)`) has no subject slot at all — it
//! cannot be fixed by setting a field. That is a bridge-contract change against
//! the frozen React lane and carries its own ticket. `parseWsUrl` is hardened for
//! both lanes here; the ATTRIBUTION half is only closed on this one.

const std = @import("std");
const zora = @import("zora");
const manager_mod = @import("manager.zig");
const CollabManager = manager_mod.CollabManager;
const Mutation = @import("crdt_lww_map.zig").Mutation;
const crypto_mod = @import("crypto.zig");

/// The grant a plugin must hold to reach ANY of these seven.
///
/// One capability for the whole module rather than a finer split, matching the
/// registration type's "single capability BY DESIGN" note. The seven are not
/// separable in practice: `get_peers` discloses who is connected, `leave_session`
/// tears down the user's session, and `mutate` writes to live sockets — there is
/// no member of this set that a plugin should hold while being refused the others.
/// The tree supports `network.websocket.*` children if a real consumer ever needs
/// the split.
const CAPABILITY = "network.websocket";

var global_allocator: ?std.mem.Allocator = null;
var global_manager: ?*CollabManager = null;

/// The app's egress ACL, or none. Same lifecycle discipline as `global_manager`:
/// ONE writer, the main thread, at boot, before any plugin exists.
///
/// Null means DENY, not "skip" — an app that wires collab without wiring an egress
/// gate gets no plugin-driven outbound connections. That is the same contract
/// zora's streaming path already states ("a host that does NOT install a gate
/// leaves streaming fail-closed at the call site"), and it is the reason this is a
/// separate setter rather than a field on `setGlobalContext`: forgetting it costs
/// a feature, never a hole.
var global_egress_gate: ?*const zora.pe.host.EgressGate = null;

/// Set the global collab context. Must be called before engine starts.
pub fn setGlobalContext(allocator: std.mem.Allocator, manager: *CollabManager) void {
    global_allocator = allocator;
    global_manager = manager;
}

/// Install the egress ACL the join path consults. Must be called before the engine
/// starts, for the same reason `setGlobalContext` must.
pub fn setEgressGate(gate: ?*const zora.pe.host.EgressGate) void {
    global_egress_gate = gate;
    warned_gate_absent = false;
}

/// Get the 7 host function definitions for registration with the engine.
///
/// Every row carries the same three security fields, and the uniformity is the
/// point: the defect this closed was ONE row-shape repeated seven times with two
/// fields absent, in a block where every neighbouring module set them. A reviewer
/// should be able to see a missing `capability` here as a hole in a column.
pub fn getHostFunctionDefs() [7]zora.pe.host.CustomHostFunction {
    return .{
        .{
            .name = "collab_create_session",
            .handler = &refuseUnidentified,
            .caller_handler = &callerCreateSession,
            .capability = CAPABILITY,
            .description = "Create a collaboration session (host mode)",
        },
        .{
            .name = "collab_join_session",
            .handler = &refuseUnidentified,
            .caller_handler = &callerJoinSession,
            .capability = CAPABILITY,
            .description = "Join a collaboration session by room code",
        },
        .{
            .name = "collab_mutate",
            .handler = &refuseUnidentified,
            .caller_handler = &callerMutate,
            .capability = CAPABILITY,
            .description = "Apply a local CRDT mutation and broadcast",
        },
        .{
            .name = "collab_mutate_batch",
            .handler = &refuseUnidentified,
            .caller_handler = &callerMutateBatch,
            .capability = CAPABILITY,
            .description = "Apply multiple CRDT mutations atomically",
        },
        .{
            .name = "collab_get_peers",
            .handler = &refuseUnidentified,
            .caller_handler = &callerGetPeers,
            .capability = CAPABILITY,
            .description = "List connected collaboration peers",
        },
        .{
            .name = "collab_get_session_info",
            .handler = &refuseUnidentified,
            .caller_handler = &callerGetSessionInfo,
            .capability = CAPABILITY,
            .description = "Get current collaboration session info",
        },
        .{
            .name = "collab_leave_session",
            .handler = &refuseUnidentified,
            .caller_handler = &callerLeaveSession,
            .capability = CAPABILITY,
            .description = "Leave the current collaboration session",
        },
    };
}

// =============================================================================
// The subject seam
// =============================================================================

/// The `handler` slot for all seven: refuse.
///
/// The registration type requires `handler` and documents that `caller_handler`
/// wins on the WASM trampoline, leaving `handler` for "any in-process/native entry
/// that calls it directly". Collab has no such entry — the WebView lane goes
/// through `bridge_handlers.zig`, not here — so the honest content of that slot is
/// a refusal. If one is ever added it will fail loudly at its first call rather
/// than silently inheriting the unattributed path this ticket removed.
fn refuseUnidentified(
    _: [*c]const u8,
    _: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    return errorResponse(out_len, "collab requires an identified caller");
}

/// The engine-resolved calling plugin id, or null when it is unusable.
///
/// The trampoline already denies an unidentifiable caller before reaching us, so
/// a null/empty id here means a host-side wiring change went wrong rather than a
/// hostile guest. Treated the same either way: no subject, no call.
fn callerId(caller_ptr: [*c]const u8, caller_len: usize) ?[]const u8 {
    if (caller_len == 0) return null;
    const p = caller_ptr orelse return null;
    return p[0..caller_len];
}

/// May `plugin_id` open a collab connection to `host`?
///
/// Delegates to the app's `EgressGate` — the SAME manifest allow-list the one-shot
/// (`handle`) and streaming (`checkHost`) HTTP paths enforce, so collab cannot
/// become a second, laxer opinion about which hosts a plugin may reach.
///
/// Fail-closed in both directions: no gate installed denies, and a host carrying
/// `%` denies. The percent guard is copied in intent from zora's
/// `streamEgressAllowed`: the matcher judges the raw text while the socket layer
/// may percent-DECODE it first, so the two could disagree about which host was
/// approved. Legitimate hostnames never contain `%`.
fn egressAllowed(plugin_id: []const u8, host: []const u8) bool {
    if (host.len == 0) return false;
    if (std.mem.indexOfScalar(u8, host, '%') != null) return false;
    const gate = global_egress_gate orelse {
        // ABSENT is not BROKEN, and the two must not look alike — the same
        // distinction desktop's path-policy slot draws. A missing gate denies
        // (correct), but silently it reads to a plugin author as "collab is
        // broken" and to an integrator as "collab has no egress control". Say
        // which it is, once, at `warn`: an app that meant to install a gate
        // finds out, and one that did not learns collab is inert by design.
        if (!warned_gate_absent) {
            warned_gate_absent = true;
            std.log.warn(
                "collab: no egress gate installed — every plugin-driven join will be REFUSED. " ++
                    "The host app must call `setEgressGate` before the engine starts.",
                .{},
            );
        }
        return false;
    };
    return gate.checkHost(gate.ctx, plugin_id, host);
}

/// Whether the absent-gate warning has been emitted. Racy by construction and
/// harmless: the worst outcome is two identical warnings.
var warned_gate_absent: bool = false;

const unidentified = "collab requires an identified caller";

/// The guest's input slice, or null when there is none. `data_ptr` is only
/// meaningful when `data_len` is non-zero — the trampoline passes null for an
/// empty body.
fn inputSlice(data_ptr: [*c]const u8, data_len: usize) ?[]const u8 {
    if (data_len == 0) return null;
    const p = data_ptr orelse return null;
    return p[0..data_len];
}

// =============================================================================
// Caller-scoped entry points — the seven the engine actually dispatches
// =============================================================================

/// Bind a listening socket on a guest-chosen port.
///
/// The capability grant is the whole control here, deliberately: an inbound
/// listener has no remote host to check against an allow-list, and this house has
/// no bind-port policy to consult. Naming that gap beats implying the ACL below
/// covers both directions — it does not.
fn callerCreateSession(
    caller_ptr: [*c]const u8,
    caller_len: usize,
    data_ptr: [*c]const u8,
    data_len: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    const who = callerId(caller_ptr, caller_len) orelse return errorResponse(out_len, unidentified);
    std.log.debug("collab: create_session by '{s}'", .{who});
    return hostCreateSession(data_ptr, data_len, out_len);
}

/// Open an outbound connection to a guest-named relay. THE egress path.
fn callerJoinSession(
    caller_ptr: [*c]const u8,
    caller_len: usize,
    data_ptr: [*c]const u8,
    data_len: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    const who = callerId(caller_ptr, caller_len) orelse return errorResponse(out_len, unidentified);
    const allocator = global_allocator orelse return errorResponse(out_len, "Collab not initialized");
    const manager = global_manager orelse return errorResponse(out_len, "Collab manager not available");
    const input = inputSlice(data_ptr, data_len) orelse return errorResponse(out_len, "Empty input");

    const parsed = std.json.parseFromSlice(struct {
        room: []const u8,
        relay: []const u8,
        name: []const u8 = "Anonymous",
    }, allocator, input, .{ .ignore_unknown_fields = true }) catch {
        return errorResponse(out_len, "Invalid JSON input");
    };
    defer parsed.deinit();

    // The ACL runs on the PARSED host, before the connect, so a refusal costs no
    // socket. It parses with the manager's own `parseWsUrl` rather than a second
    // parser here: the host this authorizes and the host `joinSession` dials must
    // be the same string, and two parsers is exactly how they stop being.
    const target = manager_mod.parseWsUrl(parsed.value.relay) orelse
        return errorResponse(out_len, "InvalidRelayUrl");
    if (!egressAllowed(who, target.host)) {
        // Guest-triggerable and recoverable, so `debug` — an `err` here would fail
        // the Zig test runner on a denial that is the system working.
        std.log.debug("collab: join refused for '{s}' — '{s}' is not in its allow-list", .{ who, target.host });
        return errorResponse(out_len, "Egress refused");
    }

    manager.joinSession(parsed.value.room, parsed.value.relay, parsed.value.name) catch |err| {
        return errorResponse(out_len, @errorName(err));
    };
    return okResponse(out_len);
}

fn callerMutate(
    caller_ptr: [*c]const u8,
    caller_len: usize,
    data_ptr: [*c]const u8,
    data_len: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    _ = callerId(caller_ptr, caller_len) orelse return errorResponse(out_len, unidentified);
    return hostMutate(data_ptr, data_len, out_len);
}

fn callerMutateBatch(
    caller_ptr: [*c]const u8,
    caller_len: usize,
    data_ptr: [*c]const u8,
    data_len: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    _ = callerId(caller_ptr, caller_len) orelse return errorResponse(out_len, unidentified);
    return hostMutateBatch(data_ptr, data_len, out_len);
}

fn callerGetPeers(
    caller_ptr: [*c]const u8,
    caller_len: usize,
    data_ptr: [*c]const u8,
    data_len: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    _ = callerId(caller_ptr, caller_len) orelse return errorResponse(out_len, unidentified);
    return hostGetPeers(data_ptr, data_len, out_len);
}

fn callerGetSessionInfo(
    caller_ptr: [*c]const u8,
    caller_len: usize,
    data_ptr: [*c]const u8,
    data_len: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    _ = callerId(caller_ptr, caller_len) orelse return errorResponse(out_len, unidentified);
    return hostGetSessionInfo(data_ptr, data_len, out_len);
}

/// Tear down the session. Subject-gated because without one, ANY plugin could end
/// the user's collaboration — a denial of service that no capability check alone
/// distinguishes from the session owner asking.
fn callerLeaveSession(
    caller_ptr: [*c]const u8,
    caller_len: usize,
    data_ptr: [*c]const u8,
    data_len: usize,
    out_len: *usize,
) callconv(.c) [*c]u8 {
    const who = callerId(caller_ptr, caller_len) orelse return errorResponse(out_len, unidentified);
    std.log.debug("collab: leave_session by '{s}'", .{who});
    return hostLeaveSession(data_ptr, data_len, out_len);
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

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

/// A stand-in for the app's ACL, so the refusal paths are exercisable without an
/// engine, a plugin or a socket. Same shape zora's own streaming-ACL tests fake.
const FakeGate = struct {
    var allowed_host: []const u8 = "";
    var asked_about_plugin: []const u8 = "";
    var asked_about_host: []const u8 = "";
    var call_count: usize = 0;

    fn handle(_: *anyopaque, _: []const u8, _: []const u8, _: std.mem.Allocator) anyerror![]u8 {
        // The join path never routes through `handle`; if it ever did, this says so.
        return error.CollabMustNotUseOneShotEgress;
    }

    fn checkHost(_: *anyopaque, plugin_id: []const u8, host: []const u8) bool {
        call_count += 1;
        asked_about_plugin = plugin_id;
        asked_about_host = host;
        return std.mem.eql(u8, host, allowed_host);
    }

    fn reset(allow: []const u8) void {
        allowed_host = allow;
        asked_about_plugin = "";
        asked_about_host = "";
        call_count = 0;
    }
};

var fake_gate_storage: zora.pe.host.EgressGate = undefined;

fn installFakeGate(allow: []const u8) void {
    FakeGate.reset(allow);
    fake_gate_storage = .{
        .ctx = @ptrCast(&FakeGate.call_count),
        .handle = FakeGate.handle,
        .checkHost = FakeGate.checkHost,
    };
    setEgressGate(&fake_gate_storage);
}

test "PLANT: every collab host fn carries a capability AND a caller-scoped handler" {
    // The #112 defect in one assertion. It was not one function missing one
    // field — it was seven rows, uniformly, each missing the same two. A gate
    // that only checked `join` would have passed while six others stayed open,
    // so this checks the COLUMN: an eighth function added without either field,
    // or an existing one quietly reverted, fails here.
    const defs = getHostFunctionDefs();
    try testing.expectEqual(@as(usize, 7), defs.len);
    for (defs) |def| {
        errdefer std.log.warn("collab: ungated host fn '{s}'", .{def.name});
        try testing.expect(def.capability != null);
        try testing.expectEqualStrings(CAPABILITY, def.capability.?);
        try testing.expect(def.caller_handler != null);
        // And the unattributed slot must not be a working implementation.
        try testing.expect(def.handler == &refuseUnidentified);
    }
}

test "the capability is a real, satisfiable, correctly-scoped node" {
    const cap = zora.pe.types.capability;
    // Well-formed by the grammar. A capability that fails validation would be a
    // fn that looks gated and is simply unreachable — a different bug wearing
    // security's clothes.
    try cap.validateCapability(CAPABILITY);

    // Satisfiable by the grants a real manifest would carry...
    try testing.expect(cap.matchCapabilityPattern("network.websocket", CAPABILITY));
    try testing.expect(cap.matchCapabilityPattern("network.*", CAPABILITY));
    try testing.expect(cap.matchCapabilityPattern("*", CAPABILITY));
    // ...and NOT by a neighbouring one. `network.http` is the grant a plugin that
    // only ever fetches would hold; it must not carry collab's sockets with it.
    try testing.expect(!cap.matchCapabilityPattern("network.http", CAPABILITY));
    try testing.expect(!cap.matchCapabilityPattern("filesystem.read", CAPABILITY));
}

test "PLANT: the unattributed handler slot refuses instead of running" {
    global_allocator = testing.allocator;
    defer global_allocator = null;

    var out_len: usize = 0;
    const raw = refuseUnidentified(null, 0, &out_len);
    try testing.expect(raw != null);
    const reply = raw[0..out_len];
    defer testing.allocator.free(reply);
    try testing.expect(std.mem.indexOf(u8, reply, "error") != null);
    try testing.expect(std.mem.indexOf(u8, reply, "identified caller") != null);
}

test "PLANT: no egress gate installed denies, rather than skipping the check" {
    setEgressGate(null);
    defer setEgressGate(null);
    // The whole point of the fix: absent policy is DENY. If this ever returns
    // true, an app that forgot to wire the gate silently gets #112 back.
    try testing.expect(!egressAllowed("some.plugin", "relay.example.com"));
}

test "PLANT: the gate is asked about the SUBJECT and the parsed host" {
    installFakeGate("relay.example.com");
    defer setEgressGate(null);

    try testing.expect(egressAllowed("api-workshop", "relay.example.com"));
    try testing.expectEqual(@as(usize, 1), FakeGate.call_count);
    // The subject reaching the ACL is the entire subject of this ticket: before
    // the fix there was no plugin id to pass, so no per-plugin allow-list could
    // ever have been consulted.
    try testing.expectEqualStrings("api-workshop", FakeGate.asked_about_plugin);
    try testing.expectEqualStrings("relay.example.com", FakeGate.asked_about_host);

    // A host the gate rejects is refused even though the gate exists.
    try testing.expect(!egressAllowed("api-workshop", "evil.example.com"));
}

test "a percent-encoded or empty host is refused BEFORE the gate is consulted" {
    installFakeGate("evil%2eexample.com");
    defer setEgressGate(null);

    // The matcher would compare the raw text while a resolver may percent-decode
    // it first, so the host approved and the host dialled could differ. Refused
    // without asking — asserted by the gate never being called.
    try testing.expect(!egressAllowed("p", "evil%2eexample.com"));
    try testing.expect(!egressAllowed("p", ""));
    try testing.expectEqual(@as(usize, 0), FakeGate.call_count);
}

test "PLANT: an absent gate warns ONCE, and installing one re-arms the warning" {
    // The absent/broken distinction, asserted rather than assumed. A missing
    // gate must deny AND say so — silently denying is how "collab is inert by
    // design" gets mistaken for "collab is broken" for a whole afternoon.
    setEgressGate(null);
    warned_gate_absent = false;
    defer setEgressGate(null);

    try testing.expect(!egressAllowed("p", "relay.example.com"));
    try testing.expect(warned_gate_absent); // said it
    try testing.expect(!egressAllowed("p", "relay.example.com"));
    try testing.expect(warned_gate_absent); // and did not say it again

    // Installing a gate re-arms, so a later teardown warns afresh rather than
    // staying quiet because a previous process phase already had its say.
    installFakeGate("relay.example.com");
    try testing.expect(!warned_gate_absent);
}
