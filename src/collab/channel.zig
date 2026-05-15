//! Channel + ChannelRegistry — multi-channel CRDT dispatch infrastructure.
//!
//! A `Channel` pairs a name with a CRDT instance, an access-control policy,
//! and optional local/remote-op callbacks (used by per-channel bridges to
//! wire ops into the host application's model layer).
//!
//! The `ChannelRegistry` is the lookup table `CollabManager` uses to route
//! inbound op-frames by their `ch` field. Channels are heap-allocated so
//! the registry can return stable `*Channel` pointers even if the slot
//! list reallocates.
//!
//! State machine (closes panel backend-architect H-4):
//!     init → open_for_registration → frozen → (deinit)
//!
//!   Callers register channels DURING setup (between `CollabManager.init`
//!   and the first `createSession`/`joinSession` call). `freeze()` is
//!   invoked by the manager as it transitions to its `networking` state.
//!   Post-freeze registration returns `error.RegistryFrozen` — this
//!   guards against threading bugs where one thread tries to register
//!   while another reads, since the registry has no internal mutex.

const std = @import("std");
const crdt_interface = @import("crdt_interface.zig");
const CrdtInterface = crdt_interface.CrdtInterface;
const OpBytes = crdt_interface.OpBytes;

// =============================================================================
// Public types
// =============================================================================

/// Maximum number of channels a single CollabManager can host.
/// Defensive cap closing security-engineer M-1: prevents an attacker who
/// gains arbitrary `register()` access (only signed native code today,
/// but defense-in-depth) from exhausting memory via runaway registration.
pub const MAX_CHANNELS: usize = 16;

/// Maximum length of a channel name in bytes. Channel names are part of
/// the wire envelope; small limit avoids large attacker-controlled keys
/// pinning hash-map entries. Names must satisfy `isValidChannelName`.
pub const MAX_CHANNEL_NAME_LEN: usize = 32;

/// Callback fired when the local user mutates state on this channel.
/// Runs INSIDE `CollabManager.mutex` after the CRDT has produced
/// `op_bytes` but BEFORE the broadcast envelope is constructed.
/// `op_bytes` is BORROWED for the call duration only.
///
/// Implementations MUST NOT block long or re-enter `CollabManager`.
pub const LocalOpFn = *const fn (ctx: *anyopaque, op_bytes: OpBytes) void;

/// Callback fired when a remote peer's op has been merged into this
/// channel's CRDT. Runs INSIDE `CollabManager.mutex` after
/// `applyRemote` returns `true` (state changed). `op_bytes` is
/// BORROWED for the call duration only.
///
/// Implementations MUST NOT block long or re-enter `CollabManager`.
pub const RemoteOpFn = *const fn (ctx: *anyopaque, peer_id: [16]u8, op_bytes: OpBytes) void;

/// One CRDT type registered with a CollabManager. Channels are
/// heap-allocated by the registry; consumers receive stable `*Channel`
/// pointers from `find()` valid for the lifetime of the registry.
pub const Channel = struct {
    /// Wire-format identifier. ASCII [a-z0-9-], 1..32 bytes, validated
    /// by `isValidChannelName` at registration time. Borrowed from the
    /// caller — registrants typically pass a `comptime` literal.
    name: []const u8,

    /// The CRDT type-erased through a vtable. The registry calls
    /// `crdt.deinit(allocator)` once per channel on `deinit`.
    crdt: CrdtInterface,

    /// Per-channel access control. Set at registration; immutable for v1.
    /// FAIL-CLOSED DEFAULT (`false`/`false`): a freshly-registered channel
    /// rejects both local writes (returns `error.ReadOnlyChannel`) and
    /// peer writes (logs + drops with `inbound_op_denied` counter bump).
    writable_by_local: bool = false,
    writable_by_peers: bool = false,

    /// Per-plugin write allowlist. Empty = host-only (no WASM plugin
    /// can mutate this channel via `collab.mutate`). The studio's
    /// `unified-model` channel uses an empty list + the v1
    /// back-compat bypass in `bridge_handlers.zig` so existing plugins
    /// keep working; future channels (`editor-text`, `blob`, ...)
    /// declare the specific plugins they trust.
    ///
    /// Borrowed from caller — typically points at a `comptime` array of
    /// string literals on the registering site.
    allowed_plugin_ids: []const []const u8 = &.{},

    /// Optional local-op observer (typically the channel's host-side
    /// bridge to wire ops into the model actor).
    on_local_op: ?LocalOpFn = null,
    on_local_op_ctx: ?*anyopaque = null,

    /// Optional remote-op observer.
    on_remote_op: ?RemoteOpFn = null,
    on_remote_op_ctx: ?*anyopaque = null,
};

/// Registration spec passed to `ChannelRegistry.register`. Mirrors the
/// fields of `Channel` so callers don't have to construct a `Channel`
/// directly (the registry heap-allocates and copies in).
pub const ChannelSpec = struct {
    name: []const u8,
    crdt: CrdtInterface,
    writable_by_local: bool = false,
    writable_by_peers: bool = false,
    allowed_plugin_ids: []const []const u8 = &.{},
    on_local_op: ?LocalOpFn = null,
    on_local_op_ctx: ?*anyopaque = null,
    on_remote_op: ?RemoteOpFn = null,
    on_remote_op_ctx: ?*anyopaque = null,
};

/// Errors raised by registry operations.
pub const RegistryError = error{
    RegistryFrozen,
    DuplicateChannel,
    InvalidChannelName,
    RegistryFull,
    OutOfMemory,
};

// =============================================================================
// Channel-name validation
// =============================================================================

/// True iff `name` is a valid channel name. Used at register time and at
/// every inbound op-frame decode (closes security-engineer H-1).
///
/// Rules (mirror `session.zig` `isValidRoomCode` discipline):
///   - 1..32 bytes
///   - ASCII [a-z 0-9 -] only
///   - No leading or trailing `-`
///   - No NUL bytes, no whitespace, no UTF-8 multibyte
pub fn isValidChannelName(name: []const u8) bool {
    if (name.len == 0 or name.len > MAX_CHANNEL_NAME_LEN) return false;
    if (name[0] == '-' or name[name.len - 1] == '-') return false;
    for (name) |c| {
        const ok = (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '-';
        if (!ok) return false;
    }
    return true;
}

// =============================================================================
// ChannelRegistry
// =============================================================================

/// Lookup table over registered channels. Owns the heap-allocated
/// `Channel` slots; `deinit` calls `crdt.deinit(allocator)` on each.
///
/// Concurrency: the registry has NO internal mutex. Callers (CollabManager)
/// hold their own mutex when invoking `register`, `freeze`, `find`,
/// `iterate`. The state machine + frozen-after-listen invariant means
/// `find` is effectively read-only on the hot path.
pub const ChannelRegistry = struct {
    pub const State = enum {
        /// Channels may be registered. Networking has NOT started.
        open_for_registration,
        /// Registration closed. `find`/`iterate` are the only allowed ops.
        /// Manager transitions to this state before accepting connections.
        frozen,
    };

    allocator: std.mem.Allocator,
    slots: std.array_list.Managed(*Channel),
    state: State,

    pub fn init(allocator: std.mem.Allocator) ChannelRegistry {
        return .{
            .allocator = allocator,
            .slots = std.array_list.Managed(*Channel).init(allocator),
            .state = .open_for_registration,
        };
    }

    /// Tear down the registry. Networking MUST be stopped before calling —
    /// the registry has no way to verify, but using channel CRDTs after
    /// `deinit` returns is a UAF.
    ///
    /// Per the threading contract in `crdt_interface.zig`, this is the
    /// CRDT's only `deinit` entry point; it runs OUTSIDE any worker
    /// thread's hot path because the manager joins all read/write threads
    /// before transitioning to teardown.
    pub fn deinit(self: *ChannelRegistry) void {
        for (self.slots.items) |ch| {
            ch.crdt.deinit(self.allocator);
            self.allocator.destroy(ch);
        }
        self.slots.deinit();
    }

    /// Register a new channel. Returns a stable `*Channel` pointer.
    pub fn register(self: *ChannelRegistry, spec: ChannelSpec) RegistryError!*Channel {
        if (self.state == .frozen) return error.RegistryFrozen;
        if (self.slots.items.len >= MAX_CHANNELS) return error.RegistryFull;
        if (!isValidChannelName(spec.name)) return error.InvalidChannelName;

        // Duplicate check — channel names form a flat namespace.
        for (self.slots.items) |existing| {
            if (std.mem.eql(u8, existing.name, spec.name)) return error.DuplicateChannel;
        }

        const ch = try self.allocator.create(Channel);
        errdefer self.allocator.destroy(ch);

        ch.* = .{
            .name = spec.name,
            .crdt = spec.crdt,
            .writable_by_local = spec.writable_by_local,
            .writable_by_peers = spec.writable_by_peers,
            .allowed_plugin_ids = spec.allowed_plugin_ids,
            .on_local_op = spec.on_local_op,
            .on_local_op_ctx = spec.on_local_op_ctx,
            .on_remote_op = spec.on_remote_op,
            .on_remote_op_ctx = spec.on_remote_op_ctx,
        };

        try self.slots.append(ch);
        return ch;
    }

    /// Close the registry to further registrations. Invoked by
    /// CollabManager before it transitions to the `networking` state.
    /// Idempotent.
    pub fn freeze(self: *ChannelRegistry) void {
        self.state = .frozen;
    }

    /// Look up a channel by name. Returns a stable pointer.
    pub fn find(self: *const ChannelRegistry, name: []const u8) ?*Channel {
        for (self.slots.items) |ch| {
            if (std.mem.eql(u8, ch.name, name)) return ch;
        }
        return null;
    }

    /// Walk all channels in REGISTRATION ORDER (deterministic, closes
    /// quality-engineer H-6). The callback runs synchronously per channel.
    pub fn iterate(
        self: *const ChannelRegistry,
        ctx: *anyopaque,
        callback: *const fn (ctx: *anyopaque, ch: *Channel) void,
    ) void {
        for (self.slots.items) |ch| callback(ctx, ch);
    }

    pub fn count(self: *const ChannelRegistry) usize {
        return self.slots.items.len;
    }
};

// =============================================================================
// Wire-side channel ACL helpers
// =============================================================================

/// Returns true if `plugin_id` is permitted to write to `ch` via the
/// bridge layer. Called by `bridge_handlers.handleMutate` (and batch
/// variant) BEFORE the mutation is forwarded to the CRDT.
///
/// Semantics:
///   - Empty `allowed_plugin_ids` AND `ch.name == "unified-model"` →
///     allow (v1 back-compat for the studio's only existing channel).
///   - Empty `allowed_plugin_ids` AND not unified-model → deny
///     (host-only channel; no WASM plugin trusted).
///   - Non-empty `allowed_plugin_ids` → check membership.
pub fn isPluginAllowedToWrite(ch: *const Channel, plugin_id: []const u8) bool {
    if (ch.allowed_plugin_ids.len == 0) {
        return std.mem.eql(u8, ch.name, "unified-model");
    }
    for (ch.allowed_plugin_ids) |allowed| {
        if (std.mem.eql(u8, allowed, plugin_id)) return true;
    }
    return false;
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "isValidChannelName: accepts valid names" {
    try testing.expect(isValidChannelName("unified-model"));
    try testing.expect(isValidChannelName("editor-text"));
    try testing.expect(isValidChannelName("a"));
    try testing.expect(isValidChannelName("blob-123"));
    try testing.expect(isValidChannelName("x" ** MAX_CHANNEL_NAME_LEN));
}

test "isValidChannelName: rejects invalid names" {
    try testing.expect(!isValidChannelName(""));
    try testing.expect(!isValidChannelName("UpperCase"));
    try testing.expect(!isValidChannelName("under_score"));
    try testing.expect(!isValidChannelName("has space"));
    try testing.expect(!isValidChannelName("-leading"));
    try testing.expect(!isValidChannelName("trailing-"));
    try testing.expect(!isValidChannelName("has.dot"));
    try testing.expect(!isValidChannelName("\x00null"));
    // Over-length: 33 chars
    try testing.expect(!isValidChannelName("a" ** (MAX_CHANNEL_NAME_LEN + 1)));
}

// Helper: a minimal CRDT that implements the vtable with no-op methods
// for tests that don't care about CRDT semantics, only registry plumbing.
const TestNoopCrdt = struct {
    const Self = @This();
    allocator: std.mem.Allocator,
    deinit_called: bool = false,

    fn applyLocal(ptr: *anyopaque, allocator: std.mem.Allocator, input: []const u8) anyerror!OpBytes {
        _ = ptr;
        return allocator.dupe(u8, input);
    }
    fn applyRemote(ptr: *anyopaque, op_bytes: OpBytes) anyerror!bool {
        _ = ptr;
        _ = op_bytes;
        return true;
    }
    fn snapshot(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror!crdt_interface.SnapshotBytes {
        _ = ptr;
        return allocator.dupe(u8, "{}");
    }
    fn loadSnapshot(ptr: *anyopaque, bytes: crdt_interface.SnapshotBytes) anyerror!void {
        _ = ptr;
        _ = bytes;
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

test "ChannelRegistry: register then find returns stable pointer" {
    const allocator = testing.allocator;
    var registry = ChannelRegistry.init(allocator);
    defer registry.deinit();

    var mock_a = TestNoopCrdt{ .allocator = allocator };
    var mock_b = TestNoopCrdt{ .allocator = allocator };

    const ch_a = try registry.register(.{
        .name = "unified-model",
        .crdt = mock_a.interface(),
        .writable_by_local = true,
        .writable_by_peers = true,
    });
    const ch_b = try registry.register(.{
        .name = "editor-text",
        .crdt = mock_b.interface(),
    });

    // Pointers from find() match the original
    try testing.expectEqual(ch_a, registry.find("unified-model").?);
    try testing.expectEqual(ch_b, registry.find("editor-text").?);
    try testing.expect(registry.find("nonexistent") == null);

    try testing.expectEqual(@as(usize, 2), registry.count());
}

test "ChannelRegistry: duplicate name rejected" {
    const allocator = testing.allocator;
    var registry = ChannelRegistry.init(allocator);
    defer registry.deinit();

    var mock = TestNoopCrdt{ .allocator = allocator };
    _ = try registry.register(.{ .name = "x", .crdt = mock.interface() });

    var mock2 = TestNoopCrdt{ .allocator = allocator };
    try testing.expectError(
        error.DuplicateChannel,
        registry.register(.{ .name = "x", .crdt = mock2.interface() }),
    );
}

test "ChannelRegistry: invalid channel name rejected" {
    const allocator = testing.allocator;
    var registry = ChannelRegistry.init(allocator);
    defer registry.deinit();

    var mock = TestNoopCrdt{ .allocator = allocator };
    try testing.expectError(
        error.InvalidChannelName,
        registry.register(.{ .name = "Bad Name", .crdt = mock.interface() }),
    );
}

test "ChannelRegistry: post-freeze register rejected" {
    const allocator = testing.allocator;
    var registry = ChannelRegistry.init(allocator);
    defer registry.deinit();

    var mock_a = TestNoopCrdt{ .allocator = allocator };
    _ = try registry.register(.{ .name = "unified-model", .crdt = mock_a.interface() });
    registry.freeze();

    var mock_b = TestNoopCrdt{ .allocator = allocator };
    try testing.expectError(
        error.RegistryFrozen,
        registry.register(.{ .name = "editor-text", .crdt = mock_b.interface() }),
    );
}

test "ChannelRegistry: freeze is idempotent" {
    const allocator = testing.allocator;
    var registry = ChannelRegistry.init(allocator);
    defer registry.deinit();
    registry.freeze();
    registry.freeze(); // no panic / no error
    try testing.expectEqual(ChannelRegistry.State.frozen, registry.state);
}

test "ChannelRegistry: deinit calls crdt.deinit per channel" {
    const allocator = testing.allocator;
    var registry = ChannelRegistry.init(allocator);

    var mock_a = TestNoopCrdt{ .allocator = allocator };
    var mock_b = TestNoopCrdt{ .allocator = allocator };
    _ = try registry.register(.{ .name = "a", .crdt = mock_a.interface() });
    _ = try registry.register(.{ .name = "b", .crdt = mock_b.interface() });

    registry.deinit();
    try testing.expect(mock_a.deinit_called);
    try testing.expect(mock_b.deinit_called);
}

test "ChannelRegistry: iterate visits channels in registration order" {
    const allocator = testing.allocator;
    var registry = ChannelRegistry.init(allocator);
    defer registry.deinit();

    var mock_a = TestNoopCrdt{ .allocator = allocator };
    var mock_b = TestNoopCrdt{ .allocator = allocator };
    var mock_c = TestNoopCrdt{ .allocator = allocator };
    _ = try registry.register(.{ .name = "first", .crdt = mock_a.interface() });
    _ = try registry.register(.{ .name = "second", .crdt = mock_b.interface() });
    _ = try registry.register(.{ .name = "third", .crdt = mock_c.interface() });

    const Ctx = struct {
        names: [3][]const u8 = .{ "", "", "" },
        idx: usize = 0,
        fn cb(ctx: *anyopaque, ch: *Channel) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (self.idx < self.names.len) {
                self.names[self.idx] = ch.name;
                self.idx += 1;
            }
        }
    };
    var ctx = Ctx{};
    registry.iterate(@ptrCast(&ctx), Ctx.cb);

    try testing.expectEqual(@as(usize, 3), ctx.idx);
    try testing.expectEqualStrings("first", ctx.names[0]);
    try testing.expectEqualStrings("second", ctx.names[1]);
    try testing.expectEqualStrings("third", ctx.names[2]);
}

test "ChannelRegistry: MAX_CHANNELS cap enforced" {
    const allocator = testing.allocator;
    var registry = ChannelRegistry.init(allocator);
    defer registry.deinit();

    // Use a static buffer of distinct mocks so each gets its own slot
    var mocks: [MAX_CHANNELS + 1]TestNoopCrdt = undefined;
    var name_buf: [MAX_CHANNELS + 1][8]u8 = undefined;

    var i: usize = 0;
    while (i < MAX_CHANNELS) : (i += 1) {
        mocks[i] = TestNoopCrdt{ .allocator = allocator };
        const name = std.fmt.bufPrint(&name_buf[i], "ch-{d:0>3}", .{i}) catch unreachable;
        _ = try registry.register(.{ .name = name, .crdt = mocks[i].interface() });
    }

    mocks[MAX_CHANNELS] = TestNoopCrdt{ .allocator = allocator };
    const overflow_name = std.fmt.bufPrint(&name_buf[MAX_CHANNELS], "ch-over", .{}) catch unreachable;
    try testing.expectError(
        error.RegistryFull,
        registry.register(.{ .name = overflow_name, .crdt = mocks[MAX_CHANNELS].interface() }),
    );
}

test "isPluginAllowedToWrite: empty allowlist + unified-model = allow" {
    const ch: Channel = .{
        .name = "unified-model",
        .crdt = undefined,
        .allowed_plugin_ids = &.{},
    };
    try testing.expect(isPluginAllowedToWrite(&ch, "any-plugin"));
}

test "isPluginAllowedToWrite: empty allowlist + non-unified = deny" {
    const ch: Channel = .{
        .name = "editor-text",
        .crdt = undefined,
        .allowed_plugin_ids = &.{},
    };
    try testing.expect(!isPluginAllowedToWrite(&ch, "any-plugin"));
}

test "isPluginAllowedToWrite: non-empty allowlist membership check" {
    const allowed = [_][]const u8{ "editor-plugin", "trusted-plugin" };
    const ch: Channel = .{
        .name = "editor-text",
        .crdt = undefined,
        .allowed_plugin_ids = &allowed,
    };
    try testing.expect(isPluginAllowedToWrite(&ch, "editor-plugin"));
    try testing.expect(isPluginAllowedToWrite(&ch, "trusted-plugin"));
    try testing.expect(!isPluginAllowedToWrite(&ch, "untrusted-plugin"));
}
