//! CollabManager — Orchestrates sessions, peers, CRDT sync, and networking.
//!
//! This is the central coordination point for collaboration. It owns:
//!   - Session state machine
//!   - CRDT document
//!   - WebSocket connections (server for hosting, client for joining)
//!   - Read threads for incoming messages
//!
//! Thread model:
//!   - Main thread: mutate(), create(), join(), leave() called from host functions
//!   - Read thread(s): one per WebSocket connection, calls processMessage()
//!   - Mutex protects shared state (session, crdt_doc, connections)
//!
//! Push events to JS via the push_callback (wired to view_push.push).

const std = @import("std");
const compat = @import("compat");
const ws = @import("websocket.zig");
const crdt_mod = @import("crdt_lww_map.zig");
const channel_mod = @import("channel.zig");
const crdt_iface = @import("crdt_interface.zig");
const session_mod = @import("session.zig");
const protocol = @import("protocol.zig");
const crypto_mod = @import("crypto.zig");
const identity_mod = @import("identity");
const json_util = @import("util_json");
const send_queue_mod = @import("send_queue.zig");
const SendQueue = send_queue_mod.SendQueue;
const net = std.Io.net;

/// Callback for pushing events to the JS layer (wired to gui.view_push.push).
pub const PushCallback = *const fn (event_type: []const u8, payload: []const u8) void;

pub const Mutation = crdt_mod.Mutation;

/// Soft cap on peers per room. Each peer costs:
///   - one accepted std.Io.net.Stream (kernel socket + small handle)
///   - one read thread (~512 KB default pthread stack on macOS)
///   - one write thread (~512 KB stack)
///   - one Connection slot in the host's `connections` ArrayList
///   - one Peer slot in `session.peers`
///   - one bounded send_queue (~50 KB at DEFAULT_CAPACITY=256)
///   - participates in every `broadcastRaw` enqueue: O(1) `push` per
///     peer under the manager mutex, no socket writes under any lock.
///     Slow peers are isolated by their own write thread (Phase 5
///     HIGH-1 fix, commit b1a2ddf).
///
/// 1024 leaves headroom for the planned 500-peer stress test
/// (~50 MB queues + ~1 GB thread stacks, well within macOS defaults).
/// Production rooms in v1 will stay much smaller — practical ceilings
/// are now bounded by host CPU/network, not by mutex contention.
const MAX_PEERS = 1024;

/// One peer connection. Read and write threads are SEPARATE: the read
/// thread consumes inbound frames into `processMessage`; the write
/// thread blocks on `send_queue.pop()` and calls `ws.writeFrame()`
/// without touching any global mutex (Phase 5 HIGH-1 fix).
///
/// `mask` is per-connection (RFC 6455 client→server frames are masked,
/// server→client are not), set at construction. The previous code
/// passed `false` for ping/pong replies regardless of side, which is a
/// spec violation for guests; routing replies through the queue picks
/// up the correct mask transparently.
const Connection = struct {
    stream: net.Stream,
    peer_id: [16]u8,
    read_thread: ?std.Thread,
    /// Per-peer outbound queue. Heap-allocated so the pointer is stable
    /// across `connections` ArrayList growth, and so the write thread
    /// can hold it directly (no per-iteration manager-mutex acquire).
    send_queue: *SendQueue,
    write_thread: ?std.Thread,
    /// Mask outbound frames? `true` for guest→host, `false` for
    /// host→guest. Captured into the write thread at spawn.
    mask: bool,
};

/// Inbound-op callback signature. Called once per CRDT op received from a
/// peer, AFTER `crdt_doc.applyRemoteOp` updates the in-memory CRDT but
/// BEFORE the host relays the op to other peers. The studio wires this
/// to `CrdtBridge.applyPeerOp` so the op also flows into the actor and
/// mutates `UnifiedModel`. Without this hook the joiner's local model
/// stays empty even though the CRDT layer has the data — the symptom
/// the Tier-1 2-instance smoke surfaced: "B (joiner) shows nothing
/// when A (host) imports a spec."
///
/// `signer` carries the 32-byte Ed25519 pubkey of the op author when
/// the op arrived via a signed wire arm (`.op` / `.ops`). Sync-replay
/// callbacks (host's snapshot bootstrap) set `signer = null` because
/// the snapshot itself is unsigned in pv:4 (snapshot signing is a
/// Tier-2 follow-up). Callers that need identity attribution (B6
/// audit, B4 role ACL) consume `signer`; callers that don't simply
/// ignore it. Widening this callback now — pre-1.0 with one caller —
/// avoids a wire-shape break later (panel-#1 system-architect
/// CRITICAL-2).
///
/// The callback runs on the read thread INSIDE the manager mutex (caller
/// of processMessage holds it). Implementations must not block long or
/// re-enter the manager — see `crdt_bridge.applyPeerOp` which submits
/// to the actor's command queue (returns quickly) for the canonical
/// fast/non-reentrant pattern.
///
/// **Slice lifetime contract**: BOTH `signer` and `payload_value` are
/// BORROWED slices into the per-message decoder's owned-bytes arena.
/// They are valid ONLY for the synchronous duration of this callback.
/// The manager frees the underlying buffer (`ParseResult.deinit`) as
/// soon as `processMessage` returns. Implementations that need to
/// retain either slice past return MUST copy:
///   - `signer`: `@memcpy` into a fixed `[identity.PUBKEY_LEN]u8` array
///     (length is decoder-enforced; the slice will always be 32 bytes
///     when non-null).
///   - `payload_value`: `allocator.dupe(u8, payload_value)`.
/// Stashing the slice itself produces a UAF the moment the next
/// message lands. This is the exact panel-#1 UAF class — do not
/// reintroduce it at the bridge seam.
///
/// `signer` is `null` ONLY for snapshot replay (the `.sync` arm in
/// `processMessage`): host-fabricated state has no authoring identity
/// in v1. For `.op` / `.ops` arms it is always present (decoder rejects
/// envelopes that omit it).
pub const InboundOpFn = *const fn (
    ctx: *anyopaque,
    peer_id: [16]u8,
    signer: ?[]const u8,
    payload_value: []const u8,
) void;

/// CollabManager lifecycle state. Enforces the
/// init → channels_registered → networking ordering so that channel
/// registration cannot race against an active session.
pub const ManagerState = enum {
    /// `init()` returned but `registerDefaultChannels()` has not been
    /// called yet. Manager is not usable: `createSession` /
    /// `joinSession` will return `error.ChannelsNotRegistered`.
    unconfigured,
    /// `registerDefaultChannels()` has run and `channels.freeze()` was
    /// called. Manager is ready to accept session start-up calls.
    channels_registered,
    /// A session is active (host or guest). Channel registry is frozen
    /// for the session's lifetime.
    networking,
};

/// Metrics that aid observability + form a hostile-traffic audit trail.
pub const Metrics = struct {
    /// Inbound ops dropped because the channel is read-only for peers
    /// (e.g. Drive-host mode). Increments per dropped op, not per peer.
    inbound_op_denied: usize = 0,
    /// Inbound frames dropped because the named channel is unknown.
    inbound_unknown_channel: usize = 0,
    /// Inbound frames dropped because pv != 3 or wire format is malformed.
    inbound_invalid_envelope: usize = 0,
    /// Inbound op / ops / sync arrived BEFORE the joiner installed the
    /// welcome salt — crypto context is null, decryption is impossible.
    /// Indicates a host that's sending channel-routed messages before
    /// welcome (a wire-order bug) OR a hostile peer trying to flood
    /// pre-handshake.
    inbound_missing_welcome: usize = 0,
    /// Inbound op / ops / sync dropped because AES-GCM decrypt failed.
    /// Causes: wrong key (mismatched salt), tampered ciphertext (failed
    /// tag check), truncated payload. Each is a defense-in-depth signal.
    inbound_decrypt_failed: usize = 0,
    /// Outbound encrypt failures (OOM, etc.). Per-op increment so a
    /// transient OOM is visible without flooding logs.
    outbound_encrypt_failed: usize = 0,
    /// B1: Inbound ops dropped because the Ed25519 signature did not
    /// verify against the claimed signer pubkey, OR the sig/signer
    /// fields were malformed at the wire layer. Distinct from
    /// `inbound_decrypt_failed` (which is AEAD tag failure / wrong key /
    /// truncated ciphertext) — this is identity authenticity, not
    /// confidentiality. A non-zero counter indicates either a hostile
    /// peer attempting forgery, a version mismatch (an older client
    /// emitting unsigned pv:3 ops to a pv:4 host), or a bug in the
    /// sign-path.
    inbound_unsigned_dropped: usize = 0,
    /// B1: Outbound sign failures (extremely rare — pure-compute Ed25519
    /// over <= 1 MiB plaintext). Each increment indicates an internal
    /// error worth investigating, not steady-state traffic.
    outbound_sign_failed: usize = 0,
};

/// Crypto suite wire-string constants. Re-exported from protocol.zig so
/// manager-internal call sites have a single source of truth (refactor
/// panel M-2). The canonical (enum ↔ wire) mapping is in
/// `crypto.Suite.fromName`/`toName`.
pub const SUITE_AES_GCM_V1: []const u8 = protocol.SUITE_AES_GCM_V1;
pub const SUITE_CHACHA_V1: []const u8 = protocol.SUITE_CHACHA_V1;

/// Suites this build advertises in the joiner role, in preference order
/// (joiner's preference first). The host picks ONE of these as its
/// locked session suite at `startHosting` time; the joiner accepts
/// whatever the host's welcome envelope returns, provided it appears
/// in this list AND `crypto.Suite.fromName` recognizes it.
///
/// Order rationale: AES-GCM first because every shipping target
/// (macOS/Windows/Linux desktop on x86-64 or AArch64) has hardware
/// AES acceleration. ChaCha second as a constant-time fallback for
/// environments without AES-NI/AArch64 crypto extensions or for
/// admin policy ("compliance requires ChaCha only").
const JOINER_SUITE_PREFS = [_][]const u8{ SUITE_AES_GCM_V1, SUITE_CHACHA_V1 };

/// True iff `name` is a suite this build can speak. Used by the guest's
/// `.welcome` arm to reject a host that returns an unsupported suite.
/// Defers to `crypto_mod.Suite.fromName` so the enum stays the single
/// source of truth — adding a suite to the enum automatically extends
/// this predicate.
pub fn isSupportedSuite(name: []const u8) bool {
    return crypto_mod.Suite.fromName(name) != null;
}

/// Pick the locked suite for a joining peer.
///
/// Host policy is Option 1 (host-locked): the host advertises ONE suite
/// chosen at `startHosting` time, and the joiner either supports it
/// (suite appears in `joiner_prefs`) or is rejected with
/// `NoCompatibleSuite`. This matches admin-side policy ("we only allow
/// ChaCha for compliance") cleanly. The alternative (joiner preference
/// wins, host filters from a set) was rejected for A2 because it
/// requires deferring host crypto initialization until the first peer
/// joins — wasted work plus a re-key window. Tracked in plan for
/// reconsideration if a real use case for per-session host suites
/// emerges.
///
/// Returns the host's locked suite (as the wire-string name) if found
/// in `joiner_prefs`, else null. The returned slice is a static string
/// (no allocation); safe to embed in the welcome envelope.
pub fn negotiateSuite(host_suite: crypto_mod.Suite, joiner_prefs: []const []const u8) ?[]const u8 {
    const host_name = host_suite.toName();
    for (joiner_prefs) |pref| {
        if (std.mem.eql(u8, pref, host_name)) return host_name;
    }
    return null;
}

pub const CollabManager = struct {
    allocator: std.mem.Allocator,
    mutex: std.Io.Mutex,
    session: session_mod.Session,
    crdt_doc: crdt_mod.CrdtDoc,
    /// Multi-channel registry. Holds the `unified-model` channel
    /// pointing to `crdt_doc` after `registerDefaultChannels()` runs.
    /// Future CRDT types (text, blob) register additional channels
    /// before the first `createSession`/`joinSession` call.
    channels: channel_mod.ChannelRegistry,
    state: ManagerState,
    metrics: Metrics,
    push_callback: ?PushCallback,

    /// Optional inbound-op callback (see `InboundOpFn`). Set via
    /// `setInboundOpCallback`. Null until wired (manager is usable
    /// without it, but the joiner's UnifiedModel will not converge).
    ///
    /// v1 wires this to `CrdtBridge.applyPeerOp` for the unified-model
    /// channel. Future channels with their own bridges register
    /// per-channel `on_remote_op` hooks instead.
    inbound_op_ctx: ?*anyopaque,
    inbound_op_fn: ?InboundOpFn,

    // Networking. Guest mode keeps the single host-side connection as
    // `connections.items[0]` so the per-peer write thread + send queue
    // plumbing applies uniformly; there is intentionally NO separate
    // `client_stream` alias (removed in Phase 5 panel review — system
    // architect H-2: aliased state across two fields was a foot-gun
    // for paths that checked one but updated the other).
    server: ?ws.Server,
    connections: std.array_list.Managed(Connection),
    running: bool,

    // Accept thread for server mode
    accept_thread: ?std.Thread,

    /// B1: local Ed25519 identity. Every outbound CRDT op is signed with
    /// this keypair BEFORE encryption; every inbound op is verified
    /// against the originating peer's published pubkey BEFORE
    /// `applyRemote`. Closes the v1 "any peer with the room key can
    /// forge any other peer's edits" gap.
    ///
    /// v1 ships ephemeral identities — a fresh keypair per
    /// `CollabManager.init` (process restart = new identity). Persistent
    /// identity via `identity.loadOrGenerate` is a B1.5 wiring step
    /// (callers can call `setIdentity` post-init BEFORE the first
    /// session to swap in a loaded keypair). True multi-device +
    /// Team-bound identity is B2.
    identity: identity_mod.Identity,

    /// B1: host-side peer-id ↔ advertised-pubkey map. Populated by the
    /// `.join` arm in host mode, used by the `.op` / `.ops` cross-check
    /// to detect peer-id self-spoofing INSIDE the room (a hostile peer
    /// claiming the connection slot of a peer that already joined with
    /// a different identity key).
    ///
    /// Semantics:
    ///   - Host mode: every successful `.join` registers `peer_id →
    ///     pubkey`. On every inbound `.op` / `.ops` we compare
    ///     `peer_pubkeys[conn.peer_id]` to `envelope.signer`. Mismatch
    ///     → drop with `inbound_unsigned_dropped++`. Missing entry →
    ///     drop with the same metric (peer skipped the join handshake).
    ///   - Guest mode: the host is the only "peer" we directly speak
    ///     to. We do NOT populate this map (we don't process other
    ///     guests' joins; relayed-join envelopes don't carry the
    ///     joiner's pubkey today). Guest verification falls through
    ///     to the signature alone, which is end-to-end authenticated.
    ///
    /// Lifecycle: entries are added in the `.join` arm AFTER
    /// `session.addPeer` succeeds, removed in `handleDisconnect`
    /// alongside `session.removePeer`. The map is freed in `deinit`
    /// (no per-entry allocations — values are inline 32-byte arrays).
    ///
    /// Closes the multi-lens CRITICAL surfaced by panel-#1
    /// (architect CRIT-1 + security HIGH-2 + coverage HIGH-4): docs
    /// promised this map existed, the wire decoded `join.pubkey`
    /// already, but no code stored or cross-checked it.
    peer_pubkeys: std.AutoHashMap([16]u8, [identity_mod.PUBKEY_LEN]u8),

    pub fn init(allocator: std.mem.Allocator) CollabManager {
        return .{
            .allocator = allocator,
            .mutex = .init,
            .session = session_mod.Session.init(allocator),
            .crdt_doc = crdt_mod.CrdtDoc.init(allocator),
            .channels = channel_mod.ChannelRegistry.init(allocator),
            .state = .unconfigured,
            .metrics = .{},
            .push_callback = null,
            .inbound_op_ctx = null,
            .inbound_op_fn = null,
            .server = null,
            .connections = std.array_list.Managed(Connection).init(allocator),
            .running = false,
            .accept_thread = null,
            .identity = identity_mod.Identity.generate(),
            .peer_pubkeys = std.AutoHashMap([16]u8, [identity_mod.PUBKEY_LEN]u8).init(allocator),
        };
    }

    /// Replace the auto-generated ephemeral identity with a caller-
    /// provided one (typically loaded via `identity.loadOrGenerate`).
    /// MUST be called BEFORE the first `createSession` / `joinSession`
    /// — the identity participates in the `join` envelope and changing
    /// it mid-session would invalidate the joiner's published pubkey
    /// on the host's peer-map.
    ///
    /// State guard: if a session is already active (`hosting`, `joining`,
    /// `connected`), the call is REFUSED with `error.SessionActive`.
    /// Without this gate, swapping mid-session would mean every in-flight
    /// outbound op would be signed by a key that the host's peer_pubkeys
    /// map does not recognize (verify would drop all our subsequent ops)
    /// AND remote peers' assumption about our identity would be violated.
    /// The window is intentionally narrow: B2 will add an
    /// `identity_rotate` wire envelope that lets the new key be
    /// announced peer-to-peer, but the v1 swap-without-announcement
    /// path is structurally unsafe.
    ///
    /// On accept: the OLD identity's secret material is zeroed via
    /// `deinit`; the new one takes its place. Caller transfers
    /// ownership of the new `Identity` to the manager.
    ///
    /// Closes panel-#1 5-lens HIGH (refactoring + architect +
    /// test-design + coverage + backend convergence).
    pub fn setIdentity(self: *CollabManager, new_identity: identity_mod.Identity) error{SessionActive}!void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        if (self.session.state != .idle) return error.SessionActive;
        self.identity.deinit();
        self.identity = new_identity;
    }

    /// Register the default channels for this manager and freeze the
    /// registry. MUST be called once, after `init()` and BEFORE the
    /// first `createSession`/`joinSession`. Idempotent (returns silently
    /// if already registered).
    ///
    /// v1 ships ONE default channel: `unified-model` wrapping
    /// `crdt_doc`. Future builds add `editor-text`, `blob`, etc.
    /// Studio integration that needs additional channels should
    /// register them BEFORE calling this method (or extend this
    /// method directly — registration order is preserved).
    ///
    /// The unified-model channel is opened bidirectionally
    /// (writable_by_local = writable_by_peers = true) for v1 Peer
    /// mode. Drive-mode (Phase B) sets one side to false on a
    /// per-session basis.
    pub fn registerDefaultChannels(self: *CollabManager) !void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        if (self.state != .unconfigured) return; // idempotent

        _ = try self.channels.register(.{
            .name = "unified-model",
            .crdt = self.crdt_doc.interface(),
            .writable_by_local = true,
            .writable_by_peers = true,
            // Empty allowed_plugin_ids + the unified-model special-case
            // in channel.isPluginAllowedToWrite means any plugin can
            // mutate this channel via collab.mutate (v1 back-compat).
        });

        self.channels.freeze();
        self.state = .channels_registered;
    }

    /// Wire the inbound-op callback (typically `CrdtBridge.applyPeerOp`).
    /// Safe to call before or after `createSession`/`joinSession`. Once
    /// set, every `.op` / `.ops` message processMessage receives is
    /// forwarded to the callback in addition to being applied to the
    /// local CRDT doc.
    pub fn setInboundOpCallback(self: *CollabManager, ctx: *anyopaque, callback: InboundOpFn) void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        self.inbound_op_ctx = ctx;
        self.inbound_op_fn = callback;
    }

    pub fn deinit(self: *CollabManager) void {
        self.stopNetworking();
        self.session.deinit();
        self.connections.deinit();
        // B1: zero the Ed25519 secret material on shutdown. Safe even
        // after `setIdentity` swapped in a different keypair — `deinit`
        // is idempotent in `identity.zig`.
        self.identity.deinit();
        // B1: pubkey map holds only inline 32-byte arrays — no per-
        // entry allocations to free, just the hash-table backing.
        self.peer_pubkeys.deinit();
        // Tear down the channel registry. The unified-model channel's
        // vtable.deinit forwards to `self.crdt_doc.deinit()` — see
        // `crdt_lww_map.zig` vtableDeinit — so `crdt_doc` is freed
        // exactly once via the channel pathway. We do NOT call
        // `self.crdt_doc.deinit()` directly here; double-free.
        if (self.state == .unconfigured) {
            // Registry was never populated; crdt_doc was never wrapped
            // by a channel. Free it directly.
            self.crdt_doc.deinit();
        }
        self.channels.deinit();
    }

    /// Set the push callback for notifying the JS layer.
    pub fn setPushCallback(self: *CollabManager, callback: PushCallback) void {
        self.push_callback = callback;
    }

    // =========================================================================
    // Session Actions (called from host functions / bridge handlers)
    // =========================================================================

    /// Create a new session (host mode). Starts embedded WebSocket server.
    /// `requested_code` is optional — if provided, it becomes the room code
    /// (must be 9 chars, e.g., XXXX-XXXX). If null/empty, a fresh one is
    /// generated. Returns the canonical room code (caller-owned reference
    /// to internal storage; valid for the lifetime of the session).
    ///
    /// `suite` selects the AEAD primitive for this session. Defaults to
    /// `.aes_gcm_v1` for back-compat with A1 peers. Callers wanting a
    /// ChaCha-only policy pass `.chacha_v1`; joiners whose `suite_prefs`
    /// don't include it are rejected with `NoCompatibleSuite`. See
    /// `negotiateSuite` for the Option 1 (host-locked) rationale.
    pub fn createSession(
        self: *CollabManager,
        name: []const u8,
        port: u16,
        requested_code: ?[]const u8,
        suite: crypto_mod.Suite,
    ) ![]const u8 {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        if (self.state == .unconfigured) return error.ChannelsNotRegistered;
        if (self.session.state != .idle) return error.SessionActive;

        // Start WebSocket server
        self.server = try ws.Server.init(.{ .port = port });
        const actual_port = self.server.?.getPort();

        // Empty string → null so the session generates one. Anything else
        // must be exactly 9 chars (XXXX-XXXX shape) or startHosting errors.
        const code_arg: ?[]const u8 = if (requested_code) |c|
            (if (c.len == 0) null else c)
        else
            null;

        try self.session.startHosting(actual_port, code_arg, suite);
        try self.session.setLocalName(name);
        self.running = true;

        // Set CRDT peer ID to match session
        self.crdt_doc.peer_id = self.session.local_peer_id;

        // Start accept thread
        self.accept_thread = std.Thread.spawn(.{}, acceptLoop, .{self}) catch |err| {
            std.log.err("collab: Failed to spawn accept thread: {}", .{err});
            return error.ThreadSpawnFailed;
        };

        self.pushStatus();
        return &self.session.room_code;
    }

    /// Join an existing session (guest mode). Connects to relay/host.
    ///
    /// Error semantics: every fallible step has an errdefer that unwinds
    /// the prior step, so a failure after partial setup leaves the
    /// manager in a clean `.idle` state. Specifically: ws.connect →
    /// SendQueue.init → session.startJoining → session.setLocalName →
    /// connections.addOne → read_thread spawn → write_thread spawn.
    /// Each subsequent step's failure must roll back the previous,
    /// including `running = true` and the partially-initialised
    /// connection slot. Phase 5 panel review HIGH-1 (refactor): the
    /// pre-fix code had three holes (session state leaked into stuck
    /// `.joining`, `running` stuck true, half-spawned thread state).
    pub fn joinSession(self: *CollabManager, room_code: []const u8, relay_url: []const u8, name: []const u8) !void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        if (self.state == .unconfigured) return error.ChannelsNotRegistered;
        if (self.session.state != .idle) return error.SessionActive;

        // Parse relay URL to extract host and port
        const host_port = parseWsUrl(relay_url) orelse return error.InvalidRelayUrl;

        // Connect as WebSocket client
        const stream = try ws.connect(self.allocator, .{
            .host = host_port.host,
            .port = host_port.port,
            .path = "/",
        });
        errdefer ws.closeStream(stream);

        // Allocate the outbound queue BEFORE we hand the connection to the
        // session/threads — failure here unwinds cleanly via errdefer.
        const queue = try SendQueue.init(self.allocator, SendQueue.DEFAULT_CAPACITY);
        errdefer queue.deinit();

        // pv:3: `startJoining` does NOT take a salt — the joiner stays
        // crypto-null until the host's `welcome` envelope arrives. From
        // here on, errors must roll back the session state machine
        // (state .joining → .idle, clear relay_url).
        try self.session.startJoining(room_code, relay_url);
        errdefer self.session.leave();

        try self.session.setLocalName(name);
        // setLocalName failure is rolled back by session.leave() above —
        // freeLocalName runs inside leave().

        self.running = true;
        errdefer self.running = false;

        // Set CRDT peer ID to match session
        self.crdt_doc.peer_id = self.session.local_peer_id;

        // Encode + enqueue the initial join message. We push to the queue
        // even before the write thread is spawned — `SendQueue.push` is
        // just a producer-side enqueue, not a blocking write. The write
        // thread drains in order once it starts. `join` is a control
        // message (refuse-to-drop) — losing it means the host never
        // tracks us as a peer.
        //
        // pv:4: include `suite_prefs` so the host can negotiate (A2)
        // PLUS `pubkey` so the host learns this peer's identity (B1).
        // A2: advertises both AES-GCM and ChaCha in preference order
        // (see `JOINER_SUITE_PREFS` doc for the AES-first rationale).
        // The host's locked suite must appear in this list; otherwise
        // negotiation returns `NoCompatibleSuite` and the host drops
        // the connection with an `error` envelope.
        // B1: pubkey is the local Ed25519 identity. The host registers
        // it in `peer_pubkeys` so subsequent signed ops from this
        // peer can be optionally cross-checked against the join-time
        // advertised key (v1 audit; full enforcement is Tier-2).
        const local_pubkey = self.identity.publicKeyBytes();
        const join_msg = try protocol.encode(self.allocator, .{
            .join = .{
                .room = room_code,
                .name = self.session.local_name,
                .peer_id = self.session.local_peer_id,
                .suite_prefs = &JOINER_SUITE_PREFS,
                .pubkey = &local_pubkey,
            },
        });
        defer self.allocator.free(join_msg);

        try queue.push(join_msg, .text, .control);

        // Register the connection. Guest connections mask outbound frames
        // (RFC 6455 client→server frames MUST be masked); spawn the read
        // and write threads with the captured queue/stream/mask so they
        // run without touching the manager mutex.
        const conn_entry = try self.connections.addOne();
        // Pop the slot back off on any subsequent failure so we don't
        // leak a half-initialised Connection (with both threads null,
        // which would let stopNetworkingLocked try to deinit a queue
        // that was already cleaned up by `queue.deinit()` errdefer).
        var conn_initialised = false;
        errdefer {
            if (!conn_initialised) {
                _ = self.connections.pop();
            }
        }
        conn_entry.* = .{
            .stream = stream,
            .peer_id = std.mem.zeroes([16]u8), // Will be set when we get peer info
            .read_thread = null,
            .send_queue = queue,
            .write_thread = null,
            .mask = true,
        };
        const idx = self.connections.items.len - 1;
        // Spawn-failure policy for guests: read and write threads are
        // the connection's lifeline. If either spawn fails, the
        // connection is unusable (guest never reads inbound state,
        // never sends outbound mutations). Refuse the join cleanly —
        // do NOT continue with a null thread (that was the acceptLoop
        // pattern and is only defensible there because other peers
        // keep working). All prior errdefers fire and unwind.
        const read_thread = std.Thread.spawn(.{}, readLoop, .{ self, idx }) catch |err| {
            std.log.err("collab: Failed to spawn guest read thread: {}", .{err});
            return error.ThreadSpawnFailed;
        };
        errdefer {
            // Best-effort: stop the read thread before unwinding. It
            // exits on `!self.running` (which the prior errdefer sets
            // to false) or on EOF (which `closeStream` errdefer
            // induces). Joining here avoids leaking the thread handle.
            read_thread.join();
        }
        const write_thread = std.Thread.spawn(.{}, writeLoop, .{ self, queue, stream, true }) catch |err| {
            std.log.err("collab: Failed to spawn guest write thread: {}", .{err});
            return error.ThreadSpawnFailed;
        };
        conn_entry.read_thread = read_thread;
        conn_entry.write_thread = write_thread;
        conn_initialised = true;

        self.pushStatus();
    }

    /// Apply a local mutation to the unified-model channel and
    /// broadcast to all peers. This is the LWW-specific back-compat
    /// wrapper around `applyLocalToChannel("unified-model", ...)`.
    ///
    /// New code (non-LWW channels) should use `applyLocalToChannel`
    /// directly with a channel-specific input encoding.
    pub fn mutate(self: *CollabManager, path: []const u8, value: []const u8) !void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        // `.joining` is also a live state — the joiner has an open TCP
        // connection to the host and is awaiting the inbound `sync`. Local
        // mutations that happen in that window (profile load, system
        // mutations triggered by load_snapshot itself) MUST be broadcast
        // so the host can converge. Rejecting in `.joining` left the
        // joiner unable to send its own ops, even though the wire was
        // open. See the 2-instance smoke diagnostics that surfaced
        // `NotInSession (version=1, batch_len=10371)` warnings.
        if (self.session.state != .connected and
            self.session.state != .hosting and
            self.session.state != .joining)
            return error.NotInSession;

        // Route through the unified-model channel. Channel ACL is
        // checked here so v1 read-only / Drive guests get the same
        // error as future channel-aware code.
        const ch = self.channels.find("unified-model") orelse return error.UnknownChannel;
        if (!ch.writable_by_local) return error.ReadOnlyChannel;

        const op = try self.crdt_doc.mutate(path, value);
        const op_bytes = try crdt_mod.encodeOpBytes(self.allocator, op);
        defer self.allocator.free(op_bytes);
        try self.broadcastChannelOp("unified-model", op_bytes);
        self.pushState();
    }

    /// Apply a batch of local mutations to the unified-model channel
    /// atomically and broadcast. LWW-specific back-compat wrapper.
    pub fn mutateBatch(self: *CollabManager, mutations: []const Mutation) !void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        // Same `.joining`-is-live logic as `mutate()` above — see comment
        // there for the smoke-test diagnostic that proved it.
        if (self.session.state != .connected and
            self.session.state != .hosting and
            self.session.state != .joining)
            return error.NotInSession;

        const ch = self.channels.find("unified-model") orelse return error.UnknownChannel;
        if (!ch.writable_by_local) return error.ReadOnlyChannel;

        const ops = try self.crdt_doc.mutateBatch(mutations);
        defer self.allocator.free(ops);

        // Encode each op to op_bytes for the wire envelope.
        const op_bytes_batch = try self.allocator.alloc([]const u8, ops.len);
        defer {
            for (op_bytes_batch) |b| self.allocator.free(b);
            self.allocator.free(op_bytes_batch);
        }
        for (ops, 0..) |op, i| {
            op_bytes_batch[i] = try crdt_mod.encodeOpBytes(self.allocator, op);
        }
        try self.broadcastChannelOps("unified-model", op_bytes_batch);
        self.pushState();
    }

    /// Apply a local change to ANY registered channel and broadcast it.
    /// This is the generic API future CRDT types (text, blob) call from
    /// their channel-specific bridges. `input` is the CRDT's preferred
    /// local-change format (LWW expects `{"path":...,"value":...}` JSON;
    /// text CRDT would have its own shape).
    ///
    /// The channel must be registered and `writable_by_local`. ACL is
    /// the channel itself; plugin-level ACL is enforced upstream by
    /// `bridge_handlers.handleMutate` before this call lands.
    pub fn applyLocalToChannel(
        self: *CollabManager,
        channel_name: []const u8,
        input: []const u8,
    ) !void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        if (self.session.state != .connected and
            self.session.state != .hosting and
            self.session.state != .joining)
            return error.NotInSession;

        const ch = self.channels.find(channel_name) orelse return error.UnknownChannel;
        if (!ch.writable_by_local) return error.ReadOnlyChannel;

        // applyLocal allocates op_bytes with `self.allocator`; we own + free.
        const op_bytes = try ch.crdt.applyLocal(self.allocator, input);
        defer self.allocator.free(op_bytes);

        try self.broadcastChannelOp(channel_name, op_bytes);

        // Fire the channel's local-op observer (if any). Bridges use
        // this to mirror the local change into the host application's
        // model layer when their flow doesn't already go through the
        // CRDT directly. Borrowed slice for the call duration.
        if (ch.on_local_op) |cb| {
            cb(ch.on_local_op_ctx.?, op_bytes);
        }

        self.pushState();
    }

    /// Leave the current session.
    pub fn leaveSession(self: *CollabManager) void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        // Send leave message to peers
        if (self.session.state != .idle) {
            const leave_msg = protocol.encode(self.allocator, .{
                .leave = .{ .peer_id = self.session.local_peer_id },
            }) catch null;
            if (leave_msg) |msg| {
                defer self.allocator.free(msg);
                // `.control` — leave-msg is not idempotent; dropping it
                // means peers keep a stale roster entry. Refuse-to-drop.
                self.broadcastRaw(msg, .control);
            }
        }

        self.stopNetworkingLocked();
        self.session.leave();
        self.pushStatus();
    }

    /// Get connected peers as JSON. Caller owns returned memory.
    pub fn getPeersJson(self: *CollabManager) ![]const u8 {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        var buf: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer buf.deinit();
        const w = &buf.writer;

        try w.writeAll("{\"peers\":[");
        for (self.session.peers.items, 0..) |p, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll("{\"id\":\"");
            try json_util.writeHex(w, &p.id);
            try w.writeAll("\",\"name\":\"");
            try json_util.writeJsonEscaped(w, p.name);
            try w.writeAll("\"}");
        }
        try w.writeAll("]}");

        return buf.toOwnedSlice();
    }

    /// Get session info as JSON. Caller owns returned memory.
    pub fn getSessionInfoJson(self: *CollabManager) ![]const u8 {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        return self.session.toJson();
    }

    /// Returns the canonical 9-byte room code for the current session, or
    /// an empty slice if idle. The returned slice points into session.zig
    /// internal storage and is valid until the session transitions to idle.
    pub fn currentRoom(self: *CollabManager) []const u8 {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        if (self.session.state == .idle) return "";
        return &self.session.room_code;
    }

    /// Returns the host-side listening port (or 0 if not hosting). Useful
    /// for tests that bind to an ephemeral port and need the actual value
    /// to dial in a guest.
    pub fn currentPort(self: *CollabManager) u16 {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        if (self.server) |*s| return s.getPort();
        return 0;
    }

    /// Returns true if the manager is currently hosting/connected on a room
    /// matching `requested`. `null` matches any active room (used when the
    /// caller didn't specify one). Used by `bridge_handlers.handleCreate` to
    /// make double-fired `collab.create` calls idempotent.
    pub fn currentRoomMatches(self: *CollabManager, requested: ?[]const u8) bool {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        if (self.session.state == .idle) return false;
        const req = requested orelse return true;
        return std.mem.eql(u8, req, &self.session.room_code);
    }

    /// Get the current merged CRDT state as JSON. Caller owns returned memory.
    pub fn getStateJson(self: *CollabManager) ![]const u8 {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        return self.crdt_doc.toModelJson();
    }

    /// Snapshot the metrics struct under the mutex. Returns a value copy
    /// so the caller can inspect without further locking. Closes the
    /// security panel H-3 / system-architect M-5 observability gap —
    /// counters that nobody can read are not an audit trail.
    pub fn getMetricsSnapshot(self: *CollabManager) Metrics {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        return self.metrics;
    }

    // =========================================================================
    // Internal: Message Processing
    // =========================================================================

    fn processMessage(self: *CollabManager, data: []const u8, from_conn_idx: usize) void {
        var result = protocol.decode(self.allocator, data) catch {
            std.log.warn("collab: Failed to decode message: {d} bytes", .{data.len});
            return;
        };
        defer result.deinit();

        // Tier-1 smoke diagnostic — info-level so we can see in release
        // exactly which arm fires. Demote to debug once the wire path is
        // confirmed end-to-end.
        std.log.info("collab: processMessage from conn[{d}] kind={s} bytes={d}", .{
            from_conn_idx,
            @tagName(result.msg),
            data.len,
        });

        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        switch (result.msg) {
            .join => |j| {
                if (self.session.peers.items.len >= MAX_PEERS) {
                    // Room full — message text uses comptime fmt so MAX_PEERS
                    // stays the single source of truth.
                    var err_buf: [64]u8 = undefined;
                    const err_text = std.fmt.bufPrint(&err_buf, "Room full (max {d} peers)", .{MAX_PEERS}) catch "Room full";
                    const err_msg = protocol.encode(self.allocator, .{
                        .@"error" = .{ .message = err_text },
                    }) catch return;
                    defer self.allocator.free(err_msg);
                    // `error` to a single peer is informational; drop-
                    // tolerant from the peer's perspective (they'll
                    // eventually time out anyway), but treat as control
                    // so it skips queue-overflow drops.
                    self.sendTo(from_conn_idx, err_msg, .control);
                    return;
                }

                self.session.addPeer(j.peer_id, j.name) catch |err| {
                    // Surface the rejection so a hostile or buggy peer is
                    // visible in logs rather than a silent black hole. We
                    // also send the peer a structured error so they can
                    // close cleanly instead of retrying indefinitely.
                    // NameTooLong specifically is the security-H-4 inbound
                    // path; OutOfMemory is left as a generic fault.
                    const reason: []const u8 = switch (err) {
                        error.NameTooLong => "Peer name exceeds 64 bytes",
                        else => "Failed to add peer",
                    };
                    std.log.warn(
                        "collab: addPeer rejected from conn[{d}]: {s} (name_len={d})",
                        .{ from_conn_idx, @errorName(err), j.name.len },
                    );
                    if (protocol.encode(self.allocator, .{
                        .@"error" = .{ .message = reason },
                    })) |err_msg| {
                        defer self.allocator.free(err_msg);
                        self.sendTo(from_conn_idx, err_msg, .control);
                    } else |_| {}
                    return;
                };

                // Update connection's peer_id
                if (from_conn_idx < self.connections.items.len) {
                    self.connections.items[from_conn_idx].peer_id = j.peer_id;
                }

                // B1: register the joiner's advertised pubkey for
                // host-side cross-checks on subsequent `.op` / `.ops`.
                // We only do this in host mode — guests never accept
                // joins and would never use the resulting map entry.
                //
                // The decoder already enforced `j.pubkey.len ==
                // PUBKEY_LEN` (`decodeFixedLen` in protocol.zig). The
                // defensive check below is a programmer-error guard
                // against a future refactor that loosens the decoder
                // constraint — if it ever fails at runtime we drop
                // the entry rather than store partial data, and the
                // first inbound `.op` from this peer will be dropped
                // by the "missing entry" branch in the cross-check.
                if (self.session.mode == .host and j.pubkey.len == identity_mod.PUBKEY_LEN) {
                    var pk_arr: [identity_mod.PUBKEY_LEN]u8 = undefined;
                    @memcpy(&pk_arr, j.pubkey[0..identity_mod.PUBKEY_LEN]);
                    // Panel #2 security HIGH-1: peer-id hijack guard.
                    //
                    // Two cases for an existing entry:
                    //   (a) SAME pubkey — legitimate idempotent re-join
                    //       (e.g. a transient reconnect raced ahead of
                    //       handleDisconnect). Allow.
                    //   (b) DIFFERENT pubkey AND the prior slot still
                    //       has a live connection — REFUSE this join.
                    //       Without this guard, a hostile peer can hijack
                    //       another peer's roster slot by replaying its
                    //       peer_id with their own pubkey: subsequent
                    //       ops signed by the hostile peer would pass
                    //       the host's cross-check (because peer_pubkeys
                    //       was overwritten) and would be relayed to all
                    //       other peers as if authored by the original
                    //       peer-id holder. This violates the
                    //       "no in-room peer-id forgery" invariant.
                    //   (c) DIFFERENT pubkey AND no live slot — a
                    //       legitimate rejoin after disconnect whose
                    //       cleanup did NOT fully propagate. Allow and
                    //       overwrite.
                    if (self.peer_pubkeys.get(j.peer_id)) |existing| {
                        if (!std.mem.eql(u8, &existing, &pk_arr)) {
                            var slot_live = false;
                            for (self.connections.items, 0..) |c, ci| {
                                if (ci == from_conn_idx) continue;
                                if (std.mem.eql(u8, &c.peer_id, &j.peer_id)) {
                                    slot_live = true;
                                    break;
                                }
                            }
                            if (slot_live) {
                                std.log.warn(
                                    "collab: refusing duplicate .join for peer {x} — slot is live with a different pubkey (hijack attempt?)",
                                    .{j.peer_id},
                                );
                                if (protocol.encode(self.allocator, .{
                                    .@"error" = .{ .message = "peer-id already in use under a different identity" },
                                })) |em| {
                                    defer self.allocator.free(em);
                                    self.sendTo(from_conn_idx, em, .control);
                                } else |_| {}
                                // Don't pollute connection slot; reset
                                // to zero so the slot is harmless. The
                                // hostile peer's socket stays alive
                                // until OS-level disconnect.
                                if (from_conn_idx < self.connections.items.len) {
                                    self.connections.items[from_conn_idx].peer_id =
                                        std.mem.zeroes([16]u8);
                                }
                                return;
                            }
                            // Stale entry from a closed connection — log
                            // and overwrite (legitimate rejoin path).
                            std.log.warn(
                                "collab: peer {x} re-joined with a different identity pubkey (stale slot — overwriting)",
                                .{j.peer_id},
                            );
                        }
                    }
                    self.peer_pubkeys.put(j.peer_id, pk_arr) catch |err| {
                        // OOM on a 16+32 byte map entry is itself a
                        // serious-host-pressure signal; refuse the
                        // joiner cleanly rather than admitting a
                        // peer we cannot cross-check.
                        std.log.warn(
                            "collab: peer_pubkeys.put OOM for joiner {x}: {s} — rejecting",
                            .{ j.peer_id, @errorName(err) },
                        );
                        if (protocol.encode(self.allocator, .{
                            .@"error" = .{ .message = "Server out of memory tracking peer identity" },
                        })) |em| {
                            defer self.allocator.free(em);
                            self.sendTo(from_conn_idx, em, .control);
                        } else |_| {}
                        self.session.removePeer(j.peer_id);
                        // Panel #2 HIGH (concurrency): the line above
                        // wrote `j.peer_id` into the connection slot
                        // (line ~898). Without resetting it back to
                        // zero here, the slot retains the unauthenticated
                        // peer-id and a later `.op` from the same socket
                        // would enter the host cross-check with that
                        // peer-id, fall into the "missing entry" branch,
                        // and only drop AT THE METRIC LAYER — the slot
                        // would keep consuming a MAX_PEERS quota and
                        // bandwidth until OS-level disconnect. Reset to
                        // zero so subsequent broadcasts skip the slot
                        // (matches the `handleDisconnect` convention)
                        // AND a properly-handshaken peer can reclaim
                        // the index on socket close.
                        if (from_conn_idx < self.connections.items.len) {
                            self.connections.items[from_conn_idx].peer_id =
                                std.mem.zeroes([16]u8);
                        }
                        return;
                    };
                }

                // pv:3 host-side path: ONLY hosts send `welcome`. Guest
                // peers in a relayed-join scenario don't need welcome
                // (they already negotiated theirs with the host during
                // their own join).
                if (self.session.mode == .host) {
                    // Suite negotiation: host policy is Option 1
                    // (host-locked). The host's session-level suite was
                    // set at `startHosting`; joiners either advertise
                    // support for it in their `suite_prefs` or are
                    // rejected with NoCompatibleSuite.
                    const chosen_suite = negotiateSuite(self.session.suite, j.suite_prefs) orelse {
                        std.log.warn(
                            "collab: NoCompatibleSuite from conn[{d}] — host suite '{s}' not in joiner prefs (count={d})",
                            .{ from_conn_idx, self.session.suite.toName(), j.suite_prefs.len },
                        );
                        const err_msg = protocol.encode(self.allocator, .{
                            .@"error" = .{ .message = "No compatible crypto suite" },
                        }) catch {
                            // Even if we can't encode the error envelope,
                            // we MUST still remove the peer or we leak a
                            // ghost roster entry (backend panel H-1).
                            self.session.removePeer(j.peer_id);
                            return;
                        };
                        defer self.allocator.free(err_msg);
                        self.sendTo(from_conn_idx, err_msg, .control);
                        // Drop the peer — it cannot participate in an
                        // encrypted session. Don't send sync/welcome.
                        self.session.removePeer(j.peer_id);
                        return;
                    };

                    // Send welcome BEFORE any sync — the joiner's CryptoContext
                    // is null until welcome lands; sending an encrypted sync
                    // first would hit the MissingWelcome gate on the joiner.
                    //
                    // Welcome encode failure (OOM) MUST roll back the
                    // partially-added peer (backend panel H-1) — without
                    // this, the peer is tracked locally but never gets
                    // welcome/sync and other peers never learn it joined
                    // (the relayed-join broadcast below is skipped on early
                    // return).
                    const welcome_msg = protocol.encode(self.allocator, .{
                        .welcome = .{
                            .salt = &self.session.salt,
                            .suite = chosen_suite,
                        },
                    }) catch |err| {
                        std.log.err(
                            "collab: failed to encode welcome for conn[{d}]: {} — rolling back peer",
                            .{ from_conn_idx, err },
                        );
                        // Best-effort error envelope so the peer gets clean feedback.
                        if (protocol.encode(self.allocator, .{
                            .@"error" = .{ .message = "Server out of memory during welcome" },
                        })) |em| {
                            defer self.allocator.free(em);
                            self.sendTo(from_conn_idx, em, .control);
                        } else |_| {}
                        self.session.removePeer(j.peer_id);
                        return;
                    };
                    defer self.allocator.free(welcome_msg);
                    // Welcome is one-shot handshake state — refuse-to-drop
                    // so a slow joiner doesn't lose its bootstrap.
                    self.sendTo(from_conn_idx, welcome_msg, .control);
                }

                // Send a `sync` for every registered channel to the new
                // peer. Tier-1 invariant: a joining peer transitions to
                // `.connected` ONLY when it receives a `sync` message
                // (see processMessage `.sync` arm). Sending one per
                // channel keeps the joiner state-complete across all
                // active CRDTs. Iteration order is registration order
                // (deterministic; closes quality-engineer H-6).
                //
                // For v1 there is exactly ONE channel (unified-model);
                // future builds with editor-text / blob channels send
                // one sync envelope per channel.
                self.sendChannelSyncs(from_conn_idx);

                // Broadcast updated peer list to all
                self.pushPeers();
                self.pushStatus();

                // If host, broadcast join to other peers. The relayed
                // `join` is a roster-control message — not idempotent,
                // refuse-to-drop on overflow.
                if (self.session.mode == .host) {
                    self.broadcastExcept(data, from_conn_idx, .control);
                }
            },
            .welcome => |wmsg| {
                // pv:3 guest-side path: install the host's salt + the
                // negotiated suite, init crypto. Only guests should
                // receive welcome — host receiving welcome is a wire
                // bug (relay reflecting? Hostile peer?) and we drop it.
                if (self.session.mode != .guest) {
                    std.log.warn("collab: ignoring welcome received in host mode", .{});
                    return;
                }

                // A2: validate the suite via `crypto_mod.Suite.fromName`
                // (closed-set lookup — adding a suite to the enum
                // automatically extends what we accept). The wire-string
                // → enum parse is the security-critical step: any string
                // not matching a known enum variant is rejected before
                // it can drive `applyWelcome`. A buggy/hostile host that
                // returns a suite outside what we advertised (or a
                // future suite we don't know yet) lands here and is
                // dropped with a clean teardown (security panel H-2 —
                // without `stopNetworkingLocked` the socket stays open
                // and the read/write threads stay alive forever).
                const chosen_suite = crypto_mod.Suite.fromName(wmsg.suite) orelse {
                    std.log.warn(
                        "collab: welcome with unsupported suite '{s}' — closing session",
                        .{wmsg.suite},
                    );
                    self.stopNetworkingLocked();
                    self.session.leaveWithReason(.host_disconnected);
                    self.pushError("Host chose unsupported crypto suite");
                    self.pushStatus();
                    return;
                };

                // Defense-in-depth: the chosen suite MUST also be one
                // we advertised in `join.suite_prefs`. Today the build's
                // advertised set is the same as `Suite.fromName`'s
                // recognized set, so this check is redundant — but if a
                // future build advertises a strict subset (e.g. policy:
                // "this client never advertises AES-GCM"), this prevents
                // the host from forcing us onto an unadvertised suite.
                const advertised = blk: {
                    const chosen_name = chosen_suite.toName();
                    for (JOINER_SUITE_PREFS) |p| {
                        if (std.mem.eql(u8, p, chosen_name)) break :blk true;
                    }
                    break :blk false;
                };
                if (!advertised) {
                    std.log.warn(
                        "collab: welcome chose suite '{s}' that we did NOT advertise — closing session",
                        .{wmsg.suite},
                    );
                    self.stopNetworkingLocked();
                    self.session.leaveWithReason(.host_disconnected);
                    self.pushError("Host returned a suite we did not advertise");
                    self.pushStatus();
                    return;
                }

                // `.salt` is the decoded 16-byte slice from the welcome
                // envelope. The protocol decoder already validated len==16.
                if (wmsg.salt.len != 16) {
                    std.log.warn("collab: welcome salt wrong length {d}", .{wmsg.salt.len});
                    return;
                }
                var salt_arr: [16]u8 = undefined;
                @memcpy(&salt_arr, wmsg.salt[0..16]);

                self.session.applyWelcome(salt_arr, chosen_suite) catch |err| {
                    // Backend panel H-2: every applyWelcome failure tears
                    // the session down. The previous code only handled
                    // WelcomeAlreadyApplied; other errors (e.g.
                    // InvalidStateTransition from a relay-induced race)
                    // silently logged + returned, leaving the guest
                    // stuck in .joining with null crypto and no recovery.
                    std.log.warn("collab: applyWelcome failed: {s}", .{@errorName(err)});
                    self.stopNetworkingLocked();
                    self.session.leaveWithReason(.host_disconnected);
                    const reason: []const u8 = switch (err) {
                        // A2: covers both salt-rotation AND suite-rotation
                        // attempts (session.applyWelcome rejects either as
                        // WelcomeAlreadyApplied when crypto is non-null).
                        error.WelcomeAlreadyApplied => "Host attempted to re-key or re-suite mid-session",
                        error.InvalidStateTransition => "Welcome arrived in invalid session state",
                    };
                    self.pushError(reason);
                    self.pushStatus();
                    return;
                };
                std.log.info("collab: welcome applied (suite={s})", .{wmsg.suite});
            },
            .leave => |l| {
                self.session.removePeer(l.peer_id);
                // Panel #2 security HIGH-4: mirror session.removePeer with
                // peer_pubkeys cleanup. Without this, the cross-check map
                // diverges from session.peers: an unauthenticated `.leave`
                // erases the roster entry but keeps the pubkey binding,
                // and the same socket can keep sending signed ops that
                // pass the cross-check (slot's peer_id is unchanged and
                // peer_pubkeys still resolves). Removing both keeps the
                // two views consistent.
                _ = self.peer_pubkeys.remove(l.peer_id);
                self.pushPeers();
                self.pushStatus();

                // Relayed `leave` is a roster-control message —
                // refuse-to-drop, same reasoning as relayed `join`.
                if (self.session.mode == .host) {
                    self.broadcastExcept(data, from_conn_idx, .control);
                }
            },
            .sync => |s| {
                // Channel-routed sync. Look up the channel by name and
                // load the snapshot into its CRDT. Unknown channel →
                // drop with a metric (closes quality-engineer C-3).
                const ch = self.channels.find(s.ch) orelse {
                    self.metrics.inbound_unknown_channel += 1;
                    std.log.warn(
                        "collab: sync for unknown channel '{s}' dropped",
                        .{s.ch},
                    );
                    return;
                };

                // pv:3: decrypt before handing to the CRDT (drops with
                // metric if pre-welcome or AEAD tag fails).
                const plaintext_snap = self.decryptInbound(s.ch, "sync", s.snapshot) orelse return;
                defer self.allocator.free(plaintext_snap);

                ch.crdt.loadSnapshot(plaintext_snap) catch |err| {
                    std.log.warn(
                        "collab: loadSnapshot failed on channel '{s}': {}",
                        .{ s.ch, err },
                    );
                    return;
                };

                // Mark the session connected (first sync received from
                // host's roster handshake). One sync is enough to
                // unblock — additional channel syncs from the same
                // host call setConnected idempotently.
                self.session.setConnected();

                // Sync replay: walk the channel's CRDT fields and
                // dispatch each through the inbound bridge. For LWW
                // (unified-model) this seeds the joiner's local
                // UnifiedModel from the host's pre-join state.
                //
                // For v1, replay is LWW-Map-specific (uses
                // `iterateFields`). Future channels with their own
                // bridges set the per-channel `on_remote_op` hook and
                // skip the legacy callback path.
                if (std.mem.eql(u8, s.ch, "unified-model")) {
                    if (self.inbound_op_fn) |cb| {
                        const ReplayCtx = struct {
                            cb: InboundOpFn,
                            cb_ctx: *anyopaque,
                            allocator: std.mem.Allocator,
                            count: usize = 0,
                        };
                        var rctx = ReplayCtx{
                            .cb = cb,
                            .cb_ctx = self.inbound_op_ctx.?,
                            .allocator = self.allocator,
                        };
                        const Callback = struct {
                            fn run(any_ctx: *anyopaque, path: []const u8, value: []const u8, peer_id: [16]u8) void {
                                const rc: *ReplayCtx = @ptrCast(@alignCast(any_ctx));
                                _ = path; // bridge derives its own key from value
                                // Snapshot replay is unsigned by design in pv:4
                                // — the host's snapshot is the trusted seed for
                                // the joining peer, not a per-op message from a
                                // specific authoring identity. Pass `null` for
                                // the signer; the bridge treats absence-of-signer
                                // as host-attributed.
                                rc.cb(rc.cb_ctx, peer_id, null, value);
                                rc.count += 1;
                            }
                        };
                        self.crdt_doc.iterateFields(@ptrCast(&rctx), Callback.run);
                        std.log.info(
                            "collab: sync replay (unified-model) → bridge.applyPeerOp ×{d}",
                            .{rctx.count},
                        );
                    }
                }

                // Per-channel remote-op replay. Future channels with
                // their own bridges hook this; v1's unified-model uses
                // the legacy callback above instead.
                _ = ch.on_remote_op;

                self.pushState();
                self.pushStatus();
            },
            .op => |o| {
                // Channel validation MUST happen BEFORE any state mutation
                // (closes security-engineer C-1/C-2). Channel name + ACL
                // are gated here so the relay path also defers to
                // writable_by_peers; Drive-host mode (Phase B) drops
                // inbound ops with no relay and no state change.
                const ch = self.channels.find(o.ch) orelse {
                    self.metrics.inbound_unknown_channel += 1;
                    std.log.warn(
                        "collab: inbound op for unknown channel '{s}' dropped",
                        .{o.ch},
                    );
                    return;
                };
                if (!ch.writable_by_peers) {
                    self.metrics.inbound_op_denied += 1;
                    std.log.warn(
                        "collab: inbound op on RO channel '{s}' dropped (drive-host mode)",
                        .{o.ch},
                    );
                    return;
                }

                // B1: host-side advertised-pubkey cross-check. The
                // connection's tracked peer_id was bound by the `.join`
                // arm; peer_pubkeys stored the pubkey advertised at
                // join time. The op's `signer` MUST equal that pubkey.
                // Mismatch → signer self-spoofing attempt (a peer
                // pretending to be another peer that already joined).
                // Missing entry → peer skipped the join handshake.
                // Both are dropped under the same metric (the wire
                // shape is malformed for an authenticated room).
                //
                // Guest mode skips this check: a guest only directly
                // speaks to the host, and relayed ops carry the
                // ORIGINAL author's signer — looking up the host's
                // peer-id slot would (correctly) not find the original
                // author's key, but a strict miss-is-drop policy would
                // reject every relayed op. The signature itself is
                // still verified below (end-to-end authenticity).
                if (self.session.mode == .host) {
                    if (from_conn_idx >= self.connections.items.len) {
                        self.metrics.inbound_unsigned_dropped += 1;
                        std.log.warn(
                            "collab: inbound op on '{s}' from out-of-bounds conn idx {d} dropped",
                            .{ o.ch, from_conn_idx },
                        );
                        return;
                    }
                    const conn_peer = self.connections.items[from_conn_idx].peer_id;
                    if (self.peer_pubkeys.get(conn_peer)) |advertised| {
                        if (o.signer.len != identity_mod.PUBKEY_LEN or
                            !std.mem.eql(u8, &advertised, o.signer))
                        {
                            self.metrics.inbound_unsigned_dropped += 1;
                            std.log.warn(
                                "collab: inbound op on '{s}' dropped — signer does not match peer's advertised pubkey (peer_id={x})",
                                .{ o.ch, conn_peer },
                            );
                            return;
                        }
                    } else {
                        // No join handshake recorded for this conn. A
                        // well-behaved peer must send `.join` before any
                        // signed `.op` / `.ops`. Reject; force the
                        // handshake.
                        self.metrics.inbound_unsigned_dropped += 1;
                        std.log.warn(
                            "collab: inbound op on '{s}' from conn[{d}] dropped — no prior join (peer_id={x})",
                            .{ o.ch, from_conn_idx, conn_peer },
                        );
                        return;
                    }
                }

                // pv:4: decrypt → verify(sig) → applyRemote. Decrypt
                // first so verify operates on PLAINTEXT op_bytes (the
                // bytes the sender signed). Order matters: a wrong-key
                // ciphertext fails decrypt and we never see plaintext;
                // a tampered ciphertext likely fails decrypt; a forged
                // signer fails verify.
                const plaintext = self.decryptInbound(o.ch, "op", o.payload) orelse return;
                defer self.allocator.free(plaintext);

                // B1: signer pubkey + sig come in as already-length-
                // validated byte slices (decoder enforced 32 / 64).
                // Re-tag here for the verify call.
                if (!verifyOpSignature(o.sig, plaintext, o.signer)) {
                    self.metrics.inbound_unsigned_dropped += 1;
                    std.log.warn(
                        "collab: inbound op on '{s}' dropped — Ed25519 verify failed",
                        .{o.ch},
                    );
                    return;
                }

                const changed = ch.crdt.applyRemote(plaintext) catch |err| {
                    std.log.warn(
                        "collab: applyRemote failed on channel '{s}': {}",
                        .{ o.ch, err },
                    );
                    return;
                };
                if (changed) {
                    self.pushState();
                }

                // For the unified-model channel, dispatch the legacy
                // inbound callback so the studio's CrdtBridge sees the
                // op flow into the model actor. Other channels use the
                // per-channel `on_remote_op` hook instead.
                const conn_peer_id = if (from_conn_idx < self.connections.items.len)
                    self.connections.items[from_conn_idx].peer_id
                else
                    std.mem.zeroes([16]u8);
                if (std.mem.eql(u8, o.ch, "unified-model")) {
                    if (self.inbound_op_fn) |cb| {
                        // Extract peer_id from the LWW op for studio's
                        // CrdtBridge fairness sub-quota. Fall back to
                        // conn_peer_id, then zero.
                        const op_peer = extractLwwPeerId(plaintext) orelse conn_peer_id;
                        // CONTRACT: asserted CROSS-REPO by studio/tests/crdt-share-test.sh
                        // REPLICATION=manual (regex 'collab: inbound op \(unified-model\)
                        // → bridge.applyPeerOp payload_len=[0-9]+'). The studio smoke
                        // greps this exact string from collab's log output. Do not
                        // rename 'inbound op' or remove 'payload_len=' without coordinating
                        // a studio test update.
                        std.log.info(
                            "collab: inbound op (unified-model) → bridge.applyPeerOp payload_len={d}",
                            .{plaintext.len},
                        );
                        // B1: signer carried through so the bridge can
                        // attribute the op to a verified Ed25519 key
                        // (B6 audit log + B4 role ACL groundwork).
                        cb(self.inbound_op_ctx.?, op_peer, o.signer, plaintext);
                    }
                }
                if (ch.on_remote_op) |cb| {
                    cb(ch.on_remote_op_ctx.?, conn_peer_id, plaintext);
                }

                // Relay only if peers are allowed to write on this
                // channel (closes system-architect HIGH Drive-host
                // split-brain). Drive-host sets writable_by_peers=false
                // → no relay → no peer-to-peer split-brain.
                //
                // Relay forwards the ORIGINAL `data` (encrypted envelope)
                // — peers downstream share the same room key and decrypt
                // independently. No re-encrypt needed. The single-op
                // path either passed verify above (we relay) or returned
                // early on failure (we never reach here for a forged op).
                if (self.session.mode == .host and ch.writable_by_peers) {
                    self.broadcastExcept(data, from_conn_idx, .crdt_op);
                }
            },
            .ops => |batch| {
                const ch = self.channels.find(batch.ch) orelse {
                    self.metrics.inbound_unknown_channel += 1;
                    std.log.warn(
                        "collab: inbound ops batch for unknown channel '{s}' dropped",
                        .{batch.ch},
                    );
                    return;
                };
                if (!ch.writable_by_peers) {
                    self.metrics.inbound_op_denied += 1;
                    std.log.warn(
                        "collab: inbound ops on RO channel '{s}' dropped (drive-host mode)",
                        .{batch.ch},
                    );
                    return;
                }

                // pv:3: pre-welcome gate (must check before per-entry
                // loop so we drop the entire batch, not just each entry).
                if (self.session.crypto == null) {
                    self.metrics.inbound_missing_welcome += 1;
                    std.log.warn(
                        "collab: ops on '{s}' arrived before welcome — dropped",
                        .{batch.ch},
                    );
                    return;
                }

                const conn_peer_id = if (from_conn_idx < self.connections.items.len)
                    self.connections.items[from_conn_idx].peer_id
                else
                    std.mem.zeroes([16]u8);

                // B1: host-side advertised-pubkey for this connection.
                // Same semantics as the `.op` arm. We hoist the lookup
                // out of the loop because all entries in a single
                // batch arrived from ONE connection and share the
                // same expected signer (the joiner that owns the
                // connection slot).
                //
                // Architectural note: future channels MAY allow
                // multi-author batches (e.g. a host forwarding a
                // bundle of mixed-author ops). For v1 the only
                // batch source is `broadcastChannelOps` from a
                // single local CRDT mutator, so single-author is
                // safe; B4 will revisit when role ACLs land.
                var expected_signer: ?[identity_mod.PUBKEY_LEN]u8 = null;
                if (self.session.mode == .host) {
                    if (from_conn_idx >= self.connections.items.len) {
                        self.metrics.inbound_unsigned_dropped += 1;
                        std.log.warn(
                            "collab: ops batch on '{s}' from out-of-bounds conn idx {d} dropped",
                            .{ batch.ch, from_conn_idx },
                        );
                        return;
                    }
                    if (self.peer_pubkeys.get(conn_peer_id)) |advertised| {
                        expected_signer = advertised;
                    } else {
                        // Same join-handshake-required policy as `.op`.
                        self.metrics.inbound_unsigned_dropped += 1;
                        std.log.warn(
                            "collab: ops batch on '{s}' from conn[{d}] dropped — no prior join (peer_id={x})",
                            .{ batch.ch, from_conn_idx, conn_peer_id },
                        );
                        return;
                    }
                }

                // B1 / panel-#1 security HIGH-1: filter forged entries
                // before relay. The pre-fix path relayed `data`
                // verbatim, which amplified a hostile peer's forged
                // entries to every other peer (each would drop them,
                // but the host paid the bandwidth and gave the
                // attacker the megaphone). Track the entries that
                // pass BOTH decrypt + verify and re-emit only those.
                //
                // Fast path: if every entry verifies, we relay `data`
                // unchanged (no re-encode, no extra allocation).
                // Slow path: if any entry was dropped, re-encode the
                // verified subset before relay. The re-encode is
                // bounded by `MAX_OPS_BATCH_LEN`.
                var verified_for_relay: std.array_list.Managed(protocol.SignedOp) = .init(self.allocator);
                defer verified_for_relay.deinit();
                verified_for_relay.ensureTotalCapacity(batch.batch.len) catch {
                    std.log.warn(
                        "collab: ops on '{s}' — relay-buffer alloc failed; dropping batch entirely",
                        .{batch.ch},
                    );
                    return;
                };

                var any_changed = false;
                for (batch.batch) |entry| {
                    // Host-side advertised-pubkey cross-check (B1).
                    // Skipped in guest mode (see `.op` arm rationale).
                    if (expected_signer) |pk| {
                        if (entry.signer.len != identity_mod.PUBKEY_LEN or
                            !std.mem.eql(u8, &pk, entry.signer))
                        {
                            self.metrics.inbound_unsigned_dropped += 1;
                            std.log.warn(
                                "collab: ops-entry on '{s}' dropped — signer mismatch vs advertised pubkey",
                                .{batch.ch},
                            );
                            continue;
                        }
                    }

                    // Per-entry decrypt (continues on failure; drops bad
                    // entries individually rather than the whole batch).
                    const plaintext = self.decryptInbound(batch.ch, "ops-entry", entry.payload) orelse continue;
                    defer self.allocator.free(plaintext);

                    // B1: per-entry verify. Even though `expected_signer`
                    // gated the wire-shape upstream, the SIGNATURE itself
                    // must still be checked — a hostile peer could
                    // claim the right pubkey but accompany it with a
                    // signature that doesn't validate over this op's
                    // plaintext (forgery without the private key).
                    if (!verifyOpSignature(entry.sig, plaintext, entry.signer)) {
                        self.metrics.inbound_unsigned_dropped += 1;
                        std.log.warn(
                            "collab: ops-entry on '{s}' dropped — Ed25519 verify failed",
                            .{batch.ch},
                        );
                        continue;
                    }

                    // Eligible for relay AFTER both checks passed.
                    // applyRemote failures below do NOT block relay —
                    // an op that fails THIS host's apply path may
                    // still apply correctly at downstream peers
                    // (e.g. version-skew tolerated by CRDT).
                    verified_for_relay.appendAssumeCapacity(entry);

                    const changed = ch.crdt.applyRemote(plaintext) catch continue;
                    if (changed) any_changed = true;

                    if (std.mem.eql(u8, batch.ch, "unified-model")) {
                        if (self.inbound_op_fn) |cb| {
                            const op_peer = extractLwwPeerId(plaintext) orelse conn_peer_id;
                            cb(self.inbound_op_ctx.?, op_peer, entry.signer, plaintext);
                        }
                    }
                    if (ch.on_remote_op) |cb| {
                        cb(ch.on_remote_op_ctx.?, conn_peer_id, plaintext);
                    }
                }
                if (any_changed) {
                    self.pushState();
                }

                // Relay only the verified subset (panel-#1 security
                // HIGH-1 closure). Three branches:
                //   - All entries verified → fast path, relay `data`.
                //   - Some entries forged   → re-encode + relay subset.
                //   - All entries forged   → no relay (don't give the
                //                              attacker a megaphone).
                if (self.session.mode == .host and ch.writable_by_peers) {
                    if (verified_for_relay.items.len == batch.batch.len) {
                        self.broadcastExcept(data, from_conn_idx, .crdt_op);
                    } else if (verified_for_relay.items.len > 0) {
                        const filtered_msg = protocol.encode(self.allocator, .{
                            .ops = .{ .ch = batch.ch, .batch = verified_for_relay.items },
                        }) catch |err| {
                            std.log.warn(
                                "collab: failed to re-encode filtered ops batch on '{s}': {s} — dropping relay (would have amplified forged entries)",
                                .{ batch.ch, @errorName(err) },
                            );
                            return;
                        };
                        defer self.allocator.free(filtered_msg);
                        self.broadcastExcept(filtered_msg, from_conn_idx, .crdt_op);
                    }
                    // else: every entry was forged or tampered. Relay
                    // nothing — the metric `inbound_unsigned_dropped`
                    // has already been incremented per dropped entry.
                }
            },
            .peers => {
                // Peer list update from relay — update session peers
                // The peers list in the message can be used to update local state
                self.pushPeers();
            },
            .ping => {
                const pong = protocol.encode(self.allocator, .{ .pong = {} }) catch return;
                defer self.allocator.free(pong);
                // Application-level pong (vs. WS-protocol pong below)
                // is a keepalive control reply — refuse-to-drop so a
                // slow peer can't make us silently appear dead.
                self.sendTo(from_conn_idx, pong, .control);
            },
            .pong => {}, // keepalive acknowledged
            .@"error" => |e| {
                std.log.warn("collab: Remote error: {s}", .{e.message});
                self.pushError(e.message);
            },
        }
    }

    // =========================================================================
    // Internal: Networking
    // =========================================================================

    fn acceptLoop(self: *CollabManager) void {
        while (self.running) {
            const stream = self.server.?.accept() catch |err| {
                if (!self.running) break;
                std.log.warn("collab: Accept failed: {}", .{err});
                continue;
            };

            const io = compat.io();
            self.mutex.lockUncancelable(io);
            // Allocate the per-peer outbound queue first; on OOM, refuse
            // the connection cleanly instead of registering a peer with
            // no way to send.
            const queue = SendQueue.init(self.allocator, SendQueue.DEFAULT_CAPACITY) catch {
                std.log.warn("collab: send_queue alloc failed; rejecting peer", .{});
                self.mutex.unlock(io);
                ws.closeStream(stream);
                continue;
            };
            const idx = self.connections.items.len;
            const entry = self.connections.addOne() catch {
                self.mutex.unlock(io);
                queue.deinit();
                ws.closeStream(stream);
                continue;
            };
            entry.* = .{
                .stream = stream,
                .peer_id = std.mem.zeroes([16]u8),
                .read_thread = null,
                .send_queue = queue,
                .write_thread = null,
                .mask = false, // host→peer frames are not masked
            };
            entry.read_thread = std.Thread.spawn(.{}, readLoop, .{ self, idx }) catch |err| blk: {
                std.log.err("collab: Failed to spawn read thread for conn {d}: {}", .{ idx, err });
                break :blk null;
            };
            entry.write_thread = std.Thread.spawn(.{}, writeLoop, .{ self, queue, stream, false }) catch |err| blk: {
                std.log.err("collab: Failed to spawn write thread for conn {d}: {}", .{ idx, err });
                break :blk null;
            };
            self.mutex.unlock(io);
        }
    }

    fn readLoop(self: *CollabManager, conn_idx: usize) void {
        // PERSISTENT read buffer + Reader, both living for the entire
        // lifetime of this read loop. CRITICAL: if either is recreated
        // per-iteration, std.Io.Reader's internal read-ahead bytes are
        // lost on each return and frames silently disappear from the
        // wire. See `websocket.readFrameFromReader` docstring for the
        // full explanation. Without this, the host's welcome+sync
        // back-to-back send was only ~50% reliable on loopback.
        var io_buf: [4096]u8 = undefined;
        const io = compat.io();
        self.mutex.lockUncancelable(io);
        if (conn_idx >= self.connections.items.len) {
            self.mutex.unlock(io);
            return;
        }
        const stream = self.connections.items[conn_idx].stream;
        self.mutex.unlock(io);
        var stream_reader = stream.reader(io, &io_buf);

        while (self.running) {
            const frame = ws.readFrameFromReader(self.allocator, &stream_reader.interface) catch |err| {
                if (!self.running) break;
                std.log.info("collab: Connection {d} read error: {}", .{ conn_idx, err });
                self.handleDisconnect(conn_idx);
                break;
            };
            defer self.allocator.free(frame.payload);

            switch (frame.opcode) {
                .text => {
                    self.processMessage(frame.payload, conn_idx);
                },
                .ping => {
                    // Pong reply now routes through the per-peer send
                    // queue so it inherits the correct mask (RFC 6455
                    // §5.5.3: pong frames follow the same masking rule
                    // as data frames). The previous direct `writeFrame`
                    // hardcoded `mask = false`, which was a spec
                    // violation for guest-side pongs. `push` is a
                    // bounded enqueue so it doesn't reintroduce the
                    // HIGH-1 mutex-hold problem; a closed queue returns
                    // `error.Closed` which we ignore (peer already gone).
                    //
                    // WS-protocol pong is a control message — refuse
                    // to drop on queue overflow.
                    self.mutex.lockUncancelable(io);
                    if (conn_idx < self.connections.items.len) {
                        self.connections.items[conn_idx].send_queue.push(frame.payload, .pong, .control) catch {};
                    }
                    self.mutex.unlock(io);
                },
                .close => {
                    self.handleDisconnect(conn_idx);
                    break;
                },
                else => {},
            }
        }
    }

    /// Tear down one peer's connection in response to read EOF or a
    /// WebSocket `.close` frame. Idempotent and bounds-checked so a
    /// double-call (e.g. read EOF followed by an inbound `.close`) is
    /// safe. Phase 5 panel: lock-ordering hygiene (security MED-2 +
    /// refactor MED-1) — `pushPeers`/`pushStatus` invoke the JS push
    /// callback, which must never be called while we hold the manager
    /// mutex. We scope the lock tightly, do all state work inside,
    /// release, then notify.
    fn handleDisconnect(self: *CollabManager, conn_idx: usize) void {
        const io = compat.io();
        var should_notify = false;
        {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);

            if (conn_idx >= self.connections.items.len) return;

            const conn = self.connections.items[conn_idx];
            // Order matters:
            //   1. Zero peer_id so concurrent broadcasts skip this slot.
            //   2. removePeer using the LOCAL copy of peer_id (the slot
            //      was zeroed in step 1, so re-reading would miss the
            //      real id — by-value capture above preserves it).
            //   3. Close the queue so the write thread will exit once
            //      it drains whatever remains.
            //   4. SHUTDOWN (not close) the stream. Closing the fd
            //      while the write thread is mid-`writeFrame` would
            //      trigger Zig 0.16's BADF programmer-bug panic.
            //      Shutdown leaves the fd valid but makes the kernel
            //      return error on pending I/O, so the write thread
            //      sees an error and falls through to its next pop.
            //      Actual `close` happens in `stopNetworkingLocked`
            //      after the write thread has been joined.
            //
            // Memory cost of a disconnected slot: the SendQueue
            // (~50 KB at default capacity) + one zombie fd, bounded
            // by MAX_PEERS for the session lifetime. Tier 2 transport
            // trait will compact this.
            //
            // Double-call safety: queue.close() is idempotent
            // (`if (self.closed) return`); stream.shutdown on an
            // already-shutdown fd returns ENOTCONN which we swallow;
            // session.removePeer on a zero peer_id is a no-op walk.
            self.connections.items[conn_idx].peer_id = std.mem.zeroes([16]u8);
            self.session.removePeer(conn.peer_id);
            // B1: drop the disconnected peer's advertised pubkey. If the
            // same peer-id ever reappears (different process, reused id)
            // it MUST re-handshake — we don't carry stale identity bindings
            // across reconnects. `remove` is no-op if the entry never
            // existed (guest-side connections never populate this map).
            _ = self.peer_pubkeys.remove(conn.peer_id);

            // Guest-side recovery: a guest only ever has ONE connection
            // (to the host). If it drops, the session is dead — v1 has
            // no anti-entropy or reconnect logic so we cannot recover
            // automatically. Without this reset, `session.state` stays
            // `.joining` / `.connected` forever, and any subsequent
            // `collab.create` or `collab.join` rejects with `SessionActive`
            // even though the user has no working transport. UX symptom
            // observed in the 2-instance smoke: host leaves → guest can
            // never start a new session without restarting the app.
            //
            // Hosts deliberately stay in `.hosting` (or transition via
            // `session.removePeer`'s own host/guest branch) — they own
            // the room and can wait for new peers. Only guests force
            // back to idle here.
            if (self.session.mode == .guest and self.session.state != .idle) {
                // Pass `.host_disconnected` so the log line names the
                // real cause — the user did NOT click Leave; the host's
                // connection died. Otherwise the bare `Left session`
                // log misled the smoke test ("I did NOT leave").
                self.session.leaveWithReason(.host_disconnected);
            }

            conn.send_queue.close();
            conn.stream.shutdown(io, .both) catch {};
            should_notify = true;
        }
        // The JS-bound push callback runs OUTSIDE the manager mutex —
        // any synchronous wait it might one day perform cannot deadlock
        // against the mutex. Pre-Phase-5 these calls were inside the
        // lock; that was latent. (security MED-2 / refactor MED-1.)
        if (should_notify) {
            self.pushPeers();
            self.pushStatus();
        }
    }

    /// Send one `sync` envelope per registered channel to `conn_idx`.
    /// Used when a peer joins — they get a state-complete bootstrap
    /// across every channel. Caller MUST hold `self.mutex`.
    fn sendChannelSyncs(self: *CollabManager, conn_idx: usize) void {
        const Ctx = struct {
            self: *CollabManager,
            conn_idx: usize,
            fn run(any_ctx: *anyopaque, ch: *channel_mod.Channel) void {
                const c: *@This() = @ptrCast(@alignCast(any_ctx));
                // Snapshot may be large; allocate with manager allocator
                // and free immediately after enqueue (the envelope is
                // dup'd into the per-peer send_queue).
                const snap = ch.crdt.snapshot(c.self.allocator) catch |err| {
                    std.log.warn(
                        "collab: snapshot failed on channel '{s}': {}",
                        .{ ch.name, err },
                    );
                    return;
                };
                defer c.self.allocator.free(snap);

                // Plaintext cap check BEFORE encrypt — symmetric with
                // the op-broadcast path (system-arch panel M-1).
                if (snap.len > MAX_SNAPSHOT_PLAINTEXT_BYTES) {
                    std.log.err(
                        "collab: snapshot plaintext too large on '{s}' ({d} > {d}) — bootstrap aborted",
                        .{ ch.name, snap.len, MAX_SNAPSHOT_PLAINTEXT_BYTES },
                    );
                    return;
                }

                // pv:3: encrypt the snapshot before envelope. Host's
                // crypto is always initialized at startHosting (this
                // function is only called from the host's .join handler
                // anyway, where the host knows it has crypto). Guard
                // defensively so a stale code path can't ship plaintext.
                const crypto = if (c.self.session.crypto) |*ctx_c| ctx_c else {
                    std.log.err(
                        "collab: sendChannelSyncs called with null crypto on '{s}' — refusing to ship plaintext snapshot",
                        .{ch.name},
                    );
                    return;
                };
                // AAD = channel name (security-panel H-1). Receiver decrypts
                // with the same AAD on the .sync arm.
                const ciphertext = crypto.encrypt(c.self.allocator, snap, ch.name) catch |err| {
                    c.self.metrics.outbound_encrypt_failed += 1;
                    std.log.err(
                        "collab: encrypt snapshot failed on channel '{s}': {s}",
                        .{ ch.name, @errorName(err) },
                    );
                    return;
                };
                defer c.self.allocator.free(ciphertext);

                const sync_msg = protocol.encode(c.self.allocator, .{
                    .sync = .{ .ch = ch.name, .snapshot = ciphertext },
                }) catch |err| {
                    std.log.warn(
                        "collab: encode sync failed on channel '{s}': {}",
                        .{ ch.name, err },
                    );
                    return;
                };
                defer c.self.allocator.free(sync_msg);
                // `sync` is the one-shot bootstrap state per channel.
                // Refuse-to-drop so a slow peer cannot lose its bootstrap.
                c.self.sendTo(c.conn_idx, sync_msg, .control);
            }
        };
        var ctx = Ctx{ .self = self, .conn_idx = conn_idx };
        self.channels.iterate(@ptrCast(&ctx), Ctx.run);
    }

    /// Decrypt an inbound channel-routed payload, handling the two
    /// drop-on-failure cases (no welcome yet, or AEAD tag failure) with
    /// metrics + log. Caller MUST `allocator.free` the returned slice.
    ///
    /// Returns null if the frame should be dropped silently. Consolidates
    /// the three near-identical sites in .sync / .op / .ops arms
    /// (refactor panel M-3). Caller already holds the manager mutex.
    ///
    /// `aad` is the channel name — bound into the GCM tag by the sender
    /// so a hostile peer cannot replay ciphertext across channels
    /// (security panel H-1).
    fn decryptInbound(
        self: *CollabManager,
        channel_name: []const u8,
        op_kind: []const u8,
        ciphertext: []const u8,
    ) ?[]u8 {
        const crypto = if (self.session.crypto) |*c| c else {
            self.metrics.inbound_missing_welcome += 1;
            std.log.warn(
                "collab: {s} on '{s}' arrived before welcome — dropped",
                .{ op_kind, channel_name },
            );
            return null;
        };
        return crypto.decrypt(self.allocator, ciphertext, channel_name) catch |err| {
            self.metrics.inbound_decrypt_failed += 1;
            std.log.warn(
                "collab: decrypt {s} failed on '{s}': {s}",
                .{ op_kind, channel_name, @errorName(err) },
            );
            return null;
        };
    }

    /// B1: verify an Ed25519 signature against the claimed signer pubkey
    /// over the plaintext op bytes. Returns true iff verify succeeds.
    ///
    /// Wire-shape sanity check: the protocol decoder already enforces
    /// `sig.len == identity.SIG_LEN` and `signer.len == identity.PUBKEY_LEN`
    /// at parse time (via `decodeFixedLen`), so by the time this is
    /// called both slices are guaranteed to have the right length. We
    /// `unreachable`-defend with an explicit length check anyway so a
    /// future refactor that bypasses the decoder cannot silently degrade
    /// to a no-op verify.
    fn verifyOpSignature(sig_bytes: []const u8, plaintext: []const u8, signer_bytes: []const u8) bool {
        if (sig_bytes.len != identity_mod.SIG_LEN) return false;
        if (signer_bytes.len != identity_mod.PUBKEY_LEN) return false;
        var sig_arr: [identity_mod.SIG_LEN]u8 = undefined;
        var signer_arr: [identity_mod.PUBKEY_LEN]u8 = undefined;
        @memcpy(&sig_arr, sig_bytes[0..identity_mod.SIG_LEN]);
        @memcpy(&signer_arr, signer_bytes[0..identity_mod.PUBKEY_LEN]);
        return identity_mod.verify(sig_arr, plaintext, signer_arr);
    }

    /// Plaintext-side cap for ops + snapshots. The wire ciphertext cap
    /// (`protocol.MAX_OP_PAYLOAD_BYTES`, `protocol.MAX_SNAPSHOT_BYTES`)
    /// is on POST-encrypt bytes. Enforcing plaintext = ciphertext-cap -
    /// `crypto_mod.AEAD_OVERHEAD` BEFORE encrypt avoids the
    /// "encrypt-then-fail-on-wire" foot-gun (system-arch panel M-1).
    pub const MAX_OP_PLAINTEXT_BYTES: usize = protocol.MAX_OP_PAYLOAD_BYTES - crypto_mod.AEAD_OVERHEAD;
    pub const MAX_SNAPSHOT_PLAINTEXT_BYTES: usize = protocol.MAX_SNAPSHOT_BYTES - crypto_mod.AEAD_OVERHEAD;

    fn broadcastChannelOp(
        self: *CollabManager,
        channel_name: []const u8,
        op_bytes: []const u8,
    ) !void {
        // pv:4 pipeline: sign(plaintext) → encrypt(plaintext) → embed
        // both into the envelope. Signing BEFORE encrypt binds the
        // signature to op AUTHORSHIP rather than to ciphertext (which
        // anyone with the room key can produce); this is the v1 B1
        // posture documented in `identity.zig`.
        //
        // Hosts always have crypto (set in startHosting); guests have
        // crypto post-welcome. Plaintext cap guard sits BEFORE encrypt
        // so we never produce ciphertext that would fail wire-cap
        // validation downstream.
        if (op_bytes.len > MAX_OP_PLAINTEXT_BYTES) {
            std.log.warn(
                "collab: op_bytes plaintext too large on '{s}' ({d} > {d})",
                .{ channel_name, op_bytes.len, MAX_OP_PLAINTEXT_BYTES },
            );
            return error.OpPlaintextTooLarge;
        }
        const crypto = if (self.session.crypto) |*c| c else return error.MissingWelcome;

        // B1: Ed25519 sign over plaintext op_bytes. `Identity.sign` is
        // allocation-free (returns a stack array). Failure here is rare
        // — it would imply an internal crypto-library bug, not a
        // recoverable runtime condition.
        const sig = self.identity.sign(op_bytes) catch |err| {
            self.metrics.outbound_sign_failed += 1;
            std.log.err("collab: outbound sign failed: {s}", .{@errorName(err)});
            return err;
        };
        const signer = self.identity.publicKeyBytes();

        // AAD = channel name. Binds ciphertext to its channel slot so a
        // peer cannot replay a ciphertext from one channel into another's
        // envelope (security-panel H-1). v1 has one channel; the binding
        // is forward-compatibility for A2's editor-text + future channels.
        const ciphertext = crypto.encrypt(self.allocator, op_bytes, channel_name) catch |err| {
            self.metrics.outbound_encrypt_failed += 1;
            std.log.err("collab: outbound encrypt failed: {s}", .{@errorName(err)});
            return err;
        };
        defer self.allocator.free(ciphertext);

        const msg = try protocol.encode(self.allocator, .{
            .op = .{
                .ch = channel_name,
                .payload = ciphertext,
                .sig = &sig,
                .signer = &signer,
            },
        });
        defer self.allocator.free(msg);
        // Single CRDT op — drop-oldest backpressure is safe (idempotent +
        // commutative, anti-entropy backstop). See SendQueue file-level
        // docstring for the policy rationale.
        self.broadcastRaw(msg, .crdt_op);
    }

    fn broadcastChannelOps(
        self: *CollabManager,
        channel_name: []const u8,
        op_bytes_batch: []const []const u8,
    ) !void {
        const crypto = if (self.session.crypto) |*c| c else return error.MissingWelcome;

        // Plaintext cap check across the batch BEFORE allocation.
        for (op_bytes_batch) |op_bytes| {
            if (op_bytes.len > MAX_OP_PLAINTEXT_BYTES) {
                std.log.warn(
                    "collab: op_bytes plaintext too large in batch on '{s}' ({d} > {d})",
                    .{ channel_name, op_bytes.len, MAX_OP_PLAINTEXT_BYTES },
                );
                return error.OpPlaintextTooLarge;
            }
        }

        // B1: pre-compute per-entry signatures over PLAINTEXT op_bytes
        // BEFORE encrypt. Each entry gets its own fresh sig (Ed25519
        // signatures are deterministic, but the IDX into the batch
        // varies — different message, different sig). The signer
        // pubkey is identical across the batch (one local identity).
        const signer = self.identity.publicKeyBytes();
        const sigs = try self.allocator.alloc([identity_mod.SIG_LEN]u8, op_bytes_batch.len);
        defer self.allocator.free(sigs);
        for (op_bytes_batch, 0..) |op_bytes, i| {
            sigs[i] = self.identity.sign(op_bytes) catch |err| {
                self.metrics.outbound_sign_failed += 1;
                std.log.err("collab: outbound sign failed (batch idx={d}): {s}", .{ i, @errorName(err) });
                return err;
            };
        }

        // Encrypt each entry independently. Each gets a fresh CSPRNG
        // nonce (`crypto.encrypt` generates one per call), so nonce
        // reuse — catastrophic for AES-GCM — is structurally impossible.
        //
        // Cleanup uses a success-counter so a partial encrypt-failure
        // mid-loop frees exactly the entries we produced — no reliance
        // on the `b.len > 0` length sentinel that would break if a
        // future AEAD ever returned a zero-byte ciphertext (refactor-
        // panel H-1).
        const encrypted_batch = try self.allocator.alloc([]const u8, op_bytes_batch.len);
        var produced: usize = 0;
        defer {
            for (encrypted_batch[0..produced]) |b| self.allocator.free(b);
            self.allocator.free(encrypted_batch);
        }

        for (op_bytes_batch, 0..) |op_bytes, i| {
            encrypted_batch[i] = crypto.encrypt(self.allocator, op_bytes, channel_name) catch |err| {
                self.metrics.outbound_encrypt_failed += 1;
                std.log.err("collab: outbound encrypt failed (batch idx={d}): {s}", .{ i, @errorName(err) });
                return err;
            };
            produced = i + 1;
        }

        // Build SignedOp entries that borrow from `encrypted_batch` +
        // `sigs` + `signer`. The slice lifetimes hold through the
        // `protocol.encode` call below — encode copies bytes into its
        // owned buffer, after which all three sources can be freed by
        // the deferred cleanups.
        const signed_batch = try self.allocator.alloc(protocol.SignedOp, op_bytes_batch.len);
        defer self.allocator.free(signed_batch);
        for (encrypted_batch, 0..) |ct, i| {
            signed_batch[i] = .{
                .payload = ct,
                .sig = &sigs[i],
                .signer = &signer,
            };
        }

        const msg = try protocol.encode(self.allocator, .{
            .ops = .{ .ch = channel_name, .batch = signed_batch },
        });
        defer self.allocator.free(msg);
        // Batched CRDT ops follow the same policy as a single op.
        self.broadcastRaw(msg, .crdt_op);
    }

    /// Push `data` into every live peer's outbound queue. O(N) in peer
    /// count and O(1) per peer; never blocks on a socket. This is the
    /// HIGH-1 fix: the manager mutex stays held only long enough to
    /// walk `connections.items` and call `push`, never long enough for
    /// a slow peer's TCP backpressure to stall the system.
    ///
    /// Host mode: every non-dead connection is a peer to fan out to.
    /// Guest mode: there is exactly one connection (the host) — added
    /// via `joinSession` — and we push to it. The pre-Phase-5 code had
    /// a `client_stream` special case that was eliminated when guest
    /// connections were routed through `connections.items` like host
    /// peers (Phase 5 panel system-architect H-2).
    ///
    /// `kind` is the backpressure policy per message (see
    /// `send_queue.MessageKind`). Control messages (join/leave/sync/
    /// peers/error/pong) preempt CRDT ops on overflow; CRDT ops drop
    /// oldest; a queue full of all-control returns `error.QueueFull`
    /// (swallowed here — control-msg loss on outbound is logged at the
    /// per-peer write thread level on the next reconnect attempt).
    fn broadcastRaw(self: *CollabManager, data: []const u8, kind: send_queue_mod.MessageKind) void {
        for (self.connections.items) |conn| {
            if (std.mem.eql(u8, &conn.peer_id, &std.mem.zeroes([16]u8))) {
                // Host mode: zero peer_id means the peer hasn't sent its
                // join yet (still mid-handshake) or has disconnected.
                // Guest mode: the single conn keeps peer_id=zero until
                // we've fully synced with the host — but we still need
                // to send our outbound traffic to that conn. Distinguish
                // by mode.
                if (self.session.mode == .host) continue;
            }
            conn.send_queue.push(data, .text, kind) catch |err| {
                // Diagnostic (backend-architect H-1): per-peer push
                // failure should be observable so silent peer-gone or
                // queue-full conditions show up in logs.
                std.log.debug("collab: broadcast push failed: {} (kind={s})", .{ err, @tagName(kind) });
            };
        }
    }

    /// Same as `broadcastRaw` but skips one connection by index. Only
    /// the host calls this (to relay a peer's message to all OTHERS).
    fn broadcastExcept(self: *CollabManager, data: []const u8, except_idx: usize, kind: send_queue_mod.MessageKind) void {
        for (self.connections.items, 0..) |conn, i| {
            if (i == except_idx) continue;
            if (std.mem.eql(u8, &conn.peer_id, &std.mem.zeroes([16]u8))) continue;
            conn.send_queue.push(data, .text, kind) catch |err| {
                std.log.debug("collab: broadcastExcept push failed: {} (kind={s})", .{ err, @tagName(kind) });
            };
        }
    }

    fn sendTo(self: *CollabManager, conn_idx: usize, data: []const u8, kind: send_queue_mod.MessageKind) void {
        if (conn_idx >= self.connections.items.len) return;
        const conn = self.connections.items[conn_idx];
        conn.send_queue.push(data, .text, kind) catch |err| {
            std.log.debug("collab: sendTo push failed: {} (kind={s})", .{ err, @tagName(kind) });
        };
    }

    /// Per-peer write thread body. Owns `queue` and `stream` for its
    /// lifetime: blocks on `queue.pop()` (no manager-mutex acquire),
    /// writes the message outside any global lock, and exits when the
    /// queue is closed-and-drained. A slow socket here delays this
    /// peer alone — every other peer's write thread keeps draining its
    /// own queue. (Phase 5 HIGH-1 fix.)
    ///
    /// Stream-close safety: when the connection is torn down, the
    /// stream is closed AND the queue is closed in the same critical
    /// section (`handleDisconnect` / `stopNetworkingLocked`). The
    /// kernel returns an error on writes to a closed socket; we ignore
    /// it. A latent fd-reuse hazard exists in theory (close → reuse →
    /// stray write hits the new owner) — pre-existing in the pre-queue
    /// design, accepted for v1, will be eliminated by the Tier 2
    /// transport trait wrapping the stream in a refcounted handle.
    fn writeLoop(self: *CollabManager, queue: *SendQueue, stream: net.Stream, mask: bool) void {
        while (true) {
            const msg = queue.pop() orelse return;
            defer self.allocator.free(msg.data);
            ws.writeFrame(stream, msg.opcode, msg.data, mask) catch {};
        }
    }

    fn stopNetworking(self: *CollabManager) void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        self.stopNetworkingLocked();
    }

    fn stopNetworkingLocked(self: *CollabManager) void {
        const io = compat.io();
        self.running = false;

        // SHUTDOWN, don't close, while threads may still be using the fds.
        // `shutdown(.both)` interrupts pending reads/writes with EOF/error
        // but keeps the fd valid until we explicitly close it. In Zig 0.16
        // a read on a CLOSED fd panics in debug (BADF is treated as
        // programmer-bug — see std/Io/Threaded.zig:errnoBug). The read
        // thread, on seeing EOF, returns from `readFrame` cleanly and
        // exits its loop on `!self.running`.
        //
        // Queue close happens alongside so the write thread observes
        // "closed and empty" after its in-flight write fails.
        for (self.connections.items) |conn| {
            conn.stream.shutdown(io, .both) catch {};
            conn.send_queue.close();
        }

        // (Phase 5 panel: the previous code carried a `client_stream`
        // alias here pointing at connections[0].stream for guests;
        // dropped in favor of a single source of truth — see the
        // CollabManager field block comment above.)
        if (self.server) |*s| {
            s.deinit();
            self.server = null;
        }

        // Drop the mutex while joining threads — read/write threads do
        // NOT take the manager mutex on their hot paths, but `readLoop`
        // takes it briefly to fetch stream/index, so holding it during a
        // join could deadlock.
        self.mutex.unlock(io);
        if (self.accept_thread) |t| {
            t.join();
            self.accept_thread = null;
        }
        for (self.connections.items) |conn| {
            if (conn.read_thread) |t| t.join();
            if (conn.write_thread) |t| t.join();
        }
        self.mutex.lockUncancelable(io);

        // Now safe to close fds — no thread holds a stale reference.
        for (self.connections.items) |conn| {
            ws.closeStream(conn.stream);
            conn.send_queue.deinit();
        }
        self.connections.clearRetainingCapacity();

        // Panel #2 security HIGH-3: clear the per-session pubkey
        // cross-check map. Stale entries from a prior session must NOT
        // survive into the next session on the same manager — a peer-id
        // collision across sessions (unlikely, but the map would grow
        // monotonically without this) would leave a stale binding that
        // a new session never registers, and the manager's "each
        // session is independent" hygiene would be violated.
        // `clearRetainingCapacity` keeps the underlying buckets so we
        // don't pay realloc on the next createSession.
        self.peer_pubkeys.clearRetainingCapacity();
    }

    // =========================================================================
    // Internal: Push Events to JS
    // =========================================================================

    fn pushState(self: *CollabManager) void {
        const callback = self.push_callback orelse return;
        const json = self.crdt_doc.toModelJson() catch return;
        defer self.allocator.free(json);

        var buf = std.array_list.Managed(u8).init(self.allocator);
        defer buf.deinit();
        buf.appendSlice("{\"model\":") catch return;
        buf.appendSlice(json) catch return;
        buf.appendSlice("}") catch return;

        callback("collab:state", buf.items);
    }

    fn pushPeers(self: *CollabManager) void {
        const callback = self.push_callback orelse return;
        const json = self.getPeersJsonLocked() catch return;
        defer self.allocator.free(json);
        callback("collab:peers", json);
    }

    fn pushStatus(self: *CollabManager) void {
        const callback = self.push_callback orelse return;
        const json = self.session.toJson() catch return;
        defer self.allocator.free(json);
        callback("collab:status", json);
    }

    fn pushError(self: *CollabManager, message: []const u8) void {
        const callback = self.push_callback orelse return;
        // Use dynamic buffer with JSON escaping to handle messages containing "
        var buf: std.Io.Writer.Allocating = .init(self.allocator);
        defer buf.deinit();
        const w = &buf.writer;
        w.writeAll("{\"message\":\"") catch return;
        json_util.writeJsonEscaped(w, message) catch return;
        w.writeAll("\"}") catch return;
        callback("collab:error", buf.written());
    }

    fn getPeersJsonLocked(self: *CollabManager) ![]const u8 {
        var buf: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer buf.deinit();
        const w = &buf.writer;

        try w.writeAll("{\"peers\":[");
        for (self.session.peers.items, 0..) |p, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll("{\"id\":\"");
            try json_util.writeHex(w, &p.id);
            try w.writeAll("\",\"name\":\"");
            try json_util.writeJsonEscaped(w, p.name);
            try w.writeAll("\"}");
        }
        try w.writeAll("]}");

        return buf.toOwnedSlice();
    }
};

// =============================================================================
// LWW op_bytes peer_id extractor
//
// The unified-model channel routes inbound ops through the legacy
// `inbound_op_fn` callback (back-compat). That callback expects the
// peer_id to be passed alongside the value bytes. With the new wire
// envelope, peer_id is INSIDE the op_bytes (under the LWW format's
// `p` field), not on the envelope itself. This helper pulls it back
// out so the studio's per-peer fairness sub-quota keeps working.
//
// For future channels with their own bridges, this helper is unused
// (they receive `conn_peer_id` via the per-channel `on_remote_op`
// hook).
// =============================================================================

fn extractLwwPeerId(op_bytes: []const u8) ?[16]u8 {
    // Use a tiny stack allocator to JSON-parse just the `p` field.
    // FixedBufferAllocator with 1 KiB is enough for any well-formed op.
    var buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const aa = fba.allocator();

    var parsed = std.json.parseFromSlice(std.json.Value, aa, op_bytes, .{}) catch return null;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return null,
    };
    const p_val = obj.get("p") orelse return null;
    const p_hex = switch (p_val) {
        .string => |s| s,
        else => return null,
    };
    var peer_id: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&peer_id, p_hex) catch return null;
    return peer_id;
}

// =============================================================================
// URL Parsing Helper
// =============================================================================

const HostPort = struct {
    host: []const u8,
    port: u16,
};

fn parseWsUrl(url: []const u8) ?HostPort {
    // Parse ws://host:port or wss://host:port
    var rest = url;
    if (std.mem.startsWith(u8, rest, "ws://")) {
        rest = rest[5..];
    } else if (std.mem.startsWith(u8, rest, "wss://")) {
        rest = rest[6..];
    } else {
        return null;
    }

    // Remove trailing path
    if (std.mem.indexOf(u8, rest, "/")) |slash| {
        rest = rest[0..slash];
    }

    // Split host:port
    if (std.mem.lastIndexOf(u8, rest, ":")) |colon| {
        const host = rest[0..colon];
        const port_str = rest[colon + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
        return .{ .host = host, .port = port };
    }

    // No port specified — default 8080
    return .{ .host = rest, .port = 8080 };
}

// =============================================================================
// Tests
// =============================================================================

test "parseWsUrl: basic" {
    const r1 = parseWsUrl("ws://192.168.1.1:9090").?;
    try std.testing.expectEqualStrings("192.168.1.1", r1.host);
    try std.testing.expectEqual(@as(u16, 9090), r1.port);
}

test "parseWsUrl: default port" {
    const r = parseWsUrl("ws://localhost").?;
    try std.testing.expectEqualStrings("localhost", r.host);
    try std.testing.expectEqual(@as(u16, 8080), r.port);
}

test "parseWsUrl: with path" {
    const r = parseWsUrl("ws://relay.example.com:443/ws").?;
    try std.testing.expectEqualStrings("relay.example.com", r.host);
    try std.testing.expectEqual(@as(u16, 443), r.port);
}

test "parseWsUrl: wss scheme" {
    const r = parseWsUrl("wss://secure.relay.io:8443").?;
    try std.testing.expectEqualStrings("secure.relay.io", r.host);
    try std.testing.expectEqual(@as(u16, 8443), r.port);
}

test "parseWsUrl: invalid" {
    try std.testing.expect(parseWsUrl("http://example.com") == null);
    try std.testing.expect(parseWsUrl("not a url") == null);
}

test "CollabManager: init and deinit" {
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();

    try std.testing.expect(mgr.session.state == .idle);
}

test "CollabManager: host + guest replicate a mutation end-to-end" {
    // Smoke test for the per-peer send-queue + WS upgrade fix. Two
    // CollabManagers on loopback: host creates a session, guest joins,
    // host mutates, guest's CRDT converges. Polls with a generous
    // deadline because the read/write threads run asynchronously; the
    // upper bound was tuned to ~1 s of wall time on macOS-arm64 dev
    // hardware. A regression that reintroduces the WS upgrade hang or
    // breaks the queue plumbing would either deadlock (test timeout)
    // or leave `guest.crdt_doc.get` returning null (test failure).
    const allocator = std.testing.allocator;

    var host = CollabManager.init(allocator);
    defer host.deinit();
    try host.registerDefaultChannels();

    const room = try host.createSession("Host", 0, null, .aes_gcm_v1);
    const port = host.currentPort();
    try std.testing.expect(port != 0);

    var guest = CollabManager.init(allocator);
    defer guest.deinit();
    try guest.registerDefaultChannels();

    var url_buf: [64]u8 = undefined;
    const relay = try std.fmt.bufPrint(&url_buf, "ws://127.0.0.1:{d}", .{port});
    try guest.joinSession(room, relay, "Guest");

    // Wait for the guest's join to land on the host (peer count == 1)
    // AND the guest to receive welcome (crypto != null). Without the
    // second gate, host.mutate races the welcome arrival on the guest
    // side — a too-fast mutate broadcasts an encrypted op the guest
    // cannot decrypt (crypto null), bumping `inbound_missing_welcome`
    // and silently dropping the op. Closes design-panel C-1.
    var peer_attempts: u32 = 0;
    while (peer_attempts < 1000) : (peer_attempts += 1) {
        host.mutex.lockUncancelable(compat.io());
        const peer_count = host.session.peers.items.len;
        host.mutex.unlock(compat.io());
        if (peer_count >= 1) break;
        compat.sleepNs(5 * std.time.ns_per_ms);
    }
    // Gate the mutate on `guest.session.state == .connected` — sync
    // arrival is what transitions the guest to .connected (after
    // welcome installs crypto and snapshot loads). Polling only on
    // crypto != null was insufficient: that exits between welcome and
    // sync, and a too-fast mutate would broadcast an op that beat the
    // sync to the guest's processMessage. Closes design-panel C-1.
    var sync_attempts: u32 = 0;
    while (sync_attempts < 1000) : (sync_attempts += 1) {
        guest.mutex.lockUncancelable(compat.io());
        const is_connected = guest.session.state == .connected;
        guest.mutex.unlock(compat.io());
        if (is_connected) break;
        compat.sleepNs(5 * std.time.ns_per_ms);
    }
    try host.mutate("model.test.field", "fortytwo");

    // Poll guest CRDT for the value to appear. Generous deadline to
    // absorb scheduler jitter on busy CI hardware.
    var attempts: u32 = 0;
    var observed: ?[]const u8 = null;
    while (attempts < 1000) : (attempts += 1) {
        guest.mutex.lockUncancelable(compat.io());
        observed = guest.crdt_doc.get("model.test.field");
        guest.mutex.unlock(compat.io());
        if (observed != null) break;
        compat.sleepNs(5 * std.time.ns_per_ms);
    }

    try std.testing.expect(observed != null);
    try std.testing.expectEqualStrings("fortytwo", observed.?);

    // Tear down explicitly to exercise the close-stream + close-queue
    // ordering in `stopNetworkingLocked` under a real connection.
    guest.leaveSession();
    host.leaveSession();
}

test "CollabManager: host + guest replicate end-to-end under chacha-v1" {
    // A2 integration smoke: same flow as the AES-GCM test above, but
    // the host's locked suite is ChaCha20-Poly1305. Validates:
    //   - Joiner advertises [aes, chacha]; host's chacha lock wins.
    //   - Welcome carries `suite: "chacha-v1"`; guest inits crypto
    //     with the matching variant.
    //   - End-to-end op encrypt/decrypt round-trip works under ChaCha.
    // A regression that hardcoded AES anywhere in the encrypt/decrypt
    // dispatch would fail decryption on the guest side
    // (inbound_decrypt_failed bump + observed stays null).
    const allocator = std.testing.allocator;

    var host = CollabManager.init(allocator);
    defer host.deinit();
    try host.registerDefaultChannels();

    const room = try host.createSession("Host", 0, null, .chacha_v1);
    try std.testing.expectEqual(crypto_mod.Suite.chacha_v1, host.session.suite);
    const port = host.currentPort();
    try std.testing.expect(port != 0);

    var guest = CollabManager.init(allocator);
    defer guest.deinit();
    try guest.registerDefaultChannels();

    var url_buf: [64]u8 = undefined;
    const relay = try std.fmt.bufPrint(&url_buf, "ws://127.0.0.1:{d}", .{port});
    try guest.joinSession(room, relay, "Guest");

    var peer_attempts: u32 = 0;
    while (peer_attempts < 1000) : (peer_attempts += 1) {
        host.mutex.lockUncancelable(compat.io());
        const peer_count = host.session.peers.items.len;
        host.mutex.unlock(compat.io());
        if (peer_count >= 1) break;
        compat.sleepNs(5 * std.time.ns_per_ms);
    }
    var sync_attempts: u32 = 0;
    while (sync_attempts < 1000) : (sync_attempts += 1) {
        guest.mutex.lockUncancelable(compat.io());
        const is_connected = guest.session.state == .connected;
        guest.mutex.unlock(compat.io());
        if (is_connected) break;
        compat.sleepNs(5 * std.time.ns_per_ms);
    }

    // After welcome, the guest's session.suite MUST match the host's.
    guest.mutex.lockUncancelable(compat.io());
    const guest_suite = guest.session.suite;
    const guest_crypto_suite = if (guest.session.crypto) |c| c.suite else .aes_gcm_v1;
    guest.mutex.unlock(compat.io());
    try std.testing.expectEqual(crypto_mod.Suite.chacha_v1, guest_suite);
    try std.testing.expectEqual(crypto_mod.Suite.chacha_v1, guest_crypto_suite);

    try host.mutate("model.chacha.field", "noncearound");

    var attempts: u32 = 0;
    var observed: ?[]const u8 = null;
    while (attempts < 1000) : (attempts += 1) {
        guest.mutex.lockUncancelable(compat.io());
        observed = guest.crdt_doc.get("model.chacha.field");
        guest.mutex.unlock(compat.io());
        if (observed != null) break;
        compat.sleepNs(5 * std.time.ns_per_ms);
    }

    try std.testing.expect(observed != null);
    try std.testing.expectEqualStrings("noncearound", observed.?);

    guest.leaveSession();
    host.leaveSession();
}

// =============================================================================
// A1 panel-finding coverage tests
// =============================================================================

test "negotiateSuite: empty joiner_prefs → null" {
    // No advertised suites means no possible mutual; reject for ANY
    // host suite.
    try std.testing.expect(negotiateSuite(.aes_gcm_v1, &.{}) == null);
    try std.testing.expect(negotiateSuite(.chacha_v1, &.{}) == null);
}

test "negotiateSuite: joiner advertises only unknown suites → null" {
    const prefs = [_][]const u8{ "unknown-suite", "another-unknown" };
    try std.testing.expect(negotiateSuite(.aes_gcm_v1, &prefs) == null);
    try std.testing.expect(negotiateSuite(.chacha_v1, &prefs) == null);
}

test "negotiateSuite: A2 matrix — host=aes, joiner=[aes] → aes" {
    const prefs = [_][]const u8{SUITE_AES_GCM_V1};
    const got = negotiateSuite(.aes_gcm_v1, &prefs);
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings(SUITE_AES_GCM_V1, got.?);
}

test "negotiateSuite: A2 matrix — host=chacha, joiner=[chacha] → chacha" {
    const prefs = [_][]const u8{SUITE_CHACHA_V1};
    const got = negotiateSuite(.chacha_v1, &prefs);
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings(SUITE_CHACHA_V1, got.?);
}

test "negotiateSuite: A2 matrix — host=aes, joiner=[aes,chacha] → aes" {
    // Joiner supports both; host's locked suite (aes) wins. Order in
    // joiner_prefs is irrelevant to the result — host-locked policy.
    const prefs = [_][]const u8{ SUITE_AES_GCM_V1, SUITE_CHACHA_V1 };
    const got = negotiateSuite(.aes_gcm_v1, &prefs);
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings(SUITE_AES_GCM_V1, got.?);
}

test "negotiateSuite: A2 matrix — host=chacha, joiner=[aes,chacha] → chacha" {
    // Joiner supports both, listing AES first; host's chacha lock
    // still wins (host policy, not joiner preference).
    const prefs = [_][]const u8{ SUITE_AES_GCM_V1, SUITE_CHACHA_V1 };
    const got = negotiateSuite(.chacha_v1, &prefs);
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings(SUITE_CHACHA_V1, got.?);
}

test "negotiateSuite: A2 matrix — host=aes, joiner=[chacha] → null (no compat)" {
    // Joiner refuses AES (e.g. policy: ChaCha-only mobile); host
    // demands AES. No overlap → NoCompatibleSuite at the call site.
    const prefs = [_][]const u8{SUITE_CHACHA_V1};
    try std.testing.expect(negotiateSuite(.aes_gcm_v1, &prefs) == null);
}

test "negotiateSuite: A2 matrix — host=chacha, joiner=[aes] → null (no compat)" {
    // Inverse: host demands ChaCha (e.g. compliance policy); joiner
    // only advertises AES. Reject.
    const prefs = [_][]const u8{SUITE_AES_GCM_V1};
    try std.testing.expect(negotiateSuite(.chacha_v1, &prefs) == null);
}

test "negotiateSuite: ignores unknown suites mixed with valid ones" {
    // Joiner forwards a future suite (pq-hybrid-v1) we don't recognize;
    // we should still negotiate to a known one on the host side. The
    // unknown entries are silently skipped (decoder already rejects
    // structurally-bad ones via printable-ASCII guards).
    const prefs = [_][]const u8{ "future-pq", SUITE_AES_GCM_V1, "yet-another" };
    const got = negotiateSuite(.aes_gcm_v1, &prefs);
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings(SUITE_AES_GCM_V1, got.?);
}

test "isSupportedSuite: both A2 suites yes, unknown no" {
    try std.testing.expect(isSupportedSuite(SUITE_AES_GCM_V1));
    try std.testing.expect(isSupportedSuite(SUITE_CHACHA_V1));
    try std.testing.expect(!isSupportedSuite("pq-hybrid-v1"));
    try std.testing.expect(!isSupportedSuite("aes-gcm-v2"));
    try std.testing.expect(!isSupportedSuite(""));
}

test "JOINER_SUITE_PREFS: ordered AES-first then ChaCha" {
    // Documents the build's advertised pref order. The host's
    // policy-driven choice ignores order (Option 1), but a future
    // joiner-preference-wins refactor would key off this.
    try std.testing.expectEqual(@as(usize, 2), JOINER_SUITE_PREFS.len);
    try std.testing.expectEqualStrings(SUITE_AES_GCM_V1, JOINER_SUITE_PREFS[0]);
    try std.testing.expectEqualStrings(SUITE_CHACHA_V1, JOINER_SUITE_PREFS[1]);
}

test "Manager.mutate pre-welcome → error.MissingWelcome" {
    // Closes design-panel C-2: a guest with crypto=null must NOT be
    // able to emit plaintext via mutate. The broadcast helper refuses.
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    // Drive the session into a state that looks like "joiner pre-welcome":
    // .joining state, crypto null. We do this by directly manipulating
    // the session — joining a real socket would require a host.
    mgr.session.state = .joining;
    mgr.session.mode = .guest;
    mgr.session.crypto = null;
    @memcpy(&mgr.session.room_code, "TEST-1234");

    try std.testing.expectError(error.MissingWelcome, mgr.mutate("path", "value"));
}

test "Metrics: inbound_missing_welcome++ on pre-welcome op" {
    // Closes design-panel H-5 (partial — pre-welcome side). Construct a
    // pv:3 `op` envelope (ciphertext bytes are opaque to the manager)
    // and drive it through processMessage on a guest with crypto=null.
    // Assert metric increments and CRDT is untouched.
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    mgr.session.state = .joining;
    mgr.session.mode = .guest;
    mgr.session.crypto = null;
    @memcpy(&mgr.session.room_code, "TEST-1234");

    // Hand-craft an op envelope with arbitrary "ciphertext" — the
    // manager should drop on the welcome gate BEFORE attempting decrypt.
    // B1: sig + signer are wire-required but parsed-only-for-shape;
    // since this test stops at the pre-decrypt welcome gate, both can
    // be filler-zero values. They MUST decode to the exact byte count
    // the protocol parser expects (64 / 32).
    const fake_ct: [28]u8 = .{0} ** 28;
    const fake_sig: [identity_mod.SIG_LEN]u8 = .{0} ** identity_mod.SIG_LEN;
    const fake_signer: [identity_mod.PUBKEY_LEN]u8 = .{0} ** identity_mod.PUBKEY_LEN;
    const env = try protocol.encode(allocator, .{
        .op = .{
            .ch = "unified-model",
            .payload = &fake_ct,
            .sig = &fake_sig,
            .signer = &fake_signer,
        },
    });
    defer allocator.free(env);

    const before = mgr.metrics.inbound_missing_welcome;
    mgr.processMessage(env, 0);
    try std.testing.expectEqual(before + 1, mgr.metrics.inbound_missing_welcome);
}

test "Metrics: inbound_decrypt_failed++ on tampered ciphertext" {
    // Closes design-panel H-5 (decrypt-fail side). Set up a guest with
    // crypto initialized to a DIFFERENT key than the ciphertext was
    // encrypted with — every decrypt MUST fail tag verification.
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    // Guest with a known room key.
    mgr.session.state = .connected;
    mgr.session.mode = .guest;
    @memcpy(&mgr.session.room_code, "ABCD-1234");
    mgr.session.salt = [_]u8{0x11} ** 16;
    mgr.session.suite = .aes_gcm_v1;
    mgr.session.crypto = crypto_mod.CryptoContext.init(.aes_gcm_v1, &mgr.session.room_code, mgr.session.salt);

    // Encrypt with a DIFFERENT (wrong-room) key. The guest's decrypt
    // will fail tag verification.
    var wrong_room: [9]u8 = undefined;
    @memcpy(&wrong_room, "WRNG-9999");
    const wrong_salt = [_]u8{0x22} ** 16;
    var wrong_crypto = crypto_mod.CryptoContext.init(.aes_gcm_v1, &wrong_room, wrong_salt);
    defer wrong_crypto.deinit();

    const plaintext = "{\"path\":\"x\",\"v\":\"1\",\"ts\":1,\"p\":\"00000000000000000000000000000000\"}";
    const ct = try wrong_crypto.encrypt(allocator, plaintext, "unified-model");
    defer allocator.free(ct);

    // B1: sig + signer are required wire fields. Decrypt fails BEFORE
    // verify is even attempted (ordering in `.op` arm: decrypt → verify),
    // so filler-zero sig/signer are fine for this test.
    const fake_sig: [identity_mod.SIG_LEN]u8 = .{0} ** identity_mod.SIG_LEN;
    const fake_signer: [identity_mod.PUBKEY_LEN]u8 = .{0} ** identity_mod.PUBKEY_LEN;
    const env = try protocol.encode(allocator, .{
        .op = .{
            .ch = "unified-model",
            .payload = ct,
            .sig = &fake_sig,
            .signer = &fake_signer,
        },
    });
    defer allocator.free(env);

    const before = mgr.metrics.inbound_decrypt_failed;
    mgr.processMessage(env, 0);
    try std.testing.expectEqual(before + 1, mgr.metrics.inbound_decrypt_failed);
}

test "broadcastChannelOp: plaintext too large → OpPlaintextTooLarge" {
    // Closes system-arch panel M-1: plaintext cap is enforced BEFORE
    // encrypt, not on wire ciphertext. A plaintext op of
    // MAX_OP_PAYLOAD_BYTES bytes would encrypt to ciphertext exceeding
    // the wire cap by 28 bytes — must reject at the encrypt site.
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    // Host has crypto immediately; .joining is also live per existing mutate logic.
    try mgr.session.startHosting(0, "TEST-1234", .aes_gcm_v1);

    // Allocate a plaintext just over MAX_OP_PLAINTEXT_BYTES.
    const oversize = try allocator.alloc(u8, CollabManager.MAX_OP_PLAINTEXT_BYTES + 1);
    defer allocator.free(oversize);
    @memset(oversize, 'X');

    try std.testing.expectError(
        error.OpPlaintextTooLarge,
        mgr.broadcastChannelOp("unified-model", oversize),
    );
}

test "broadcastChannelOp: emitted envelope is ciphertext, not plaintext" {
    // Closes design-panel H-1: a refactor that bypassed `crypto.encrypt`
    // and shipped plaintext via base64 would silently pass round-trip
    // tests. This test inspects what `crypto.encrypt` produces directly
    // and asserts it differs from the plaintext + has the expected
    // length (plaintext + AEAD overhead).
    const allocator = std.testing.allocator;
    const salt = [_]u8{0x55} ** 16;
    var ctx = crypto_mod.CryptoContext.init(.aes_gcm_v1, "AAAA-1111", salt);
    defer ctx.deinit();

    const plaintext = "{\"path\":\"audit\",\"v\":\"42\",\"ts\":7,\"p\":\"aa\"}";
    const ct = try ctx.encrypt(allocator, plaintext, "unified-model");
    defer allocator.free(ct);

    // Length: nonce(12) + plaintext + tag(16).
    try std.testing.expectEqual(plaintext.len + crypto_mod.AEAD_OVERHEAD, ct.len);
    // Bytes differ from plaintext (would fail if encrypt was a no-op).
    try std.testing.expect(!std.mem.eql(u8, ct[12 .. 12 + plaintext.len], plaintext));
}

test "getMetricsSnapshot: returns value copy under mutex" {
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    // Bump a counter directly (no need to drive real traffic).
    mgr.metrics.inbound_missing_welcome = 3;
    const snap = mgr.getMetricsSnapshot();
    try std.testing.expectEqual(@as(usize, 3), snap.inbound_missing_welcome);

    // Mutating the snapshot must NOT affect the manager's metrics.
    var snap_mut = snap;
    snap_mut.inbound_missing_welcome = 99;
    try std.testing.expectEqual(@as(usize, 3), mgr.metrics.inbound_missing_welcome);
}

// =============================================================================
// B1: signed-op verify tests
// =============================================================================
//
// All three tests below drive `processMessage` synchronously on a guest
// manager whose crypto context has been hand-set to a known key. We then
// craft an envelope whose payload is encrypted with the SAME key the
// guest holds — so decrypt always succeeds. The verify outcome is what
// each test isolates.

/// Test helper: bring `mgr` into a "post-welcome guest" state with a
/// shared crypto context, so processMessage can decrypt without going
/// through the real handshake. The returned CryptoContext is the SAME
/// instance the manager holds — caller can use it to encrypt ciphertext
/// that the manager will successfully decrypt.
fn _b1TestSetupGuest(mgr: *CollabManager, room_code: []const u8, salt: [16]u8) void {
    mgr.session.state = .connected;
    mgr.session.mode = .guest;
    @memcpy(mgr.session.room_code[0..@min(room_code.len, mgr.session.room_code.len)], room_code[0..@min(room_code.len, mgr.session.room_code.len)]);
    mgr.session.salt = salt;
    mgr.session.suite = .aes_gcm_v1;
    mgr.session.crypto = crypto_mod.CryptoContext.init(.aes_gcm_v1, &mgr.session.room_code, salt);
}

test "B1: valid sig over valid plaintext → applyRemote + no drop" {
    // Round-trip: sign with one identity, send through wire, the
    // receiver's verify accepts AND applyRemote runs (CRDT state
    // changes — the strong assertion). Metric absence is necessary
    // but not sufficient: a buggy verify that returns true but skips
    // applyRemote would pass metric-only assertions.
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    const salt = [_]u8{0xAA} ** 16;
    _b1TestSetupGuest(&mgr, "TEST-1234", salt);

    var sender = identity_mod.Identity.generate();
    defer sender.deinit();

    // Use a real LWW op JSON shape (path/v/ts/p) so applyRemote
    // does something observable (CRDT state changes).
    const plaintext = "{\"path\":\"k\",\"v\":\"v1\",\"ts\":100,\"p\":\"01020304050607080910111213141516\"}";
    const sig = try sender.sign(plaintext);
    const signer = sender.publicKeyBytes();

    // Encrypt with the SAME context the manager will decrypt with.
    var enc_ctx = crypto_mod.CryptoContext.init(.aes_gcm_v1, &mgr.session.room_code, salt);
    defer enc_ctx.deinit();
    const ct = try enc_ctx.encrypt(allocator, plaintext, "unified-model");
    defer allocator.free(ct);

    const env = try protocol.encode(allocator, .{ .op = .{
        .ch = "unified-model",
        .payload = ct,
        .sig = &sig,
        .signer = &signer,
    } });
    defer allocator.free(env);

    // Pre-conditions.
    try std.testing.expect(mgr.crdt_doc.get("k") == null);
    const before_unsigned = mgr.metrics.inbound_unsigned_dropped;
    const before_decrypt = mgr.metrics.inbound_decrypt_failed;

    mgr.processMessage(env, 0);

    // No drop on either path.
    try std.testing.expectEqual(before_unsigned, mgr.metrics.inbound_unsigned_dropped);
    try std.testing.expectEqual(before_decrypt, mgr.metrics.inbound_decrypt_failed);

    // State actually mutated. Without this, a verify that "succeeds"
    // by accident (e.g. wrong path branched on, returns OK, applyRemote
    // never called) would still pass the metric assertions above.
    const v = mgr.crdt_doc.get("k") orelse return error.TestExpectedKeyPresent;
    try std.testing.expectEqualSlices(u8, "v1", v);
}

test "B1: forged sig (wrong signer) → inbound_unsigned_dropped++" {
    // Attacker forges an op claiming Alice's pubkey as signer but
    // signs with their OWN key. Manager decrypts (room key shared) but
    // verify fails because the signature was made by a different key
    // than the one in `signer`.
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    const salt = [_]u8{0xCC} ** 16;
    _b1TestSetupGuest(&mgr, "TEST-FORG", salt);

    var alice = identity_mod.Identity.generate();
    defer alice.deinit();
    var mallory = identity_mod.Identity.generate();
    defer mallory.deinit();

    const plaintext = "{\"path\":\"k\",\"v\":\"hostile\",\"ts\":200,\"p\":\"00000000000000000000000000000000\"}";
    // mallory signs.
    const sig = try mallory.sign(plaintext);
    // ... but the envelope claims alice as signer.
    const claimed_signer = alice.publicKeyBytes();

    var enc_ctx = crypto_mod.CryptoContext.init(.aes_gcm_v1, &mgr.session.room_code, salt);
    defer enc_ctx.deinit();
    const ct = try enc_ctx.encrypt(allocator, plaintext, "unified-model");
    defer allocator.free(ct);

    const env = try protocol.encode(allocator, .{ .op = .{
        .ch = "unified-model",
        .payload = ct,
        .sig = &sig,
        .signer = &claimed_signer,
    } });
    defer allocator.free(env);

    const before = mgr.metrics.inbound_unsigned_dropped;
    try std.testing.expect(mgr.crdt_doc.get("k") == null);

    mgr.processMessage(env, 0);

    try std.testing.expectEqual(before + 1, mgr.metrics.inbound_unsigned_dropped);
    // State did NOT mutate — the strong assertion. A regression that
    // forgets to early-return after the verify-fail metric increment
    // would let applyRemote run anyway; this catches it.
    try std.testing.expect(mgr.crdt_doc.get("k") == null);
}

test "B1: tampered sig bits → inbound_unsigned_dropped++" {
    // Valid signer pubkey but the signature itself was bit-flipped in
    // transit. Verify rejects; manager increments the unsigned-drop
    // counter (NOT inbound_decrypt_failed — decrypt succeeded; this
    // is an authenticity failure).
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    const salt = [_]u8{0xDD} ** 16;
    _b1TestSetupGuest(&mgr, "TEST-TAMP", salt);

    var alice = identity_mod.Identity.generate();
    defer alice.deinit();

    const plaintext = "{\"path\":\"k\",\"v\":\"vt\",\"ts\":300,\"p\":\"00000000000000000000000000000000\"}";
    var sig = try alice.sign(plaintext);
    // Bit-flip the first sig byte. Ed25519 sig verification rejects
    // any change to either the signature or message (constant-time
    // per the spec; our `verify` collapses to false).
    sig[0] ^= 0x01;
    const signer = alice.publicKeyBytes();

    var enc_ctx = crypto_mod.CryptoContext.init(.aes_gcm_v1, &mgr.session.room_code, salt);
    defer enc_ctx.deinit();
    const ct = try enc_ctx.encrypt(allocator, plaintext, "unified-model");
    defer allocator.free(ct);

    const env = try protocol.encode(allocator, .{ .op = .{
        .ch = "unified-model",
        .payload = ct,
        .sig = &sig,
        .signer = &signer,
    } });
    defer allocator.free(env);

    const before_unsigned = mgr.metrics.inbound_unsigned_dropped;
    const before_decrypt = mgr.metrics.inbound_decrypt_failed;
    try std.testing.expect(mgr.crdt_doc.get("k") == null);

    mgr.processMessage(env, 0);

    try std.testing.expectEqual(before_unsigned + 1, mgr.metrics.inbound_unsigned_dropped);
    // Decrypt path was clean — assert we didn't double-count.
    try std.testing.expectEqual(before_decrypt, mgr.metrics.inbound_decrypt_failed);
    // State did NOT mutate.
    try std.testing.expect(mgr.crdt_doc.get("k") == null);
}

test "B1: identity contract — sign/verify round-trip + stable pubkey" {
    // White-box: paired with the broadcast/processMessage round-trip
    // tests, this asserts the per-message contract the broadcast path
    // depends on: (a) `Identity.sign` produces a sig that `verify`
    // accepts with the same pubkey, (b) `publicKeyBytes()` is stable
    // across calls. Without (b), the host's advertised pubkey at join
    // time would drift from the pubkey used to sign later ops.
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();
    try mgr.session.startHosting(0, "TEST-OUT1", .aes_gcm_v1);

    const expected_pubkey = mgr.identity.publicKeyBytes();

    const plaintext = "{\"path\":\"a\",\"v\":\"b\",\"ts\":1,\"p\":\"00000000000000000000000000000000\"}";
    const sig = try mgr.identity.sign(plaintext);
    try std.testing.expect(identity_mod.verify(sig, plaintext, expected_pubkey));

    const pk2 = mgr.identity.publicKeyBytes();
    try std.testing.expectEqualSlices(u8, &expected_pubkey, &pk2);
}

test "B1: outbound .join carries local identity pubkey on the wire" {
    // Captured-envelope test (panel HIGH-COVERAGE #146). Re-encodes the
    // SAME pubkey path that `joinSession` uses to construct a .join
    // envelope, then decodes it and asserts the `pubkey` field is byte-
    // identical to the local identity's pubkey. Without this assertion,
    // a regression that drops the .join.pubkey field (or threads a
    // stale/zeroed copy) would silently produce a session where the
    // host cannot cross-check signed ops against an advertised key.
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    const local_pubkey = mgr.identity.publicKeyBytes();

    // Build a .join envelope exactly the way joinSession does.
    const peer_id = [_]u8{0x11} ** 16;
    const env = try protocol.encode(allocator, .{ .join = .{
        .room = "ROOM-TEST",
        .name = "Tester",
        .peer_id = peer_id,
        .suite_prefs = &.{protocol.SUITE_AES_GCM_V1},
        .pubkey = &local_pubkey,
    } });
    defer allocator.free(env);

    // Decode and assert the pubkey survived encode→decode unchanged.
    var dec = try protocol.decode(allocator, env);
    defer dec.deinit();
    switch (dec.msg) {
        .join => |j| {
            try std.testing.expect(j.pubkey.len == identity_mod.PUBKEY_LEN);
            try std.testing.expectEqualSlices(u8, &local_pubkey, j.pubkey);
        },
        else => return error.TestExpectedJoinEnvelope,
    }
}

test "B1: .ops mixed batch — forged + tampered entries dropped, valid kept" {
    // Panel HIGH-COVERAGE #145. The .ops arm filters forged/tampered
    // entries from the batch BEFORE applying them locally AND before
    // relaying. This test drives the verify path with a mixed batch
    // of [valid, forged-signer, valid, tampered-sig] and asserts that
    // ONLY the two valid entries mutate state, and the unsigned-drop
    // metric counts exactly 2 (one per forged entry).
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    const salt = [_]u8{0xEE} ** 16;
    _b1TestSetupGuest(&mgr, "TEST-MIX1", salt);

    var alice = identity_mod.Identity.generate();
    defer alice.deinit();
    var mallory = identity_mod.Identity.generate();
    defer mallory.deinit();

    var enc_ctx = crypto_mod.CryptoContext.init(.aes_gcm_v1, &mgr.session.room_code, salt);
    defer enc_ctx.deinit();

    // Entry 1: VALID. alice signs, alice claims, kept and applied.
    const pt1 = "{\"path\":\"k1\",\"v\":\"v1\",\"ts\":100,\"p\":\"01020304050607080910111213141516\"}";
    const sig1 = try alice.sign(pt1);
    const signer1 = alice.publicKeyBytes();
    const ct1 = try enc_ctx.encrypt(allocator, pt1, "unified-model");
    defer allocator.free(ct1);

    // Entry 2: FORGED. mallory signs but claims alice as signer.
    // verify fails because alice's pubkey can't verify mallory's sig.
    const pt2 = "{\"path\":\"k2\",\"v\":\"forged\",\"ts\":200,\"p\":\"00000000000000000000000000000000\"}";
    const sig2 = try mallory.sign(pt2);
    const signer2_claimed = alice.publicKeyBytes();
    const ct2 = try enc_ctx.encrypt(allocator, pt2, "unified-model");
    defer allocator.free(ct2);

    // Entry 3: VALID. alice signs, alice claims, kept and applied.
    const pt3 = "{\"path\":\"k3\",\"v\":\"v3\",\"ts\":300,\"p\":\"01020304050607080910111213141516\"}";
    const sig3 = try alice.sign(pt3);
    const signer3 = alice.publicKeyBytes();
    const ct3 = try enc_ctx.encrypt(allocator, pt3, "unified-model");
    defer allocator.free(ct3);

    // Entry 4: TAMPERED. alice signs, but a sig bit is flipped in
    // transit. verify fails.
    const pt4 = "{\"path\":\"k4\",\"v\":\"tampered\",\"ts\":400,\"p\":\"01020304050607080910111213141516\"}";
    var sig4 = try alice.sign(pt4);
    sig4[0] ^= 0x01;
    const signer4 = alice.publicKeyBytes();
    const ct4 = try enc_ctx.encrypt(allocator, pt4, "unified-model");
    defer allocator.free(ct4);

    const batch = [_]protocol.SignedOp{
        .{ .payload = ct1, .sig = &sig1, .signer = &signer1 },
        .{ .payload = ct2, .sig = &sig2, .signer = &signer2_claimed },
        .{ .payload = ct3, .sig = &sig3, .signer = &signer3 },
        .{ .payload = ct4, .sig = &sig4, .signer = &signer4 },
    };
    const env = try protocol.encode(allocator, .{ .ops = .{
        .ch = "unified-model",
        .batch = &batch,
    } });
    defer allocator.free(env);

    const before_dropped = mgr.metrics.inbound_unsigned_dropped;
    try std.testing.expect(mgr.crdt_doc.get("k1") == null);
    try std.testing.expect(mgr.crdt_doc.get("k2") == null);
    try std.testing.expect(mgr.crdt_doc.get("k3") == null);
    try std.testing.expect(mgr.crdt_doc.get("k4") == null);

    mgr.processMessage(env, 0);

    // Exactly two drops — one per forged/tampered entry.
    try std.testing.expectEqual(before_dropped + 2, mgr.metrics.inbound_unsigned_dropped);

    // VALID entries applied.
    const v1 = mgr.crdt_doc.get("k1") orelse return error.TestExpectedK1Present;
    try std.testing.expectEqualSlices(u8, "v1", v1);
    const v3 = mgr.crdt_doc.get("k3") orelse return error.TestExpectedK3Present;
    try std.testing.expectEqualSlices(u8, "v3", v3);

    // FORGED + TAMPERED entries did NOT mutate state.
    try std.testing.expect(mgr.crdt_doc.get("k2") == null);
    try std.testing.expect(mgr.crdt_doc.get("k4") == null);
}

test "B1: setIdentity rejected while session is non-idle" {
    // Panel HIGH #139: swapping the local identity mid-session would
    // invalidate the host's peer_pubkeys cross-check (the host stored
    // the OLD pubkey at .join time) AND the peer's advertised .join
    // pubkey for all already-established peers. Guard at the API
    // boundary with `error.SessionActive`.
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    // session.state == .idle → setIdentity must succeed (the supported
    // rotation case is between sessions, not during one).
    const rotated_a = identity_mod.Identity.generate();
    // No defer — ownership transfers into mgr on success; manager.deinit
    // will zero the secret material.
    try mgr.setIdentity(rotated_a);

    // Now flip session into a non-idle state (mirroring an active
    // session) and confirm setIdentity returns SessionActive.
    mgr.session.state = .connected;
    var rotated_b = identity_mod.Identity.generate();
    defer rotated_b.deinit(); // setIdentity will not take it; we own cleanup.
    try std.testing.expectError(error.SessionActive, mgr.setIdentity(rotated_b));

    // Reset state so mgr.deinit's normal teardown runs cleanly.
    mgr.session.state = .idle;
}

// =============================================================================
// B1 Panel #2: host-mode cross-check tests
// =============================================================================
//
// The B1 verify tests above all use `_b1TestSetupGuest` (mode=.guest), which
// SKIPS the host-side peer_pubkeys cross-check (gated on
// `session.mode == .host` in the .op/.ops arms). The cross-check itself —
// the second wall behind sig verify — was therefore untested. Panel #2
// (security, coverage) flagged this as a HIGH coverage gap. These tests
// drive the host-mode path directly.
//
// To avoid the cost of a real WebSocket handshake, the helper below builds
// a host-mode manager with hand-injected `Connection` slots backed by real
// `SendQueue` instances (in-memory ring buffers) and `undefined` net.Stream
// values. The cross-check + verify path returns BEFORE any stream I/O, so
// the undefined stream is never touched. The SendQueue is real so tests
// CAN observe the relay path's "did anything get enqueued?" question.

const HostTestConn = struct {
    queue: *SendQueue,
};

fn _b1TestSetupHost(
    mgr: *CollabManager,
    allocator: std.mem.Allocator,
    room_code: []const u8,
    salt: [16]u8,
    n_conns: usize,
) ![]HostTestConn {
    mgr.session.state = .connected;
    mgr.session.mode = .host;
    @memcpy(mgr.session.room_code[0..@min(room_code.len, mgr.session.room_code.len)], room_code[0..@min(room_code.len, mgr.session.room_code.len)]);
    mgr.session.salt = salt;
    mgr.session.suite = .aes_gcm_v1;
    mgr.session.crypto = crypto_mod.CryptoContext.init(.aes_gcm_v1, &mgr.session.room_code, salt);

    const conns = try allocator.alloc(HostTestConn, n_conns);
    errdefer allocator.free(conns);

    var i: usize = 0;
    while (i < n_conns) : (i += 1) {
        const q = try SendQueue.init(allocator, 32);
        errdefer q.deinit();
        conns[i] = .{ .queue = q };
        // peer_id starts zero — caller assigns after setup.
        try mgr.connections.append(.{
            .stream = undefined,
            .peer_id = std.mem.zeroes([16]u8),
            .read_thread = null,
            .send_queue = q,
            .write_thread = null,
            .mask = false,
        });
    }
    return conns;
}

fn _b1TestTeardownHost(mgr: *CollabManager, allocator: std.mem.Allocator, conns: []HostTestConn) void {
    // Clear connections list BEFORE deinit so the manager's stopNetworking
    // path doesn't try to shutdown the undefined streams. We own the
    // SendQueues we created via the helper.
    mgr.connections.clearRetainingCapacity();
    for (conns) |c| c.queue.deinit();
    allocator.free(conns);
    // Reset state so mgr.deinit's normal teardown runs cleanly.
    // SessionMode has no .idle variant (host|guest only); leaving the
    // mode set is harmless because deinit is mode-insensitive.
    mgr.session.state = .idle;
}

test "B1: host-mode .op with signer != advertised → dropped, no apply" {
    // Panel #2 HIGH (security + coverage): the host-side cross-check at
    // manager.zig (.op arm) compares `o.signer` against the pubkey the
    // peer advertised at .join time. A peer that claims to be Alice
    // (her peer_id in the connection slot, her pubkey signed) but sends
    // ops with Mallory's pubkey as `signer` MUST be dropped — this is
    // the second wall behind sig verify and was untested in panel #1's
    // closure.
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    const salt = [_]u8{0xA1} ** 16;
    const conns = try _b1TestSetupHost(&mgr, allocator, "TEST-HOSTMM", salt, 1);
    defer _b1TestTeardownHost(&mgr, allocator, conns);

    var alice = identity_mod.Identity.generate();
    defer alice.deinit();
    var mallory = identity_mod.Identity.generate();
    defer mallory.deinit();

    const alice_peer_id = [_]u8{0xAA} ** 16;
    mgr.connections.items[0].peer_id = alice_peer_id;
    try mgr.peer_pubkeys.put(alice_peer_id, alice.publicKeyBytes());

    // Mallory signs an op claiming Mallory's pubkey as signer, sent
    // from Alice's connection slot. Cross-check should drop.
    const plaintext = "{\"path\":\"k\",\"v\":\"hostile\",\"ts\":100,\"p\":\"01020304050607080910111213141516\"}";
    const sig = try mallory.sign(plaintext);
    const mallory_pk = mallory.publicKeyBytes();

    var enc_ctx = crypto_mod.CryptoContext.init(.aes_gcm_v1, &mgr.session.room_code, salt);
    defer enc_ctx.deinit();
    const ct = try enc_ctx.encrypt(allocator, plaintext, "unified-model");
    defer allocator.free(ct);

    const env = try protocol.encode(allocator, .{ .op = .{
        .ch = "unified-model",
        .payload = ct,
        .sig = &sig,
        .signer = &mallory_pk,
    } });
    defer allocator.free(env);

    const before = mgr.metrics.inbound_unsigned_dropped;
    try std.testing.expect(mgr.crdt_doc.get("k") == null);

    mgr.processMessage(env, 0);

    try std.testing.expectEqual(before + 1, mgr.metrics.inbound_unsigned_dropped);
    try std.testing.expect(mgr.crdt_doc.get("k") == null);
}

test "B1: host-mode .op from peer with no prior .join → dropped" {
    // Panel #2 HIGH: a connection that bypassed the join handshake
    // (no peer_pubkeys entry for its slot's peer_id) MUST be dropped
    // by the host cross-check, even if the signature itself is valid.
    // This forces the handshake; without the guard, an attacker could
    // open a raw socket and skip .join to bypass the pubkey-binding
    // gate entirely.
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    const salt = [_]u8{0xA2} ** 16;
    const conns = try _b1TestSetupHost(&mgr, allocator, "TEST-HOSTNJ", salt, 1);
    defer _b1TestTeardownHost(&mgr, allocator, conns);

    var alice = identity_mod.Identity.generate();
    defer alice.deinit();

    // Alice's peer_id is set on the connection slot, but we deliberately
    // do NOT call peer_pubkeys.put — modeling a peer that skipped .join.
    mgr.connections.items[0].peer_id = [_]u8{0xBB} ** 16;

    // Alice signs cleanly — the SIG verify would pass. The cross-check
    // is what must drop the op.
    const plaintext = "{\"path\":\"k\",\"v\":\"v1\",\"ts\":200,\"p\":\"01020304050607080910111213141516\"}";
    const sig = try alice.sign(plaintext);
    const alice_pk = alice.publicKeyBytes();

    var enc_ctx = crypto_mod.CryptoContext.init(.aes_gcm_v1, &mgr.session.room_code, salt);
    defer enc_ctx.deinit();
    const ct = try enc_ctx.encrypt(allocator, plaintext, "unified-model");
    defer allocator.free(ct);

    const env = try protocol.encode(allocator, .{ .op = .{
        .ch = "unified-model",
        .payload = ct,
        .sig = &sig,
        .signer = &alice_pk,
    } });
    defer allocator.free(env);

    const before = mgr.metrics.inbound_unsigned_dropped;
    mgr.processMessage(env, 0);

    try std.testing.expectEqual(before + 1, mgr.metrics.inbound_unsigned_dropped);
    try std.testing.expect(mgr.crdt_doc.get("k") == null);
}

test "B1: host-mode .ops all-forged batch — no relay (no amplification)" {
    // Panel #2 HIGH-COVERAGE: the .ops arm's filter-forged-relay logic
    // has three branches: fast (all verified), slow (subset re-encode),
    // and no-relay (all forged). The mixed-batch test covers fast +
    // slow; this test covers the no-relay branch — the host MUST NOT
    // re-broadcast even an empty .ops envelope. Otherwise a hostile
    // peer gets a "megaphone" via the host's relay machinery (bandwidth
    // amplification, even if no state mutates).
    //
    // Setup: 2 connections (Alice = sender, Bob = relay target). Alice
    // sends an all-forged batch. Assert: Bob's send queue stays empty
    // AND the unsigned-drop metric increments by exactly batch.len.
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    const salt = [_]u8{0xA3} ** 16;
    const conns = try _b1TestSetupHost(&mgr, allocator, "TEST-HOSTNR", salt, 2);
    defer _b1TestTeardownHost(&mgr, allocator, conns);

    var alice = identity_mod.Identity.generate();
    defer alice.deinit();
    var mallory = identity_mod.Identity.generate();
    defer mallory.deinit();
    var bob = identity_mod.Identity.generate();
    defer bob.deinit();

    const alice_peer_id = [_]u8{0xA1} ** 16;
    const bob_peer_id = [_]u8{0xB1} ** 16;
    mgr.connections.items[0].peer_id = alice_peer_id;
    mgr.connections.items[1].peer_id = bob_peer_id;
    try mgr.peer_pubkeys.put(alice_peer_id, alice.publicKeyBytes());
    try mgr.peer_pubkeys.put(bob_peer_id, bob.publicKeyBytes());

    var enc_ctx = crypto_mod.CryptoContext.init(.aes_gcm_v1, &mgr.session.room_code, salt);
    defer enc_ctx.deinit();

    // Two forged entries: Mallory signs, claims Alice as signer. The
    // host cross-check should drop on signer-mismatch (signer == Alice
    // pubkey claimed, but the connection's peer_id is Alice's — the
    // signer matches the advertised pubkey, so cross-check passes;
    // then sig verify fails because Mallory signed, not Alice).
    //
    // Wait — that's not what we want. We need entries that pass
    // cross-check (signer == advertised) but FAIL verify. So:
    //   - signer field = Alice's pubkey (matches what peer_pubkeys says)
    //   - sig = Mallory signed
    //   - This is the classic "forged sig with claimed signer" attack.
    const pt1 = "{\"path\":\"k1\",\"v\":\"forg1\",\"ts\":100,\"p\":\"01020304050607080910111213141516\"}";
    const sig1 = try mallory.sign(pt1);
    const ct1 = try enc_ctx.encrypt(allocator, pt1, "unified-model");
    defer allocator.free(ct1);

    const pt2 = "{\"path\":\"k2\",\"v\":\"forg2\",\"ts\":200,\"p\":\"01020304050607080910111213141516\"}";
    const sig2 = try mallory.sign(pt2);
    const ct2 = try enc_ctx.encrypt(allocator, pt2, "unified-model");
    defer allocator.free(ct2);

    const alice_pk = alice.publicKeyBytes();
    const batch = [_]protocol.SignedOp{
        .{ .payload = ct1, .sig = &sig1, .signer = &alice_pk },
        .{ .payload = ct2, .sig = &sig2, .signer = &alice_pk },
    };
    const env = try protocol.encode(allocator, .{ .ops = .{
        .ch = "unified-model",
        .batch = &batch,
    } });
    defer allocator.free(env);

    const before = mgr.metrics.inbound_unsigned_dropped;

    // Arrived from Alice's connection (idx 0).
    mgr.processMessage(env, 0);

    // Both entries dropped (verify failed for each).
    try std.testing.expectEqual(before + 2, mgr.metrics.inbound_unsigned_dropped);
    // No state mutated.
    try std.testing.expect(mgr.crdt_doc.get("k1") == null);
    try std.testing.expect(mgr.crdt_doc.get("k2") == null);
    // STRONG ASSERTION: Bob's send queue is empty. Without the no-relay
    // branch, the host would have re-broadcast the original (forged)
    // envelope OR an empty subset envelope; either way Bob's queue
    // would have an entry. The verified_for_relay.items.len == 0 branch
    // (the implicit else at the end of the .ops arm) is what ensures
    // this. A regression that falls through to broadcastExcept of an
    // empty subset would still enqueue a frame here.
    try std.testing.expectEqual(@as(usize, 0), conns[1].queue.count);
}

test "B1: host-mode duplicate .join with different pubkey on live slot → refused" {
    // Panel #2 security HIGH: peer-id hijack guard. If a hostile peer
    // tries to re-join with the same peer_id but a different pubkey
    // while the original slot is still alive, the host MUST refuse
    // (NOT overwrite peer_pubkeys). Otherwise the hostile peer's
    // subsequent signed ops would pass the cross-check (their pubkey
    // is in the map) and would be relayed to other peers as if
    // authored by the original peer.
    const allocator = std.testing.allocator;
    var mgr = CollabManager.init(allocator);
    defer mgr.deinit();
    try mgr.registerDefaultChannels();

    const salt = [_]u8{0xA4} ** 16;
    const conns = try _b1TestSetupHost(&mgr, allocator, "TEST-HOSTDJ", salt, 2);
    defer _b1TestTeardownHost(&mgr, allocator, conns);

    var alice = identity_mod.Identity.generate();
    defer alice.deinit();
    var mallory = identity_mod.Identity.generate();
    defer mallory.deinit();

    const alice_peer_id = [_]u8{0xCC} ** 16;

    // Alice is connected on slot 0 with her pubkey registered.
    mgr.connections.items[0].peer_id = alice_peer_id;
    try mgr.peer_pubkeys.put(alice_peer_id, alice.publicKeyBytes());
    // Alice in session.peers too (so the relayed-join check stays sane).
    try mgr.session.addPeer(alice_peer_id, "Alice");

    // Mallory's hostile join: SAME peer_id, Mallory's pubkey. The
    // attacker uses slot 1 (still live for the host).
    const mallory_pk = mallory.publicKeyBytes();
    const env = try protocol.encode(allocator, .{ .join = .{
        .room = "TEST-HOSTDJ",
        .name = "MalloryAsAlice",
        .peer_id = alice_peer_id,
        .suite_prefs = &.{protocol.SUITE_AES_GCM_V1},
        .pubkey = &mallory_pk,
    } });
    defer allocator.free(env);

    mgr.processMessage(env, 1);

    // peer_pubkeys[alice_peer_id] MUST still be Alice's pubkey. The
    // hostile join was refused, not allowed-to-overwrite.
    const stored = mgr.peer_pubkeys.get(alice_peer_id) orelse {
        return error.TestExpectedAlicePubkeyStillPresent;
    };
    try std.testing.expectEqualSlices(u8, &alice.publicKeyBytes(), &stored);

    // Slot 1's peer_id was reset to zero by the refuse-overwrite path
    // (matches the convention from the put-OOM rollback).
    try std.testing.expectEqualSlices(
        u8,
        &std.mem.zeroes([16]u8),
        &mgr.connections.items[1].peer_id,
    );
}
