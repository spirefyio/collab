//! Collaboration Session State Machine
//!
//!          create()          peer connects
//! IDLE ──────────► HOSTING ──────────────► CONNECTED
//!   │                                        │
//!   │   join(code)                           │ all peers leave
//!   └──────────► JOINING ──► CONNECTED ──────┘
//!                   │            │           │
//!                   │ error      │ leave()   │ error
//!                   └──► IDLE ◄──┘───────────┘

const std = @import("std");
const compat = @import("compat");
const crypto_mod = @import("crypto.zig");
const protocol = @import("protocol.zig");
const json_util = @import("util_json");

pub const SessionState = enum {
    idle,
    hosting,
    joining,
    connected,
};

pub const SessionMode = enum {
    host, // This peer started the session (running embedded relay)
    guest, // This peer joined an existing session
};

pub const Peer = struct {
    id: [16]u8,
    name: []const u8,
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    state: SessionState,
    mode: SessionMode,
    room_code: [9]u8,
    salt: [16]u8,
    /// CryptoContext for AEAD encrypt/decrypt of channel-routed messages.
    ///
    /// Invariants (pv:3):
    ///   - host mode: non-null after `startHosting` returns (HKDF over
    ///     fresh salt; key derived once per session, under the host's
    ///     locked suite).
    ///   - guest mode: null after `startJoining`; non-null after
    ///     `applyWelcome` succeeds with the host-supplied salt + suite.
    ///   - idle / error: null (cleared by `leaveWithReason` / `setError`,
    ///     which also secureZero the key material via `crypto.deinit`).
    ///
    /// The MissingWelcome gate in `manager.zig` `.op` / `.ops` / `.sync`
    /// arms is load-bearing: any null crypto observed during inbound
    /// channel-routed traffic MUST drop the frame and never expose
    /// plaintext. The companion broadcast path (`broadcastChannelOp`
    /// etc.) returns `error.MissingWelcome` if called with null crypto —
    /// belt-and-suspenders against a future caller that bypasses the
    /// session-state guard.
    crypto: ?crypto_mod.CryptoContext,
    /// Host-locked AEAD suite for this session (A2+). On hosts: set at
    /// `startHosting` time and embedded in every welcome envelope; the
    /// host's `CryptoContext` is initialized to this suite immediately.
    /// On guests: set when `applyWelcome` lands the host's chosen suite.
    /// Defaults to `.aes_gcm_v1` in `.idle` for completeness; the field
    /// is only load-bearing when `crypto != null`.
    suite: crypto_mod.Suite,
    peers: std.array_list.Managed(Peer),
    local_peer_id: [16]u8,
    local_name: []const u8,
    /// True iff `local_name` was duped via `allocator` (i.e. set via
    /// `setLocalName`). False when `local_name` still points at the static
    /// "Anonymous" literal from `init`. Tracking this lets `deinit`/`leave`
    /// free the dupe without trying to free a string literal.
    local_name_owned: bool,
    relay_url: []const u8,
    error_msg: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator) Session {
        var local_peer_id: [16]u8 = undefined;
        compat.io().random(&local_peer_id);

        return .{
            .allocator = allocator,
            .state = .idle,
            .mode = .host,
            .room_code = std.mem.zeroes([9]u8),
            .salt = std.mem.zeroes([16]u8),
            .crypto = null,
            .suite = .aes_gcm_v1,
            .peers = std.array_list.Managed(Peer).init(allocator),
            .local_peer_id = local_peer_id,
            .local_name = "Anonymous",
            .local_name_owned = false,
            .relay_url = "",
            .error_msg = null,
        };
    }

    pub fn deinit(self: *Session) void {
        self.clearPeers();
        self.peers.deinit();
        if (self.crypto) |*c| c.deinit();
        // Security panel M-2: zero salt + room_code on teardown. Combined
        // with `CryptoContext.deinit`'s `secureZero` on the key, a memory
        // dump after session end yields no usable key material.
        std.crypto.secureZero(u8, &self.salt);
        std.crypto.secureZero(u8, &self.room_code);
        self.freeError();
        self.freeLocalName();
        if (self.relay_url.len > 0) {
            self.allocator.free(self.relay_url);
        }
    }

    /// Max display-name length (bytes). Phase 5 panel security H-4:
    /// the peer-supplied name is duped on every host's `addPeer`, so
    /// without a cap a malicious peer could submit a 10 MB name and
    /// force the host to allocate ~10 MB × (peers-1) for the relay
    /// broadcast. 64 bytes is comfortably more than any sane human
    /// display name and well below the WS upgrade Sec-WebSocket-Key
    /// cap of 256.
    pub const MAX_NAME_LEN: usize = 64;

    /// Replace the local peer's display name. Frees the previously-owned
    /// name (if any) and takes ownership of a fresh dupe. Safe to call
    /// multiple times across host/join/leave cycles. Returns
    /// `error.NameTooLong` if `name.len > MAX_NAME_LEN` — see the
    /// constant's doc for the rationale.
    pub fn setLocalName(self: *Session, name: []const u8) !void {
        if (name.len > MAX_NAME_LEN) return error.NameTooLong;
        const owned = try self.allocator.dupe(u8, name);
        self.freeLocalName();
        self.local_name = owned;
        self.local_name_owned = true;
    }

    fn freeLocalName(self: *Session) void {
        if (self.local_name_owned) {
            self.allocator.free(self.local_name);
            self.local_name_owned = false;
        }
        self.local_name = "Anonymous";
    }

    /// Generator alphabet — the subset `generateRoomCode` emits when picking
    /// random characters. Excludes the visually-ambiguous glyphs (0/O/1/I)
    /// so an auto-generated code is unambiguous when read aloud or typed.
    /// This is a GENERATION concern, not a validation concern: when a user
    /// types `TEAM-2026` they know what they meant, even though it contains
    /// `0`. See `isValidRoomCode` for the validator alphabet (broader).
    pub const ROOM_CODE_GEN_CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    /// Validation alphabet — what a CUSTOM room code is allowed to contain.
    /// Any uppercase ASCII alphanumeric, with the dash anchored at index 4.
    /// Phase 5 panel security H-2: the original threat is that
    /// `startHosting` accepted ANY 9-byte slice, letting a caller smuggle
    /// control characters, NULs, or whitespace into the canonical
    /// `[9]u8` buffer that flows back into log lines, `toJson` output,
    /// and the HKDF key derivation. The relaxed alphabet (A-Z + 0-9 + dash
    /// at idx 4) still blocks every one of those byte classes while
    /// preserving the UX where a human types a memorable code like
    /// `TEAM-2026` and it just works. The visually-ambiguous-character
    /// exclusion (no 0/O/1/I) belongs to the GENERATOR (humans benefit
    /// when codes WE invent are unambiguous) but not to the VALIDATOR
    /// (humans typing their own code are explicit about what they meant).
    /// `startJoining` deliberately does NOT use this — a joining peer
    /// round-trips whatever bytes the host put on the wire and has no
    /// business second-guessing the host's choice; lenient parsing on
    /// receive, strict construction on send.
    pub fn isValidRoomCode(code: []const u8) bool {
        if (code.len != 9) return false;
        if (code[4] != '-') return false;
        for (code, 0..) |c, i| {
            if (i == 4) continue;
            const is_upper = c >= 'A' and c <= 'Z';
            const is_digit = c >= '0' and c <= '9';
            if (!is_upper and !is_digit) return false;
        }
        return true;
    }

    /// Transition to hosting state. If `requested_code` is provided and is
    /// a well-formed room code (see `isValidRoomCode`), it becomes the
    /// canonical room code; otherwise a fresh one is generated. The 9-byte
    /// length + charset matches the codec used by `startJoining` (XXXX-XXXX,
    /// dash at index 4) so any code accepted here can round-trip on the wire.
    ///
    /// `suite` selects the AEAD primitive for this hosting session. The
    /// host advertises this single suite in every welcome envelope; a
    /// joiner whose `suite_prefs` doesn't include it is rejected with
    /// `NoCompatibleSuite`. Default: `.aes_gcm_v1` (A2 back-compat with A1
    /// peers). Set to `.chacha_v1` for ChaCha-only environments (older
    /// mobile without AES-NI, constant-time policy requirements).
    pub fn startHosting(
        self: *Session,
        port: u16,
        requested_code: ?[]const u8,
        suite: crypto_mod.Suite,
    ) !void {
        if (self.state != .idle) return error.InvalidStateTransition;

        if (requested_code) |code| {
            if (!isValidRoomCode(code)) return error.InvalidRoomCode;
            @memcpy(&self.room_code, code[0..9]);
        } else {
            self.room_code = crypto_mod.generateRoomCode();
        }
        self.salt = crypto_mod.generateSalt();
        self.suite = suite;
        self.crypto = crypto_mod.CryptoContext.init(suite, &self.room_code, self.salt);
        self.mode = .host;
        self.state = .hosting;

        // Generate relay URL from local IP
        var url_buf: [64]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, "ws://0.0.0.0:{d}", .{port}) catch return error.InternalError;
        if (self.relay_url.len > 0) self.allocator.free(self.relay_url);
        self.relay_url = try self.allocator.dupe(u8, url);

        std.log.info(
            "collab: Hosting session, room={s} port={d} suite={s}",
            .{ self.room_code, port, suite.toName() },
        );
    }

    /// Transition to joining state.
    ///
    /// Under pv:3 the joiner does NOT init crypto here — the salt isn't
    /// known until the host sends `welcome` back. `crypto` stays null
    /// until `applyWelcome(salt, suite)` lands. Until then the manager
    /// layer drops any inbound `op`/`ops`/`sync` with `MissingWelcome`.
    pub fn startJoining(self: *Session, room_code: []const u8, relay_url: []const u8) !void {
        if (self.state != .idle) return error.InvalidStateTransition;

        if (room_code.len != 9) return error.InvalidRoomCode;
        @memcpy(&self.room_code, room_code[0..9]);
        // Salt is zero placeholder until welcome arrives. `crypto` stays
        // null — do NOT derive a key from the zero salt (pre-pv:3 the
        // code did, which silently produced a key the host couldn't
        // match anyway). The MissingWelcome gate in the manager layer
        // is the load-bearing check.
        self.salt = std.mem.zeroes([16]u8);
        self.crypto = null;
        self.mode = .guest;
        self.state = .joining;

        if (self.relay_url.len > 0) self.allocator.free(self.relay_url);
        self.relay_url = try self.allocator.dupe(u8, relay_url);

        std.log.info("collab: Joining session, room={s} relay={s} (awaiting welcome)", .{ self.room_code, relay_url });
    }

    /// Install the host-provided session salt + suite and initialize the
    /// `CryptoContext`. Called by the manager layer when the inbound
    /// `welcome` envelope arrives. Idempotent on success: a second
    /// welcome with the same (salt, suite) is a no-op. A welcome arriving
    /// with a DIFFERENT salt OR suite after one has already been applied
    /// is rejected (`error.WelcomeAlreadyApplied`) because re-keying or
    /// re-suiting mid-session would silently break message authenticity.
    ///
    /// Only valid in `.joining` (or `.connected`, idempotent) state on
    /// the guest side. Hosts already have crypto at `startHosting`.
    pub fn applyWelcome(self: *Session, salt: [16]u8, suite: crypto_mod.Suite) !void {
        if (self.mode != .guest) return error.InvalidStateTransition;
        if (self.state != .joining and self.state != .connected) {
            return error.InvalidStateTransition;
        }

        if (self.crypto != null) {
            // Idempotency: identical (salt, suite) → silently accept
            // (host re-send). Any drift is a re-key attempt and rejected.
            if (std.mem.eql(u8, &self.salt, &salt) and self.suite == suite) return;
            return error.WelcomeAlreadyApplied;
        }

        self.salt = salt;
        self.suite = suite;
        self.crypto = crypto_mod.CryptoContext.init(suite, &self.room_code, self.salt);
        std.log.info(
            "collab: applied welcome (salt + suite={s} installed, crypto initialized)",
            .{suite.toName()},
        );
    }

    /// Transition to connected state (peer successfully joined or was joined by a peer).
    pub fn setConnected(self: *Session) void {
        if (self.state == .hosting or self.state == .joining) {
            self.state = .connected;
            std.log.info("collab: Session connected ({d} peers)", .{self.peers.items.len});
        }
    }

    /// Add a peer to the session. Phase 5 panel security H-4 (inbound):
    /// the wire-supplied `name` is duped here on every host. Without a cap
    /// a hostile peer could submit a multi-megabyte display name and pin
    /// that allocation across every host in the room. The same
    /// `MAX_NAME_LEN` ceiling that `setLocalName` enforces on outbound also
    /// applies inbound — over-cap names are rejected at this boundary so
    /// the caller (manager.zig handshake handler) can log + drop the
    /// connection rather than silently truncating identity.
    pub fn addPeer(self: *Session, id: [16]u8, name: []const u8) !void {
        if (name.len > MAX_NAME_LEN) return error.NameTooLong;

        // Don't add ourselves
        if (std.mem.eql(u8, &id, &self.local_peer_id)) return;

        // Don't add duplicates
        for (self.peers.items) |p| {
            if (std.mem.eql(u8, &p.id, &id)) return;
        }

        const owned_name = try self.allocator.dupe(u8, name);
        try self.peers.append(.{ .id = id, .name = owned_name });

        // Transition to connected if we were hosting/joining
        if (self.state == .hosting or self.state == .joining) {
            self.state = .connected;
        }

        std.log.info("collab: Peer joined: {s} ({d} total)", .{ name, self.peers.items.len });
    }

    /// Remove a peer from the session.
    pub fn removePeer(self: *Session, id: [16]u8) void {
        for (self.peers.items, 0..) |p, i| {
            if (std.mem.eql(u8, &p.id, &id)) {
                self.allocator.free(p.name);
                _ = self.peers.swapRemove(i);
                std.log.info("collab: Peer left ({d} remaining)", .{self.peers.items.len});

                // If all peers left and we were connected, go back to hosting/idle
                if (self.peers.items.len == 0 and self.state == .connected) {
                    self.state = if (self.mode == .host) .hosting else .idle;
                }
                return;
            }
        }
    }

    /// Leave the session and return to idle. `reason` is used only for
    /// the log line so an involuntary teardown (host dropped, network
    /// died) doesn't get logged as if the local user clicked Leave —
    /// the smoke test surfaced this as "I did NOT leave the session"
    /// confusion after a host crash auto-reset the joiner.
    pub fn leave(self: *Session) void {
        self.leaveWithReason(.user_request);
    }

    pub const LeaveReason = enum {
        user_request, // explicit Leave click / collab.leave bridge call
        host_disconnected, // peer connection died — guest auto-recovery
        host_shutdown, // local app is exiting (e.g. CollabManager.deinit)
    };

    pub fn leaveWithReason(self: *Session, reason: LeaveReason) void {
        self.clearPeers();
        if (self.crypto) |*c| c.deinit();
        self.crypto = null;
        // Security panel M-2: zero key-derivation inputs alongside the
        // key material itself. A memory dump post-leave should not yield
        // a usable (room_code, salt) → key pair.
        std.crypto.secureZero(u8, &self.salt);
        std.crypto.secureZero(u8, &self.room_code);
        if (self.relay_url.len > 0) {
            self.allocator.free(self.relay_url);
            self.relay_url = "";
        }
        self.freeLocalName();
        self.state = .idle;
        self.freeError();
        const msg = switch (reason) {
            .user_request => "collab: Left session (user request)",
            .host_disconnected => "collab: Host connection lost; session ended (not user-initiated)",
            .host_shutdown => "collab: Session ended (app shutting down)",
        };
        std.log.info("{s}", .{msg});
    }

    /// Set error state and return to idle.
    pub fn setError(self: *Session, msg: []const u8) void {
        self.freeError();
        self.error_msg = self.allocator.dupe(u8, msg) catch null;
        self.clearPeers();
        if (self.crypto) |*c| c.deinit();
        self.crypto = null;
        // Security panel M-2: zero salt + room_code parallel to crypto.deinit.
        std.crypto.secureZero(u8, &self.salt);
        std.crypto.secureZero(u8, &self.room_code);
        self.state = .idle;
        std.log.warn("collab: Session error: {s}", .{msg});
    }

    /// Get session info as JSON. Caller owns returned memory.
    pub fn toJson(self: *const Session) ![]const u8 {
        var buf: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer buf.deinit();
        const w = &buf.writer;

        try w.writeAll("{\"state\":\"");
        try w.writeAll(@tagName(self.state));
        try w.writeAll("\",\"mode\":\"");
        try w.writeAll(@tagName(self.mode));
        try w.writeAll("\",\"room\":\"");
        if (self.state != .idle) {
            try w.writeAll(&self.room_code);
        }
        try w.writeAll("\",\"relay\":\"");
        try writeEscaped(w, self.relay_url);
        try w.writeAll("\",\"peer_count\":");
        try w.print("{d}", .{self.peers.items.len});
        try w.writeAll(",\"peers\":[");
        for (self.peers.items, 0..) |p, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll("{\"id\":\"");
            try writeHex(w, &p.id);
            try w.writeAll("\",\"name\":\"");
            try writeEscaped(w, p.name);
            try w.writeAll("\"}");
        }
        try w.writeAll("]");
        if (self.error_msg) |err| {
            try w.writeAll(",\"error\":\"");
            try writeEscaped(w, err);
            try w.writeByte('"');
        }
        try w.writeByte('}');

        return buf.toOwnedSlice();
    }

    fn clearPeers(self: *Session) void {
        for (self.peers.items) |p| {
            self.allocator.free(p.name);
        }
        self.peers.clearRetainingCapacity();
    }

    fn freeError(self: *Session) void {
        if (self.error_msg) |msg| {
            self.allocator.free(msg);
            self.error_msg = null;
        }
    }
};

const writeEscaped = json_util.writeJsonEscaped;
const writeHex = json_util.writeHex;

// =============================================================================
// Tests
// =============================================================================

test "Session: lifecycle idle → hosting → connected → idle" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try std.testing.expect(session.state == .idle);

    try session.startHosting(8080, null, .aes_gcm_v1);
    try std.testing.expect(session.state == .hosting);
    try std.testing.expect(session.room_code[4] == '-');
    try std.testing.expect(session.crypto != null);

    // Peer joins
    try session.addPeer([_]u8{0xAA} ** 16, "Alice");
    try std.testing.expect(session.state == .connected);
    try std.testing.expectEqual(@as(usize, 1), session.peers.items.len);

    // Peer leaves
    session.removePeer([_]u8{0xAA} ** 16);
    try std.testing.expectEqual(@as(usize, 0), session.peers.items.len);
    try std.testing.expect(session.state == .hosting); // back to hosting

    session.leave();
    try std.testing.expect(session.state == .idle);
}

test "Session: joining flow (crypto null until welcome)" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.startJoining("ABCD-1234", "ws://192.168.1.1:8080");
    try std.testing.expect(session.state == .joining);
    try std.testing.expect(session.mode == .guest);
    // pv:3 invariant: crypto is null until welcome arrives.
    try std.testing.expect(session.crypto == null);

    // Apply welcome installs the salt + initializes crypto.
    const salt = [_]u8{0x42} ** 16;
    try session.applyWelcome(salt, .aes_gcm_v1);
    try std.testing.expect(session.crypto != null);
    try std.testing.expectEqual(crypto_mod.Suite.aes_gcm_v1, session.suite);

    session.setConnected();
    try std.testing.expect(session.state == .connected);
}

test "Session: applyWelcome idempotent on identical salt+suite" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.startJoining("ABCD-1234", "ws://1.2.3.4:8080");
    const salt = [_]u8{0x77} ** 16;
    try session.applyWelcome(salt, .chacha_v1);
    // Second call with same (salt, suite) → no-op success, no crypto re-init.
    try session.applyWelcome(salt, .chacha_v1);
    try std.testing.expect(session.crypto != null);
    try std.testing.expectEqual(crypto_mod.Suite.chacha_v1, session.suite);
}

test "Session: applyWelcome rejects re-key with different salt" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.startJoining("ABCD-1234", "ws://1.2.3.4:8080");
    const salt1 = [_]u8{0x11} ** 16;
    const salt2 = [_]u8{0x22} ** 16;
    try session.applyWelcome(salt1, .aes_gcm_v1);
    try std.testing.expectError(error.WelcomeAlreadyApplied, session.applyWelcome(salt2, .aes_gcm_v1));
}

test "Session: applyWelcome rejects re-suite with same salt" {
    // A2 invariant: re-suiting mid-session is rejected with the same
    // error path as re-keying. A peer that already installed AES-GCM
    // must NOT silently swap to ChaCha on a later welcome (a Tier-2
    // attacker controlling the host could otherwise downgrade or
    // force-rotate mid-flight).
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.startJoining("ABCD-1234", "ws://1.2.3.4:8080");
    const salt = [_]u8{0x11} ** 16;
    try session.applyWelcome(salt, .aes_gcm_v1);
    try std.testing.expectError(
        error.WelcomeAlreadyApplied,
        session.applyWelcome(salt, .chacha_v1),
    );
}

test "Session: applyWelcome from host mode → InvalidStateTransition" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.startHosting(8080, null, .aes_gcm_v1);
    const salt = [_]u8{0x33} ** 16;
    try std.testing.expectError(error.InvalidStateTransition, session.applyWelcome(salt, .aes_gcm_v1));
}

test "Session: startHosting with chacha-v1 locks suite + crypto matches" {
    // A2 happy-path: host can choose ChaCha; `session.suite` reflects
    // the lock; `session.crypto.?.suite` matches (so encrypt/decrypt
    // dispatches to ChaCha20-Poly1305).
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.startHosting(8080, null, .chacha_v1);
    try std.testing.expectEqual(crypto_mod.Suite.chacha_v1, session.suite);
    try std.testing.expect(session.crypto != null);
    try std.testing.expectEqual(crypto_mod.Suite.chacha_v1, session.crypto.?.suite);
}

test "Session: error transitions to idle" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.startHosting(8080, null, .aes_gcm_v1);
    session.setError("connection lost");
    try std.testing.expect(session.state == .idle);
    try std.testing.expect(session.error_msg != null);
}

test "Session: duplicate peer not added" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.startHosting(8080, null, .aes_gcm_v1);
    const id = [_]u8{0xAA} ** 16;
    try session.addPeer(id, "Alice");
    try session.addPeer(id, "Alice"); // duplicate
    try std.testing.expectEqual(@as(usize, 1), session.peers.items.len);
}

test "Session: setLocalName rejects names over MAX_NAME_LEN" {
    // Phase 5 panel security H-4 (outbound): the host duplicates the local
    // peer name into every WS handshake; a 10 MB name would amplify into a
    // 10 MB allocation per peer. Reject at the setter so the rest of the
    // codebase can treat `session.local_name.len <= MAX_NAME_LEN` as an
    // invariant.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    const oversized = "A" ** (Session.MAX_NAME_LEN + 1);
    try std.testing.expectError(error.NameTooLong, session.setLocalName(oversized));
    // On failure the previous-name allocation must not have been disturbed.
    try std.testing.expect(!session.local_name_owned);
    try std.testing.expectEqualStrings("Anonymous", session.local_name);

    // Exactly at the cap still works.
    const at_cap = "A" ** Session.MAX_NAME_LEN;
    try session.setLocalName(at_cap);
    try std.testing.expectEqual(@as(usize, Session.MAX_NAME_LEN), session.local_name.len);
}

test "Session: addPeer rejects names over MAX_NAME_LEN" {
    // Phase 5 panel security H-4 (inbound): same cap on the receive path —
    // a malicious peer cannot force the host to allocate an arbitrary-size
    // dupe of their advertised display name.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.startHosting(8080, null, .aes_gcm_v1);
    const id = [_]u8{0xCC} ** 16;
    const oversized = "X" ** (Session.MAX_NAME_LEN + 1);
    try std.testing.expectError(error.NameTooLong, session.addPeer(id, oversized));
    try std.testing.expectEqual(@as(usize, 0), session.peers.items.len);

    // Exactly-at-cap inbound name accepted (matches the outbound symmetry).
    const at_cap = "X" ** Session.MAX_NAME_LEN;
    try session.addPeer(id, at_cap);
    try std.testing.expectEqual(@as(usize, 1), session.peers.items.len);
}

test "Session: startHosting rejects malformed custom room codes" {
    // Phase 5 panel security H-2: `requested_code` historically only had a
    // length check. Each of the rows below would previously have been
    // memcpy'd into `room_code` and propagated to log lines, JSON state, and
    // the HKDF key derivation. The validator now requires the same shape
    // that `generateRoomCode` produces.
    const allocator = std.testing.allocator;

    const Case = struct { code: []const u8, label: []const u8 };
    const bad_cases = [_]Case{
        .{ .code = "TOOSHORT", .label = "too short" },
        .{ .code = "WAYTOOLONGCODE", .label = "too long" },
        .{ .code = "ABCD_1234", .label = "wrong separator" },
        .{ .code = "ABCDX1234", .label = "no separator at index 4" },
        .{ .code = "abcd-1234", .label = "lowercase not allowed" },
        .{ .code = "AB\x00D-1234", .label = "NUL byte in payload" },
        .{ .code = "ABCD-12 4", .label = "space in payload" },
        .{ .code = "ABCD-12!4", .label = "punctuation in payload" },
        .{ .code = "ABCD-1234\n", .label = "trailing newline (length 10)" },
    };

    // Phase 5 H-2 follow-up: the validator's job is to block byte classes
    // that corrupt log output / HKDF input — control chars, whitespace,
    // non-ASCII. Visually-ambiguous-but-still-ASCII-alnum codes (containing
    // `0`, `O`, `1`, `I`) ARE accepted: that exclusion is a generator UX
    // concern, not a validator security concern. Locking these out broke
    // the auto-generated codes the JS ShareDialog produces.
    const good_cases = [_][]const u8{
        "TEAM-2026", "ABC0-1234", "ABCD-12I4", "AAAA-BBBB", "0000-1111",
    };
    for (good_cases) |code| {
        var session = Session.init(allocator);
        defer session.deinit();
        session.startHosting(8080, code, .aes_gcm_v1) catch |e| {
            std.log.err("expected accept for '{s}'", .{code});
            return e;
        };
        try std.testing.expect(session.state == .hosting);
        try std.testing.expectEqualSlices(u8, code, &session.room_code);
    }

    for (bad_cases) |c| {
        var session = Session.init(allocator);
        defer session.deinit();
        const err = session.startHosting(8080, c.code, .aes_gcm_v1);
        std.testing.expectError(error.InvalidRoomCode, err) catch |e| {
            std.log.err("expected InvalidRoomCode for case '{s}' ({s})", .{ c.code, c.label });
            return e;
        };
        try std.testing.expect(session.state == .idle);
    }

    // The generator's own output must always pass — round-trip property.
    var session = Session.init(allocator);
    defer session.deinit();
    const generated = crypto_mod.generateRoomCode();
    try session.startHosting(8080, &generated, .aes_gcm_v1);
    try std.testing.expect(session.state == .hosting);
    try std.testing.expectEqualSlices(u8, &generated, &session.room_code);
}

test "Session: setLocalName frees previous owned name across host/leave/host cycles" {
    // Regression for the pre-existing leak: manager.createSession + .joinSession
    // used to assign session.local_name = allocator.dupe(...) directly, which
    // overwrote the field without freeing the previous dupe (or the static
    // "Anonymous" pointer was overwritten leak-free, but a second
    // host-after-leave cycle leaked the first dupe). The general-allocator
    // checked-allocator under std.testing.allocator will fail the test if
    // any dupe is leaked across the cycles below.
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    // Initial: pointer is the static "Anonymous" literal, not owned.
    try std.testing.expect(!session.local_name_owned);

    try session.setLocalName("Alice");
    try std.testing.expect(session.local_name_owned);
    try std.testing.expectEqualStrings("Alice", session.local_name);

    // Setting again must free "Alice" before duping "Bob".
    try session.setLocalName("Bob");
    try std.testing.expectEqualStrings("Bob", session.local_name);

    // leave() resets to the static "Anonymous" and frees the dupe.
    session.leave();
    try std.testing.expect(!session.local_name_owned);
    try std.testing.expectEqualStrings("Anonymous", session.local_name);

    // Subsequent setLocalName works again after leave.
    try session.setLocalName("Carol");
    try std.testing.expectEqualStrings("Carol", session.local_name);
    // deinit (via the test's defer) must free "Carol" — the testing
    // allocator's leak check is the actual assertion.
}

test "Session: toJson produces valid JSON" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.startHosting(8080, null, .aes_gcm_v1);
    try session.addPeer([_]u8{0xBB} ** 16, "Bob");

    const json = try session.toJson();
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"state\":\"connected\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "Bob") != null);
}
