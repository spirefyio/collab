//! Collaboration Protocol — Message encode/decode (pv:4)
//!
//! Wire format: JSON text frames over WebSocket. Each frame is a
//! self-describing envelope with a `t` (type) field.
//!
//! Message types:
//!   join    — Peer joining a room (advertises pv + suite_prefs + pubkey)
//!   welcome — Host's response to join: salt + chosen crypto suite
//!   peers   — Peer list update
//!   leave   — Peer leaving
//!   sync    — Full CRDT snapshot for one channel (joiner bootstrap)
//!   op      — Single CRDT operation on one channel (B1: signed)
//!   ops     — Batch of CRDT operations on one channel (B1: each signed)
//!   ping    — Keepalive request
//!   pong    — Keepalive response
//!   error   — Error message
//!
//! Multi-channel envelope (pv:4):
//!   {"t":"op","pv":4,"ch":"<channel>","payload":"<base64(nonce||ct||tag)>",
//!    "sig":"<base64-64>","signer":"<base64-32>"}
//!   {"t":"sync","pv":4,"ch":"<channel>","snapshot":"<base64(nonce||ct||tag)>"}
//!   {"t":"ops","pv":4,"ch":"<channel>","batch":[
//!     {"payload":"<base64>","sig":"<base64-64>","signer":"<base64-32>"},
//!     ...]}
//!
//! payload / snapshot / batch entries are ALWAYS base64-encoded AEAD
//! ciphertext (12-byte nonce ‖ ciphertext ‖ 16-byte tag) — the protocol
//! layer remains agnostic to each CRDT's internal serialization and the
//! receiver must decrypt before handing bytes to the CRDT layer. For the
//! LWW-Map `unified-model` channel the decrypted bytes are UTF-8 JSON of
//! `{"path":...,"v":...,"ts":...,"p":...}` — see
//! `crdt_lww_map.encodeOpBytes`.
//!
//! B1 signed-op shape (pv:4):
//!   - `sig` = Ed25519 signature (64 bytes, base64) over PLAINTEXT op_bytes
//!     (BEFORE AEAD encryption). Signing ciphertext would weaken the
//!     binding — the signature would prove "this peer encrypted this
//!     ciphertext" instead of "this peer authored this op".
//!   - `signer` = Ed25519 public key (32 bytes, base64) of the op author.
//!     The receiver verifies `sig` over the decrypted plaintext under
//!     `signer`'s pubkey. Mismatch / malformed → drop with
//!     `metrics.inbound_unsigned_dropped++`. This closes the v1 "any peer
//!     with the room key can forge any other peer's edits" gap documented
//!     in `crypto.zig` and `channel-acl.md`.
//!   - `sync` is NOT signed in pv:4. The host's snapshot is the
//!     session-start state; the post-snapshot signed-op stream provides
//!     incremental authenticity. Snapshot signing is Tier-2 (deferred to
//!     the Team feature where workspace-level identity is in scope).
//!
//! Welcome handshake (pv:4):
//!   {"t":"welcome","pv":4,"salt":"<base64-16-bytes>","suite":"aes-gcm-v1"}
//!
//! Sent by the host AFTER it accepts a peer's `join`, BEFORE any `sync`.
//! Carries the room's session salt + the negotiated crypto suite. The
//! joiner uses these to init its `CryptoContext`; until welcome arrives,
//! the joiner's crypto is null and inbound op/ops/sync are dropped with
//! `error.MissingWelcome` by the manager layer.
//!
//! Suite negotiation: the join envelope advertises `suite_prefs` (an
//! array of suite IDs the joiner supports). The host picks the highest-
//! numbered mutually-supported suite. If no overlap → `error.NoCompatibleSuite`
//! and the host sends an `error` envelope before dropping the connection.
//! v1 ships with one suite (`aes-gcm-v1`); A2 adds `chacha-v1`; A3 adds
//! `pq-hybrid-v1` (X25519+ML-KEM-768 hybrid).
//!
//! Identity exchange: the join envelope ALSO advertises `pubkey` (the
//! joiner's Ed25519 identity, 32 bytes base64). The host registers it in
//! its peer-id ↔ pubkey map; subsequent signed `op`s from this peer can
//! be cross-checked against the advertised pubkey for audit / Tier-2
//! self-spoofing guards. v1 only requires the field's presence + shape;
//! the cross-check is wired by the manager layer.
//!
//! pv:1 / pv:2 / pv:3 are NOT supported. No deployed peers exist for
//! pre-B1 wire; receiving a pv != 4 frame on a channel-routed message
//! returns `error.UnknownProtocolVersion`. The bump from pv:3 → pv:4
//! coincides with B1 — peers running A2 (pv:3) cannot interoperate with
//! B1 peers, by design (signed ops require identity exchange at join).
//!
//! Payload caps (closes security-engineer C-3):
//!   - `MAX_FRAME_BYTES`        16 MiB total envelope size
//!   - `MAX_OP_PAYLOAD_BYTES`   1 MiB per op payload (decoded ciphertext)
//!   - `MAX_SNAPSHOT_BYTES`     16 MiB per snapshot (decoded ciphertext)
//!   - `MAX_OPS_BATCH_LEN`      256 ops per `ops` batch
//!   - `MAX_SUITE_PREFS`        8 suite names per join
//!   - `MAX_SIG_BYTES`          64 bytes (Ed25519 sig exact size, exact-match)
//!   - `MAX_PUBKEY_BYTES`       32 bytes (Ed25519 pubkey exact size, exact-match)
//!   These are enforced in the decoder; oversize frames are rejected.
//!   The payload caps account for AEAD overhead (+28 bytes per op /
//!   snapshot: 12 nonce + 16 tag) implicitly — plaintext op_bytes have
//!   their own cap inside the manager layer.

const std = @import("std");
const channel_mod = @import("channel.zig");
const identity_mod = @import("identity");

/// Wire protocol version emitted by this build.
pub const PROTOCOL_VERSION: u32 = 4;

/// Payload-size caps (closes security-engineer C-3).
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OP_PAYLOAD_BYTES: usize = 1 * 1024 * 1024;
pub const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OPS_BATCH_LEN: usize = 256;
/// Cap on the size of the `suite_prefs` array in a `join` envelope.
/// 8 is comfortably more than the foreseeable supported suite count
/// (v1: 1, A2: 2, A3: 3, plus a few experimental headroom slots) and
/// keeps the malformed-join attack surface bounded.
pub const MAX_SUITE_PREFS: usize = 8;
/// Cap on suite-ID length. v1 names like `"aes-gcm-v1"` are 10 chars;
/// 32 leaves room for future qualified names without inviting log-spam
/// attacks via huge suite names.
pub const MAX_SUITE_NAME_LEN: usize = 32;
/// Exact-match expected size for an Ed25519 signature (B1). The decoder
/// rejects any decoded `sig` field whose length isn't exactly this —
/// Ed25519 signatures are fixed-width by spec. Sourced from
/// `identity.SIG_LEN` so the wire-layer cap and the crypto primitive
/// stay in lockstep automatically — a future migration to a different
/// signature suite changes one line in identity.zig and the protocol
/// layer follows without manual reconciliation (panel-#1 refactor
/// MED, security MED-1, closes constant-drift risk).
pub const SIG_BYTES: usize = identity_mod.SIG_LEN;
/// Exact-match expected size for an Ed25519 public key (B1). The decoder
/// rejects any decoded `signer` / `pubkey` field whose length isn't
/// exactly this. Sourced from `identity.PUBKEY_LEN` for the same
/// single-source-of-truth reason as SIG_BYTES above.
pub const PUBKEY_BYTES: usize = identity_mod.PUBKEY_LEN;

comptime {
    // Defense-in-depth assertion: catches the failure mode where a
    // future change to identity.SIG_LEN / PUBKEY_LEN silently breaks
    // the wire-format expectations. Ed25519 sizes are RFC-fixed, but
    // a refactor that switches identity.zig to a different scheme
    // (Ed448, ML-DSA) would also need a wire bump, and this assertion
    // forces that conversation at build time instead of letting it
    // pass a green test suite under accidental wire-shape divergence.
    if (SIG_BYTES != 64) @compileError("protocol.SIG_BYTES expected Ed25519 sig size (64)");
    if (PUBKEY_BYTES != 32) @compileError("protocol.PUBKEY_BYTES expected Ed25519 pubkey size (32)");
}

/// Crypto suite wire-string constants. Lives in `protocol.zig` (not
/// `manager.zig`) so encoder + decoder + manager all reference the same
/// constant — a typo cannot drift between sender and receiver (refactor
/// panel M-2). The canonical (enum ↔ wire) mapping is in
/// `crypto.zig` `Suite.fromName`/`toName`; these constants must stay in
/// lockstep with the names that helper returns.
pub const SUITE_AES_GCM_V1: []const u8 = "aes-gcm-v1";
/// A2: ChaCha20-Poly1305 suite. Same key/nonce/tag layout as AES-GCM
/// (`AEAD_OVERHEAD = 28` is suite-agnostic), so no wire-format change
/// beyond the new ID string.
pub const SUITE_CHACHA_V1: []const u8 = "chacha-v1";

pub const MessageType = enum {
    join,
    welcome,
    peers,
    leave,
    sync,
    op,
    ops,
    ping,
    pong,
    @"error",
};

pub const PeerInfo = struct {
    id: [16]u8,
    name: []const u8,
};

/// One signed-op entry inside an `ops` batch (B1). Wire shape:
/// `{"payload":"<base64>","sig":"<base64-64>","signer":"<base64-32>"}`.
/// All three byte slices are borrowed from the decoder's owned-bytes
/// arena and remain valid until `ParseResult.deinit`.
pub const SignedOp = struct {
    /// Encrypted op_bytes (decoded from base64, still ciphertext).
    payload: []const u8,
    /// Ed25519 signature over the PLAINTEXT op_bytes (BEFORE encrypt).
    /// 64 bytes after base64-decode; enforced by the decoder.
    sig: []const u8,
    /// Ed25519 public key of the op author. 32 bytes after base64-decode.
    signer: []const u8,
};

pub const Message = union(MessageType) {
    join: struct {
        room: []const u8,
        name: []const u8,
        peer_id: [16]u8,
        /// Protocol version this peer speaks. Currently MUST equal 4.
        pv: u32 = PROTOCOL_VERSION,
        /// Cipher suites this peer can speak, in preference order
        /// (highest-preference first). The host picks the highest-numbered
        /// mutually-supported suite. Borrowed slices into the decoder's
        /// parsed-JSON store; valid for `ParseResult.deinit` lifetime.
        /// v1 emits `["aes-gcm-v1"]`. Empty is rejected by the host with
        /// `error.NoCompatibleSuite`.
        suite_prefs: []const []const u8 = &.{},
        /// B1: 32-byte Ed25519 identity public key (decoded from base64).
        /// The host registers this in its peer-id ↔ pubkey map; later
        /// signed ops from this peer are cross-checked against it.
        /// Borrowed slice into the decoder's allocation; valid until
        /// `ParseResult.deinit`.
        pubkey: []const u8 = &.{},
    },
    welcome: struct {
        /// 16-byte session salt used in HKDF key derivation. Decoded from
        /// base64; borrowed slice into the decoder's allocation.
        salt: []const u8,
        /// Negotiated cipher suite ID (one of the join's `suite_prefs`).
        /// Borrowed slice into the decoder's parsed-JSON store.
        suite: []const u8,
        /// Protocol version. MUST equal 4 (welcome was introduced in pv:3,
        /// retained in pv:4).
        pv: u32 = PROTOCOL_VERSION,
    },
    peers: struct {
        list: []const PeerInfo,
    },
    leave: struct {
        peer_id: [16]u8,
    },
    sync: struct {
        /// Channel name (e.g. "unified-model"). Required.
        ch: []const u8,
        /// Encrypted snapshot bytes (decoded from base64 over the wire,
        /// still ciphertext). The manager layer decrypts with the session
        /// CryptoContext before handing to `crdt.loadSnapshot`. Borrowed
        /// slice into the decoder's allocation; consume before
        /// `ParseResult.deinit`.
        snapshot: []const u8,
    },
    op: struct {
        ch: []const u8,
        /// Encrypted op_bytes (decoded from base64, still ciphertext).
        /// Manager decrypts before `crdt.applyRemote`.
        payload: []const u8,
        /// B1: Ed25519 signature over PLAINTEXT op_bytes (BEFORE encrypt).
        /// Manager verifies AFTER decrypt + BEFORE applyRemote. 64 bytes
        /// after base64-decode; enforced by the decoder.
        sig: []const u8,
        /// B1: 32-byte Ed25519 pubkey of the op author. Manager looks up
        /// or registers against the peer's join-time advertised pubkey.
        signer: []const u8,
    },
    ops: struct {
        ch: []const u8,
        /// B1: Array of signed-op entries. Each entry is decrypted +
        /// verified independently before `applyRemote`.
        batch: []const SignedOp,
    },
    ping: void,
    pong: void,
    @"error": struct {
        message: []const u8,
    },
};

const Base64 = std.base64.standard;

// =============================================================================
// Encoder
// =============================================================================

/// Encode a message to JSON bytes. Caller owns returned memory.
pub fn encode(allocator: std.mem.Allocator, msg: Message) ![]const u8 {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    const w = &buf.writer;

    switch (msg) {
        .join => |j| {
            try w.writeAll("{\"t\":\"join\",\"pv\":");
            try w.print("{d}", .{j.pv});
            try w.writeAll(",\"room\":\"");
            try writeEscaped(w, j.room);
            try w.writeAll("\",\"name\":\"");
            try writeEscaped(w, j.name);
            try w.writeAll("\",\"peer\":\"");
            try writeHex(w, &j.peer_id);
            try w.writeAll("\",\"suite_prefs\":[");
            for (j.suite_prefs, 0..) |suite, i| {
                if (i > 0) try w.writeByte(',');
                try w.writeByte('"');
                try writeEscaped(w, suite);
                try w.writeByte('"');
            }
            try w.writeAll("],\"pubkey\":\"");
            try writeBase64(w, j.pubkey);
            try w.writeAll("\"}");
        },
        .welcome => |wmsg| {
            try w.writeAll("{\"t\":\"welcome\",\"pv\":");
            try w.print("{d}", .{wmsg.pv});
            try w.writeAll(",\"salt\":\"");
            try writeBase64(w, wmsg.salt);
            try w.writeAll("\",\"suite\":\"");
            try writeEscaped(w, wmsg.suite);
            try w.writeAll("\"}");
        },
        .peers => |p| {
            try w.writeAll("{\"t\":\"peers\",\"list\":[");
            for (p.list, 0..) |peer, i| {
                if (i > 0) try w.writeByte(',');
                try w.writeAll("{\"id\":\"");
                try writeHex(w, &peer.id);
                try w.writeAll("\",\"name\":\"");
                try writeEscaped(w, peer.name);
                try w.writeAll("\"}");
            }
            try w.writeAll("]}");
        },
        .leave => |l| {
            try w.writeAll("{\"t\":\"leave\",\"peer\":\"");
            try writeHex(w, &l.peer_id);
            try w.writeAll("\"}");
        },
        .sync => |s| {
            try w.writeAll("{\"t\":\"sync\",\"pv\":");
            try w.print("{d}", .{PROTOCOL_VERSION});
            try w.writeAll(",\"ch\":\"");
            try writeEscaped(w, s.ch);
            try w.writeAll("\",\"snapshot\":\"");
            try writeBase64(w, s.snapshot);
            try w.writeAll("\"}");
        },
        .op => |o| {
            try w.writeAll("{\"t\":\"op\",\"pv\":");
            try w.print("{d}", .{PROTOCOL_VERSION});
            try w.writeAll(",\"ch\":\"");
            try writeEscaped(w, o.ch);
            try w.writeAll("\",\"payload\":\"");
            try writeBase64(w, o.payload);
            try w.writeAll("\",\"sig\":\"");
            try writeBase64(w, o.sig);
            try w.writeAll("\",\"signer\":\"");
            try writeBase64(w, o.signer);
            try w.writeAll("\"}");
        },
        .ops => |b| {
            try w.writeAll("{\"t\":\"ops\",\"pv\":");
            try w.print("{d}", .{PROTOCOL_VERSION});
            try w.writeAll(",\"ch\":\"");
            try writeEscaped(w, b.ch);
            try w.writeAll("\",\"batch\":[");
            for (b.batch, 0..) |entry, i| {
                if (i > 0) try w.writeByte(',');
                try w.writeAll("{\"payload\":\"");
                try writeBase64(w, entry.payload);
                try w.writeAll("\",\"sig\":\"");
                try writeBase64(w, entry.sig);
                try w.writeAll("\",\"signer\":\"");
                try writeBase64(w, entry.signer);
                try w.writeAll("\"}");
            }
            try w.writeAll("]}");
        },
        .ping => try w.writeAll("{\"t\":\"ping\"}"),
        .pong => try w.writeAll("{\"t\":\"pong\"}"),
        .@"error" => |e| {
            try w.writeAll("{\"t\":\"error\",\"message\":\"");
            try writeEscaped(w, e.message);
            try w.writeAll("\"}");
        },
    }

    return buf.toOwnedSlice();
}

fn writeBase64(w: *std.Io.Writer, bytes: []const u8) !void {
    var tmp_buf: [4096]u8 = undefined;
    var remaining = bytes;
    while (remaining.len > 0) {
        // Encode in chunks that fit in tmp_buf. Each 3 input bytes → 4 output bytes.
        const max_in = (tmp_buf.len / 4) * 3;
        const chunk_len = @min(remaining.len, max_in);
        const out = Base64.Encoder.encode(&tmp_buf, remaining[0..chunk_len]);
        try w.writeAll(out);
        remaining = remaining[chunk_len..];
    }
}

// =============================================================================
// Decoder
// =============================================================================

/// Decode result with manually-tracked allocations (the slices that point
/// into base64-decoded buffers are returned via this struct so the caller
/// can free them after consuming the message).
pub const ParseResult = struct {
    msg: Message,
    parsed: std.json.Parsed(std.json.Value),
    /// Per-payload base64-decoded buffers. Each entry was allocated via
    /// `allocator.alloc(u8, n)` and is freed in `deinit`.
    owned_bytes: std.array_list.Managed([]u8),
    /// Slice-of-SignedOp allocation for `.ops` batch (null for other
    /// types). Each entry's `payload` / `sig` / `signer` byte slices are
    /// borrowed from `owned_bytes`; only the outer array allocation
    /// itself is owned here.
    batch_alloc: ?[]SignedOp = null,
    /// Slice-of-slices allocation for `.join.suite_prefs` (null for
    /// other types). Allocated as `[][]const u8`. The inner slices are
    /// borrowed from `parsed` (not heap-owned).
    suite_prefs_alloc: ?[][]const u8 = null,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ParseResult) void {
        for (self.owned_bytes.items) |b| self.allocator.free(b);
        self.owned_bytes.deinit();
        if (self.batch_alloc) |b| self.allocator.free(b);
        if (self.suite_prefs_alloc) |b| self.allocator.free(b);
        self.parsed.deinit();
    }
};

pub fn decode(allocator: std.mem.Allocator, data: []const u8) !ParseResult {
    if (data.len > MAX_FRAME_BYTES) return error.FrameTooLarge;

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    errdefer parsed.deinit();

    var owned_bytes = std.array_list.Managed([]u8).init(allocator);
    errdefer {
        for (owned_bytes.items) |b| allocator.free(b);
        owned_bytes.deinit();
    }

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidMessage,
    };

    const t_val = obj.get("t") orelse return error.MissingType;
    const t = switch (t_val) {
        .string => |s| s,
        else => return error.InvalidType,
    };

    // -------- Stateless control frames --------
    if (std.mem.eql(u8, t, "ping")) {
        return .{ .msg = .{ .ping = {} }, .parsed = parsed, .owned_bytes = owned_bytes, .allocator = allocator };
    }
    if (std.mem.eql(u8, t, "pong")) {
        return .{ .msg = .{ .pong = {} }, .parsed = parsed, .owned_bytes = owned_bytes, .allocator = allocator };
    }

    // -------- Roster control --------
    if (std.mem.eql(u8, t, "join")) {
        // pv: REQUIRED on join under pv:4. Missing `pv` is treated as a
        // pre-v4 peer and rejected — there is no plaintext-fallback path
        // any more (encryption + signed-op identity are always-on). The
        // pv field has been present since pv:2 so any well-formed v2+
        // peer always emits it.
        const pv_val = obj.get("pv") orelse return error.UnknownProtocolVersion;
        const pv: u32 = switch (pv_val) {
            .integer => |i| if (i < 0) return error.InvalidField else @intCast(i),
            else => return error.InvalidField,
        };
        if (pv != PROTOCOL_VERSION) return error.UnknownProtocolVersion;

        const room = getStr(obj, "room") orelse return error.MissingField;
        const name = getStr(obj, "name") orelse return error.MissingField;
        const peer_hex = getStr(obj, "peer") orelse return error.MissingField;
        var peer_id: [16]u8 = undefined;
        _ = std.fmt.hexToBytes(&peer_id, peer_hex) catch return error.InvalidPeerId;

        // suite_prefs: REQUIRED on join under pv:3+. The host needs the
        // joiner's supported suite list to negotiate. Empty array →
        // host responds with NoCompatibleSuite + drops connection.
        const suite_prefs_val = obj.get("suite_prefs") orelse return error.MissingField;
        const prefs_arr = switch (suite_prefs_val) {
            .array => |a| a,
            else => return error.InvalidField,
        };
        if (prefs_arr.items.len > MAX_SUITE_PREFS) return error.BatchTooLarge;
        const prefs = try allocator.alloc([]const u8, prefs_arr.items.len);
        errdefer allocator.free(prefs);
        for (prefs_arr.items, 0..) |item, i| {
            const s = switch (item) {
                .string => |str| str,
                else => return error.InvalidField,
            };
            // Reject empty (no useful prefs entry can have len 0) +
            // oversize (DoS) + non-ASCII-printable (security M-4: a
            // hostile suite name like `"\x1b[2J"` would inject ANSI
            // escapes into log output).
            if (s.len == 0 or s.len > MAX_SUITE_NAME_LEN) return error.InvalidField;
            if (!isPrintableAscii(s)) return error.InvalidField;
            prefs[i] = s;
        }

        // B1 (pv:4): pubkey REQUIRED. 32 bytes Ed25519 public key,
        // base64-encoded. Validated for exact length before allocator
        // bookkeeping — a malformed pubkey is rejected here so the host's
        // peer-id ↔ pubkey map never sees a partial entry.
        const pubkey_b64 = getStr(obj, "pubkey") orelse return error.MissingField;
        const pubkey = try decodeFixedLen(allocator, &owned_bytes, pubkey_b64, PUBKEY_BYTES);

        return .{
            .msg = .{ .join = .{
                .room = room,
                .name = name,
                .peer_id = peer_id,
                .pv = pv,
                .suite_prefs = prefs,
                .pubkey = pubkey,
            } },
            .parsed = parsed,
            .owned_bytes = owned_bytes,
            .suite_prefs_alloc = prefs,
            .allocator = allocator,
        };
    }

    if (std.mem.eql(u8, t, "welcome")) {
        const pv_val = obj.get("pv") orelse return error.UnknownProtocolVersion;
        const pv: u32 = switch (pv_val) {
            .integer => |i| if (i < 0) return error.InvalidField else @intCast(i),
            else => return error.InvalidField,
        };
        if (pv != PROTOCOL_VERSION) return error.UnknownProtocolVersion;

        // Validate all NON-allocating fields BEFORE we allocate the salt
        // buffer. This avoids a double-free hazard where the salt has
        // already been appended to `owned_bytes` but a later `return
        // error.X` triggers both the inner errdefer and the outer
        // `owned_bytes` cleanup.
        const salt_b64 = getStr(obj, "salt") orelse return error.MissingField;
        const suite = getStr(obj, "suite") orelse return error.MissingField;
        if (suite.len == 0 or suite.len > MAX_SUITE_NAME_LEN) return error.InvalidField;
        if (!isPrintableAscii(suite)) return error.InvalidField;

        // Salt is fixed 16 bytes → 24 base64 chars (with padding). The
        // bounded decoder rejects anything that decodes to > 32 bytes
        // defensively (no expected legitimate salt is bigger; oversize
        // is malformed).
        const salt = try decodeBase64Bounded(allocator, salt_b64, 32);
        errdefer allocator.free(salt);
        if (salt.len != 16) return error.InvalidField;
        try owned_bytes.append(salt);
        // From here on, only the outer `owned_bytes` cleanup owns
        // `salt` — do NOT free it again on any error path below.

        return .{
            .msg = .{ .welcome = .{ .salt = salt, .suite = suite, .pv = pv } },
            .parsed = parsed,
            .owned_bytes = owned_bytes,
            .allocator = allocator,
        };
    }

    if (std.mem.eql(u8, t, "leave")) {
        const peer_hex = getStr(obj, "peer") orelse return error.MissingField;
        var peer_id: [16]u8 = undefined;
        _ = std.fmt.hexToBytes(&peer_id, peer_hex) catch return error.InvalidPeerId;
        return .{
            .msg = .{ .leave = .{ .peer_id = peer_id } },
            .parsed = parsed,
            .owned_bytes = owned_bytes,
            .allocator = allocator,
        };
    }

    // -------- Channel-routed messages: pv MUST be present and == 3 --------
    if (std.mem.eql(u8, t, "sync")) {
        try requireCurrentPv(obj);
        const ch = try requireChannel(obj);
        const snap_b64 = getStr(obj, "snapshot") orelse return error.MissingField;
        const snap = try decodeBase64Bounded(allocator, snap_b64, MAX_SNAPSHOT_BYTES);
        errdefer allocator.free(snap);
        try owned_bytes.append(snap);
        return .{
            .msg = .{ .sync = .{ .ch = ch, .snapshot = snap } },
            .parsed = parsed,
            .owned_bytes = owned_bytes,
            .allocator = allocator,
        };
    }

    if (std.mem.eql(u8, t, "op")) {
        try requireCurrentPv(obj);
        const ch = try requireChannel(obj);
        const payload_b64 = getStr(obj, "payload") orelse return error.MissingField;
        // B1: sig + signer are REQUIRED on pv:4 op. Manager drops the op
        // post-decrypt if verify fails; the decoder only checks shape.
        const sig_b64 = getStr(obj, "sig") orelse return error.MissingField;
        const signer_b64 = getStr(obj, "signer") orelse return error.MissingField;

        const payload = try decodeBase64Bounded(allocator, payload_b64, MAX_OP_PAYLOAD_BYTES);
        {
            // SCOPED errdefer: fires ONLY if `append` itself fails. After
            // the block exits normally, `payload` is owned by
            // `owned_bytes` — and if a LATER step (sig/signer decode)
            // errors, the outer `owned_bytes` cleanup frees `payload`.
            // Without this scope, the errdefer would survive past the
            // append and double-free.
            errdefer allocator.free(payload);
            try owned_bytes.append(payload);
        }
        const sig = try decodeFixedLen(allocator, &owned_bytes, sig_b64, SIG_BYTES);
        const signer = try decodeFixedLen(allocator, &owned_bytes, signer_b64, PUBKEY_BYTES);
        return .{
            .msg = .{ .op = .{
                .ch = ch,
                .payload = payload,
                .sig = sig,
                .signer = signer,
            } },
            .parsed = parsed,
            .owned_bytes = owned_bytes,
            .allocator = allocator,
        };
    }

    if (std.mem.eql(u8, t, "ops")) {
        try requireCurrentPv(obj);
        const ch = try requireChannel(obj);
        const batch_val = obj.get("batch") orelse return error.MissingField;
        const arr = switch (batch_val) {
            .array => |a| a,
            else => return error.InvalidField,
        };
        if (arr.items.len > MAX_OPS_BATCH_LEN) return error.BatchTooLarge;

        // B1: each batch entry is an OBJECT with payload + sig + signer
        // — replaces pv:3's bare-base64-string entries. Mixed batch
        // shapes are rejected (`.string` entry → InvalidField).
        const decoded = try allocator.alloc(SignedOp, arr.items.len);
        errdefer allocator.free(decoded);

        for (arr.items, 0..) |item, i| {
            const entry_obj = switch (item) {
                .object => |o| o,
                else => return error.InvalidField,
            };
            const p_b64 = getStr(entry_obj, "payload") orelse return error.MissingField;
            const s_b64 = getStr(entry_obj, "sig") orelse return error.MissingField;
            const k_b64 = getStr(entry_obj, "signer") orelse return error.MissingField;

            const payload = try decodeBase64Bounded(allocator, p_b64, MAX_OP_PAYLOAD_BYTES);
            {
                // SCOPED errdefer (same rationale as `.op` arm) — fires
                // only if append() fails; ownership transfers to
                // `owned_bytes` on success so later sig/signer errors
                // don't double-free.
                errdefer allocator.free(payload);
                try owned_bytes.append(payload);
            }
            const sig = try decodeFixedLen(allocator, &owned_bytes, s_b64, SIG_BYTES);
            const signer = try decodeFixedLen(allocator, &owned_bytes, k_b64, PUBKEY_BYTES);

            decoded[i] = .{ .payload = payload, .sig = sig, .signer = signer };
        }

        return .{
            .msg = .{ .ops = .{ .ch = ch, .batch = decoded } },
            .parsed = parsed,
            .owned_bytes = owned_bytes,
            .batch_alloc = decoded,
            .allocator = allocator,
        };
    }

    if (std.mem.eql(u8, t, "error")) {
        const message = getStr(obj, "message") orelse return error.MissingField;
        return .{
            .msg = .{ .@"error" = .{ .message = message } },
            .parsed = parsed,
            .owned_bytes = owned_bytes,
            .allocator = allocator,
        };
    }

    if (std.mem.eql(u8, t, "peers")) {
        // Peers list decoding — full decode not needed on client side for v1.
        return .{
            .msg = .{ .peers = .{ .list = &.{} } },
            .parsed = parsed,
            .owned_bytes = owned_bytes,
            .allocator = allocator,
        };
    }

    return error.UnknownMessageType;
}

fn requireCurrentPv(obj: std.json.ObjectMap) !void {
    const pv_val = obj.get("pv") orelse return error.UnknownProtocolVersion;
    const pv: u32 = switch (pv_val) {
        .integer => |i| if (i < 0) return error.InvalidField else @intCast(i),
        else => return error.InvalidField,
    };
    if (pv != PROTOCOL_VERSION) return error.UnknownProtocolVersion;
}

/// Decode a base64 field that MUST decode to exactly `expected_len` bytes
/// (used for fixed-width Ed25519 signatures + pubkeys). Appends the
/// allocation to `owned_bytes` so the caller doesn't need a separate
/// errdefer. Returns the borrowed slice for embedding in the Message.
fn decodeFixedLen(
    allocator: std.mem.Allocator,
    owned_bytes: *std.array_list.Managed([]u8),
    b64: []const u8,
    expected_len: usize,
) ![]u8 {
    // Cap to expected_len + a small fudge so a hostile sender cannot DoS
    // us by sending megabytes of base64 for a 64-byte signature. The
    // exact-length check below catches the legit cases.
    const decoded = try decodeBase64Bounded(allocator, b64, expected_len * 2);
    errdefer allocator.free(decoded);
    if (decoded.len != expected_len) return error.InvalidField;
    try owned_bytes.append(decoded);
    return decoded;
}

fn requireChannel(obj: std.json.ObjectMap) ![]const u8 {
    const ch = getStr(obj, "ch") orelse return error.MissingField;
    if (!channel_mod.isValidChannelName(ch)) return error.InvalidChannelName;
    return ch;
}

fn decodeBase64Bounded(
    allocator: std.mem.Allocator,
    b64: []const u8,
    max_decoded_bytes: usize,
) ![]u8 {
    // Compute exact decode size; reject early on cap violation so we
    // never allocate more than `max_decoded_bytes`.
    const decoded_len = Base64.Decoder.calcSizeForSlice(b64) catch return error.InvalidBase64;
    if (decoded_len > max_decoded_bytes) return error.PayloadTooLarge;

    const out = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(out);
    Base64.Decoder.decode(out, b64) catch return error.InvalidBase64;
    return out;
}

fn getStr(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

/// True iff every byte in `s` is printable 7-bit ASCII (0x20..0x7E).
/// Suite IDs and other log-bound short strings must pass this — a
/// hostile name like `"\x1b[2J"` would inject ANSI escapes into log
/// streams / log-aggregator output (security panel M-4).
fn isPrintableAscii(s: []const u8) bool {
    for (s) |b| {
        if (b < 0x20 or b > 0x7E) return false;
    }
    return true;
}

const json_util = @import("util_json");
const writeEscaped = json_util.writeJsonEscaped;
const writeHex = json_util.writeHex;

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "encode/decode ping" {
    const allocator = testing.allocator;
    const json = try encode(allocator, .{ .ping = {} });
    defer allocator.free(json);
    try testing.expectEqualStrings("{\"t\":\"ping\"}", json);

    var result = try decode(allocator, json);
    defer result.deinit();
    try testing.expect(result.msg == .ping);
}

test "encode/decode pong" {
    const allocator = testing.allocator;
    const json = try encode(allocator, .{ .pong = {} });
    defer allocator.free(json);
    try testing.expectEqualStrings("{\"t\":\"pong\"}", json);

    var result = try decode(allocator, json);
    defer result.deinit();
    try testing.expect(result.msg == .pong);
}

// Fixed-shape test vectors. The decoder treats sig + signer as opaque
// byte blobs — it does NOT crypto-verify them here. That happens in
// `manager.zig`. We just need lengths to match SIG_BYTES / PUBKEY_BYTES.
const TEST_SIG: [SIG_BYTES]u8 = blk: {
    var s: [SIG_BYTES]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = @intCast(i & 0xFF);
    break :blk s;
};
const TEST_SIGNER: [PUBKEY_BYTES]u8 = blk: {
    var p: [PUBKEY_BYTES]u8 = undefined;
    for (&p, 0..) |*b, i| b.* = @intCast(0xA0 +% i);
    break :blk p;
};

test "encode/decode op pv:4 with channel + payload + sig + signer" {
    const allocator = testing.allocator;
    // Payload here is opaque ciphertext-ish bytes — the decoder treats
    // it as a base64 blob; round-trip equality is what matters.
    const op_payload = "ciphertext-bytes-treated-as-opaque";
    const json = try encode(allocator, .{ .op = .{
        .ch = "unified-model",
        .payload = op_payload,
        .sig = &TEST_SIG,
        .signer = &TEST_SIGNER,
    } });
    defer allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"pv\":4") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"ch\":\"unified-model\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"sig\":\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"signer\":\"") != null);

    var result = try decode(allocator, json);
    defer result.deinit();
    try testing.expectEqualStrings("unified-model", result.msg.op.ch);
    try testing.expectEqualStrings(op_payload, result.msg.op.payload);
    try testing.expectEqual(@as(usize, SIG_BYTES), result.msg.op.sig.len);
    try testing.expectEqualSlices(u8, &TEST_SIG, result.msg.op.sig);
    try testing.expectEqual(@as(usize, PUBKEY_BYTES), result.msg.op.signer.len);
    try testing.expectEqualSlices(u8, &TEST_SIGNER, result.msg.op.signer);
}

test "encode/decode sync pv:4 with channel + base64 snapshot" {
    const allocator = testing.allocator;
    const snap = "encrypted-snapshot-bytes";
    const json = try encode(allocator, .{ .sync = .{ .ch = "unified-model", .snapshot = snap } });
    defer allocator.free(json);

    var result = try decode(allocator, json);
    defer result.deinit();
    try testing.expectEqualStrings("unified-model", result.msg.sync.ch);
    try testing.expectEqualStrings(snap, result.msg.sync.snapshot);
}

test "encode/decode ops pv:4 with channel + signed batch" {
    const allocator = testing.allocator;
    const op1 = "encrypted-op-1";
    const op2 = "encrypted-op-2";
    const batch: [2]SignedOp = .{
        .{ .payload = op1, .sig = &TEST_SIG, .signer = &TEST_SIGNER },
        .{ .payload = op2, .sig = &TEST_SIG, .signer = &TEST_SIGNER },
    };
    const json = try encode(allocator, .{ .ops = .{ .ch = "unified-model", .batch = &batch } });
    defer allocator.free(json);
    try testing.expect(std.mem.indexOf(u8, json, "\"pv\":4") != null);

    var result = try decode(allocator, json);
    defer result.deinit();
    try testing.expectEqualStrings("unified-model", result.msg.ops.ch);
    try testing.expectEqual(@as(usize, 2), result.msg.ops.batch.len);
    try testing.expectEqualStrings(op1, result.msg.ops.batch[0].payload);
    try testing.expectEqualStrings(op2, result.msg.ops.batch[1].payload);
    try testing.expectEqualSlices(u8, &TEST_SIG, result.msg.ops.batch[0].sig);
    try testing.expectEqualSlices(u8, &TEST_SIGNER, result.msg.ops.batch[1].signer);
}

test "encode/decode join carries pv + suite_prefs + pubkey" {
    const allocator = testing.allocator;
    const peer_id = [_]u8{0xBB} ** 16;
    const prefs: [1][]const u8 = .{"aes-gcm-v1"};
    const json = try encode(allocator, .{ .join = .{
        .room = "ABCD-1234",
        .name = "Alice",
        .peer_id = peer_id,
        .suite_prefs = &prefs,
        .pubkey = &TEST_SIGNER,
    } });
    defer allocator.free(json);
    try testing.expect(std.mem.indexOf(u8, json, "\"pv\":4") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"suite_prefs\":[\"aes-gcm-v1\"]") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"pubkey\":\"") != null);

    var result = try decode(allocator, json);
    defer result.deinit();
    try testing.expectEqual(@as(u32, PROTOCOL_VERSION), result.msg.join.pv);
    try testing.expectEqualStrings("ABCD-1234", result.msg.join.room);
    try testing.expectEqual(@as(usize, 1), result.msg.join.suite_prefs.len);
    try testing.expectEqualStrings("aes-gcm-v1", result.msg.join.suite_prefs[0]);
    try testing.expectEqual(@as(usize, PUBKEY_BYTES), result.msg.join.pubkey.len);
    try testing.expectEqualSlices(u8, &TEST_SIGNER, result.msg.join.pubkey);
}

test "encode/decode welcome carries salt + suite (pv:4)" {
    const allocator = testing.allocator;
    const salt = [_]u8{0x42} ** 16;
    const json = try encode(allocator, .{ .welcome = .{
        .salt = &salt,
        .suite = "aes-gcm-v1",
    } });
    defer allocator.free(json);
    try testing.expect(std.mem.indexOf(u8, json, "\"t\":\"welcome\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"pv\":4") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"suite\":\"aes-gcm-v1\"") != null);

    var result = try decode(allocator, json);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 16), result.msg.welcome.salt.len);
    try testing.expectEqualSlices(u8, &salt, result.msg.welcome.salt);
    try testing.expectEqualStrings("aes-gcm-v1", result.msg.welcome.suite);
}

test "decode welcome with wrong-length salt → InvalidField" {
    const allocator = testing.allocator;
    // 8-byte salt encoded → "AAAAAAAAAAA=" (8 zero bytes base64'd is 12 chars
    // with padding, decoding to 8 bytes). The decoder rejects anything that
    // doesn't decode to exactly 16 bytes.
    const json = "{\"t\":\"welcome\",\"pv\":4,\"salt\":\"AAAAAAAAAAA=\",\"suite\":\"aes-gcm-v1\"}";
    try testing.expectError(error.InvalidField, decode(allocator, json));
}

test "decode welcome missing pv → UnknownProtocolVersion" {
    const allocator = testing.allocator;
    // 16-byte salt of 0x42 → "QkJCQkJCQkJCQkJCQkJCQg==" (24 base64 chars).
    try testing.expectError(
        error.UnknownProtocolVersion,
        decode(allocator, "{\"t\":\"welcome\",\"salt\":\"QkJCQkJCQkJCQkJCQkJCQg==\",\"suite\":\"aes-gcm-v1\"}"),
    );
}

test "decode welcome missing suite → MissingField" {
    const allocator = testing.allocator;
    try testing.expectError(
        error.MissingField,
        decode(allocator, "{\"t\":\"welcome\",\"pv\":4,\"salt\":\"QkJCQkJCQkJCQkJCQkJCQg==\"}"),
    );
}

test "decode join missing suite_prefs → MissingField" {
    const allocator = testing.allocator;
    const json = "{\"t\":\"join\",\"pv\":4,\"room\":\"ABCD-1234\",\"name\":\"Alice\",\"peer\":\"cccccccccccccccccccccccccccccccc\"}";
    try testing.expectError(error.MissingField, decode(allocator, json));
}

test "decode join with too many suite_prefs → BatchTooLarge" {
    const allocator = testing.allocator;
    // 9 entries — over MAX_SUITE_PREFS=8.
    const json = "{\"t\":\"join\",\"pv\":4,\"room\":\"ABCD-1234\",\"name\":\"A\",\"peer\":\"00000000000000000000000000000000\",\"suite_prefs\":[\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\",\"h\",\"i\"]}";
    try testing.expectError(error.BatchTooLarge, decode(allocator, json));
}

test "decode welcome missing salt → MissingField" {
    const allocator = testing.allocator;
    try testing.expectError(
        error.MissingField,
        decode(allocator, "{\"t\":\"welcome\",\"pv\":4,\"suite\":\"aes-gcm-v1\"}"),
    );
}

test "decode welcome with overlong suite → InvalidField" {
    const allocator = testing.allocator;
    // 33-char suite name (over MAX_SUITE_NAME_LEN=32).
    const json = "{\"t\":\"welcome\",\"pv\":4,\"salt\":\"QkJCQkJCQkJCQkJCQkJCQg==\",\"suite\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}";
    try testing.expectError(error.InvalidField, decode(allocator, json));
}

test "decode welcome with ANSI-escape in suite → InvalidField" {
    // Closes security panel M-4: a hostile suite name containing
    // control characters / ANSI escapes must be rejected before it
    // can pollute logs.
    const allocator = testing.allocator;
    const json = "{\"t\":\"welcome\",\"pv\":4,\"salt\":\"QkJCQkJCQkJCQkJCQkJCQg==\",\"suite\":\"aes\\u001b[2J\"}";
    try testing.expectError(error.InvalidField, decode(allocator, json));
}

test "decode join with empty suite_prefs entry → InvalidField" {
    // Closes security panel L-2: empty-string entries must be rejected
    // alongside oversize entries.
    const allocator = testing.allocator;
    const json = "{\"t\":\"join\",\"pv\":4,\"room\":\"ABCD-1234\",\"name\":\"A\",\"peer\":\"00000000000000000000000000000000\",\"suite_prefs\":[\"\"]}";
    try testing.expectError(error.InvalidField, decode(allocator, json));
}

test "decode op with pv:1 → UnknownProtocolVersion" {
    // Closes coverage panel gap 6: explicit pv:1 case (previously only
    // pv:2 + pv:99 were tested).
    const allocator = testing.allocator;
    try testing.expectError(
        error.UnknownProtocolVersion,
        decode(allocator, "{\"t\":\"op\",\"pv\":1,\"ch\":\"unified-model\",\"payload\":\"e30=\"}"),
    );
}

test "decode op with pv:3 → UnknownProtocolVersion" {
    // B1 wire bump: pv:3 (A2-era) is rejected by pv:4-built peers. No
    // silent downgrade — a pv:3 peer must upgrade to interop with B1.
    const allocator = testing.allocator;
    try testing.expectError(
        error.UnknownProtocolVersion,
        decode(allocator, "{\"t\":\"op\",\"pv\":3,\"ch\":\"unified-model\",\"payload\":\"e30=\"}"),
    );
}

test "encode/decode error" {
    const allocator = testing.allocator;
    const json = try encode(allocator, .{ .@"error" = .{ .message = "room full" } });
    defer allocator.free(json);

    var result = try decode(allocator, json);
    defer result.deinit();
    try testing.expectEqualStrings("room full", result.msg.@"error".message);
}

test "decode invalid message shape" {
    const allocator = testing.allocator;
    try testing.expectError(error.InvalidMessage, decode(allocator, "\"not an object\""));
    try testing.expectError(error.MissingType, decode(allocator, "{}"));
    try testing.expectError(error.UnknownMessageType, decode(allocator, "{\"t\":\"foobar\"}"));
}

test "decode op missing pv → UnknownProtocolVersion" {
    const allocator = testing.allocator;
    try testing.expectError(
        error.UnknownProtocolVersion,
        decode(allocator, "{\"t\":\"op\",\"ch\":\"unified-model\",\"payload\":\"e30=\"}"),
    );
}

test "decode op with pv != 4 → UnknownProtocolVersion" {
    const allocator = testing.allocator;
    try testing.expectError(
        error.UnknownProtocolVersion,
        decode(allocator, "{\"t\":\"op\",\"pv\":99,\"ch\":\"unified-model\",\"payload\":\"e30=\"}"),
    );
    // pv:2 (the legacy pre-encryption version) must also be rejected —
    // no silent downgrade, no plaintext fallback.
    try testing.expectError(
        error.UnknownProtocolVersion,
        decode(allocator, "{\"t\":\"op\",\"pv\":2,\"ch\":\"unified-model\",\"payload\":\"e30=\"}"),
    );
}

test "decode op missing ch → MissingField" {
    const allocator = testing.allocator;
    try testing.expectError(
        error.MissingField,
        decode(allocator, "{\"t\":\"op\",\"pv\":4,\"payload\":\"e30=\"}"),
    );
}

test "decode op with invalid channel name → InvalidChannelName" {
    const allocator = testing.allocator;
    try testing.expectError(
        error.InvalidChannelName,
        decode(allocator, "{\"t\":\"op\",\"pv\":4,\"ch\":\"Bad Channel\",\"payload\":\"e30=\"}"),
    );
}

test "decode op missing payload → MissingField" {
    const allocator = testing.allocator;
    try testing.expectError(
        error.MissingField,
        decode(allocator, "{\"t\":\"op\",\"pv\":4,\"ch\":\"unified-model\"}"),
    );
}

test "decode op with invalid base64 → InvalidBase64" {
    const allocator = testing.allocator;
    // sig + signer fields must be present as strings to get past the
    // up-front MissingField check, but they are not parsed before
    // payload — `decodeBase64Bounded(payload)` fails first. Use empty
    // strings (valid base64 decoding to 0 bytes; harmless).
    try testing.expectError(
        error.InvalidBase64,
        decode(allocator, "{\"t\":\"op\",\"pv\":4,\"ch\":\"unified-model\",\"payload\":\"!!!notbase64!!!\",\"sig\":\"\",\"signer\":\"\"}"),
    );
}

test "decodeBase64Bounded: oversized → PayloadTooLarge" {
    const allocator = testing.allocator;
    // Build a b64 string whose decoded length is > the cap. We use a
    // small custom cap (10 bytes) to keep the test cheap. 12 unpadded
    // base64 chars decode to 9 bytes; 16 decode to 12 bytes — we feed
    // 16 chars to push past the 10-byte cap.
    const b64 = "AAAABBBBCCCCDDDD"; // 16 chars → 12 decoded bytes
    try testing.expectError(error.PayloadTooLarge, decodeBase64Bounded(allocator, b64, 10));
}

test "decodeBase64Bounded: within-cap → success" {
    const allocator = testing.allocator;
    const b64 = "aGVsbG8="; // "hello" (5 bytes)
    const decoded = try decodeBase64Bounded(allocator, b64, MAX_OP_PAYLOAD_BYTES);
    defer allocator.free(decoded);
    try testing.expectEqualStrings("hello", decoded);
}

test "decode frame over MAX_FRAME_BYTES → FrameTooLarge" {
    const allocator = testing.allocator;
    // Allocate exactly the limit + 1 and feed it through. Use a cheap pad.
    const sz = MAX_FRAME_BYTES + 1;
    const oversize = try allocator.alloc(u8, sz);
    defer allocator.free(oversize);
    @memset(oversize, ' ');
    try testing.expectError(error.FrameTooLarge, decode(allocator, oversize));
}

// =============================================================================
// B1 (pv:4) — signed-op + identity-pubkey field tests
// =============================================================================

test "B1: decode op missing sig → MissingField" {
    const allocator = testing.allocator;
    // payload + signer present; sig missing → MissingField. (signer's b64
    // empty is harmless since decode-payload runs first; sig check happens
    // up-front during string-field gathering.)
    try testing.expectError(
        error.MissingField,
        decode(allocator, "{\"t\":\"op\",\"pv\":4,\"ch\":\"unified-model\",\"payload\":\"e30=\",\"signer\":\"\"}"),
    );
}

test "B1: decode op missing signer → MissingField" {
    const allocator = testing.allocator;
    try testing.expectError(
        error.MissingField,
        decode(allocator, "{\"t\":\"op\",\"pv\":4,\"ch\":\"unified-model\",\"payload\":\"e30=\",\"sig\":\"\"}"),
    );
}

test "B1: decode op with wrong-length sig → InvalidField" {
    const allocator = testing.allocator;
    // sig decoded length must be exactly 64. "AAAA" → 3 bytes only.
    // signer is 32 bytes of zero ("A"*43 + "=").
    const json =
        "{\"t\":\"op\",\"pv\":4,\"ch\":\"unified-model\"," ++
        "\"payload\":\"e30=\"," ++
        "\"sig\":\"AAAA\"," ++
        "\"signer\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}";
    try testing.expectError(error.InvalidField, decode(allocator, json));
}

test "B1: decode op with wrong-length signer → InvalidField" {
    const allocator = testing.allocator;
    // signer decoded length must be exactly 32; "AAAA" → 3 bytes.
    // sig is 64 bytes of zero ("A"*86 + "==").
    const json =
        "{\"t\":\"op\",\"pv\":4,\"ch\":\"unified-model\"," ++
        "\"payload\":\"e30=\"," ++
        "\"sig\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"," ++
        "\"signer\":\"AAAA\"}";
    try testing.expectError(error.InvalidField, decode(allocator, json));
}

test "B1: decode join missing pubkey → MissingField" {
    const allocator = testing.allocator;
    const json = "{\"t\":\"join\",\"pv\":4,\"room\":\"R-1\",\"name\":\"A\",\"peer\":\"00000000000000000000000000000000\",\"suite_prefs\":[\"aes-gcm-v1\"]}";
    try testing.expectError(error.MissingField, decode(allocator, json));
}

test "B1: decode join with wrong-length pubkey → InvalidField" {
    const allocator = testing.allocator;
    // pubkey decoded length must be exactly 32. "AAAA" → 3 bytes.
    const json = "{\"t\":\"join\",\"pv\":4,\"room\":\"R-1\",\"name\":\"A\",\"peer\":\"00000000000000000000000000000000\",\"suite_prefs\":[\"aes-gcm-v1\"],\"pubkey\":\"AAAA\"}";
    try testing.expectError(error.InvalidField, decode(allocator, json));
}

test "B1: decode ops with mixed batch shapes → InvalidField" {
    // A pv:4 ops batch is an array of OBJECTS; a bare string entry
    // (legacy pv:3 shape) must be rejected, not silently accepted.
    const allocator = testing.allocator;
    const json =
        "{\"t\":\"ops\",\"pv\":4,\"ch\":\"unified-model\",\"batch\":[\"e30=\"]}";
    try testing.expectError(error.InvalidField, decode(allocator, json));
}

test "B1: decode ops batch missing sig in entry → MissingField" {
    const allocator = testing.allocator;
    const json =
        "{\"t\":\"ops\",\"pv\":4,\"ch\":\"unified-model\",\"batch\":[" ++
        "{\"payload\":\"e30=\",\"signer\":\"\"}]}";
    try testing.expectError(error.MissingField, decode(allocator, json));
}

test "B1: decode under failing allocator — no leaks at every fail point" {
    // Panel C5 / refactoring-expert HIGH: the .op and .ops decode arms
    // use a scoped-errdefer pattern around `decodeBase64Bounded` so that
    // ownership transfers to `owned_bytes` only after a successful
    // `append`. If a LATER alloc inside the loop fails, the bytes
    // already owned by `owned_bytes` are freed by its top-level
    // errdefer — NOT by the scoped one — so we avoid double-free.
    //
    // This sweep drives the decoder under `std.testing.FailingAllocator`
    // configured to fail at every position 0..fail_index from a real
    // 2-entry pv:4 .ops envelope (already verified valid by the round-
    // trip test above). At each fail point the test allocator must
    // report NO LEAK. Single test, two assertions: either decode
    // succeeds (alloc cap large enough) or decode returns an error; in
    // BOTH branches the testing allocator's leak detector is the gate.
    const valid_json =
        "{\"t\":\"ops\",\"pv\":4,\"ch\":\"unified-model\",\"batch\":[" ++
        "{\"payload\":\"e30=\"," ++
        "\"sig\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"," ++
        "\"signer\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}," ++
        "{\"payload\":\"e30=\"," ++
        "\"sig\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"," ++
        "\"signer\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}" ++
        "]}";

    // Probe successive failure points until we find an upper bound that
    // lets the happy path complete — covers every cleanup branch on the
    // way. 64 is comfortably beyond any single decode path's alloc
    // count for this envelope.
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{
            .fail_index = i,
        });
        const fa_allocator = fa.allocator();
        if (decode(fa_allocator, valid_json)) |r| {
            var r_mut = r;
            r_mut.deinit();
        } else |_| {
            // Any error path is acceptable; what we care about is that
            // the testing.allocator parent reports no leak (enforced
            // automatically when the test scope exits AND no manual
            // free is needed beyond the deinit on the success branch).
        }
    }
}
