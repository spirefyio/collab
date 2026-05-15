//! Wire Encryption for Collaboration (Tier 1 — shared room secret)
//!
//! Key derivation: room_code + session_salt → AES-256-GCM key via HKDF.
//! The relay sees only opaque encrypted blobs.
//! Salt is exchanged during join handshake (in the clear — prevents precomputation).
//!
//! ## Trust model (be honest about what this is and is not)
//!
//! This is NOT true end-to-end encryption in the usual sense (per-user
//! public keys, forward secrecy, authenticated handshake). It is symmetric
//! AES-256-GCM with a key derived from a shared room secret that every peer
//! types in to join. The threat model it actually defends against:
//!
//!   * Relay / man-in-the-middle WITHOUT the room code → opaque ciphertext,
//!     cannot decrypt or forge ops. (This is real and load-bearing.)
//!   * Bystander on the same network without the code → same protection.
//!
//! What it does NOT defend against (Tier 2 follow-ups):
//!
//!   * Compromised peer (someone with the code is fully trusted; matches the
//!     CRDT-1 v1 "trust every peer in the room" posture documented in
//!     CLAUDE.md "Real-time collab (CRDT)").
//!   * Per-message authenticity beyond GCM's symmetric tag — any peer with
//!     the key can forge any other peer's edits indistinguishably. There is
//!     no per-peer signing yet.
//!   * Forward secrecy — the room key is stable for the session lifetime.
//!     A future replay of captured ciphertext after the code is shared post
//!     hoc would decrypt.
//!
//! TODO(Tier2): introduce per-peer Ed25519 keypairs + signed ops so a
//! malicious peer can be detected and pinned, and the bridge can drop their
//! batches at the boundary (mirrors the structural-op deny list pattern).
//! TODO(Tier2): consider a session-key ratchet (Double Ratchet style) once
//! per-peer keys exist, to recover forward secrecy.

const std = @import("std");
const compat = @import("compat");
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

/// Wire-string names for each suite. Kept here so `Suite.fromName` /
/// `Suite.toName` are the single source of truth for the (enum ↔ wire)
/// mapping. `protocol.zig` re-exports these as `SUITE_AES_GCM_V1` /
/// `SUITE_CHACHA_V1` for encoder/decoder use.
pub const SUITE_NAME_AES_GCM_V1: []const u8 = "aes-gcm-v1";
pub const SUITE_NAME_CHACHA_V1: []const u8 = "chacha-v1";

/// AEAD suites this build understands. Both ship with 256-bit keys,
/// 96-bit nonces, and 128-bit tags — the wire envelope shape
/// (`nonce ‖ ciphertext ‖ tag`) and the `AEAD_OVERHEAD` constant are
/// identical across all members. A future suite with different sizes
/// MUST update `AEAD_OVERHEAD` to be a per-suite function, not a const.
pub const Suite = enum {
    aes_gcm_v1,
    chacha_v1,

    /// Parse a wire-string suite name into an enum value. Returns null
    /// for any unknown name — callers convert that to `error.UnknownSuite`
    /// at their boundary. The lookup is closed-set: adding a suite
    /// requires editing this function, so a typo on the wire cannot
    /// accidentally match a half-implemented suite.
    pub fn fromName(name: []const u8) ?Suite {
        if (std.mem.eql(u8, name, SUITE_NAME_AES_GCM_V1)) return .aes_gcm_v1;
        if (std.mem.eql(u8, name, SUITE_NAME_CHACHA_V1)) return .chacha_v1;
        return null;
    }

    /// Render an enum value as the wire-string suite name. Inverse of
    /// `fromName`. The return value is a static string literal (no
    /// allocation); safe to embed directly in encoded JSON.
    pub fn toName(self: Suite) []const u8 {
        return switch (self) {
            .aes_gcm_v1 => SUITE_NAME_AES_GCM_V1,
            .chacha_v1 => SUITE_NAME_CHACHA_V1,
        };
    }
};

/// Encryption context for a session.
///
/// Carries the AEAD suite + a 256-bit symmetric key. Both `aes_gcm_v1`
/// and `chacha_v1` share the same key/nonce/tag layout, so the wire
/// shape (`AEAD_OVERHEAD = 28`) is independent of suite.
///
/// The suite is fixed at `init` time. Re-keying or re-suiting an existing
/// context is intentionally NOT supported — that would silently break
/// every in-flight encrypt/decrypt. To change suite, deinit + init fresh.
pub const CryptoContext = struct {
    suite: Suite,
    key: [32]u8,

    /// Derive encryption key from room code and session salt under the
    /// given suite. The HKDF info string is suite-agnostic — the suite
    /// only changes which AEAD primitive consumes the key in
    /// `encrypt`/`decrypt`, not how the key is derived. This means
    /// two peers MUST agree on the suite via the welcome handshake;
    /// deriving the same key under different suites would yield
    /// incompatible ciphertext.
    pub fn init(suite: Suite, room_code: []const u8, salt: [16]u8) CryptoContext {
        // HKDF: extract from room_code using salt, then expand with context info
        const prk = HkdfSha256.extract(&salt, room_code);
        var key: [32]u8 = undefined;
        HkdfSha256.expand(&key, "spirefy-collab-v1", prk);
        return .{ .suite = suite, .key = key };
    }

    /// Encrypt plaintext, binding `aad` (Additional Authenticated Data) into
    /// the GCM tag. The AAD is not encrypted — it's authenticated. A receiver
    /// passing different AAD to `decrypt` will fail the tag check.
    ///
    /// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes).
    /// Caller owns returned memory.
    ///
    /// AAD policy: every collab call site MUST pass the channel name
    /// (e.g. `"unified-model"`) as AAD. This binds the ciphertext to its
    /// channel slot, so a peer (or hostile relay) cannot replay a ciphertext
    /// from one channel into another channel's envelope. v1 has one channel
    /// so the binding is structurally redundant, but A2's editor-text and
    /// future channels rely on it; landing the contract now avoids a
    /// pv:4 break later. See security-panel finding H-1 (2026-05-14).
    pub fn encrypt(
        self: *const CryptoContext,
        allocator: std.mem.Allocator,
        plaintext: []const u8,
        aad: []const u8,
    ) ![]u8 {
        // Both supported suites share 12-byte nonce + 16-byte tag (so
        // `AEAD_OVERHEAD = 28` is suite-agnostic). The constants come
        // from AES-GCM for naming familiarity; comptime-asserted below.
        const nonce_len = Aes256Gcm.nonce_length; // 12
        const tag_len = Aes256Gcm.tag_length; // 16
        comptime {
            std.debug.assert(ChaCha20Poly1305.nonce_length == nonce_len);
            std.debug.assert(ChaCha20Poly1305.tag_length == tag_len);
            std.debug.assert(ChaCha20Poly1305.key_length == 32);
        }
        const total = nonce_len + plaintext.len + tag_len;

        var output = try allocator.alloc(u8, total);
        errdefer allocator.free(output);

        // Generate random nonce. 96-bit CSPRNG nonce; birthday-bound at
        // ~2^32 encryptions per key. v1 sessions are unbounded — a busy
        // editor-text channel at 100 ops/sec hits the bound in ~500 days.
        // Tier-2 follow-up: session-lifetime op counter + forced
        // re-handshake before 2^31 ops (tracked in plan file).
        const nonce: *[nonce_len]u8 = output[0..nonce_len];
        compat.io().random(nonce);

        // Encrypt: plaintext → ciphertext (same length) + tag bound to AAD.
        var tag: [tag_len]u8 = undefined;
        const ciphertext = output[nonce_len .. nonce_len + plaintext.len];
        switch (self.suite) {
            .aes_gcm_v1 => Aes256Gcm.encrypt(ciphertext, &tag, plaintext, aad, nonce.*, self.key),
            .chacha_v1 => ChaCha20Poly1305.encrypt(ciphertext, &tag, plaintext, aad, nonce.*, self.key),
        }

        // Append tag
        @memcpy(output[nonce_len + plaintext.len ..], &tag);

        return output;
    }

    /// Decrypt ciphertext (nonce || ciphertext || tag format), verifying
    /// the GCM tag against `aad`. The receiver MUST pass the SAME AAD the
    /// sender used; mismatched AAD returns `error.DecryptionFailed`.
    ///
    /// Returns plaintext. Caller owns returned memory.
    pub fn decrypt(
        self: *const CryptoContext,
        allocator: std.mem.Allocator,
        encrypted: []const u8,
        aad: []const u8,
    ) ![]u8 {
        const nonce_len = Aes256Gcm.nonce_length;
        const tag_len = Aes256Gcm.tag_length;

        if (encrypted.len < nonce_len + tag_len) return error.InvalidCiphertext;

        const nonce: *const [nonce_len]u8 = encrypted[0..nonce_len];
        const plaintext_len = encrypted.len - nonce_len - tag_len;
        const ciphertext = encrypted[nonce_len .. nonce_len + plaintext_len];
        const tag: *const [tag_len]u8 = encrypted[nonce_len + plaintext_len ..][0..tag_len];

        const plaintext = try allocator.alloc(u8, plaintext_len);
        errdefer allocator.free(plaintext);

        switch (self.suite) {
            .aes_gcm_v1 => Aes256Gcm.decrypt(plaintext, ciphertext, tag.*, aad, nonce.*, self.key) catch {
                return error.DecryptionFailed;
            },
            .chacha_v1 => ChaCha20Poly1305.decrypt(plaintext, ciphertext, tag.*, aad, nonce.*, self.key) catch {
                return error.DecryptionFailed;
            },
        }

        return plaintext;
    }

    /// Zero out the key material defensively against dead-store-elimination.
    /// A naive `@memset` is DCE-able by the optimizer (the field is never
    /// read after deinit). `std.crypto.secureZero` uses volatile semantics
    /// to defeat DCE. See security-panel M-1 (2026-05-14).
    pub fn deinit(self: *CryptoContext) void {
        std.crypto.secureZero(u8, &self.key);
    }
};

/// AEAD overhead per encrypt: 12-byte nonce + 16-byte tag = 28 bytes.
/// Callers gate plaintext size against the wire cap (MAX_OP_PAYLOAD_BYTES,
/// MAX_SNAPSHOT_BYTES) BEFORE encrypt to avoid mid-send rejection.
pub const AEAD_OVERHEAD: usize = Aes256Gcm.nonce_length + Aes256Gcm.tag_length;

/// Generate a random session salt (16 bytes).
pub fn generateSalt() [16]u8 {
    var salt: [16]u8 = undefined;
    compat.io().random(&salt);
    return salt;
}

/// Generate a room code: 8 uppercase alphanumeric chars in XXXX-XXXX format.
/// The alphabet excludes 0/O/1/I to keep auto-generated codes unambiguous
/// when read aloud or typed. Custom user-typed codes are NOT restricted to
/// this set — see `session.zig` `isValidRoomCode` for the validation rules.
pub fn generateRoomCode() [9]u8 {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I confusion
    var code: [9]u8 = undefined;
    var rand_bytes: [8]u8 = undefined;
    compat.io().random(&rand_bytes);

    var out_idx: usize = 0;
    for (rand_bytes, 0..) |b, i| {
        if (i == 4) {
            code[out_idx] = '-';
            out_idx += 1;
        }
        code[out_idx] = chars[b % chars.len];
        out_idx += 1;
    }

    return code;
}

// =============================================================================
// Tests
// =============================================================================

test "CryptoContext: encrypt/decrypt round-trip with AAD (aes-gcm-v1)" {
    const allocator = std.testing.allocator;
    const salt = generateSalt();
    var ctx = CryptoContext.init(.aes_gcm_v1, "ABCD-1234", salt);
    defer ctx.deinit();

    const plaintext = "hello world, this is a CRDT operation";
    const aad = "unified-model";
    const encrypted = try ctx.encrypt(allocator, plaintext, aad);
    defer allocator.free(encrypted);

    // Encrypted should be larger (nonce + tag overhead)
    try std.testing.expect(encrypted.len == plaintext.len + AEAD_OVERHEAD);

    const decrypted = try ctx.decrypt(allocator, encrypted, aad);
    defer allocator.free(decrypted);
    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "CryptoContext: encrypt/decrypt round-trip with AAD (chacha-v1)" {
    // A2 parity test: same round-trip property under ChaCha20-Poly1305.
    const allocator = std.testing.allocator;
    const salt = generateSalt();
    var ctx = CryptoContext.init(.chacha_v1, "ABCD-1234", salt);
    defer ctx.deinit();

    const plaintext = "hello world, this is a CRDT operation";
    const aad = "unified-model";
    const encrypted = try ctx.encrypt(allocator, plaintext, aad);
    defer allocator.free(encrypted);

    // Wire overhead is identical to AES-GCM (12 nonce + 16 tag).
    try std.testing.expect(encrypted.len == plaintext.len + AEAD_OVERHEAD);

    const decrypted = try ctx.decrypt(allocator, encrypted, aad);
    defer allocator.free(decrypted);
    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "CryptoContext: cross-suite decryption fails" {
    // Critical A2 invariant: a ciphertext produced under one suite MUST
    // NOT decrypt under a different suite, even when key + nonce + AAD
    // are otherwise identical. The two AEADs are mathematically distinct
    // — ChaCha20-Poly1305 reading AES-GCM output gets garbage at best
    // and a tag-mismatch at worst. This is the test that catches a
    // future regression where someone "factors out" the dispatch and
    // accidentally hardcodes one primitive in both encrypt and decrypt.
    const allocator = std.testing.allocator;
    const salt = [_]u8{0x42} ** 16; // identical salt so the two ctxs share a key
    var aes = CryptoContext.init(.aes_gcm_v1, "room", salt);
    defer aes.deinit();
    var cha = CryptoContext.init(.chacha_v1, "room", salt);
    defer cha.deinit();
    try std.testing.expectEqualSlices(u8, &aes.key, &cha.key);

    // Encrypt under AES; attempt decrypt under ChaCha → fail.
    const encrypted = try aes.encrypt(allocator, "plaintext", "aad");
    defer allocator.free(encrypted);
    try std.testing.expectError(
        error.DecryptionFailed,
        cha.decrypt(allocator, encrypted, "aad"),
    );

    // And the reverse: ChaCha-encrypted bytes fail under AES.
    const encrypted2 = try cha.encrypt(allocator, "plaintext", "aad");
    defer allocator.free(encrypted2);
    try std.testing.expectError(
        error.DecryptionFailed,
        aes.decrypt(allocator, encrypted2, "aad"),
    );
}

test "Suite: fromName / toName round-trip" {
    try std.testing.expectEqual(Suite.aes_gcm_v1, Suite.fromName("aes-gcm-v1").?);
    try std.testing.expectEqual(Suite.chacha_v1, Suite.fromName("chacha-v1").?);
    try std.testing.expect(Suite.fromName("pq-hybrid-v1") == null);
    try std.testing.expect(Suite.fromName("") == null);
    try std.testing.expect(Suite.fromName("aes-gcm-v2") == null);

    try std.testing.expectEqualStrings("aes-gcm-v1", Suite.aes_gcm_v1.toName());
    try std.testing.expectEqualStrings("chacha-v1", Suite.chacha_v1.toName());

    // Round-trip: every variant survives a toName → fromName cycle.
    inline for (.{ Suite.aes_gcm_v1, Suite.chacha_v1 }) |s| {
        try std.testing.expectEqual(s, Suite.fromName(s.toName()).?);
    }
}

test "CryptoContext: AAD mismatch fails decryption (both suites)" {
    const allocator = std.testing.allocator;
    inline for (.{ Suite.aes_gcm_v1, Suite.chacha_v1 }) |suite| {
        const salt = generateSalt();
        var ctx = CryptoContext.init(suite, "ABCD-1234", salt);
        defer ctx.deinit();

        const plaintext = "channel-bound message";
        const encrypted = try ctx.encrypt(allocator, plaintext, "unified-model");
        defer allocator.free(encrypted);

        // Decrypting with a DIFFERENT channel name as AAD must fail —
        // this is the channel-binding invariant that prevents cross-channel
        // ciphertext replay (security-panel H-1).
        try std.testing.expectError(
            error.DecryptionFailed,
            ctx.decrypt(allocator, encrypted, "editor-text"),
        );
    }
}

test "CryptoContext: same plaintext yields different ciphertext (nonce randomness)" {
    // Closes security-panel L-1 / quality-panel design M-4: assert
    // fresh CSPRNG nonces per encrypt so a future regression that
    // hard-codes the nonce would be caught.
    const allocator = std.testing.allocator;
    inline for (.{ Suite.aes_gcm_v1, Suite.chacha_v1 }) |suite| {
        const salt = generateSalt();
        var ctx = CryptoContext.init(suite, "room", salt);
        defer ctx.deinit();

        const plaintext = "deterministic-looking input";
        const enc1 = try ctx.encrypt(allocator, plaintext, "ch");
        defer allocator.free(enc1);
        const enc2 = try ctx.encrypt(allocator, plaintext, "ch");
        defer allocator.free(enc2);

        try std.testing.expect(!std.mem.eql(u8, enc1, enc2));
        // But both decrypt to the same plaintext.
        const pt1 = try ctx.decrypt(allocator, enc1, "ch");
        defer allocator.free(pt1);
        const pt2 = try ctx.decrypt(allocator, enc2, "ch");
        defer allocator.free(pt2);
        try std.testing.expectEqualStrings(pt1, pt2);
    }
}

test "CryptoContext: different keys produce different ciphertext" {
    const allocator = std.testing.allocator;
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    var ctx1 = CryptoContext.init(.aes_gcm_v1, "room-a", salt1);
    defer ctx1.deinit();
    var ctx2 = CryptoContext.init(.aes_gcm_v1, "room-b", salt2);
    defer ctx2.deinit();

    const plaintext = "same plaintext";
    const enc1 = try ctx1.encrypt(allocator, plaintext, "");
    defer allocator.free(enc1);
    const enc2 = try ctx2.encrypt(allocator, plaintext, "");
    defer allocator.free(enc2);

    // Different keys/nonces → different ciphertext
    try std.testing.expect(!std.mem.eql(u8, enc1, enc2));
}

test "CryptoContext: wrong key fails decryption" {
    const allocator = std.testing.allocator;
    const salt = generateSalt();
    var ctx1 = CryptoContext.init(.aes_gcm_v1, "correct-room", salt);
    defer ctx1.deinit();
    var ctx2 = CryptoContext.init(.aes_gcm_v1, "wrong-room", salt);
    defer ctx2.deinit();

    const encrypted = try ctx1.encrypt(allocator, "secret", "ch");
    defer allocator.free(encrypted);

    try std.testing.expectError(
        error.DecryptionFailed,
        ctx2.decrypt(allocator, encrypted, "ch"),
    );
}

test "CryptoContext: same room+salt produce same key (suite-independent)" {
    // HKDF is suite-agnostic — only encrypt/decrypt branch on suite.
    // So two ctxs over the same room+salt+different-suite have the
    // SAME key; only the AEAD primitive differs.
    const salt = [_]u8{0x42} ** 16;
    const ctx1 = CryptoContext.init(.aes_gcm_v1, "ABCD-1234", salt);
    const ctx2 = CryptoContext.init(.aes_gcm_v1, "ABCD-1234", salt);
    const ctx3 = CryptoContext.init(.chacha_v1, "ABCD-1234", salt);
    try std.testing.expectEqualSlices(u8, &ctx1.key, &ctx2.key);
    try std.testing.expectEqualSlices(u8, &ctx1.key, &ctx3.key);
}

test "CryptoContext: empty plaintext (both suites)" {
    const allocator = std.testing.allocator;
    inline for (.{ Suite.aes_gcm_v1, Suite.chacha_v1 }) |suite| {
        const salt = generateSalt();
        var ctx = CryptoContext.init(suite, "room", salt);
        defer ctx.deinit();

        const encrypted = try ctx.encrypt(allocator, "", "ch");
        defer allocator.free(encrypted);
        try std.testing.expectEqual(@as(usize, AEAD_OVERHEAD), encrypted.len);

        const decrypted = try ctx.decrypt(allocator, encrypted, "ch");
        defer allocator.free(decrypted);
        try std.testing.expectEqual(@as(usize, 0), decrypted.len);
    }
}

test "CryptoContext: truncated ciphertext rejected" {
    const allocator = std.testing.allocator;
    const salt = generateSalt();
    var ctx = CryptoContext.init(.aes_gcm_v1, "room", salt);
    defer ctx.deinit();

    // Too short to contain nonce + tag
    try std.testing.expectError(error.InvalidCiphertext, ctx.decrypt(allocator, "short", ""));
}

test "generateRoomCode: format XXXX-XXXX" {
    const code = generateRoomCode();
    try std.testing.expectEqual(@as(usize, 9), code.len);
    try std.testing.expectEqual(@as(u8, '-'), code[4]);

    // All chars should be alphanumeric (no 0, O, 1, I)
    for (code, 0..) |c, i| {
        if (i == 4) continue;
        try std.testing.expect(std.ascii.isAlphanumeric(c));
    }
}
