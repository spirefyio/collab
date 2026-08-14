//! Peer identity on the wire: 16 raw bytes, carried as exactly 32 hex
//! characters.
//!
//! ONE PARSER, ONE CONTRACT (#382 C-1). Four call sites used to hand-roll this
//! decode — `protocol.zig` for `.join` and `.leave`, `crdt_lww_map.zig` for op
//! bytes and for snapshot fields — and all four shared the same defect, because
//! all four were the same three lines copied:
//!
//!     var peer_id: [16]u8 = undefined;
//!     _ = std.fmt.hexToBytes(&peer_id, hex) catch ...;
//!
//! `std.fmt.hexToBytes` rejects odd-length, over-long, and non-hex input. It
//! does NOT reject a SHORT even-length string: `""` writes zero bytes and
//! returns an empty slice with no error. The written length was discarded at
//! every site, so `"p":""` or `"peer":"00"` left most of a 16-byte identity as
//! undefined stack memory — a different value on every receiver, from
//! byte-identical signed input.
//!
//! What that buys an attacker depends on the site. On `.join` the parsed id
//! becomes the connection's tracked identity and the key of the
//! `peer_pubkeys` map, so an undefined id is an unpredictable map key. On an
//! op it is the LWW tiebreaker AND the studio's per-peer fairness bucket, so
//! two receivers can disagree about which of two concurrent writes won —
//! divergence with no message lost and nothing logged.
//!
//! The encode side was already canonical (`json_util.writeHex`); this is its
//! missing counterpart.

const std = @import("std");

/// Raw peer identity width, in bytes.
pub const LEN: usize = 16;

/// Wire width, in hex characters. Always `LEN * 2` — a peer id is never
/// abbreviated, zero-padded short, or elided on the wire, so anything of a
/// different length is malformed rather than lenient.
pub const HEX_LEN: usize = LEN * 2;

/// A peer identity. Type alias, not a distinct type: `[16]u8` sites across the
/// tree are already this, and a mechanical sweep to the name is cosmetic and
/// out of scope here.
pub const PeerId = [LEN]u8;

pub const ParseError = error{InvalidPeerId};

/// Parse exactly `HEX_LEN` hex characters into a peer id.
///
/// The length check is the entire point of this function. Do not "simplify" it
/// away on the grounds that `hexToBytes` validates its input — it validates
/// every property except the one that mattered.
pub fn parseHex(hex: []const u8) ParseError!PeerId {
    if (hex.len != HEX_LEN) return error.InvalidPeerId;

    var out: PeerId = undefined;
    const written = std.fmt.hexToBytes(&out, hex) catch return error.InvalidPeerId;

    // Unreachable given the length check above. Asserted rather than discarded
    // because discarding this exact value is what made the four copies wrong,
    // and a future refactor that loosens the check should fail here loudly
    // instead of silently returning undefined bytes again.
    if (written.len != LEN) return error.InvalidPeerId;

    return out;
}

// =============================================================================
// Witnesses
// =============================================================================

test "parseHex: a well-formed id round-trips" {
    const id = try parseHex("0102030405060708090a0b0c0d0e0f10");
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
        &id,
    );
}

test "parseHex: short even-length hex is REFUSED, not silently accepted" {
    // The #382 C-1 defect, stated as a test. Each of these is even-length and
    // valid hex, so `std.fmt.hexToBytes` accepts every one of them and writes
    // FEWER than 16 bytes, leaving the rest of the array undefined.
    const hostile = [_][]const u8{
        "", // writes 0 bytes — all 16 undefined
        "00", // writes 1
        "aabb", // writes 2
        "0102030405060708090a0b0c0d0e0f", // writes 15 — one byte short
    };
    for (hostile) |hex| {
        try std.testing.expectError(error.InvalidPeerId, parseHex(hex));

        // And measure the counterfactual: the raw call the old code made
        // accepts it and reports how little it wrote.
        var raw: PeerId = undefined;
        const written = std.fmt.hexToBytes(&raw, hex) catch unreachable;
        try std.testing.expect(written.len < LEN);
    }
}

test "parseHex: over-long, odd-length, and non-hex are refused" {
    try std.testing.expectError(
        error.InvalidPeerId,
        parseHex("0102030405060708090a0b0c0d0e0f1011"), // 34 chars
    );
    try std.testing.expectError(error.InvalidPeerId, parseHex("0" ** 31)); // odd
    try std.testing.expectError(error.InvalidPeerId, parseHex("z" ** 32)); // non-hex
}
