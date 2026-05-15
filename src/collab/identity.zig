//! Per-peer cryptographic identity for Spirefy collab.
//!
//! B1 introduces an Ed25519 keypair per local install. Every outbound CRDT
//! op is signed with this key BEFORE encryption; every inbound op is
//! verified against the originator's published pubkey BEFORE `applyRemote`.
//! This closes the v1 "any peer with the room key can forge any other
//! peer's edits" gap documented in `crypto.zig`'s Tier-2 TODO.
//!
//! ## Threat model — what B1 defends against
//!
//! A peer that has joined a session but does NOT hold any other peer's
//! Ed25519 private key cannot:
//!   - Forge an op that appears to come from another peer (would need
//!     that peer's secret key to produce a valid signature).
//!   - Tamper with another peer's op in transit (any byte flip
//!     invalidates the signature).
//!   - Inject an op with no signer field (rejected at the verify gate).
//!
//! ## What B1 does NOT defend against (Tier-2 scope)
//!
//!   - **Replay**: a peer that records signed ops and replays them later.
//!     The signature is still valid. CRDT idempotency means the replay
//!     is harmless for the unified-model channel (same op_bytes →
//!     LWW resolves identically), but future channels (text editor) MUST
//!     gate replays via a per-(peer, op_id) monotonic counter. Tracked
//!     in plan's "replay protection" Tier-2 follow-up.
//!   - **Key loss = locked out**. Phase C2 social-recovery + multi-device
//!     are out of scope here. If a user deletes their `peer.key` they
//!     get a fresh identity; old workspaces don't recognize them.
//!   - **OS keychain integration**. B1 ships with file-based storage at
//!     `$XDG_CONFIG_HOME/spirefy/identity/peer.key` (0600). B2 (Team
//!     feature) is when keychain integration lands per the plan.
//!
//! ## Why Ed25519 specifically
//!
//! Fast sign (~30µs) + fast verify (~100µs) per op on commodity x86_64.
//! Small wire footprint: 32-byte pubkey + 64-byte signature per op
//! (vs. ECDSA P-256 sig at 70+ bytes DER-encoded). Constant-time by
//! design (no timing oracle for the secret). Well-vetted in std.crypto.
//! No external dependency, pure Zig.
//!
//! ## Module layout (current scope-tightening)
//!
//! Lives under `src/collab/` for B1 because identity is consumed ONLY by
//! the collab module today. When B2 (Team) lands and introduces external
//! account binding, this should be promoted to a top-level `src/identity/`
//! module per the plan file. The current placement keeps build.zig
//! diff-free while the API is still settling.

const std = @import("std");
const compat = @import("compat");
const Ed25519 = std.crypto.sign.Ed25519;

/// 32-byte Ed25519 public key. Stable wire shape — embedded in `join`
/// envelopes as base64 and shared with every peer in the room.
pub const PUBKEY_LEN: usize = Ed25519.PublicKey.encoded_length;

/// 64-byte Ed25519 secret key (seed + cached pubkey). Stored on disk
/// at `peer.key`. NEVER transmitted over the wire.
pub const SECRET_LEN: usize = Ed25519.SecretKey.encoded_length;

/// 64-byte Ed25519 signature. Embedded per-op as base64 in pv:4
/// envelopes.
pub const SIG_LEN: usize = Ed25519.Signature.encoded_length;

/// A loaded or freshly-generated identity. Owns no allocations — the
/// keypair is a value type. The owning `CollabManager` calls `deinit`
/// at shutdown to zero the secret material.
pub const Identity = struct {
    keypair: Ed25519.KeyPair,

    /// Generate a fresh Ed25519 identity from the OS CSPRNG. Callers
    /// MUST persist the result via `saveTo` if they want it to survive
    /// process restart — a process-only identity is fine for tests but
    /// loses workspace continuity across launches.
    pub fn generate() Identity {
        return .{ .keypair = Ed25519.KeyPair.generate(compat.io()) };
    }

    /// Reconstruct an identity from a 64-byte secret-key blob (the
    /// shape `peer.key` stores on disk). The pubkey is derived from
    /// the secret deterministically — no separate pubkey field needed
    /// on disk.
    pub fn fromSecretBytes(secret_bytes: [SECRET_LEN]u8) !Identity {
        const sk = try Ed25519.SecretKey.fromBytes(secret_bytes);
        const kp = try Ed25519.KeyPair.fromSecretKey(sk);
        return .{ .keypair = kp };
    }

    /// Sign a message with this identity. Returns the 64-byte signature
    /// as a fixed-size array (no allocation). Callers serialize via
    /// `std.base64` when embedding in the wire envelope.
    ///
    /// AAD policy: the message MUST be the PLAINTEXT op_bytes (BEFORE
    /// AEAD encryption). Signing ciphertext would weaken the binding —
    /// the signature would prove "this peer encrypted this ciphertext"
    /// instead of "this peer authored this op". Plaintext signing is
    /// what the verify gate in `manager.zig` reverses on receive.
    pub fn sign(self: *const Identity, msg: []const u8) ![SIG_LEN]u8 {
        const sig = try self.keypair.sign(msg, null);
        return sig.toBytes();
    }

    /// Return this identity's 32-byte public key (suitable for wire
    /// transmission via base64). Cheap — just slices the keypair's
    /// cached pubkey bytes.
    pub fn publicKeyBytes(self: *const Identity) [PUBKEY_LEN]u8 {
        return self.keypair.public_key.toBytes();
    }

    /// Zero the secret key material. Safe to call multiple times.
    /// `compat`-style: defeats DCE on the final write so a memory dump
    /// after shutdown does not yield the seed.
    pub fn deinit(self: *Identity) void {
        std.crypto.secureZero(u8, &self.keypair.secret_key.bytes);
    }
};

/// Verify a signature against a 32-byte pubkey. Returns true iff the
/// signature is well-formed AND validates over `msg` under `pubkey_bytes`.
/// Any error path (malformed pubkey, malformed sig, non-canonical s,
/// tag mismatch) collapses to `false` — the caller's interest is binary
/// (accept op vs drop op), and propagating crypto-internal errors to the
/// hot-path manager would leak information about exact failure mode.
pub fn verify(sig_bytes: [SIG_LEN]u8, msg: []const u8, pubkey_bytes: [PUBKEY_LEN]u8) bool {
    const pk = Ed25519.PublicKey.fromBytes(pubkey_bytes) catch return false;
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    sig.verify(msg, pk) catch return false;
    return true;
}

// =============================================================================
// File-based keystore
// =============================================================================

/// Default relative path under the user's config directory.
/// `$XDG_CONFIG_HOME/spirefy/identity/peer.key` on Linux;
/// `~/Library/Application Support/spirefy/identity/peer.key` on macOS;
/// `%APPDATA%\spirefy\identity\peer.key` on Windows (paths resolved
/// at runtime by `defaultPeerKeyPath`).
pub const SPIREFY_DIR_NAME: []const u8 = "spirefy";
pub const IDENTITY_DIR_NAME: []const u8 = "identity";
pub const KEY_FILENAME: []const u8 = "peer.key";

/// Resolve the absolute path to the keystore file for this user. Caller
/// owns the returned slice. On error (no config dir available, e.g.
/// `$HOME` unset in a CI container), returns
/// `error.ConfigDirUnavailable` — caller decides whether to fall back
/// to a process-only identity (tests) or refuse to host (production).
pub fn defaultPeerKeyPath(allocator: std.mem.Allocator) ![]u8 {
    // std.fs.getAppDataDir handles per-OS conventions (XDG / Library
    // Application Support / APPDATA). Adds the appname (`spirefy`)
    // already; we layer `identity/peer.key` on top.
    const app_dir = std.fs.getAppDataDir(allocator, SPIREFY_DIR_NAME) catch {
        return error.ConfigDirUnavailable;
    };
    defer allocator.free(app_dir);

    return std.fs.path.join(allocator, &.{ app_dir, IDENTITY_DIR_NAME, KEY_FILENAME });
}

/// Persist a 64-byte secret key blob to `path` (absolute) with 0600
/// permissions (owner-only on POSIX; no-op on Windows where ACLs
/// differ). Creates parent directories if missing. Overwrites an
/// existing file atomically: writes to `path.tmp` and renames over
/// `path` so a crash mid-write cannot leave a half-written key.
///
/// SECURITY: never log the contents of `secret_bytes`. The 64-byte
/// blob is the FULL secret material from which the pubkey is derived;
/// possession is identity.
pub fn saveSecretBytes(path: []const u8, secret_bytes: [SECRET_LEN]u8) !void {
    const io = compat.io();

    // Ensure parent directory exists; ignore EEXIST. Keystore dir is
    // 0o700 (owner-only) — the file is 0o600 inside it, but a
    // world-readable parent leaks the existence of the keystore and
    // its filename to anyone with directory list permission. Tightened
    // per panel-#1 security HIGH-3 (closes "keystore parent dir
    // world-readable" finding). On Windows the mode bits are a no-op
    // (the enum is `u0`); ACL inheritance from `%APPDATA%` is
    // user-only by default.
    if (std.fs.path.dirname(path)) |parent| {
        const owner_only_dir: std.Io.File.Permissions = .fromMode(0o700);
        std.Io.Dir.createDirAbsolute(io, parent, owner_only_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            // The parent's parent may also be missing; walk up. The
            // recursive walker uses the same 0o700 mode so an intermediate
            // `spirefy/` dir created by us is also owner-only. This is
            // strictly tighter than the previous .default_dir (0o755).
            error.FileNotFound => try createDirAbsoluteRecursive(io, parent),
            else => return err,
        };
    }

    // Write to a sibling tmp file with 0600, fsync to make the bytes
    // durable, then rename over the destination. The rename itself is
    // atomic on every supported OS (POSIX rename(2); Windows NTFS
    // MoveFileEx with REPLACE_EXISTING) — but WITHOUT fsync, a power
    // loss between the write and the post-rename writeback can leave
    // a renamed-but-empty file. fsync before rename closes that gap
    // (panel-#1 backend HIGH).
    var tmp_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try std.fmt.bufPrint(&tmp_path_buf, "{s}.tmp", .{path});

    // Function-scope errdefer for the tmp file: fires on ANY failure
    // between `createFileAbsolute` and `renameAbsolute` (panel-#1
    // refactor HIGH — the previous inner-block errdefer fell out of
    // scope BEFORE rename, so a rename failure left the tmp behind
    // as a 0600-permission leak). `renamed` flips to `true` only
    // once the rename has consumed the tmp file successfully.
    var renamed: bool = false;
    errdefer if (!renamed) {
        std.Io.Dir.deleteFileAbsolute(io, tmp_path) catch {};
    };

    // 0600 = read+write for owner only. On Windows std.fs ignores the
    // bits (ACLs apply separately); the file inherits parent ACLs
    // which by default are user-only under %APPDATA%.
    const file = try std.Io.Dir.createFileAbsolute(io, tmp_path, .{
        .permissions = std.Io.File.Permissions.fromMode(0o600),
    });
    {
        defer file.close(io);
        try file.writeStreamingAll(io, &secret_bytes);
        // fsync the data before rename. Without this, a kernel crash
        // or power loss between `writeStreamingAll` returning and the
        // filesystem journaling the write can leave a renamed-but-
        // empty file — which loadSecretBytes then rejects as
        // `InvalidKeyFile`, silently destroying the user's identity.
        try file.sync(io);
    }

    try std.Io.Dir.renameAbsolute(tmp_path, path, io);
    renamed = true;
}

/// Recursively create absolute directory paths. Used as a fallback when
/// `createDirAbsolute` returns `FileNotFound` — the parent's parent is
/// also missing.
///
/// SECURITY: every directory we create is 0o700 (owner-only). The
/// keystore is owner-only by design and any intermediate directory
/// we create on the way to it MUST also be owner-only — leaving an
/// intermediate `spirefy/` dir at 0o755 would advertise to other
/// local users that this account has a Spirefy install. Tightened
/// per panel-#1 security HIGH-3.
fn createDirAbsoluteRecursive(io: std.Io, abs_dir: []const u8) !void {
    const owner_only_dir: std.Io.File.Permissions = .fromMode(0o700);
    if (std.fs.path.dirname(abs_dir)) |parent| {
        std.Io.Dir.createDirAbsolute(io, parent, owner_only_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            error.FileNotFound => try createDirAbsoluteRecursive(io, parent),
            else => return err,
        };
    }
    std.Io.Dir.createDirAbsolute(io, abs_dir, owner_only_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

/// Read a 64-byte secret key blob from `path` (absolute). Returns
/// `error.FileNotFound` if the file is missing — callers typically
/// treat that as "generate a fresh identity". Any other I/O error
/// propagates. Returns `error.InvalidKeyFile` if the file's length
/// is not exactly `SECRET_LEN` bytes (corrupted, truncated, or a
/// different format).
pub fn loadSecretBytes(path: []const u8) ![SECRET_LEN]u8 {
    const io = compat.io();
    const file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);

    // Read into a buffer that's one byte LARGER than SECRET_LEN so we
    // can detect extra bytes (corruption / future format) in a single
    // read.
    var buf: [SECRET_LEN + 1]u8 = undefined;
    var bufs: [1][]u8 = .{buf[0..]};
    const n = try file.readStreaming(io, &bufs);
    if (n != SECRET_LEN) return error.InvalidKeyFile;

    var out: [SECRET_LEN]u8 = undefined;
    @memcpy(&out, buf[0..SECRET_LEN]);
    return out;
}

/// Load an identity from disk if `path` exists, otherwise generate a
/// fresh one and persist it to `path`. This is the "default behavior"
/// for `CollabManager.init` — every launch ends with a usable identity.
///
/// On `error.ConfigDirUnavailable` (no config dir resolvable), the
/// caller is expected to fall back to a process-only identity via
/// `Identity.generate()`. Production builds should refuse to host
/// in that case (no persistent identity = workspaces can't recognize
/// us across launches), but tests can run anyway.
pub fn loadOrGenerate(allocator: std.mem.Allocator) !Identity {
    const path = try defaultPeerKeyPath(allocator);
    defer allocator.free(path);
    return loadOrGenerateAtPath(path);
}

/// Variant of `loadOrGenerate` that takes an explicit path. Used by
/// tests (writing to a tmp dir) and any future "import this key file"
/// affordance. Allocates nothing.
pub fn loadOrGenerateAtPath(path: []const u8) !Identity {
    if (loadSecretBytes(path)) |bytes| {
        return Identity.fromSecretBytes(bytes) catch |err| {
            // The file exists but doesn't deserialize. Refuse to
            // silently overwrite — that would destroy a possibly-
            // recoverable key. Operator must move the bad file aside.
            std.log.err(
                "collab.identity: '{s}' exists but contains invalid Ed25519 key material: {s}",
                .{ path, @errorName(err) },
            );
            return error.InvalidKeyFile;
        };
    } else |load_err| switch (load_err) {
        error.FileNotFound => {
            // First-launch path: generate + persist. `errdefer id.deinit()`
            // zeroes the freshly-generated secret material on any failure
            // path below — without it, a save failure would propagate the
            // error AND leak the generated secret bytes to the allocator's
            // freed-but-un-zeroed memory (panel-#1 refactor HIGH).
            var id = Identity.generate();
            errdefer id.deinit();
            const secret = id.keypair.secret_key.toBytes();
            saveSecretBytes(path, secret) catch |save_err| {
                // We couldn't persist — surface clearly. Returning the
                // unsaved identity would mask the failure and the next
                // launch would generate a different key, silently
                // breaking workspace continuity. The errdefer above
                // zeroes the secret on the way out.
                std.log.err(
                    "collab.identity: generated identity but failed to save to '{s}': {s}",
                    .{ path, @errorName(save_err) },
                );
                return save_err;
            };
            std.log.info("collab.identity: generated and saved fresh identity at '{s}'", .{path});
            return id;
        },
        else => return load_err,
    }
}

// =============================================================================
// Tests
// =============================================================================

test "Identity: generate produces non-zero keypair" {
    const id = Identity.generate();
    const pk = id.publicKeyBytes();
    // Non-zero pubkey (probability of all-zero CSPRNG output is ~0)
    var any_nonzero = false;
    for (pk) |b| {
        if (b != 0) {
            any_nonzero = true;
            break;
        }
    }
    try std.testing.expect(any_nonzero);
}

test "Identity: sign + verify round-trip" {
    const id = Identity.generate();
    const msg = "hello, ed25519";
    const sig = try id.sign(msg);
    try std.testing.expect(verify(sig, msg, id.publicKeyBytes()));
}

test "Identity: tampered message fails verify" {
    const id = Identity.generate();
    const msg = "original message";
    const sig = try id.sign(msg);
    try std.testing.expect(!verify(sig, "tampered message", id.publicKeyBytes()));
}

test "Identity: wrong pubkey fails verify" {
    const a = Identity.generate();
    const b = Identity.generate();
    const msg = "alice signs this";
    const sig = try a.sign(msg);
    // Signed by A, verified against B's pubkey → reject.
    try std.testing.expect(!verify(sig, msg, b.publicKeyBytes()));
}

test "Identity: tampered signature fails verify" {
    const id = Identity.generate();
    const msg = "needs a valid sig";
    var sig = try id.sign(msg);
    sig[0] ^= 0x01; // flip one bit
    try std.testing.expect(!verify(sig, msg, id.publicKeyBytes()));
}

test "Identity: serialization round-trip preserves identity" {
    const id1 = Identity.generate();
    const secret = id1.keypair.secret_key.toBytes();

    var id2 = try Identity.fromSecretBytes(secret);
    defer id2.deinit();

    try std.testing.expectEqualSlices(u8, &id1.publicKeyBytes(), &id2.publicKeyBytes());

    // A signature produced by id1 verifies under id2's (identical) pubkey.
    const msg = "round-trip me";
    const sig = try id1.sign(msg);
    try std.testing.expect(verify(sig, msg, id2.publicKeyBytes()));
}

test "Identity: deinit zeroes secret material" {
    var id = Identity.generate();
    // Snapshot a byte that's overwhelmingly likely non-zero.
    const before = id.keypair.secret_key.bytes[0];
    id.deinit();
    try std.testing.expect(id.keypair.secret_key.bytes[0] == 0);
    // Don't assert `before != 0` outright — there's a 1/256 chance the
    // CSPRNG produced 0x00. We only assert post-state is zero.
    _ = before;
}

test "verify: malformed pubkey returns false (not error)" {
    // A pubkey whose Curve25519 decode fails (e.g. all-0xFF). The
    // verifier MUST return false rather than propagate the error, so
    // hot-path callers can branch on a single bool without try/catch
    // boilerplate.
    const bad_pk: [PUBKEY_LEN]u8 = .{0xFF} ** PUBKEY_LEN;
    const bad_sig: [SIG_LEN]u8 = .{0} ** SIG_LEN;
    try std.testing.expect(!verify(bad_sig, "msg", bad_pk));
}

test "saveSecretBytes + loadSecretBytes: round-trip via tmp file" {
    // Use a tmp dir to avoid clobbering the user's real peer.key.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const allocator = std.testing.allocator;
    const real_path = try tmp.dir.realPathFileAlloc(compat.io(), ".", allocator);
    defer allocator.free(real_path);
    const key_path = try std.fs.path.join(allocator, &.{ real_path, "peer.key" });
    defer allocator.free(key_path);

    const id = Identity.generate();
    const secret = id.keypair.secret_key.toBytes();
    try saveSecretBytes(key_path, secret);

    const loaded = try loadSecretBytes(key_path);
    try std.testing.expectEqualSlices(u8, &secret, &loaded);

    // The reconstructed identity must produce the same pubkey.
    var id2 = try Identity.fromSecretBytes(loaded);
    defer id2.deinit();
    try std.testing.expectEqualSlices(u8, &id.publicKeyBytes(), &id2.publicKeyBytes());
}

test "loadOrGenerateAtPath: missing file → generate + persist; second call → load" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const allocator = std.testing.allocator;
    const real_path = try tmp.dir.realPathFileAlloc(compat.io(), ".", allocator);
    defer allocator.free(real_path);
    const key_path = try std.fs.path.join(allocator, &.{ real_path, "sub", "peer.key" });
    defer allocator.free(key_path);

    // First call: file doesn't exist → generate + save.
    var id1 = try loadOrGenerateAtPath(key_path);
    defer id1.deinit();
    const pk1 = id1.publicKeyBytes();

    // Second call: file exists → load the same identity (pubkey
    // must match exactly — no fresh generation).
    var id2 = try loadOrGenerateAtPath(key_path);
    defer id2.deinit();
    try std.testing.expectEqualSlices(u8, &pk1, &id2.publicKeyBytes());
}

test "loadOrGenerateAtPath: save failure → error propagated, no leak" {
    // Panel #2 coverage HIGH-1: the `errdefer id.deinit()` at
    // loadOrGenerateAtPath ensures the freshly-generated secret is
    // zeroed if persistence fails. Without it, the generated Identity
    // value (with secret material) would silently outlive the failing
    // call site and live as dead bytes in the caller's stack frame.
    //
    // Drive the failure by pointing at a path whose parent dir
    // CANNOT be created (a non-existent path on a read-only mount, or
    // here: a path whose parent name itself contains a NUL byte which
    // the POSIX create call rejects with InvalidUtf8 / NameTooLong).
    // We pick a path whose parent directory creation would step on a
    // regular file that's already there — `mkdir` fails with
    // `error.PathAlreadyExists` or `error.NotDir`, which propagates
    // through `createDirAbsoluteRecursive` → `saveSecretBytes` →
    // `loadOrGenerateAtPath`.
    //
    // The strong assertion is purely "the call returned an error". The
    // `errdefer id.deinit()` zero-pass is mechanical once the error
    // path runs — testing-allocator leak detector at scope exit is
    // the structural verifier that no allocations leaked.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const allocator = std.testing.allocator;
    const real_path = try tmp.dir.realPathFileAlloc(compat.io(), ".", allocator);
    defer allocator.free(real_path);

    // Create a regular file at the location we'll try to use as a
    // parent directory; this makes `createDirAbsoluteRecursive` fail
    // with `NotDir` (POSIX) when it walks past this segment.
    const blocker_path = try std.fs.path.join(allocator, &.{ real_path, "blocker" });
    defer allocator.free(blocker_path);
    {
        const io = compat.io();
        const f = try std.Io.Dir.createFileAbsolute(io, blocker_path, .{});
        f.close(io);
    }

    // key_path lives UNDER the blocker — so mkdir-recursive must try
    // to make `blocker/sub` and fail because `blocker` is a file.
    const key_path = try std.fs.path.join(allocator, &.{ real_path, "blocker", "sub", "peer.key" });
    defer allocator.free(key_path);

    // The call MUST return an error. The exact error variant depends
    // on the platform's mkdir behavior under a NOT-A-DIRECTORY parent
    // (NotDir on POSIX, PathAlreadyExists/AccessDenied elsewhere) —
    // accept any error variant. The point is: errdefer fires, secret
    // bytes are zeroed, no allocation leaks.
    const result = loadOrGenerateAtPath(key_path);
    try std.testing.expect(std.meta.isError(result));
}

test "loadSecretBytes: too-short file → InvalidKeyFile" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const allocator = std.testing.allocator;
    const real_path = try tmp.dir.realPathFileAlloc(compat.io(), ".", allocator);
    defer allocator.free(real_path);
    const key_path = try std.fs.path.join(allocator, &.{ real_path, "short.key" });
    defer allocator.free(key_path);

    // Write only 32 bytes (half of SECRET_LEN).
    const io = compat.io();
    const f = try std.Io.Dir.createFileAbsolute(io, key_path, .{});
    {
        defer f.close(io);
        try f.writeStreamingAll(io, &[_]u8{0} ** 32);
    }

    try std.testing.expectError(error.InvalidKeyFile, loadSecretBytes(key_path));
}

test "loadSecretBytes: too-long file → InvalidKeyFile" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const allocator = std.testing.allocator;
    const real_path = try tmp.dir.realPathFileAlloc(compat.io(), ".", allocator);
    defer allocator.free(real_path);
    const key_path = try std.fs.path.join(allocator, &.{ real_path, "long.key" });
    defer allocator.free(key_path);

    // Write 128 bytes (twice SECRET_LEN). Refuse to silently truncate.
    const io = compat.io();
    const f = try std.Io.Dir.createFileAbsolute(io, key_path, .{});
    {
        defer f.close(io);
        try f.writeStreamingAll(io, &[_]u8{0xAB} ** 128);
    }

    try std.testing.expectError(error.InvalidKeyFile, loadSecretBytes(key_path));
}
