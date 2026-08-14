//! LWW-Map CRDT (Last-Writer-Wins Map)
//!
//! Every field is tracked as a register: {value, timestamp, peer_id}.
//! Registers at one path are ordered by the TOTAL key
//! `(timestamp, peer_id, value_bytes)` — see `OrderingKey`, which owns the
//! argument for why all three components are load-bearing.
//!
//! RETRACTION (#393), recorded here rather than only in the ticket. This header
//! used to state a two-component rule and conclude "Result: ALL peers always
//! converge to the SAME state." The conclusion was FALSE, and not theoretically:
//! `(timestamp, peer_id)` is a PARTIAL order, so two ops agreeing on both but
//! carrying different values did not replace each other and each replica kept
//! whichever it happened to see first. Two honest replicas holding an IDENTICAL
//! delivered set were measured diverging at cbc5e46 — the witness is
//! `#393 PROBE D` below. Strong convergence needs same-set to imply same-state,
//! and a merge rule that consults arrival order is not a function of the set.
//!
//! Uses a namespaced path system so any plugin can share state:
//!   "model.nodes.<id>.x"                → node X position
//!   "plugin.<plugin-id>.<anything>"      → plugin-specific state
//!
//! Delete operations use a tombstone: value = "" (empty), which means "deleted."
//!
//! ## Role in the multi-channel collab architecture
//!
//! `CrdtDoc` implements `CrdtInterface` (see `crdt_interface.zig`) via
//! the `interface()` method. `CollabManager` registers ONE instance as
//! the `unified-model` channel; future CRDT types (text, blob) register
//! their own channel names and share the same transport.

const std = @import("std");
const compat = @import("compat");
const crdt_interface = @import("crdt_interface.zig");
const peer_id_mod = @import("peer_id.zig");
const CrdtInterface = crdt_interface.CrdtInterface;
const OpBytes = crdt_interface.OpBytes;
const SnapshotBytes = crdt_interface.SnapshotBytes;

/// A single CRDT field: value + causal metadata.
pub const CrdtField = struct {
    /// JSON-encoded value. Empty string means tombstone (deleted).
    value: []const u8,
    /// Lamport logical timestamp (increments on every mutation).
    timestamp: u64,
    /// Peer that last wrote this field.
    peer_id: [16]u8,
};

/// A single mutation request (path + value).
pub const Mutation = struct {
    path: []const u8,
    value: []const u8,
};

// =============================================================================
// TIMESTAMP POLICY (#386, superseding #382 C-3)
//
// #382 C-3 collapsed three different jobs into one number and got all three
// wrong. RETRACTION, recorded here rather than only in the ticket: the previous
// comment on this constant claimed `1 << 62` "keeps the wire format closed
// under its own arithmetic". It does not, and the claim was refuted by
// measurement, not argument — an op admitted at exactly `1 << 62` left the
// clock at `1 << 62 + 1`, which the emit-side guard then refused forever. `>=`
// would only have moved the cliff one value down. The mistake was structural:
//
//   an ABSOLUTE acceptance ceiling is never closed under Lamport's `+1`,
//   because the value it admits is the value the clock must then exceed.
//
// The three jobs, now three constants:
//
//   MAX_TIMESTAMP            what the WIRE can carry. Hard, external, not a
//                            policy — `maxInt(i64)`, because that is where a
//                            JSON integer stops.
//   MAX_FORWARD_JUMP         the acceptance policy for LIVE ops. RELATIVE to
//                            the local clock, which is the whole point: a
//                            relative bound rises with the clock instead of
//                            standing in front of it, so the admitted set is
//                            closed under `+1` by construction.
//   MAX_SNAPSHOT_TIMESTAMP   the acceptance bound for SNAPSHOT fields, where
//                            no relative bound is meaningful (a joining peer
//                            has no causal frame yet). Absolute, and set to
//                            leave `SNAPSHOT_WRITE_HEADROOM` writes available.
//
// The live path and the snapshot path answer different questions, which is why
// they get different bounds rather than one shared constant — sharing one was
// #382's original error and the first draft of #386 reproduced it. Each
// constant's own doc carries the argument for its value.
// =============================================================================

/// The wire's hard ceiling. `ts` is written as a bare JSON number and every
/// decoder accepts only `std.json.Value.integer`, which tops out at
/// `maxInt(i64)`; a larger number parses as `.number_string` and is refused.
/// This is a property of the encoding, not a policy choice, so it is not
/// negotiable and not tunable.
pub const MAX_TIMESTAMP: u64 = std.math.maxInt(i64);

/// How far ahead of the LOCAL clock a single live remote op may jump. This is
/// the ONLY acceptance policy for live ops, and it is deliberately relative.
///
/// SECOND RETRACTION, and it belongs here because the first draft of this very
/// fix repeated the mistake it was written to close. That draft added an
/// absolute `MAX_ADMISSIBLE_TIMESTAMP` below the wire ceiling and refused ops
/// above it. The witness in this file caught it within one build: a peer whose
/// clock legitimately reached that ceiling emitted ops its OWN decoder then
/// rejected — the identical failure #382 had, relocated to a nicer constant.
///
/// The reason is arithmetic and admits no clever choice of value. If decoders
/// accept up to `A`, then `applyRemoteOp` can leave the clock at `A + 1`, and
/// the next local write emits `A + 2`, which needs `A + 2 <= A`. No absolute
/// `A` below the wire ceiling can be closed under Lamport's `+1`.
///
/// A RELATIVE bound has no such fixed point: the admitted ceiling always sits
/// `MAX_FORWARD_JUMP` above wherever the clock currently is, so it rises with
/// the clock instead of standing in front of it. That is what makes the
/// admitted set closed under `+1` by construction rather than by argument.
///
/// What it costs an attacker: dragging a peer to the wire ceiling now takes
/// ~2^31 successive admitted ops instead of one message, each individually
/// signed, decrypted, and under the frame cap. A silent one-shot brick becomes
/// a sustained flood that the fairness quota and the metrics can both see.
///
/// 2^32 (~4.29e9) sits far above any legitimate divergence: peers bootstrap
/// from a `sync` snapshot before live ops arrive (the `.sync` arm's
/// `setConnected` invariant), so the honest forward jump is the op count
/// accumulated during one disconnect, not the session's whole history.
pub const MAX_FORWARD_JUMP: u64 = 1 << 32;

/// Local writes a loaded snapshot must leave available.
///
/// The snapshot side is the one place the relative bound cannot apply: a
/// joining peer has no causal frame of its own yet — adopting the host's frame
/// wholesale is the entire point of a snapshot — so "how far ahead is this?"
/// has no meaningful answer. An absolute reserve is the honest substitute, and
/// it is safe here precisely because a snapshot is adopted rather than chained:
/// nothing downstream has to exceed the value we accepted except this peer's
/// own writes, and this reserve is what guarantees it has some.
///
/// 2^40 is ~1.1e12 writes; at a sustained 1,000 writes/second, ~34,000 years.
pub const SNAPSHOT_WRITE_HEADROOM: u64 = 1 << 40;

/// The largest timestamp `loadSnapshot` will adopt for a field. A field above
/// this is DROPPED — not clamped, and not cause to refuse the whole snapshot.
///
/// Dropping is what keeps this convergent: the bound is a compile-time
/// constant, so every peer drops exactly the same field and they still agree.
/// Clamping would have each peer invent a different replacement timestamp from
/// its own clock, which is precisely how a CRDT stops being one.
///
/// Note what this does for state that is ALREADY poisoned: a `.spf` written by
/// the `1 << 62` build carries fields at ~4.61e18, far below this bound, so
/// those fields load normally and leave ~4.61e18 writes of room. The
/// already-poisoned case needs neither clamp nor quarantine — it was never the
/// data that was wrong, it was the ceiling standing in front of it.
pub const MAX_SNAPSHOT_TIMESTAMP: u64 = MAX_TIMESTAMP - SNAPSHOT_WRITE_HEADROOM;

/// A CRDT operation — the unit of replication sent over the wire.
pub const CrdtOp = struct {
    path: []const u8,
    value: []const u8,
    timestamp: u64,
    peer_id: [16]u8,
};

/// The key the LWW comparison is total on, and the ONE place that order is
/// defined. Both a stored `CrdtField` and an inbound `CrdtOp` project onto it.
///
/// Registers at one path are ordered by `(timestamp, peer_id, value)` in that
/// order of significance. The third component is not decoration — it is what
/// makes the relation an order at all. `(timestamp, peer_id)` alone is PARTIAL:
/// it ranks two registers equal whenever both components tie, and "equal" in a
/// merge rule means the winner is decided by whichever arrived first. Arrival
/// order is not a function of the delivered set, so two replicas given exactly
/// the same operations can disagree, permanently, with no anti-entropy to
/// repair them. That is #393, and it was measured rather than argued.
///
/// Comparing the value BYTES closes it by exhaustion: if all three components
/// are equal the two registers are indistinguishable, so no tie-break is owed.
/// A digest was considered and rejected — a collision reintroduces exactly the
/// divergence this removes, and it costs a hash per comparison that raw bytes
/// do not.
///
/// The bytes compared are the DECODED value, which is what both types already
/// hold: `std.json` unescapes before this module dupes, so a hostile peer
/// cannot manufacture two orderings of one register by respelling the envelope
/// (`"a"` and `"a"` arrive as the same byte). `#393 PROBE G` measures it.
///
/// Nothing about an attacker's freedom to choose values is a weakness here.
/// They may pick any value they like; they cannot make two DIFFERENT values
/// compare equal, which is the only thing that broke convergence.
pub const OrderingKey = struct {
    timestamp: u64,
    peer_id: [16]u8,
    value: []const u8,

    pub fn ofField(field: CrdtField) OrderingKey {
        return .{
            .timestamp = field.timestamp,
            .peer_id = field.peer_id,
            .value = field.value,
        };
    }

    pub fn ofOp(op: CrdtOp) OrderingKey {
        return .{
            .timestamp = op.timestamp,
            .peer_id = op.peer_id,
            .value = op.value,
        };
    }

    /// Total order over two registers at ONE path. `.eq` means the registers
    /// are equivalent — never "unresolved", which is the distinction the old
    /// two-component rule silently lost.
    pub fn order(self: OrderingKey, other: OrderingKey) std.math.Order {
        return switch (std.math.order(self.timestamp, other.timestamp)) {
            .eq => switch (std.mem.order(u8, &self.peer_id, &other.peer_id)) {
                .eq => std.mem.order(u8, self.value, other.value),
                else => |by_peer| by_peer,
            },
            else => |by_time| by_time,
        };
    }
};

/// LWW-Map CRDT document.
/// Thread safety: callers must synchronize access externally.
pub const CrdtDoc = struct {
    allocator: std.mem.Allocator,
    fields: std.StringHashMap(CrdtField),
    clock: u64,
    peer_id: [16]u8,

    pub fn init(allocator: std.mem.Allocator) CrdtDoc {
        var peer_id: [16]u8 = undefined;
        compat.io().random(&peer_id);
        return .{
            .allocator = allocator,
            .fields = std.StringHashMap(CrdtField).init(allocator),
            .clock = 0,
            .peer_id = peer_id,
        };
    }

    pub fn initWithPeerId(allocator: std.mem.Allocator, peer_id: [16]u8) CrdtDoc {
        return .{
            .allocator = allocator,
            .fields = std.StringHashMap(CrdtField).init(allocator),
            .clock = 0,
            .peer_id = peer_id,
        };
    }

    pub fn deinit(self: *CrdtDoc) void {
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.value);
        }
        self.fields.deinit();
    }

    /// Apply a local mutation. Returns the CrdtOp to broadcast to peers.
    pub fn mutate(self: *CrdtDoc, path: []const u8, value: []const u8) !CrdtOp {
        // #386 emit side, and #392 RETRACTS what this comment used to claim.
        //
        // It said this guard was "unreachable by construction" and justified
        // that with two constants — `MAX_ADMISSIBLE_TIMESTAMP` and
        // `WRITE_HEADROOM` — that DO NOT EXIST in this file. They were the
        // first draft's names, deleted when the policy became relative, and the
        // comment was never updated. So the change that retracted three false
        // doc claims shipped a fourth. Found by the gate on bf4eaff.
        //
        // WHAT IS ACTUALLY TRUE, measured (#392 PROBE B): exhaustion is
        // reachable. From a snapshot at `MAX_SNAPSHOT_TIMESTAMP`, 255 admitted
        // forward jumps plus one op at the wire ceiling put the clock at
        // 9223372036854775808 — one PAST `MAX_TIMESTAMP` — and every later
        // local write returns `ClockExhausted`. The relative bound made the
        // brick cost 256 signed ops instead of one message; it did not make it
        // impossible, and this comment should never have said otherwise.
        //
        // Kept as a guard rather than an assert because the alternative at the
        // true wire ceiling is emitting bytes no peer — including a future self
        // reading its own snapshot — can decode. Refusing the write and saying
        // so is strictly better than silently splitting the room.
        if (self.clock >= MAX_TIMESTAMP) return error.ClockExhausted;
        self.clock += 1;

        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);

        const field = CrdtField{
            .value = owned_value,
            .timestamp = self.clock,
            .peer_id = self.peer_id,
        };

        if (self.fields.getPtr(path)) |existing| {
            // Path exists — replace value in-place
            self.allocator.free(existing.value);
            existing.* = field;
        } else {
            // New path — allocate key
            const owned_path = try self.allocator.dupe(u8, path);
            errdefer self.allocator.free(owned_path);
            try self.fields.put(owned_path, field);
        }

        return CrdtOp{
            .path = path,
            .value = value,
            .timestamp = self.clock,
            .peer_id = self.peer_id,
        };
    }

    /// Apply a batch of local mutations. Returns ops to broadcast; caller owns
    /// the returned slice.
    ///
    /// RETRACTION (#387, gate HIGH-7): this used to say "atomically" and did
    /// not deliver it. Two of the three ways it failed are closed here — the
    /// returned slice leaked on any error, and a clock that ran out part-way
    /// through committed a prefix and then refused the rest. Both are now
    /// impossible: the clock is checked for the WHOLE batch before the first
    /// mutation lands, so `ClockExhausted` is an all-or-nothing answer.
    ///
    /// What remains, stated rather than implied: an allocation failure inside
    /// `mutate` still commits the mutations before it while returning an error,
    /// and the manager propagates that error before broadcasting — so the
    /// committed prefix is local-only and diverges from every peer. Closing
    /// that means staging every dupe before any install, which is a real
    /// restructure of the mutate/install seam rather than a hardening patch.
    /// Tracked as its own ticket; do not read the absence of "atomically" here
    /// as the absence of a known defect.
    pub fn mutateBatch(self: *CrdtDoc, mutations: []const Mutation) ![]CrdtOp {
        // Preflight the clock for the whole batch, so `ClockExhausted` is an
        // all-or-nothing answer rather than a committed prefix.
        //
        // #392 (gate HIGH): the ceiling check below is NOT redundant, and the
        // comment that used to sit here — claiming the subtraction "keeps it in
        // range for any clock value" — was false. `applyRemoteOp` can leave the
        // clock at `MAX_TIMESTAMP + 1` (measured, PROBE B), and once it does,
        // `MAX_TIMESTAMP - self.clock` UNDERFLOWS. In a safe build that is a
        // panic inside a peer's message loop, reached even by an empty batch.
        // Check the ceiling first; only then is the subtraction defined.
        if (self.clock >= MAX_TIMESTAMP) return error.ClockExhausted;
        if (mutations.len > MAX_TIMESTAMP - self.clock) return error.ClockExhausted;

        const ops = try self.allocator.alloc(CrdtOp, mutations.len);
        errdefer self.allocator.free(ops);

        for (mutations, 0..) |m, i| {
            ops[i] = try self.mutate(m.path, m.value);
        }
        return ops;
    }

    /// Merge a remote operation. Returns true if local state changed.
    /// Implements LWW: higher timestamp wins; tie-break by peer_id (lexicographic).
    pub fn applyRemoteOp(self: *CrdtDoc, op: CrdtOp) !bool {
        // #386: refuse before touching the clock. Both guards run here and not
        // only at the wire boundary, because this is the invariant that keeps
        // the emit side live, and the direct-call path (tests, and any future
        // in-process caller) must not be able to bypass it.

        // The wire ceiling. An invariant check, not a policy: `std.json`
        // decodes `.integer` as i64, so a decoded op cannot exceed this — but
        // a direct in-process caller can, and the clock arithmetic below is
        // only safe because nothing above this gets past here.
        if (op.timestamp > MAX_TIMESTAMP) return error.TimestampOutOfRange;

        // The acceptance policy. Written as a subtraction on the OP's side so
        // it cannot overflow for any `op.timestamp`, rather than as
        // `self.clock + MAX_FORWARD_JUMP` which would have to reason about the
        // clock's own range to be safe.
        if (op.timestamp > MAX_FORWARD_JUMP and
            op.timestamp - MAX_FORWARD_JUMP > self.clock)
        {
            return error.TimestampTooFarAhead;
        }

        // Advance Lamport clock: max(local, remote) + 1. CHECKED addition, not
        // `+|`. Saturation was #382's habit of hiding a broken invariant behind
        // a plausible-looking value; here the guard above proves `@max` is at
        // most `MAX_TIMESTAMP` (~9.22e18), which is less than half the u64
        // range, so an overflow would be a real bug and should trap rather than
        // silently pin the clock at a value nothing can exceed.
        self.clock = @max(self.clock, op.timestamp) + 1;

        if (self.fields.getPtr(op.path)) |existing| {
            if (!shouldReplace(existing.*, op)) {
                return false; // Local value wins, no change
            }
            // #382 C-2: allocate the replacement BEFORE freeing the old value.
            // The other order left a freed pointer in the map whenever the dupe
            // failed, because the error propagates out of a half-updated entry
            // — a later read, snapshot, replace, or deinit then uses or
            // double-frees it. `mutate` above already had this order; this arm
            // was the odd one out.
            const owned_value = try self.allocator.dupe(u8, op.value);
            self.allocator.free(existing.value);
            existing.* = CrdtField{
                .value = owned_value,
                .timestamp = op.timestamp,
                .peer_id = op.peer_id,
            };
            return true;
        }

        // New path — allocate key and value
        const owned_path = try self.allocator.dupe(u8, op.path);
        errdefer self.allocator.free(owned_path);
        const owned_value = try self.allocator.dupe(u8, op.value);
        errdefer self.allocator.free(owned_value);

        try self.fields.put(owned_path, CrdtField{
            .value = owned_value,
            .timestamp = op.timestamp,
            .peer_id = op.peer_id,
        });

        return true;
    }

    /// LWW comparison: should the incoming op replace the existing field?
    ///
    /// Deliberately a thin call onto `OrderingKey.order` and nothing more. The
    /// rule is stated in exactly one place so a second site cannot re-derive a
    /// subtly different — or, as in #393, a merely PARTIAL — version of it.
    ///
    /// Strictly `.gt`, which is also what keeps `applyRemote` idempotent as the
    /// `CrdtInterface` contract requires: an op already merged compares `.eq`
    /// against itself and reports no change.
    fn shouldReplace(existing: CrdtField, incoming: CrdtOp) bool {
        return OrderingKey.ofOp(incoming).order(OrderingKey.ofField(existing)) == .gt;
    }

    /// Serialize the full CRDT state for syncing a new peer.
    /// Format: JSON object mapping path → {v, ts, p (hex)}.
    pub fn snapshot(self: *const CrdtDoc) ![]const u8 {
        var buf: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer buf.deinit();
        const w = &buf.writer;

        try w.writeByte('{');
        var first = true;
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            if (!first) try w.writeByte(',');
            first = false;

            // "path":{"v":"value","ts":123,"p":"hex"}
            try w.writeByte('"');
            try writeJsonEscaped(w, entry.key_ptr.*);
            try w.writeAll("\":{\"v\":");
            try w.writeByte('"');
            try writeJsonEscaped(w, entry.value_ptr.value);
            try w.writeAll("\",\"ts\":");
            try w.print("{d}", .{entry.value_ptr.timestamp});
            try w.writeAll(",\"p\":\"");
            try writeHex(w, &entry.value_ptr.peer_id);
            try w.writeAll("\"}");
        }
        try w.writeByte('}');

        return buf.toOwnedSlice();
    }

    /// Load a full CRDT snapshot (received from host peer).
    /// Replaces all local state — atomically: on ANY failure the document is
    /// left exactly as it was.
    ///
    /// #386 C-4: the previous order was `clearAll()` first, then parse, and it
    /// was wrong three separate ways. (1) `clearAll` frees every field value,
    /// so passing a slice this document owns — `doc.get("k").?` is the obvious
    /// way to get one — freed the parser's own input before it read it. (2) With
    /// `.alloc_if_needed` (the default) an unescaped JSON string points INTO
    /// `data`, so even a caller-owned `data` that merely outlives the call is
    /// not enough if anything frees it mid-parse. (3) Malformed JSON, or an OOM
    /// part-way through the loop, left the document empty or half-populated
    /// with no way back.
    ///
    /// Staging fixes all three at once: every read from `parsed` — and every
    /// dupe out of it — completes while `data` is still live, and the old state
    /// is destroyed only in the commit block, which cannot fail.
    pub fn loadSnapshot(self: *CrdtDoc, data: []const u8) !void {
        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, data, .{});
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => return error.InvalidSnapshot,
        };

        var staged = std.StringHashMap(CrdtField).init(self.allocator);
        errdefer {
            var sit = staged.iterator();
            while (sit.next()) |e| {
                self.allocator.free(e.key_ptr.*);
                self.allocator.free(e.value_ptr.value);
            }
            staged.deinit();
        }
        var staged_clock: u64 = self.clock;

        var it = obj.iterator();
        while (it.next()) |entry| {
            const path = entry.key_ptr.*;
            const field_obj = switch (entry.value_ptr.*) {
                .object => |o| o,
                else => continue,
            };

            const v_val = field_obj.get("v") orelse continue;
            const ts_val = field_obj.get("ts") orelse continue;
            const p_val = field_obj.get("p") orelse continue;

            const value = switch (v_val) {
                .string => |s| s,
                else => continue,
            };
            // #382: a negative `ts` used to reach `@intCast` unguarded, which is
            // illegal behaviour — a hostile snapshot took the whole process down
            // in Debug/ReleaseSafe rather than dropping one field. The op
            // decoder guarded this; the snapshot decoder did not. Found while
            // verifying C-1's siblings, not reported by the gate.
            const ts: u64 = switch (ts_val) {
                .integer => |i| if (i < 0) continue else @intCast(i),
                else => continue,
            };
            // #386, snapshot side — see `MAX_SNAPSHOT_TIMESTAMP` for why this
            // is an absolute bound here and a relative one for live ops, and
            // why the field is dropped rather than clamped.
            if (ts > MAX_SNAPSHOT_TIMESTAMP) continue;
            const peer_hex = switch (p_val) {
                .string => |s| s,
                else => continue,
            };

            const peer_id = peer_id_mod.parseHex(peer_hex) catch continue;

            const owned_path = try self.allocator.dupe(u8, path);
            errdefer self.allocator.free(owned_path);
            const owned_value = try self.allocator.dupe(u8, value);
            errdefer self.allocator.free(owned_value);

            try staged.put(owned_path, CrdtField{
                .value = owned_value,
                .timestamp = ts,
                .peer_id = peer_id,
            });

            // Advance clock past any timestamp in the snapshot
            staged_clock = @max(staged_clock, ts);
        }

        // Commit. Every fallible step is above this line; nothing below can
        // fail, so the document is either fully replaced or fully untouched.
        // The free loop is spelled out rather than delegated to `clearAll`
        // because this path replaces the map wholesale instead of emptying it,
        // and `clearAndFree` followed by `deinit` would be two teardowns of one
        // allocation to save one line.
        var old = self.fields.iterator();
        while (old.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            self.allocator.free(e.value_ptr.value);
        }
        self.fields.deinit();
        self.fields = staged;
        self.clock = staged_clock;
    }

    /// Export the merged CRDT state as a flat JSON object: {"path": "value", ...}
    /// Tombstones (empty value) are omitted.
    pub fn toModelJson(self: *const CrdtDoc) ![]const u8 {
        var buf: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer buf.deinit();
        const w = &buf.writer;

        try w.writeByte('{');
        var first = true;
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            // Skip tombstones
            if (entry.value_ptr.value.len == 0) continue;

            if (!first) try w.writeByte(',');
            first = false;

            try w.writeByte('"');
            try writeJsonEscaped(w, entry.key_ptr.*);
            try w.writeAll("\":");

            // Value is already JSON-encoded, write it raw
            try w.writeAll(entry.value_ptr.value);
        }
        try w.writeByte('}');

        return buf.toOwnedSlice();
    }

    /// Get the value at a path, or null if not present / tombstoned.
    pub fn get(self: *const CrdtDoc, path: []const u8) ?[]const u8 {
        const field = self.fields.get(path) orelse return null;
        if (field.value.len == 0) return null; // tombstone
        return field.value;
    }

    /// Number of non-tombstone fields.
    /// Iterate every (path, value, peer_id, timestamp) entry currently
    /// in the CRDT doc. Used by `manager.processMessage(.sync)` so the
    /// joiner can replay the host's existing state through the bridge
    /// into its local UnifiedModel — without this, a joiner that
    /// connects AFTER the host has imported sees the data only in the
    /// CRDT layer, never in the actor / UI.
    pub fn iterateFields(
        self: *const CrdtDoc,
        ctx: *anyopaque,
        callback: *const fn (ctx: *anyopaque, path: []const u8, value: []const u8, peer_id: [16]u8) void,
    ) void {
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            callback(ctx, entry.key_ptr.*, entry.value_ptr.value, entry.value_ptr.peer_id);
        }
    }

    pub fn fieldCount(self: *const CrdtDoc) usize {
        var count: usize = 0;
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.value.len > 0) count += 1;
        }
        return count;
    }

    fn clearAll(self: *CrdtDoc) void {
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.value);
        }
        self.fields.clearAndFree();
    }

    // =========================================================================
    // CrdtInterface adapter
    //
    // The vtable wrappers below let `CollabManager` route ops to this
    // CRDT via the same dispatch path used by future CRDT types (text,
    // blob). The wire-side `op_bytes` encoding is the same JSON shape
    // the old `protocol.encode(.op = CrdtOp{...})` produced — the field
    // names `path`/`v`/`ts`/`p` are preserved so a 2-instance smoke
    // run from the previous tree is on-the-wire identical.
    // =========================================================================

    /// Caller-facing input to `applyLocal` via the vtable:
    /// `{"path":"...","value":"..."}`.
    /// We use `value` (long form) on the inbound path to mirror the
    /// existing `bridge_handlers.collab.mutate` JSON shape; the on-the-
    /// wire short form (`v`) is emitted inside `encodeOpBytes` below.
    fn vtableApplyLocal(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        input: []const u8,
    ) anyerror!OpBytes {
        const self: *CrdtDoc = @ptrCast(@alignCast(ptr));
        const parsed = try std.json.parseFromSlice(struct {
            path: []const u8,
            value: []const u8,
        }, allocator, input, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const op = try self.mutate(parsed.value.path, parsed.value.value);
        return try encodeOpBytes(allocator, op);
    }

    fn vtableApplyRemote(ptr: *anyopaque, op_bytes: OpBytes) anyerror!bool {
        const self: *CrdtDoc = @ptrCast(@alignCast(ptr));
        const op = try decodeOpBytes(self.allocator, op_bytes);
        // `decodeOpBytes` returns owned `path` + `value` strings; the
        // CRDT dupes them again into its own storage during
        // `applyRemoteOp`, so the transient copies must be freed here.
        defer self.allocator.free(op.path);
        defer self.allocator.free(op.value);
        return try self.applyRemoteOp(op);
    }

    fn vtableSnapshot(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!SnapshotBytes {
        const self: *CrdtDoc = @ptrCast(@alignCast(ptr));
        // `snapshot()` already uses `self.allocator`; for v1 the manager
        // and the CRDT share an allocator, so this is fine. If they ever
        // diverge, dup into `allocator` here.
        if (self.allocator.ptr != allocator.ptr) {
            const native = try self.snapshot();
            defer self.allocator.free(native);
            return try allocator.dupe(u8, native);
        }
        return try self.snapshot();
    }

    fn vtableLoadSnapshot(ptr: *anyopaque, bytes: SnapshotBytes) anyerror!void {
        const self: *CrdtDoc = @ptrCast(@alignCast(ptr));
        try self.loadSnapshot(bytes);
    }

    fn vtableDeinit(ptr: *anyopaque, allocator: std.mem.Allocator) void {
        const self: *CrdtDoc = @ptrCast(@alignCast(ptr));
        _ = allocator;
        self.deinit();
    }

    const vtable_inst: CrdtInterface.VTable = .{
        .applyLocal = vtableApplyLocal,
        .applyRemote = vtableApplyRemote,
        .snapshot = vtableSnapshot,
        .loadSnapshot = vtableLoadSnapshot,
        .deinit = vtableDeinit,
    };

    /// Type-erase `self` for `Channel.crdt`. The returned interface holds
    /// `self` by pointer; `self` must outlive the channel registration.
    pub fn interface(self: *CrdtDoc) CrdtInterface {
        return .{ .ptr = self, .vtable = &vtable_inst };
    }
};

// =============================================================================
// LWW-Map op wire encoding (used by the CrdtInterface adapter)
// =============================================================================

/// Encode one CrdtOp to opaque bytes: `{"path":"...","v":"...","ts":N,"p":"hex"}`.
/// Caller owns the returned slice; free with the same `allocator`.
pub fn encodeOpBytes(allocator: std.mem.Allocator, op: CrdtOp) ![]u8 {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    const w = &buf.writer;

    try w.writeAll("{\"path\":\"");
    try json_util.writeJsonEscaped(w, op.path);
    try w.writeAll("\",\"v\":\"");
    try json_util.writeJsonEscaped(w, op.value);
    try w.writeAll("\",\"ts\":");
    try w.print("{d}", .{op.timestamp});
    try w.writeAll(",\"p\":\"");
    try json_util.writeHex(w, &op.peer_id);
    try w.writeAll("\"}");

    return buf.toOwnedSlice();
}

/// Decode opaque bytes back into a CrdtOp.
///
/// OWNERSHIP: the returned `path` and `value` are each a SEPARATE allocation
/// owned by the caller, made with `allocator`. Free both. They do not point
/// into the parse buffer and they do not share one.
///
/// RETRACTION (#387, gate MED-19): this comment previously said the opposite —
/// that the fields "point into a heap-allocated `std.json.Parsed` buffer" and
/// that the caller must merely consume the op before that buffer is freed. The
/// implementation has duped into the caller's allocator since the arena was
/// introduced (see the `dupe` pair at the end of this function). Every existing
/// caller frees correctly, which is exactly why the wrong contract survived:
/// nothing was measuring the documentation. A new caller following it would
/// leak both allocations on every op.
pub fn decodeOpBytes(allocator: std.mem.Allocator, bytes: []const u8) !CrdtOp {
    // Parse into a private arena so the JSON allocations don't leak
    // even if `applyRemoteOp` is interrupted by an OOM in the doc.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, aa, bytes, .{});

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidOpBytes,
    };
    const path_val = obj.get("path") orelse return error.InvalidOpBytes;
    const v_val = obj.get("v") orelse return error.InvalidOpBytes;
    const ts_val = obj.get("ts") orelse return error.InvalidOpBytes;
    const p_val = obj.get("p") orelse return error.InvalidOpBytes;

    const path_s = switch (path_val) {
        .string => |s| s,
        else => return error.InvalidOpBytes,
    };
    const v_s = switch (v_val) {
        .string => |s| s,
        else => return error.InvalidOpBytes,
    };
    const ts: u64 = switch (ts_val) {
        .integer => |i| if (i < 0) return error.InvalidOpBytes else @intCast(i),
        else => return error.InvalidOpBytes,
    };
    // #386: the wire ceiling, checked here so the invariant is stated at the
    // boundary that owns it. Structurally unreachable — `std.json` yields
    // `.integer` as i64 and the negative case returned above — which is the
    // point: if it ever fires, the decoder's own assumptions have changed.
    //
    // Deliberately NOT the acceptance policy. Admission is `applyRemoteOp`'s
    // job because it is relative to a clock this function cannot see; putting
    // an absolute acceptance bound here is exactly the mistake #382 made and
    // the first draft of #386 repeated.
    if (ts > MAX_TIMESTAMP) return error.InvalidOpBytes;
    const p_hex = switch (p_val) {
        .string => |s| s,
        else => return error.InvalidOpBytes,
    };
    const peer_id = peer_id_mod.parseHex(p_hex) catch return error.InvalidOpBytes;

    // Dup the borrowed strings into the caller's allocator so they
    // outlive the arena. `applyRemoteOp` will dupe them again into its
    // own storage; the temporary duplication is acceptable for v1 and
    // can be elided in a future tightness pass.
    const path_owned = try allocator.dupe(u8, path_s);
    errdefer allocator.free(path_owned);
    const v_owned = try allocator.dupe(u8, v_s);
    errdefer allocator.free(v_owned);

    return .{
        .path = path_owned,
        .value = v_owned,
        .timestamp = ts,
        .peer_id = peer_id,
    };
}

// =============================================================================
// Helpers — delegated to shared utility
// =============================================================================

const json_util = @import("util_json");
const writeJsonEscaped = json_util.writeJsonEscaped;
const writeHex = json_util.writeHex;

// =============================================================================
// Tests
// =============================================================================

test "CrdtDoc: basic mutate and get" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    const op = try doc.mutate("model.nodes.A.x", "100");
    try std.testing.expectEqualStrings("model.nodes.A.x", op.path);
    try std.testing.expectEqualStrings("100", op.value);
    try std.testing.expectEqual(@as(u64, 1), op.timestamp);

    const val = doc.get("model.nodes.A.x");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("100", val.?);
}

test "CrdtDoc: mutate overwrites previous value" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    _ = try doc.mutate("x", "1");
    _ = try doc.mutate("x", "2");
    try std.testing.expectEqualStrings("2", doc.get("x").?);
    try std.testing.expectEqual(@as(u64, 2), doc.clock);
}

test "CrdtDoc: applyRemoteOp merges correctly" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    // Apply remote op to empty doc
    const changed = try doc.applyRemoteOp(.{
        .path = "model.nodes.A.x",
        .value = "42",
        .timestamp = 5,
        .peer_id = [_]u8{0xFF} ** 16,
    });
    try std.testing.expect(changed);
    try std.testing.expectEqualStrings("42", doc.get("model.nodes.A.x").?);
}

test "CrdtDoc: LWW higher timestamp wins" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    // Set local value at ts=1
    _ = try doc.mutate("x", "local");

    // Remote op with higher timestamp should win
    const changed = try doc.applyRemoteOp(.{
        .path = "x",
        .value = "remote",
        .timestamp = 10,
        .peer_id = [_]u8{0x01} ** 16,
    });
    try std.testing.expect(changed);
    try std.testing.expectEqualStrings("remote", doc.get("x").?);
}

test "CrdtDoc: LWW lower timestamp loses" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    // Set local value at ts=1
    _ = try doc.mutate("x", "local");

    // Manually set a high timestamp field
    const key = try allocator.dupe(u8, "y");
    const val = try allocator.dupe(u8, "high");
    try doc.fields.put(key, .{
        .value = val,
        .timestamp = 100,
        .peer_id = doc.peer_id,
    });

    // Remote op with lower timestamp should lose
    const changed = try doc.applyRemoteOp(.{
        .path = "y",
        .value = "low",
        .timestamp = 5,
        .peer_id = [_]u8{0xFF} ** 16,
    });
    try std.testing.expect(!changed);
    try std.testing.expectEqualStrings("high", doc.get("y").?);
}

test "CrdtDoc: LWW timestamp tie breaks by peer_id" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.initWithPeerId(allocator, [_]u8{0x01} ** 16);
    defer doc.deinit();

    // Set value
    _ = try doc.mutate("x", "low_peer");

    // Remote op with same timestamp but higher peer_id should win
    const changed = try doc.applyRemoteOp(.{
        .path = "x",
        .value = "high_peer",
        .timestamp = 1, // same as local
        .peer_id = [_]u8{0xFF} ** 16, // higher than 0x01
    });
    try std.testing.expect(changed);
    try std.testing.expectEqualStrings("high_peer", doc.get("x").?);
}

test "CrdtDoc: snapshot and loadSnapshot round-trip" {
    const allocator = std.testing.allocator;

    // Create doc with some state
    var doc1 = CrdtDoc.init(allocator);
    defer doc1.deinit();
    _ = try doc1.mutate("a", "1");
    _ = try doc1.mutate("b", "2");
    _ = try doc1.mutate("c", "3");

    // Snapshot
    const snap = try doc1.snapshot();
    defer allocator.free(snap);

    // Load into fresh doc
    var doc2 = CrdtDoc.init(allocator);
    defer doc2.deinit();
    try doc2.loadSnapshot(snap);

    // Verify all fields match
    try std.testing.expectEqualStrings("1", doc2.get("a").?);
    try std.testing.expectEqualStrings("2", doc2.get("b").?);
    try std.testing.expectEqualStrings("3", doc2.get("c").?);
}

test "CrdtDoc: toModelJson excludes tombstones" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    _ = try doc.mutate("alive", "\"yes\"");
    _ = try doc.mutate("dead", ""); // tombstone

    const json = try doc.toModelJson();
    defer allocator.free(json);

    // Should contain "alive" but not "dead"
    try std.testing.expect(std.mem.indexOf(u8, json, "alive") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "dead") == null);
}

test "CrdtDoc: Lamport clock advances on remote ops" {
    const allocator = std.testing.allocator;
    var doc = CrdtDoc.init(allocator);
    defer doc.deinit();

    _ = try doc.applyRemoteOp(.{
        .path = "x",
        .value = "1",
        .timestamp = 50,
        .peer_id = [_]u8{0xAA} ** 16,
    });

    // Clock should be max(0, 50) + 1 = 51
    try std.testing.expectEqual(@as(u64, 51), doc.clock);

    // Next local mutation should use clock=52
    const op = try doc.mutate("y", "2");
    try std.testing.expectEqual(@as(u64, 52), op.timestamp);
}

test "CrdtDoc: concurrent non-conflicting edits merge cleanly" {
    const allocator = std.testing.allocator;

    var doc_a = CrdtDoc.initWithPeerId(allocator, [_]u8{0xAA} ** 16);
    defer doc_a.deinit();
    var doc_b = CrdtDoc.initWithPeerId(allocator, [_]u8{0xBB} ** 16);
    defer doc_b.deinit();

    // Alice edits path "x", Bob edits path "y" — no conflict
    const op_a = try doc_a.mutate("x", "100");
    const op_b = try doc_b.mutate("y", "200");

    // Cross-apply
    _ = try doc_a.applyRemoteOp(op_b);
    _ = try doc_b.applyRemoteOp(op_a);

    // Both docs should have both values
    try std.testing.expectEqualStrings("100", doc_a.get("x").?);
    try std.testing.expectEqualStrings("200", doc_a.get("y").?);
    try std.testing.expectEqualStrings("100", doc_b.get("x").?);
    try std.testing.expectEqualStrings("200", doc_b.get("y").?);
}

test "CrdtDoc: convergence on same-field conflict" {
    const allocator = std.testing.allocator;

    var doc_a = CrdtDoc.initWithPeerId(allocator, [_]u8{0xAA} ** 16);
    defer doc_a.deinit();
    var doc_b = CrdtDoc.initWithPeerId(allocator, [_]u8{0xBB} ** 16);
    defer doc_b.deinit();

    // Both edit the same path concurrently (ts=1 for both)
    const op_a = try doc_a.mutate("x", "alice");
    const op_b = try doc_b.mutate("x", "bob");

    // Cross-apply
    _ = try doc_a.applyRemoteOp(op_b);
    _ = try doc_b.applyRemoteOp(op_a);

    // Both should converge to the same value (BB > AA, so Bob wins)
    try std.testing.expectEqualStrings(doc_a.get("x").?, doc_b.get("x").?);
    try std.testing.expectEqualStrings("bob", doc_a.get("x").?);
}

// =============================================================================
// #382 WITNESSES — hostile-input handling
//
// Every finding in #382 was CONFIRMED-BY-READING when filed. These make each
// one executable, and print the measured value rather than only asserting it.
// The peer-id half lives in peer_id.zig beside the parser it guards.
// =============================================================================

test "#382 C-2 WITNESS: a failed replacement leaves the old value live, not freed" {
    // The defect: `free(existing.value)` ran BEFORE the fallible dupe, so an
    // allocation failure propagated out of a half-updated entry, leaving a
    // freed pointer in the map.
    //
    // The measurement has two halves and BOTH matter. The visible one is that
    // the map still reads back its original value. The decisive one is silent:
    // `deinit` below frees that value exactly once. Before the fix it had
    // already been freed, so this test ended in a DOUBLE FREE and
    // `std.testing.allocator` failed on it.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const alloc = failing.allocator();

    var doc = CrdtDoc.initWithPeerId(alloc, .{0x11} ** 16);
    defer doc.deinit();

    _ = try doc.applyRemoteOp(.{
        .path = "k",
        .value = "\"first\"",
        .timestamp = 10,
        .peer_id = .{0x11} ** 16,
    });
    try std.testing.expectEqualStrings("\"first\"", doc.get("k").?);

    // Arm the allocator so the NEXT allocation fails. On the replace path that
    // is precisely the dupe of the incoming value.
    failing.fail_index = failing.alloc_index;

    const result = doc.applyRemoteOp(.{
        .path = "k",
        .value = "\"second\"",
        .timestamp = 20,
        .peer_id = .{0x22} ** 16,
    });
    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expect(failing.has_induced_failure);

    const after = doc.get("k") orelse return error.TestExpectedFieldPresent;
    std.debug.print(
        "\n  #382 C-2: replacement OOM'd; map still holds {s} ({d} bytes, readable)\n",
        .{ after, after.len },
    );
    try std.testing.expectEqualStrings("\"first\"", after);
}

// -----------------------------------------------------------------------------
// #386 WITNESSES — the timestamp policy.
//
// RETRACTION, at the site that carried it. Two tests used to live here under
// #382 C-3. One was titled "after a hostile timestamp, this peer can still be
// heard" and planted `maxInt(i64)` — which was PAST the `1 << 62` cap in force
// at the time, so it only ever exercised the refusal path. For every timestamp
// that cap actually ADMITTED, its title was false, and the defect it claimed to
// witness was live the whole time it was green. This is the "a gate can certify
// a bound it never checks" class, found in my own test.
//
// The arms below plant AT and BELOW the acceptance ceiling, which is where the
// old cap failed, and every one of them prints the clock it measured.
// -----------------------------------------------------------------------------

test "#386 ARM 1: the admitted set is CLOSED under +1 at every clock the policy can reach" {
    // The general statement of what #382 got wrong, and the arm that caught the
    // first draft of #386 getting it wrong again. For each starting clock,
    // admit the largest op the policy allows, then make a local write and put
    // it through the REAL encoder and the REAL decoder — the same pair every
    // other peer in the room runs.
    //
    // "The clock is a sensible number" is NOT the claim. "What this peer emits
    // next, its own room still accepts" is, and only a round-trip can say so.
    // The first draft passed an absolute acceptance ceiling and failed right
    // here, on the last row.
    const allocator = std.testing.allocator;

    const starts = [_]u64{
        0,
        1_000_000,
        MAX_TIMESTAMP / 2,
        // Deliberately at the far end: a peer walked to within a hair of the
        // wire ceiling by ~2^31 admitted ops. Even here it must still emit
        // something decodable.
        MAX_TIMESTAMP - MAX_FORWARD_JUMP - 10,
    };

    for (starts, 1..) |start, row| {
        var doc = CrdtDoc.initWithPeerId(allocator, .{0x33} ** 16);
        defer doc.deinit();
        doc.clock = start;

        const ts = start + MAX_FORWARD_JUMP; // the largest op admissible here
        const changed = try doc.applyRemoteOp(.{
            .path = "k",
            .value = "\"poison\"",
            .timestamp = ts,
            .peer_id = .{0x44} ** 16,
        });

        const op = try doc.mutate("k2", "\"mine\"");
        const bytes = try encodeOpBytes(allocator, op);
        defer allocator.free(bytes);
        const decoded = try decodeOpBytes(allocator, bytes);
        defer allocator.free(decoded.path);
        defer allocator.free(decoded.value);

        std.debug.print(
            \\
            \\  #386 ARM 1 row {d}: clock {d} -> admitted ts {d} (changed={})
            \\    clock now      {d}
            \\    local write ts {d}   round-trips: {}
            \\    writes left    {d}
            \\
        , .{
            row,       start,        ts,                                changed,
            doc.clock, op.timestamp, decoded.timestamp == op.timestamp, MAX_TIMESTAMP - doc.clock,
        });

        try std.testing.expect(changed);
        try std.testing.expectEqual(op.timestamp, decoded.timestamp);
        try std.testing.expectEqualStrings("\"mine\"", decoded.value);
    }
}

test "#386 ARM 2: ONE hostile op can no longer move the clock more than the jump bound" {
    // The one-message brick, measured as the quantity it actually is. #382's
    // answer to "how far can a single signed op drag this peer's clock?" was
    // "all the way to the cap, from anywhere". It is now bounded by a constant.
    const allocator = std.testing.allocator;

    var doc = CrdtDoc.initWithPeerId(allocator, .{0x33} ** 16);
    defer doc.deinit();

    const before = doc.clock;
    // The most hostile op that will be admitted at all.
    _ = try doc.applyRemoteOp(.{
        .path = "k",
        .value = "\"poison\"",
        .timestamp = MAX_FORWARD_JUMP,
        .peer_id = .{0x44} ** 16,
    });
    const moved = doc.clock - before;

    // What #382 would have permitted from the same starting point.
    const under_382: u64 = (1 << 62) + 1;

    std.debug.print(
        \\
        \\  #386 ARM 2: worst single-op clock movement
        \\    #382 permitted  {d}
        \\    #386 permits    {d}
        \\    ops to reach the wire ceiling: {d}
        \\
    , .{ under_382, moved, MAX_TIMESTAMP / MAX_FORWARD_JUMP });

    try std.testing.expect(moved <= MAX_FORWARD_JUMP + 1);
    try std.testing.expect(moved < under_382);
}

test "#386 ARM 3: a timestamp above the WIRE ceiling is refused on both boundaries" {
    const allocator = std.testing.allocator;

    var doc = CrdtDoc.initWithPeerId(allocator, .{0x33} ** 16);
    defer doc.deinit();

    // Direct-call path: past the wire ceiling entirely. No decoder can produce
    // this, which is exactly why the guard lives on the in-process path too.
    const over = MAX_TIMESTAMP + 1;
    try std.testing.expectError(error.TimestampOutOfRange, doc.applyRemoteOp(.{
        .path = "k",
        .value = "\"x\"",
        .timestamp = over,
        .peer_id = .{0x44} ** 16,
    }));

    // Wire path: a number too large for a JSON integer parses as
    // `.number_string`, so the decoder refuses it before any of this.
    const hostile = try std.fmt.allocPrint(
        allocator,
        "{{\"path\":\"k\",\"v\":\"\\\"x\\\"\",\"ts\":{d},\"p\":\"{s}\"}}",
        .{ over, "ab" ** 16 },
    );
    defer allocator.free(hostile);
    try std.testing.expectError(error.InvalidOpBytes, decodeOpBytes(allocator, hostile));

    std.debug.print(
        "\n  #386 ARM 3: ts={d} refused at both boundaries; clock unmoved at {d}\n",
        .{ over, doc.clock },
    );
    try std.testing.expectEqual(@as(u64, 0), doc.clock);
}

test "#386 ARM 4: the forward-jump bound refuses a jump the ceiling alone would allow" {
    // Defense in depth, measured separately from the ceiling so a regression in
    // one cannot be masked by the other. This timestamp is comfortably ADMISSIBLE
    // — the ceiling has no objection — and is refused purely for arriving too
    // far ahead of where this peer's clock actually is.
    const allocator = std.testing.allocator;

    var doc = CrdtDoc.initWithPeerId(allocator, .{0x33} ** 16);
    defer doc.deinit();
    _ = try doc.mutate("seed", "\"1\"");

    const too_far = doc.clock + MAX_FORWARD_JUMP + 1;
    try std.testing.expect(too_far <= MAX_TIMESTAMP); // not the wire ceiling's doing
    try std.testing.expectError(error.TimestampTooFarAhead, doc.applyRemoteOp(.{
        .path = "k",
        .value = "\"x\"",
        .timestamp = too_far,
        .peer_id = .{0x44} ** 16,
    }));

    // Non-vacuity: one below the bound is ACCEPTED, so this is not passing by
    // refusing everything.
    const just_inside = doc.clock + MAX_FORWARD_JUMP;
    try std.testing.expect(try doc.applyRemoteOp(.{
        .path = "k",
        .value = "\"x\"",
        .timestamp = just_inside,
        .peer_id = .{0x44} ** 16,
    }));

    std.debug.print(
        "\n  #386 ARM 4: jump bound {d} — refused {d}, accepted {d}, clock now {d}\n",
        .{ MAX_FORWARD_JUMP, too_far, just_inside, doc.clock },
    );
}

test "#386 ARM 5: a snapshot poisoned by the OLD 1<<62 cap now loads AND still writes" {
    // The contagion arm. Under #382 this exact snapshot — the timestamp that
    // build's own cap admitted — set a fresh peer's clock to a value its own
    // `mutate` then refused forever, on an UNRELATED path, across a restart,
    // for every peer that synced. That is the durable half of the defect, and
    // it is the half a `.spf` on disk still carries today.
    const allocator = std.testing.allocator;

    const OLD_CAP: u64 = 1 << 62;

    var doc = CrdtDoc.initWithPeerId(allocator, .{0x55} ** 16);
    defer doc.deinit();

    const poisoned = try std.fmt.allocPrint(
        allocator,
        "{{\"k\":{{\"v\":\"\\\"poison\\\"\",\"ts\":{d},\"p\":\"{s}\"}}}}",
        .{ OLD_CAP, "44" ** 16 },
    );
    defer allocator.free(poisoned);

    try doc.loadSnapshot(poisoned);

    // Unrelated path — the field the attacker never touched.
    const op = try doc.mutate("k2", "\"mine\"");

    std.debug.print(
        \\
        \\  #386 ARM 5: loaded a snapshot poisoned by the 1<<62 build
        \\    field ts             {d}
        \\    clock after the write {d}
        \\    unrelated write ts    {d}  <- #382 returned error.ClockExhausted here
        \\    writes left           {d}
        \\
    , .{ OLD_CAP, doc.clock, op.timestamp, MAX_TIMESTAMP - doc.clock });

    try std.testing.expectEqualStrings("\"poison\"", doc.get("k").?);
    try std.testing.expectEqual(OLD_CAP + 1, op.timestamp);

    // Counterfactual, computed rather than asserted: under the old absolute cap
    // this clock was AT the emit-side refusal, so the write above could not
    // have happened.
    try std.testing.expect(doc.clock >= OLD_CAP);
    std.debug.print(
        "    under #382's cap ({d}) mutate refused at clock>={d}: {}\n",
        .{ OLD_CAP, OLD_CAP, doc.clock >= OLD_CAP },
    );
}

test "#386 ARM 6: a snapshot timestamp inside the write reserve is DROPPED, not adopted" {
    // The one timestamp class still refused on the snapshot side, and the
    // reason it is dropped per-field rather than clamped: the bound is a
    // constant, so every peer drops the same field and they still converge.
    const allocator = std.testing.allocator;

    var doc = CrdtDoc.initWithPeerId(allocator, .{0x55} ** 16);
    defer doc.deinit();

    const snap = try std.fmt.allocPrint(
        allocator,
        "{{\"bad\":{{\"v\":\"\\\"x\\\"\",\"ts\":{d},\"p\":\"{s}\"}}," ++
            "\"good\":{{\"v\":\"\\\"y\\\"\",\"ts\":7,\"p\":\"{s}\"}}}}",
        .{ MAX_SNAPSHOT_TIMESTAMP + 1, "ab" ** 16, "cd" ** 16 },
    );
    defer allocator.free(snap);

    try doc.loadSnapshot(snap);

    std.debug.print(
        "\n  #386 ARM 6: over-ceiling field dropped={} sibling survived={s} clock={d}\n",
        .{ doc.get("bad") == null, doc.get("good").?, doc.clock },
    );

    // Not passing by refusing the whole snapshot — the well-formed sibling is in.
    try std.testing.expect(doc.get("bad") == null);
    try std.testing.expectEqualStrings("\"y\"", doc.get("good").?);
    try std.testing.expectEqual(@as(u64, 7), doc.clock);
}

test "#386 C-4: loadSnapshot is transactional — a bad snapshot leaves the document intact" {
    // Gate CRITICAL-4. The old order cleared first and parsed second, so
    // malformed JSON emptied the document on the way to reporting the error.
    const allocator = std.testing.allocator;

    var doc = CrdtDoc.initWithPeerId(allocator, .{0x66} ** 16);
    defer doc.deinit();
    _ = try doc.mutate("keep", "\"original\"");
    const clock_before = doc.clock;

    try std.testing.expectError(error.SyntaxError, doc.loadSnapshot("{not json"));
    try std.testing.expectError(error.InvalidSnapshot, doc.loadSnapshot("[]"));

    std.debug.print(
        "\n  #386 C-4: after 2 refused snapshots, field={s} clock={d} (was {d})\n",
        .{ doc.get("keep") orelse "<GONE>", doc.clock, clock_before },
    );

    try std.testing.expectEqualStrings("\"original\"", doc.get("keep").?);
    try std.testing.expectEqual(clock_before, doc.clock);
}

test "#386 C-4: loadSnapshot survives being handed a slice the document itself owns" {
    // The aliasing half. `get` returns a document-owned value; the old order
    // freed it via `clearAll` and then handed the freed bytes to the parser.
    // Under the testing allocator that is a use-after-free, so this test is a
    // real memory-safety measurement and not a shape assertion.
    const allocator = std.testing.allocator;

    var doc = CrdtDoc.initWithPeerId(allocator, .{0x77} ** 16);
    defer doc.deinit();

    // A field whose VALUE is itself a well-formed snapshot document.
    const inner = "{\"a\":{\"v\":\"\\\"1\\\"\",\"ts\":3,\"p\":\"" ++ "ab" ** 16 ++ "\"}}";
    _ = try doc.mutate("self", inner);

    const aliased = doc.get("self").?;
    try doc.loadSnapshot(aliased);

    std.debug.print(
        "  #386 C-4: aliased loadSnapshot ok — a={s} clock={d}\n",
        .{ doc.get("a").?, doc.clock },
    );
    try std.testing.expectEqualStrings("\"1\"", doc.get("a").?);
}

test "#382 WITNESS: a snapshot's negative ts and short peer id are skipped, not fatal" {
    // Found while verifying C-1's siblings, NOT reported by the gate. The op
    // decoder guarded a negative `ts`; the snapshot decoder reached `@intCast`
    // unguarded, which is illegal behaviour — a hostile snapshot took the whole
    // process down in Debug rather than dropping one field.
    const allocator = std.testing.allocator;

    var doc = CrdtDoc.initWithPeerId(allocator, .{0x55} ** 16);
    defer doc.deinit();

    try doc.loadSnapshot(
        "{\"neg\":{\"v\":\"\\\"a\\\"\",\"ts\":-1,\"p\":\"" ++ "cd" ** 16 ++ "\"}," ++
            "\"shortp\":{\"v\":\"\\\"b\\\"\",\"ts\":5,\"p\":\"00\"}," ++
            "\"ok\":{\"v\":\"\\\"c\\\"\",\"ts\":7,\"p\":\"" ++ "ef" ** 16 ++ "\"}}",
    );

    std.debug.print(
        "\n  #382 snapshot: neg-ts={any} short-p={any} well-formed={any}\n",
        .{ doc.get("neg") != null, doc.get("shortp") != null, doc.get("ok") },
    );

    // Both hostile fields dropped; the well-formed one survives, so this is not
    // passing by refusing the whole snapshot.
    try std.testing.expect(doc.get("neg") == null);
    try std.testing.expect(doc.get("shortp") == null);
    try std.testing.expectEqualStrings("\"c\"", doc.get("ok").?);
}

test "#382 C-1 WITNESS: an op carrying a SHORT peer id is refused by the decoder" {
    // The `decodeOpBytes` call site, distinct from the snapshot one above and
    // from peer_id.zig's parser tests. All three exist because the defect was
    // four copies of one mistake, and closing three of four is how it comes
    // back.
    const allocator = std.testing.allocator;

    const hostile = "{\"path\":\"k\",\"v\":\"\\\"x\\\"\",\"ts\":5,\"p\":\"00\"}";
    try std.testing.expectError(error.InvalidOpBytes, decodeOpBytes(allocator, hostile));

    const empty = "{\"path\":\"k\",\"v\":\"\\\"x\\\"\",\"ts\":5,\"p\":\"\"}";
    try std.testing.expectError(error.InvalidOpBytes, decodeOpBytes(allocator, empty));

    // Not passing by refusing everything: the well-formed sibling decodes.
    const good = "{\"path\":\"k\",\"v\":\"\\\"x\\\"\",\"ts\":5,\"p\":\"" ++ "ab" ** 16 ++ "\"}";
    const op = try decodeOpBytes(allocator, good);
    defer allocator.free(op.path);
    defer allocator.free(op.value);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xAB} ** 16), &op.peer_id);
}

// =============================================================================
// #393 WITNESSES — the LWW order is TOTAL
//
// Found by the Codex SOL MAX design consultation on #392, and measured before
// it was believed. Neither I nor either of the two prior adversarial gates had
// found it; it was live in shipped code and independent of the timestamp
// question entirely.
//
// The arms that exercise convergence drive the REAL wire codec through the
// `CrdtInterface` vtable rather than hand-built structs, because an order that
// is total in memory but not after a round-trip is not total at the only place
// replicas actually meet.
// =============================================================================

test "#393 PROBE D: ops equal in ts AND peer converge regardless of arrival order" {
    // The equivocation witness, and the permanent regression test for the
    // defect itself.
    //
    // Both ops are individually well-formed and clear every existing guard.
    // They agree on timestamp and on peer_id — and `p` is attacker-chosen
    // (#383), so signing both members of the pair needs no privileged position
    // — differing only in VALUE. Under the old two-component rule neither
    // replaced the other, so each replica kept whichever it happened to see
    // first and no anti-entropy exists to repair the split.
    const allocator = std.testing.allocator;

    const equivocating_peer: [16]u8 = .{0x7F} ** 16;
    const p = CrdtOp{ .path = "k", .value = "\"A\"", .timestamp = 9, .peer_id = equivocating_peer };
    const q = CrdtOp{ .path = "k", .value = "\"B\"", .timestamp = 9, .peer_id = equivocating_peer };

    const p_bytes = try encodeOpBytes(allocator, p);
    defer allocator.free(p_bytes);
    const q_bytes = try encodeOpBytes(allocator, q);
    defer allocator.free(q_bytes);

    // Two honest replicas. Identical delivered SET, opposite delivered ORDER.
    var doc_pq = CrdtDoc.initWithPeerId(allocator, .{0x01} ** 16);
    defer doc_pq.deinit();
    var doc_qp = CrdtDoc.initWithPeerId(allocator, .{0x02} ** 16);
    defer doc_qp.deinit();

    _ = try doc_pq.interface().applyRemote(p_bytes);
    _ = try doc_pq.interface().applyRemote(q_bytes);
    _ = try doc_qp.interface().applyRemote(q_bytes);
    _ = try doc_qp.interface().applyRemote(p_bytes);

    const saw_pq = doc_pq.get("k").?;
    const saw_qp = doc_qp.get("k").?;

    std.debug.print(
        \\
        \\  #393 PROBE D: identical delivered set, opposite arrival order
        \\    peer A saw P then Q -> {s}
        \\    peer B saw Q then P -> {s}
        \\    DIVERGED: {}
        \\
    , .{ saw_pq, saw_qp, !std.mem.eql(u8, saw_pq, saw_qp) });

    try std.testing.expectEqualStrings(saw_pq, saw_qp);
    // Non-vacuity: they agree on the value the ORDER names, rather than by both
    // dropping the field or both keeping whatever came first.
    try std.testing.expectEqualStrings("\"B\"", saw_pq);
}

test "#393 PROBE G: two wire spellings of one register produce the SAME ordering key" {
    // Canonicality. The tie-break compares DECODED value bytes, so a hostile
    // peer cannot mint a second, differently-ordered copy of one register by
    // respelling its JSON envelope. Were this to fail, PROBE D would reopen
    // through the encoder rather than through the comparator.
    const allocator = std.testing.allocator;

    const hex = "7f" ** 16;
    const plain = "{\"path\":\"k\",\"v\":\"\\\"a\\\"\",\"ts\":9,\"p\":\"" ++ hex ++ "\"}";
    const respelled = "{\"path\":\"k\",\"v\":\"\\u0022\\u0061\\u0022\",\"ts\":9,\"p\":\"" ++ hex ++ "\"}";

    const a = try decodeOpBytes(allocator, plain);
    defer allocator.free(a.path);
    defer allocator.free(a.value);
    const b = try decodeOpBytes(allocator, respelled);
    defer allocator.free(b.path);
    defer allocator.free(b.value);

    const ord = OrderingKey.ofOp(a).order(OrderingKey.ofOp(b));
    std.debug.print(
        \\
        \\  #393 PROBE G: canonicality of the ordering key
        \\    plain envelope     -> {d} decoded bytes {any}
        \\    \u-escaped envelope -> {d} decoded bytes {any}
        \\    ordering key compares: {s}
        \\
    , .{ a.value.len, a.value, b.value.len, b.value, @tagName(ord) });

    try std.testing.expectEqualSlices(u8, a.value, b.value);
    try std.testing.expectEqual(std.math.Order.eq, ord);
}

test "#393: the ordering key survives the wire — encode then decode preserves it" {
    // The round-trip invariant: ordering_key(reg) == ordering_key(decode(encode(reg))).
    // Distinct from PROBE G, which fixes the ENVELOPE and varies its spelling;
    // this fixes the register and varies nothing, guarding against codec drift
    // that would silently reorder registers a replica already holds.
    const allocator = std.testing.allocator;

    const cases = [_]CrdtOp{
        .{ .path = "k", .value = "\"plain\"", .timestamp = 1, .peer_id = .{0x00} ** 16 },
        .{ .path = "k", .value = "\"quote\\\"inside\"", .timestamp = 2, .peer_id = .{0xFF} ** 16 },
        .{ .path = "k", .value = "", .timestamp = 3, .peer_id = .{0xAB} ** 16 }, // tombstone
        .{ .path = "k", .value = "{\"nested\":[1,2,3]}", .timestamp = MAX_TIMESTAMP, .peer_id = .{0x7F} ** 16 },
    };

    for (cases, 1..) |op, row| {
        const bytes = try encodeOpBytes(allocator, op);
        defer allocator.free(bytes);
        const back = try decodeOpBytes(allocator, bytes);
        defer allocator.free(back.path);
        defer allocator.free(back.value);

        const ord = OrderingKey.ofOp(op).order(OrderingKey.ofOp(back));
        std.debug.print(
            "  #393 round-trip row {d}: ts {d}, {d} value bytes -> ordering key compares {s}\n",
            .{ row, op.timestamp, op.value.len, @tagName(ord) },
        );
        try std.testing.expectEqual(std.math.Order.eq, ord);
    }
}

test "#393: value is the LAST discriminator, not a shortcut past ts or peer" {
    // Non-vacuity for the fix itself. A suite that only proved "equal ts and
    // equal peer converge" would also pass if the comparator had been replaced
    // by a bare value comparison — a different, and wrong, CRDT. Each row plants
    // a value that would LOSE on bytes alone and must still win on the more
    // significant component, so a regression names WHICH component broke.
    const zero: [16]u8 = .{0x00} ** 16;
    const high: [16]u8 = .{0xFF} ** 16;

    // Higher ts wins even though its value sorts lower.
    const newer = OrderingKey{ .timestamp = 2, .peer_id = zero, .value = "\"a\"" };
    const older = OrderingKey{ .timestamp = 1, .peer_id = high, .value = "\"z\"" };
    try std.testing.expectEqual(std.math.Order.gt, newer.order(older));

    // Same ts: higher peer wins even though its value sorts lower.
    const loud = OrderingKey{ .timestamp = 5, .peer_id = high, .value = "\"a\"" };
    const quiet = OrderingKey{ .timestamp = 5, .peer_id = zero, .value = "\"z\"" };
    try std.testing.expectEqual(std.math.Order.gt, loud.order(quiet));

    // Only once ts AND peer tie does the value decide.
    const val_b = OrderingKey{ .timestamp = 5, .peer_id = high, .value = "\"b\"" };
    const val_a = OrderingKey{ .timestamp = 5, .peer_id = high, .value = "\"a\"" };
    try std.testing.expectEqual(std.math.Order.gt, val_b.order(val_a));

    // Total: identical registers compare EQUAL. That is the property the old
    // rule lost, and the one idempotency below rests on.
    try std.testing.expectEqual(std.math.Order.eq, val_b.order(val_b));

    std.debug.print(
        "\n  #393 significance: ts outranks value, peer outranks value, value settles only the last tie\n",
        .{},
    );
}

test "#393: replaying an already-merged op reports no change (CrdtInterface contract)" {
    // `crdt_interface.zig` states idempotency as a contract every CRDT must
    // meet. It survives the third component precisely because equal registers
    // now compare `.eq` rather than being ranked by arrival, so this is a
    // witness for the contract and not merely for the comparator.
    const allocator = std.testing.allocator;

    var doc = CrdtDoc.initWithPeerId(allocator, .{0x01} ** 16);
    defer doc.deinit();

    const op = CrdtOp{ .path = "k", .value = "\"v\"", .timestamp = 4, .peer_id = .{0x7F} ** 16 };
    const bytes = try encodeOpBytes(allocator, op);
    defer allocator.free(bytes);

    const first = try doc.interface().applyRemote(bytes);
    const second = try doc.interface().applyRemote(bytes);
    const third = try doc.interface().applyRemote(bytes);

    std.debug.print(
        "\n  #393 idempotency: applyRemote x3 -> changed={} {} {}; value still {s}\n",
        .{ first, second, third, doc.get("k").? },
    );

    try std.testing.expect(first);
    try std.testing.expect(!second);
    try std.testing.expect(!third);
    try std.testing.expectEqualStrings("\"v\"", doc.get("k").?);
}
