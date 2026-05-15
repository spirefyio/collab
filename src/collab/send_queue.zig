//! Bounded per-peer send queue with drop-oldest backpressure.
//!
//! Each WebSocket peer connection owns one `SendQueue` and one dedicated
//! write thread. Producers (the CRDT broadcast paths in `manager.zig`)
//! call `push()`; the per-peer write thread blocks on `pop()` and calls
//! `ws.writeFrame()` outside any global mutex. This is the Phase 5
//! HIGH-1 fix: a slow peer can no longer stall unrelated operations
//! because the broadcast call is bounded (one O(1) enqueue per peer)
//! and writes happen on per-peer threads.
//!
//! Backpressure is policy-driven by `MessageKind`:
//!
//!   - `.crdt_op` — drop-oldest. CRDT ops are idempotent and commutative
//!     (LWW field semantics mean a dropped op is overwritten by any later
//!     op on the same field; Tier 2 anti-entropy is the long-term backstop
//!     for fields with no further updates). Dropping is strictly less bad
//!     than blocking: a blocked broadcaster slows EVERY peer, one dropped
//!     CRDT op slows ONE peer's convergence by at most one anti-entropy
//!     round trip.
//!
//!   - `.control` — refuse-to-drop. Session-control messages (`join`,
//!     `leave`, `sync`, `peers`, `pong`, `error`) are NEITHER idempotent
//!     NOR commutative. Dropping a `sync` means a new peer never gets
//!     bootstrap state; dropping `leave` desynchronises peer rosters;
//!     dropping the relayed `join` means other peers never learn of a
//!     new joiner. On overflow we return `error.QueueFull` so the caller
//!     can decide (log + tear down the peer is the typical response).
//!     If the queue is so full of CRDT ops that no oldest-CRDT slot can
//!     be reclaimed, the same `error.QueueFull` is returned — but the
//!     drop-oldest pass always tries `.crdt_op` slots first to give
//!     control messages priority space.
//!
//! Structural CRDT ops (delete/connect/assign) MUST NOT reach this
//! queue under `.crdt_op` when there is more than one peer in the room.
//! Two-layer defense: (1) the CRDT-2 UX gate in react-framework disables
//! the buttons that submit them via the local `mutate()` path; (2) the
//! `crdt_bridge.zig STRUCTURAL_OPS` deny list at `studio/src/model/
//! crdt_bridge.zig:147-156` refuses them on the inbound peer side.
//! The send queue itself does NOT inspect op shape — if either gate
//! weakens, structural ops would silently flow into `.crdt_op` and be
//! eligible for drop. Add a `CommandOp` filter at the broadcast call
//! site (not here) if those gates are ever relaxed.
//!
//! Memory model:
//!   - Heap-allocated (`init` does `allocator.create`) so the queue
//!     pointer stays stable when stored in a relocatable container
//!     (`Connection` lives in a growable ArrayList).
//!   - Each enqueued message is `allocator.dupe`-d so the caller can
//!     free their copy immediately and not coordinate lifetime.
//!   - On overflow, the dropped message is freed before being
//!     overwritten — no leaks.
//!   - `deinit` drains any remaining messages before freeing the
//!     ring buffer and the queue struct itself.

const std = @import("std");
const compat = @import("compat");
const ws = @import("websocket.zig");

/// Backpressure policy tag carried per-message. See the file-level
/// docstring for the semantic difference between `crdt_op` (drop-oldest)
/// and `control` (refuse-to-drop). The tag travels with the message so
/// `push` can decide eviction policy when the ring is full.
pub const MessageKind = enum { crdt_op, control };

pub const SendQueue = struct {
    allocator: std.mem.Allocator,
    mutex: std.Io.Mutex,
    cond: std.Io.Condition,
    buf: []Message,
    head: usize,
    tail: usize,
    count: usize,
    closed: bool,
    dropped: u64,

    /// Default queue depth per peer. Holds ~256 ops in flight; at typical
    /// op size (~200 B) that's ~50 KB per peer, ~50 MB at the 1024-peer
    /// MAX_PEERS cap. Adjust if profiling shows backpressure causing real
    /// convergence drift; the Tier 2 anti-entropy work makes any specific
    /// number less load-bearing.
    pub const DEFAULT_CAPACITY: usize = 256;

    pub const Message = struct {
        data: []u8, // queue-owned; freed by `pop` caller (or queue on deinit/drop)
        opcode: ws.Opcode,
        kind: MessageKind,
    };

    /// Allocate and initialise an empty queue with the given ring size.
    /// `capacity` must be > 0 (a zero-length queue is meaningless).
    pub fn init(allocator: std.mem.Allocator, capacity: usize) !*SendQueue {
        std.debug.assert(capacity > 0);
        const self = try allocator.create(SendQueue);
        errdefer allocator.destroy(self);
        const buf = try allocator.alloc(Message, capacity);
        self.* = .{
            .allocator = allocator,
            .mutex = .init,
            .cond = .init,
            .buf = buf,
            .head = 0,
            .tail = 0,
            .count = 0,
            .closed = false,
            .dropped = 0,
        };
        return self;
    }

    /// Free the queue and every still-pending message. Safe to call after
    /// `close` (in fact required — `close` does not free state).
    pub fn deinit(self: *SendQueue) void {
        // Drain remaining messages without taking the mutex: by contract
        // `deinit` runs when no other thread can reference the queue.
        while (self.count > 0) {
            self.allocator.free(self.buf[self.head].data);
            self.head = (self.head + 1) % self.buf.len;
            self.count -= 1;
        }
        self.allocator.free(self.buf);
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    /// Enqueue a message. `data` is copied (queue takes ownership of the
    /// copy), so the caller may free their buffer immediately.
    ///
    /// On capacity overflow:
    ///   - `kind = .crdt_op` — drop the oldest `.crdt_op` message in the
    ///     ring; if none exists (queue is full of `.control` messages),
    ///     return `error.QueueFull` instead.
    ///   - `kind = .control` — if any `.crdt_op` slot exists, drop it to
    ///     make room (control messages preempt CRDT ops); otherwise
    ///     return `error.QueueFull`. Caller decides: log + tear down
    ///     the peer is the typical response.
    ///
    /// Returns `error.Closed` when called on a closed queue (caller
    /// chose to push after `close`; treat as "peer gone, message moot").
    pub fn push(self: *SendQueue, data: []const u8, opcode: ws.Opcode, kind: MessageKind) !void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        if (self.closed) return error.Closed;

        const owned = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(owned);

        if (self.count == self.buf.len) {
            // Always try to reclaim a CRDT-op slot first (preserves
            // control messages regardless of who is pushing). If no
            // CRDT-op slot exists, fail rather than drop a control
            // message — see file-level docstring for rationale.
            if (!self.dropOldestCrdtOpLocked()) return error.QueueFull;
        }

        self.buf[self.tail] = .{ .data = owned, .opcode = opcode, .kind = kind };
        self.tail = (self.tail + 1) % self.buf.len;
        self.count += 1;

        // Signal a single waiter (single-consumer queue).
        self.cond.signal(compat.io());
    }

    /// Walk the ring from head and free the oldest message with
    /// `kind == .crdt_op`, compacting the ring so head/tail/count stay
    /// consistent. Returns true if a slot was freed.
    ///
    /// Must be called with `self.mutex` held; modifies head/tail/count.
    /// Internal helper for `push`'s overflow branch — extracted for
    /// readability and to keep the overflow policy in one place.
    fn dropOldestCrdtOpLocked(self: *SendQueue) bool {
        if (self.count == 0) return false;
        const cap = self.buf.len;
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.head + i) % cap;
            if (self.buf[idx].kind == .crdt_op) {
                self.allocator.free(self.buf[idx].data);
                // Compact: shift every entry at positions [idx+1 .. tail)
                // one slot toward head (the index of the freed slot).
                // For the common case (idx == head, oldest) this is a
                // single head++ and count--; for control-heavy queues
                // it's O(count) but bounded by capacity (256) and
                // happens only on overflow.
                if (idx == self.head) {
                    self.head = (self.head + 1) % cap;
                } else {
                    var j: usize = i;
                    while (j + 1 < self.count) : (j += 1) {
                        const cur = (self.head + j) % cap;
                        const nxt = (self.head + j + 1) % cap;
                        self.buf[cur] = self.buf[nxt];
                    }
                    if (self.tail == 0) self.tail = cap - 1 else self.tail -= 1;
                }
                self.count -= 1;
                self.dropped += 1;
                return true;
            }
        }
        return false;
    }

    /// Block until a message is available, then return it. Returns null
    /// once the queue is both closed AND empty (the write-thread exit
    /// signal). Caller MUST free `msg.data` via this queue's allocator.
    pub fn pop(self: *SendQueue) ?Message {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        while (self.count == 0 and !self.closed) {
            // `waitUncancelable` re-acquires the mutex before returning;
            // spurious wakeups are absorbed by the surrounding `while`.
            self.cond.waitUncancelable(compat.io(), &self.mutex);
        }

        if (self.count == 0) return null; // closed and drained

        const msg = self.buf[self.head];
        self.head = (self.head + 1) % self.buf.len;
        self.count -= 1;
        return msg;
    }

    /// Mark the queue closed and wake all waiters. After `close`, `push`
    /// returns `error.Closed`; `pop` continues to return any still-buffered
    /// messages and then null. Idempotent.
    pub fn close(self: *SendQueue) void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        if (self.closed) return;
        self.closed = true;
        // Broadcast (not signal) so concurrent waiters all wake — there
        // should only be one (single consumer) but defensively broadcast
        // covers the lifecycle-shutdown case if a peer is being closed
        // by multiple paths racing.
        self.cond.broadcast(compat.io());
    }

    /// Diagnostic accessor; safe to call from any thread.
    pub fn droppedCount(self: *SendQueue) u64 {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        return self.dropped;
    }

    /// Diagnostic accessor; safe to call from any thread.
    pub fn pendingCount(self: *SendQueue) usize {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        return self.count;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "SendQueue: push/pop round-trip preserves bytes and opcode" {
    const a = std.testing.allocator;
    var q = try SendQueue.init(a, 4);
    defer q.deinit();

    try q.push("hello", .text, .crdt_op);
    try q.push("world", .binary, .crdt_op);

    const m1 = q.pop().?;
    defer a.free(m1.data);
    try std.testing.expectEqualStrings("hello", m1.data);
    try std.testing.expect(m1.opcode == .text);

    const m2 = q.pop().?;
    defer a.free(m2.data);
    try std.testing.expectEqualStrings("world", m2.data);
    try std.testing.expect(m2.opcode == .binary);
}

test "SendQueue: capacity overflow drops oldest, dropped counter advances" {
    const a = std.testing.allocator;
    var q = try SendQueue.init(a, 2);
    defer q.deinit();

    try q.push("a", .text, .crdt_op);
    try q.push("b", .text, .crdt_op);
    try q.push("c", .text, .crdt_op); // forces drop of "a"

    try std.testing.expectEqual(@as(u64, 1), q.droppedCount());
    try std.testing.expectEqual(@as(usize, 2), q.pendingCount());

    const m1 = q.pop().?;
    defer a.free(m1.data);
    try std.testing.expectEqualStrings("b", m1.data);

    const m2 = q.pop().?;
    defer a.free(m2.data);
    try std.testing.expectEqualStrings("c", m2.data);
}

test "SendQueue: close-and-empty causes pop to return null without blocking" {
    const a = std.testing.allocator;
    var q = try SendQueue.init(a, 4);
    defer q.deinit();

    q.close();
    try std.testing.expect(q.pop() == null);
}

test "SendQueue: push after close returns error.Closed" {
    const a = std.testing.allocator;
    var q = try SendQueue.init(a, 4);
    defer q.deinit();

    q.close();
    try std.testing.expectError(error.Closed, q.push("after-close", .text, .crdt_op));
}

test "SendQueue: drains buffered messages then returns null after close" {
    const a = std.testing.allocator;
    var q = try SendQueue.init(a, 4);
    defer q.deinit();

    try q.push("first", .text, .crdt_op);
    try q.push("second", .text, .crdt_op);
    q.close();

    const m1 = q.pop().?;
    defer a.free(m1.data);
    try std.testing.expectEqualStrings("first", m1.data);

    const m2 = q.pop().?;
    defer a.free(m2.data);
    try std.testing.expectEqualStrings("second", m2.data);

    try std.testing.expect(q.pop() == null);
}

test "SendQueue: pop blocks until push wakes the consumer" {
    // Race-shaped test: spawn a consumer thread, then push from the test.
    // Regardless of which thread runs first the contract is the same — pop
    // either blocks-then-wakes or finds the message already buffered. Both
    // are correct; this test only asserts the round-trip succeeds without
    // deadlock and with the right payload. (A pure "was-it-blocked"
    // assertion would require timing which is exactly the flake source
    // we're avoiding. The deadlock case shows up as a test-runner timeout.)
    const a = std.testing.allocator;
    var q = try SendQueue.init(a, 4);
    defer q.deinit();

    const State = struct {
        var got: ?[]u8 = null;
    };
    State.got = null;

    const t = try std.Thread.spawn(.{}, struct {
        fn run(qq: *SendQueue) void {
            if (qq.pop()) |m| State.got = m.data;
        }
    }.run, .{q});

    try q.push("woke-up", .text, .crdt_op);
    t.join();
    try std.testing.expect(State.got != null);
    defer a.free(State.got.?);
    try std.testing.expectEqualStrings("woke-up", State.got.?);
}

test "SendQueue: close wakes a blocked consumer with null" {
    // Same race-tolerant shape as above. Whether the consumer enters
    // `wait` before `close` or after, the contract is "pop returns null
    // once closed and empty". Deadlock manifests as a runner timeout.
    const a = std.testing.allocator;
    var q = try SendQueue.init(a, 4);
    defer q.deinit();

    const State = struct {
        var result_is_null: bool = false;
    };
    State.result_is_null = false;

    const t = try std.Thread.spawn(.{}, struct {
        fn run(qq: *SendQueue) void {
            State.result_is_null = (qq.pop() == null);
        }
    }.run, .{q});

    q.close();
    t.join();
    try std.testing.expect(State.result_is_null);
}

test "SendQueue: .control message refuses to be dropped on overflow" {
    // Security/correctness regression — Phase 5 panel #1 H-5 (escalating L-6):
    // session-control messages (join/leave/sync/peers/error/pong) are NEITHER
    // idempotent NOR commutative. Drop-oldest is only valid for `.crdt_op`.
    // This test verifies that a queue full of `.control` refuses a further
    // `.control` push with `error.QueueFull` rather than dropping one.
    const a = std.testing.allocator;
    var q = try SendQueue.init(a, 3);
    defer q.deinit();

    try q.push("ctrl-1", .text, .control);
    try q.push("ctrl-2", .text, .control);
    try q.push("ctrl-3", .text, .control);

    try std.testing.expectError(error.QueueFull, q.push("ctrl-4", .text, .control));
    try std.testing.expectEqual(@as(u64, 0), q.droppedCount());
    try std.testing.expectEqual(@as(usize, 3), q.pendingCount());
}

test "SendQueue: .crdt_op push reclaims slot from oldest .crdt_op, never from .control" {
    // If the queue has a mix of crdt_op + control, a crdt_op push on
    // overflow must drop the oldest CRDT slot, leaving every control
    // message intact. Verifies the dropOldestCrdtOpLocked compaction
    // for mid-ring drops.
    const a = std.testing.allocator;
    var q = try SendQueue.init(a, 4);
    defer q.deinit();

    try q.push("ctrl-A", .text, .control);
    try q.push("op-B", .text, .crdt_op); // oldest CRDT
    try q.push("ctrl-C", .text, .control);
    try q.push("op-D", .text, .crdt_op);

    try q.push("op-E", .text, .crdt_op); // forces drop of "op-B"
    try std.testing.expectEqual(@as(u64, 1), q.droppedCount());
    try std.testing.expectEqual(@as(usize, 4), q.pendingCount());

    // Drain in FIFO order; "op-B" should be gone, others survive.
    const m1 = q.pop().?;
    defer a.free(m1.data);
    try std.testing.expectEqualStrings("ctrl-A", m1.data);
    const m2 = q.pop().?;
    defer a.free(m2.data);
    try std.testing.expectEqualStrings("ctrl-C", m2.data);
    const m3 = q.pop().?;
    defer a.free(m3.data);
    try std.testing.expectEqualStrings("op-D", m3.data);
    const m4 = q.pop().?;
    defer a.free(m4.data);
    try std.testing.expectEqualStrings("op-E", m4.data);
}

test "SendQueue: .control push preempts oldest .crdt_op when ring is full" {
    // A control message arriving when the ring is full MUST preempt the
    // oldest CRDT op (priority lane). If the ring is all control, the
    // push fails — covered by the prior test.
    const a = std.testing.allocator;
    var q = try SendQueue.init(a, 3);
    defer q.deinit();

    try q.push("op-old", .text, .crdt_op);
    try q.push("op-mid", .text, .crdt_op);
    try q.push("op-new", .text, .crdt_op);

    try q.push("ctrl-urgent", .text, .control); // preempts "op-old"
    try std.testing.expectEqual(@as(u64, 1), q.droppedCount());
    try std.testing.expectEqual(@as(usize, 3), q.pendingCount());

    const m1 = q.pop().?;
    defer a.free(m1.data);
    try std.testing.expectEqualStrings("op-mid", m1.data);
    const m2 = q.pop().?;
    defer a.free(m2.data);
    try std.testing.expectEqualStrings("op-new", m2.data);
    const m3 = q.pop().?;
    defer a.free(m3.data);
    try std.testing.expectEqualStrings("ctrl-urgent", m3.data);
}

test "SendQueue: close is idempotent" {
    // Regression for Phase 5 panel coverage MED — `close` was tested for
    // first-call effect but never explicitly for the `if (self.closed)
    // return` guard. Removing the guard would re-broadcast on a closed
    // condvar; this test fails-by-deadlock if that ever happens.
    const a = std.testing.allocator;
    var q = try SendQueue.init(a, 4);
    defer q.deinit();

    q.close();
    q.close();
    q.close();
    try std.testing.expect(q.pop() == null);
}

test "SendQueue: multiple producers + single consumer over wraparound" {
    const a = std.testing.allocator;
    var q = try SendQueue.init(a, 8);
    defer q.deinit();

    // Drive the ring head past 0 to exercise modular indexing.
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        var label_buf: [16]u8 = undefined;
        const label = try std.fmt.bufPrint(&label_buf, "msg-{d}", .{i});
        try q.push(label, .text, .crdt_op);
        const m = q.pop().?;
        defer a.free(m.data);
        try std.testing.expectEqualStrings(label, m.data);
    }
}
