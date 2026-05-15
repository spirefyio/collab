//! Minimal RFC 6455 WebSocket Implementation
//!
//! Client: HTTP upgrade handshake → frame read/write loop
//! Server: Accept HTTP upgrade → frame read/write loop (for LAN host mode)
//!
//! Frame types: text, binary, ping, pong, close
//! Masking: required for client→server frames per RFC 6455
//!
//! Uses `std.Io.net.Stream` underneath. Non-blocking receive via dedicated
//! read thread per connection (managed by caller). `compat.io()` is the
//! process-lifetime Io singleton — threading it through every function
//! signature would be shotgun surgery across the collab subsystem.

const std = @import("std");
const compat = @import("compat");
const net = std.Io.net;

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,
};

pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    payload: []const u8,
};

pub const Error = error{
    ConnectionClosed,
    InvalidFrame,
    PayloadTooLarge,
    HandshakeFailed,
    InvalidUpgrade,
    StreamError,
} || std.mem.Allocator.Error;

const MAX_PAYLOAD_SIZE = 1024 * 1024; // 1MB max frame payload

// =============================================================================
// Frame Encoding/Decoding
// =============================================================================

/// Write a WebSocket frame to the stream.
/// If `mask` is true (required for client→server), applies random masking.
pub fn writeFrame(stream: net.Stream, opcode: Opcode, payload: []const u8, mask: bool) !void {
    var io_buf: [64]u8 = undefined;
    var stream_writer = stream.writer(compat.io(), &io_buf);
    const w = &stream_writer.interface;

    var header: [14]u8 = undefined; // max header size: 2 + 8 + 4
    var header_len: usize = 0;

    // Byte 0: FIN + opcode
    header[0] = 0x80 | @as(u8, @intFromEnum(opcode));
    header_len = 1;

    // Byte 1: MASK bit + payload length
    const mask_bit: u8 = if (mask) 0x80 else 0x00;
    if (payload.len < 126) {
        header[1] = mask_bit | @as(u8, @intCast(payload.len));
        header_len = 2;
    } else if (payload.len <= 65535) {
        header[1] = mask_bit | 126;
        std.mem.writeInt(u16, header[2..4], @intCast(payload.len), .big);
        header_len = 4;
    } else {
        header[1] = mask_bit | 127;
        std.mem.writeInt(u64, header[2..10], @intCast(payload.len), .big);
        header_len = 10;
    }

    // Masking key (4 bytes) if masked
    var mask_key: [4]u8 = undefined;
    if (mask) {
        compat.io().random(&mask_key);
        @memcpy(header[header_len..][0..4], &mask_key);
        header_len += 4;
    }

    // Send header
    w.writeAll(header[0..header_len]) catch return Error.StreamError;

    // Send payload (masked if needed)
    if (mask and payload.len > 0) {
        // Mask in chunks to avoid large allocation
        var buf: [4096]u8 = undefined;
        var offset: usize = 0;
        while (offset < payload.len) {
            const chunk_len = @min(buf.len, payload.len - offset);
            for (0..chunk_len) |i| {
                buf[i] = payload[offset + i] ^ mask_key[(offset + i) % 4];
            }
            w.writeAll(buf[0..chunk_len]) catch return Error.StreamError;
            offset += chunk_len;
        }
    } else {
        if (payload.len > 0) {
            w.writeAll(payload) catch return Error.StreamError;
        }
    }

    w.flush() catch return Error.StreamError;
}

/// Read a single WebSocket frame from a persistent Reader.
///
/// CRITICAL: the Reader's underlying buffer MUST survive across calls.
/// `std.Io.Reader` reads from the kernel into its buffer in chunks (often
/// larger than what a single call consumes), then exposes consumed bytes
/// to the caller. If the buffer is recreated per-call (e.g. stack-allocated
/// in a wrapper), bytes that the kernel delivered into the buffer beyond
/// what the call consumed are PERMANENTLY LOST when the buffer goes out
/// of scope — the next kernel read will not redeliver them.
///
/// This was the root cause of the "sync arrives ~50% of the time"
/// flakiness in the two-instance integration test (2026-05-14): the host
/// wrote welcome+sync back-to-back, both arrived in the guest's recv
/// buffer, but the guest's `readFrame` used a per-call 64-byte stack
/// buffer that pulled welcome + read-ahead from sync, then discarded
/// the read-ahead bytes on return. The next `readFrame` call asked the
/// kernel for the sync bytes, but the kernel had already delivered them
/// upstream — the read blocked until the host closed the connection,
/// at which point the guest's read loop saw a close opcode (synthesized
/// from a partial frame) instead of the sync.
///
/// Caller owns the returned payload memory.
pub fn readFrameFromReader(allocator: std.mem.Allocator, r: *std.Io.Reader) !Frame {
    // Read first 2 bytes
    var head: [2]u8 = undefined;
    readExact(r, &head) catch return Error.ConnectionClosed;

    const fin = (head[0] & 0x80) != 0;
    const opcode: Opcode = @enumFromInt(@as(u4, @truncate(head[0] & 0x0F)));
    const masked = (head[1] & 0x80) != 0;
    var payload_len: u64 = head[1] & 0x7F;

    // Extended payload length
    if (payload_len == 126) {
        var ext: [2]u8 = undefined;
        readExact(r, &ext) catch return Error.ConnectionClosed;
        payload_len = std.mem.readInt(u16, &ext, .big);
    } else if (payload_len == 127) {
        var ext: [8]u8 = undefined;
        readExact(r, &ext) catch return Error.ConnectionClosed;
        payload_len = std.mem.readInt(u64, &ext, .big);
    }

    if (payload_len > MAX_PAYLOAD_SIZE) return Error.PayloadTooLarge;

    // Masking key
    var mask_key: [4]u8 = undefined;
    if (masked) {
        readExact(r, &mask_key) catch return Error.ConnectionClosed;
    }

    // Read payload
    const len: usize = @intCast(payload_len);
    const payload = try allocator.alloc(u8, len);
    errdefer allocator.free(payload);

    if (len > 0) {
        readExact(r, payload) catch return Error.ConnectionClosed;

        // Unmask
        if (masked) {
            for (payload, 0..) |*b, i| {
                b.* ^= mask_key[i % 4];
            }
        }
    }

    return .{ .fin = fin, .opcode = opcode, .payload = payload };
}

/// One-shot variant: builds a Reader with a stack-local buffer and
/// reads one frame. SAFE ONLY for handshake / test paths that read
/// exactly one frame from a stream and discard the rest — anything
/// that loops over multiple frames MUST use `readFrameFromReader`
/// with a buffer that persists across iterations (see the docstring
/// on `readFrameFromReader` for the lost-bytes hazard).
pub fn readFrame(allocator: std.mem.Allocator, stream: net.Stream) !Frame {
    var io_buf: [64]u8 = undefined;
    var stream_reader = stream.reader(compat.io(), &io_buf);
    return readFrameFromReader(allocator, &stream_reader.interface);
}

// =============================================================================
// Buffer-based frame parsing (for tests/fuzzing; mirrors readFrame logic)
// =============================================================================

pub const ParsedFrame = struct {
    frame: Frame,
    consumed: usize,
};

/// Parse a single WebSocket frame out of an in-memory buffer.
/// Returns error.NeedMoreData if the buffer does not yet contain a full frame.
/// Caller owns `frame.payload` memory (allocated via `allocator`) on success.
pub fn parseFrameFromBuffer(
    allocator: std.mem.Allocator,
    data: []const u8,
) !ParsedFrame {
    if (data.len < 2) return error.NeedMoreData;

    const fin = (data[0] & 0x80) != 0;
    const opcode: Opcode = @enumFromInt(@as(u4, @truncate(data[0] & 0x0F)));
    const masked = (data[1] & 0x80) != 0;
    const short_len: u64 = data[1] & 0x7F;

    var cursor: usize = 2;
    var payload_len: u64 = short_len;

    if (short_len == 126) {
        if (data.len < cursor + 2) return error.NeedMoreData;
        payload_len = std.mem.readInt(u16, data[cursor..][0..2], .big);
        cursor += 2;
    } else if (short_len == 127) {
        if (data.len < cursor + 8) return error.NeedMoreData;
        payload_len = std.mem.readInt(u64, data[cursor..][0..8], .big);
        cursor += 8;
    }

    if (payload_len > MAX_PAYLOAD_SIZE) return Error.PayloadTooLarge;

    var mask_key: [4]u8 = undefined;
    if (masked) {
        if (data.len < cursor + 4) return error.NeedMoreData;
        @memcpy(&mask_key, data[cursor..][0..4]);
        cursor += 4;
    }

    const len: usize = @intCast(payload_len);
    if (data.len < cursor + len) return error.NeedMoreData;

    const payload = try allocator.alloc(u8, len);
    errdefer allocator.free(payload);

    if (len > 0) {
        @memcpy(payload, data[cursor..][0..len]);
        if (masked) {
            for (payload, 0..) |*b, i| {
                b.* ^= mask_key[i % 4];
            }
        }
    }
    cursor += len;

    return .{
        .frame = .{ .fin = fin, .opcode = opcode, .payload = payload },
        .consumed = cursor,
    };
}

// =============================================================================
// WebSocket Client
// =============================================================================

pub const ClientConfig = struct {
    host: []const u8,
    port: u16 = 8080,
    path: []const u8 = "/",
};

/// Connect to a WebSocket server. Performs HTTP upgrade handshake.
/// Returns the connected stream ready for frame read/write.
pub fn connect(allocator: std.mem.Allocator, config: ClientConfig) !net.Stream {
    const io = compat.io();

    // Resolve address (IP literal only; no DNS)
    const address = try net.IpAddress.parse(config.host, config.port);
    const stream = try address.connect(io, .{ .mode = .stream });
    errdefer stream.close(io);

    // Generate Sec-WebSocket-Key (16 random bytes, base64-encoded)
    var key_bytes: [16]u8 = undefined;
    compat.io().random(&key_bytes);
    var key_buf: [24]u8 = undefined;
    const ws_key = std.base64.standard.Encoder.encode(&key_buf, &key_bytes);

    // Build HTTP upgrade request
    var req_buf: [1024]u8 = undefined;
    const req = std.fmt.bufPrint(
        &req_buf,
        "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}:{d}\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: {s}\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
        .{ config.path, config.host, config.port, ws_key },
    ) catch return Error.HandshakeFailed;

    // Write request
    {
        var wbuf: [128]u8 = undefined;
        var sw = stream.writer(io, &wbuf);
        sw.interface.writeAll(req) catch return Error.StreamError;
        sw.interface.flush() catch return Error.StreamError;
    }

    // Read the HTTP response line-by-line until the empty CRLF that
    // terminates the header block. We must NOT use `readSliceShort` here:
    // it is documented to fill `dest` and only return short on EOF, so on
    // a still-open socket it blocks past the last response byte waiting
    // for more — which is the bug that masqueraded as "macOS-arm64 stdlib
    // hang" prior to this fix. `takeDelimiterInclusive('\n')` instead
    // refills only as needed to find the next CRLF, so each call returns
    // as soon as a full line is in the buffer. The reader's internal
    // buffer must be >= max line length; 512 B is comfortable for HTTP.
    const MAX_HEADER_LINES = 64; // DoS guard: cap header count
    {
        var rbuf: [512]u8 = undefined;
        var sr = stream.reader(io, &rbuf);
        const status_line = sr.interface.takeDelimiterInclusive('\n') catch return Error.HandshakeFailed;
        if (!std.mem.startsWith(u8, status_line, "HTTP/1.1 101")) return Error.InvalidUpgrade;

        var lines: usize = 0;
        while (true) : (lines += 1) {
            if (lines >= MAX_HEADER_LINES) return Error.InvalidUpgrade;
            const line = sr.interface.takeDelimiterInclusive('\n') catch return Error.HandshakeFailed;
            const trimmed = std.mem.trimEnd(u8, line, "\r\n");
            if (trimmed.len == 0) break; // empty line — end of headers
            // Note: we intentionally don't validate Sec-WebSocket-Accept here
            // (parity with the pre-fix behaviour). The server's correctness
            // is its own responsibility for v1; harden when collab leaves
            // experimental.
        }
        // Bytes the kernel may have delivered past "\r\n\r\n" remain in
        // `rbuf`, which dies with this block. v1 protocol contract: the
        // server does not send WS frames until the client writes its
        // first frame, so the kernel buffer is empty here. If that ever
        // changes, switch to a stream-owned reader or do raw netRead
        // until '\r\n\r\n' is seen.
    }

    _ = allocator; // allocator available for future use (e.g., extensions)
    return stream;
}

// =============================================================================
// WebSocket Server (Embedded Relay)
// =============================================================================

pub const ServerConfig = struct {
    port: u16 = 8080,
    max_connections: u16 = 10,
};

/// A minimal WebSocket server that accepts connections and performs HTTP upgrade.
pub const Server = struct {
    listener: net.Server,

    pub fn init(config: ServerConfig) !Server {
        const io = compat.io();
        const address: net.IpAddress = .{ .ip4 = .unspecified(config.port) };
        const listener = try address.listen(io, .{
            .reuse_address = true,
        });
        return .{ .listener = listener };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit(compat.io());
    }

    /// Accept a new WebSocket connection. Performs HTTP upgrade handshake.
    /// Blocks until a client connects.
    pub fn accept(self: *Server) !net.Stream {
        const io = compat.io();
        const stream = try self.listener.accept(io);
        errdefer stream.close(io);

        // Read HTTP upgrade request line-by-line until the empty CRLF
        // that ends the header block. See the parity comment in `connect`
        // for why `readSliceShort` was the wrong primitive here. We must
        // copy the Sec-WebSocket-Key value out of the reader's internal
        // buffer before the next `takeDelimiterInclusive` call, since
        // each call may rebase/refill and invalidate previously returned
        // slices.
        const MAX_HEADER_LINES = 64; // DoS guard: cap header count
        const MAX_KEY_LEN = 256; // Sec-WebSocket-Key is 24 chars; allow slack
        var client_key_buf: [MAX_KEY_LEN]u8 = undefined;
        var client_key_len: usize = 0;
        {
            var rbuf: [512]u8 = undefined;
            var sr = stream.reader(io, &rbuf);
            // First line is the request line ("GET / HTTP/1.1"). We don't
            // currently enforce method/path/version — keep parity with the
            // pre-fix behaviour, which also skipped that check.
            _ = sr.interface.takeDelimiterInclusive('\n') catch return Error.HandshakeFailed;

            const key_prefix = "Sec-WebSocket-Key: ";
            var lines: usize = 0;
            while (true) : (lines += 1) {
                if (lines >= MAX_HEADER_LINES) return Error.InvalidUpgrade;
                const line = sr.interface.takeDelimiterInclusive('\n') catch return Error.HandshakeFailed;
                const trimmed = std.mem.trimEnd(u8, line, "\r\n");
                if (trimmed.len == 0) break; // empty line — end of headers
                if (std.mem.startsWith(u8, trimmed, key_prefix)) {
                    const val = trimmed[key_prefix.len..];
                    if (val.len == 0 or val.len > MAX_KEY_LEN) return Error.InvalidUpgrade;
                    @memcpy(client_key_buf[0..val.len], val);
                    client_key_len = val.len;
                }
            }
        }
        if (client_key_len == 0) return Error.InvalidUpgrade;
        const client_key = client_key_buf[0..client_key_len];

        // Compute Sec-WebSocket-Accept: SHA1(key + magic) → base64
        const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        var hasher = std.crypto.hash.Sha1.init(.{});
        hasher.update(client_key);
        hasher.update(magic);
        const hash = hasher.finalResult();
        var accept_buf: [28]u8 = undefined;
        const accept_key = std.base64.standard.Encoder.encode(&accept_buf, &hash);

        // Send HTTP 101 response
        var resp_buf: [256]u8 = undefined;
        const resp = std.fmt.bufPrint(
            &resp_buf,
            "HTTP/1.1 101 Switching Protocols\r\n" ++
                "Upgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Sec-WebSocket-Accept: {s}\r\n" ++
                "\r\n",
            .{accept_key},
        ) catch return Error.HandshakeFailed;

        {
            var wbuf: [128]u8 = undefined;
            var sw = stream.writer(io, &wbuf);
            sw.interface.writeAll(resp) catch return Error.StreamError;
            sw.interface.flush() catch return Error.StreamError;
        }

        return stream;
    }

    /// Get the port the server is listening on.
    pub fn getPort(self: *const Server) u16 {
        return self.listener.socket.address.getPort();
    }
};

// =============================================================================
// Stream close helper — abstraction point for collab/manager.zig to close
// streams without tracking io at each call site.
// =============================================================================

/// Close a stream using the process-lifetime io.
pub fn closeStream(stream: net.Stream) void {
    stream.close(compat.io());
}

// =============================================================================
// Helpers
// =============================================================================

fn readExact(r: *std.Io.Reader, buf: []u8) !void {
    r.readSliceAll(buf) catch return Error.StreamError;
}

// =============================================================================
// Tests
// =============================================================================

/// Helper: create a connected TCP socket pair via loopback.
/// Uses a thread to connect since accept() blocks.
fn createSocketPair() !struct { server: net.Stream, client: net.Stream } {
    const io = compat.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    // Shared state for thread to store client stream
    const State = struct {
        var client_stream: ?net.Stream = null;
        var done: bool = false;
    };
    State.client_stream = null;
    State.done = false;

    const thread = try std.Thread.spawn(.{}, struct {
        fn run(p: u16) void {
            const a: net.IpAddress = .{ .ip4 = .loopback(p) };
            State.client_stream = a.connect(compat.io(), .{ .mode = .stream }) catch null;
            State.done = true;
        }
    }.run, .{port});

    const server_stream = try listener.accept(io);

    thread.join();

    return .{
        .server = server_stream,
        .client = State.client_stream orelse return error.ConnectionFailed,
    };
}

test "writeFrame/readFrame round-trip (unmasked)" {
    const allocator = std.testing.allocator;
    const pair = try createSocketPair();
    const io = compat.io();
    defer pair.server.close(io);
    defer pair.client.close(io);

    const payload = "hello websocket";
    try writeFrame(pair.server, .text, payload, false);

    const frame = try readFrame(allocator, pair.client);
    defer allocator.free(frame.payload);

    try std.testing.expect(frame.fin);
    try std.testing.expect(frame.opcode == .text);
    try std.testing.expectEqualStrings(payload, frame.payload);
}

test "writeFrame/readFrame round-trip (masked)" {
    const allocator = std.testing.allocator;
    const pair = try createSocketPair();
    const io = compat.io();
    defer pair.server.close(io);
    defer pair.client.close(io);

    const payload = "masked payload test data";
    try writeFrame(pair.client, .text, payload, true);

    const frame = try readFrame(allocator, pair.server);
    defer allocator.free(frame.payload);

    try std.testing.expect(frame.fin);
    try std.testing.expect(frame.opcode == .text);
    try std.testing.expectEqualStrings(payload, frame.payload);
}

test "writeFrame/readFrame: ping/pong" {
    const allocator = std.testing.allocator;
    const pair = try createSocketPair();
    const io = compat.io();
    defer pair.server.close(io);
    defer pair.client.close(io);

    try writeFrame(pair.server, .ping, "", false);
    const ping_frame = try readFrame(allocator, pair.client);
    defer allocator.free(ping_frame.payload);
    try std.testing.expect(ping_frame.opcode == .ping);

    try writeFrame(pair.client, .pong, "", true);
    const pong_frame = try readFrame(allocator, pair.server);
    defer allocator.free(pong_frame.payload);
    try std.testing.expect(pong_frame.opcode == .pong);
}

test "writeFrame/readFrame: close frame" {
    const allocator = std.testing.allocator;
    const pair = try createSocketPair();
    const io = compat.io();
    defer pair.server.close(io);
    defer pair.client.close(io);

    var close_payload: [2]u8 = undefined;
    std.mem.writeInt(u16, &close_payload, 1000, .big);
    try writeFrame(pair.server, .close, &close_payload, false);

    const frame = try readFrame(allocator, pair.client);
    defer allocator.free(frame.payload);
    try std.testing.expect(frame.opcode == .close);
    try std.testing.expectEqual(@as(usize, 2), frame.payload.len);
}

test "Server.accept + connect: HTTP upgrade round-trip" {
    // Previously skipped under the (incorrect) theory that `.port = 0`
    // hit a stdlib bug. The actual hang was `readSliceShort` on the
    // request/response, which only returns on EOF, not on partial read.
    // The line-by-line `takeDelimiterInclusive` upgrade in `connect`
    // and `Server.accept` fixes both sides; this test exercises both
    // and would catch a regression on either.
    const allocator = std.testing.allocator;
    const io = compat.io();

    var ws_server = try Server.init(.{ .port = 0 });
    defer ws_server.deinit();
    const port = ws_server.getPort();

    const State = struct {
        var client_stream: ?net.Stream = null;
        var client_error: ?anyerror = null;
    };
    State.client_stream = null;
    State.client_error = null;

    const thread = try std.Thread.spawn(.{}, struct {
        fn run(p: u16) void {
            // Use production `connect` so this test would catch a
            // regression in the client-side upgrade path too.
            const stream = connect(std.testing.allocator, .{
                .host = "127.0.0.1",
                .port = p,
                .path = "/",
            }) catch |err| {
                State.client_error = err;
                return;
            };
            State.client_stream = stream;
        }
    }.run, .{port});

    const ws_stream = try ws_server.accept();
    defer ws_stream.close(io);

    thread.join();
    if (State.client_error) |err| return err;
    const client_stream = State.client_stream orelse return error.ConnectionFailed;
    defer client_stream.close(io);

    // Exchange a real frame in each direction to prove the post-upgrade
    // stream is healthy and we didn't desync the reader/writer buffers.
    try writeFrame(ws_stream, .text, "hello from server", false);
    const recv1 = try readFrame(allocator, client_stream);
    defer allocator.free(recv1.payload);
    try std.testing.expectEqualStrings("hello from server", recv1.payload);

    try writeFrame(client_stream, .text, "hello back from client", true);
    const recv2 = try readFrame(allocator, ws_stream);
    defer allocator.free(recv2.payload);
    try std.testing.expectEqualStrings("hello back from client", recv2.payload);
}
