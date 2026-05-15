//! P2P Collaboration Module
//!
//! Real-time collaboration via room codes — no login, no account.
//! Multiple peers (capped at 3 free), like a Zoom call for your workflow.
//!
//! Two modes:
//!   - Host Session: Studio starts embedded WebSocket relay (LAN/VPN/direct)
//!   - Join Session: Connect to any relay (works through NAT/firewalls)
//!
//! Architecture:
//!   - ALL networking in Zig (WebView/JS never touches the network)
//!   - LWW-Map CRDT for conflict-free state sync
//!   - AES-256-GCM wire encryption with a key derived from the shared
//!     room code + salt — opaque to the relay, but NOT true E2E in the
//!     per-user-keypair sense; every peer with the room code is fully
//!     trusted at v1. See `crypto.zig` for the threat model + Tier 2 TODOs.
//!   - Only diffs sent over the wire (full state sync only on peer join)

pub const crdt_interface = @import("crdt_interface.zig");
pub const crdt = @import("crdt_lww_map.zig");
pub const crdt_text = @import("crdt_text.zig"); // STUB (NotImplemented) — see file docstring
pub const crdt_blob = @import("crdt_blob.zig"); // STUB (NotImplemented) — see file docstring
pub const channel = @import("channel.zig");
pub const protocol = @import("protocol.zig");
pub const crypto = @import("crypto.zig");
pub const identity = @import("identity.zig");
pub const websocket = @import("websocket.zig");
pub const send_queue = @import("send_queue.zig");
pub const session = @import("session.zig");
pub const manager = @import("manager.zig");
pub const host_functions = @import("host_functions.zig");
pub const bridge_handlers = @import("bridge_handlers.zig");

pub const CollabManager = manager.CollabManager;
pub const CrdtDoc = crdt.CrdtDoc;
pub const CrdtOp = crdt.CrdtOp;
pub const Mutation = crdt.Mutation;
pub const Session = session.Session;
pub const SessionState = session.SessionState;
pub const CrdtInterface = crdt_interface.CrdtInterface;
pub const Channel = channel.Channel;
pub const ChannelRegistry = channel.ChannelRegistry;

test {
    @import("std").testing.refAllDecls(@This());
}
