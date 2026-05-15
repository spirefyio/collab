// Package relay is the opaque WebSocket broker that pairs collab peers
// by room code. The server never decrypts payloads — it forwards
// ciphertext bytes between peers in the same room.
//
// Room codes follow the studio Share/Join format `XXXX-XXXX` (uppercase
// alphanumerics) so the relay can be used as a drop-in target for the
// existing Zig CollabManager.
package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Defaults sized for a small workspace session (≤16 peers, ≤1 MiB ops).
// Override per-deployment via Config or environment variables in cmd/relay.
const (
	DefaultMaxPeersPerRoom  = 16
	DefaultMaxMessageBytes  = 1 << 20
	DefaultPongWait         = 60 * time.Second
	DefaultPingPeriod       = 50 * time.Second
	DefaultWriteWait        = 10 * time.Second
	DefaultSendBufferLength = 64
)

// roomCodePattern matches the studio Share/Join code shape (e.g. ABCD-1234).
var roomCodePattern = regexp.MustCompile(`^[A-Z0-9]{4}-[A-Z0-9]{4}$`)

type Config struct {
	MaxPeersPerRoom  int
	MaxMessageBytes  int64
	PongWait         time.Duration
	PingPeriod       time.Duration
	WriteWait        time.Duration
	SendBufferLength int
	ReadBufferBytes  int
	WriteBufferBytes int
}

func DefaultConfig() Config {
	return Config{
		MaxPeersPerRoom:  DefaultMaxPeersPerRoom,
		MaxMessageBytes:  DefaultMaxMessageBytes,
		PongWait:         DefaultPongWait,
		PingPeriod:       DefaultPingPeriod,
		WriteWait:        DefaultWriteWait,
		SendBufferLength: DefaultSendBufferLength,
		ReadBufferBytes:  4096,
		WriteBufferBytes: 4096,
	}
}

// Hub owns the rooms-by-code map. It does not own peer goroutines —
// each peer drives its own reader/writer pump and self-removes via
// hub.leave when the WS closes.
type Hub struct {
	mu     sync.Mutex
	rooms  map[string]*Room
	cfg    Config
	logger *slog.Logger
}

func NewHub(cfg Config, logger *slog.Logger) *Hub {
	if logger == nil {
		logger = slog.Default()
	}
	return &Hub{
		rooms:  make(map[string]*Room),
		cfg:    cfg,
		logger: logger,
	}
}

// RoomCount is the number of currently-active rooms. Useful for /health
// extensions and operational metrics.
func (h *Hub) RoomCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.rooms)
}

// RoomSize reports the peer count for one room, or 0 if no such room.
func (h *Hub) RoomSize(code string) int {
	h.mu.Lock()
	room, ok := h.rooms[code]
	h.mu.Unlock()
	if !ok {
		return 0
	}
	return room.size()
}

func (h *Hub) join(roomCode, peerID string, peer *Peer) error {
	if !roomCodePattern.MatchString(roomCode) {
		return errors.New("invalid room code (want XXXX-XXXX, uppercase alphanumerics)")
	}
	if peerID == "" {
		return errors.New("peer id is required")
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	room, exists := h.rooms[roomCode]
	if !exists {
		room = newRoom(roomCode, h.cfg.MaxPeersPerRoom)
		h.rooms[roomCode] = room
	}
	if err := room.add(peerID, peer); err != nil {
		if !exists && room.size() == 0 {
			// just-created room, undo
			delete(h.rooms, roomCode)
		}
		return err
	}
	peer.room = room
	return nil
}

func (h *Hub) leave(roomCode, peerID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	room, ok := h.rooms[roomCode]
	if !ok {
		return
	}
	room.remove(peerID)
	if room.size() == 0 {
		delete(h.rooms, roomCode)
	}
}

// Room is a single collab session bucket. Peers fan-out via broadcast.
type Room struct {
	code     string
	maxPeers int
	mu       sync.RWMutex
	peers    map[string]*Peer
	created  time.Time
}

func newRoom(code string, max int) *Room {
	return &Room{
		code:     code,
		maxPeers: max,
		peers:    make(map[string]*Peer),
		created:  time.Now(),
	}
}

func (r *Room) add(id string, p *Peer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.peers[id]; exists {
		return fmt.Errorf("peer %q already in room %q", id, r.code)
	}
	if len(r.peers) >= r.maxPeers {
		return fmt.Errorf("room %q full (max %d peers)", r.code, r.maxPeers)
	}
	r.peers[id] = p
	return nil
}

func (r *Room) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.peers, id)
}

func (r *Room) size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.peers)
}

// broadcast fans out msg to every peer in the room except the sender.
// Returns the number of peers the message was queued to. If a peer's
// send buffer is full the message is dropped for that peer — the
// broker never blocks the sender on a slow consumer. Drops are
// counted via the dropped return so the caller can decide to log or
// metric them.
func (r *Room) broadcast(senderID string, msg []byte) (forwarded, dropped int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for id, peer := range r.peers {
		if id == senderID {
			continue
		}
		select {
		case peer.send <- msg:
			forwarded++
		default:
			dropped++
		}
	}
	return forwarded, dropped
}

// Peer wraps a single WebSocket connection. The reader and writer
// goroutines coordinate via send (chan) and ctx (cancellation).
type Peer struct {
	id     string
	conn   *websocket.Conn
	room   *Room
	send   chan []byte
	hub    *Hub
	logger *slog.Logger

	closeOnce sync.Once
	ctx       context.Context
	cancel    context.CancelFunc
}

func newPeer(id string, conn *websocket.Conn, hub *Hub) *Peer {
	ctx, cancel := context.WithCancel(context.Background())
	return &Peer{
		id:     id,
		conn:   conn,
		hub:    hub,
		send:   make(chan []byte, hub.cfg.SendBufferLength),
		logger: hub.logger.With("peer", id),
		ctx:    ctx,
		cancel: cancel,
	}
}

// close terminates the peer: cancels the writer, removes from the
// room, closes the send channel, and closes the underlying connection.
// Idempotent via sync.Once so both the reader and writer pumps can
// call it on exit.
func (p *Peer) close() {
	p.closeOnce.Do(func() {
		p.cancel()
		if p.room != nil {
			p.hub.leave(p.room.code, p.id)
		}
		close(p.send)
		_ = p.conn.Close()
	})
}

func (p *Peer) readPump() {
	defer p.close()
	p.conn.SetReadLimit(p.hub.cfg.MaxMessageBytes)
	_ = p.conn.SetReadDeadline(time.Now().Add(p.hub.cfg.PongWait))
	p.conn.SetPongHandler(func(string) error {
		return p.conn.SetReadDeadline(time.Now().Add(p.hub.cfg.PongWait))
	})
	for {
		_, payload, err := p.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				p.logger.Warn("ws read err", "err", err)
			}
			return
		}
		if p.room != nil {
			fwd, drop := p.room.broadcast(p.id, payload)
			if drop > 0 {
				p.logger.Warn("relay drops on broadcast", "room", p.room.code, "forwarded", fwd, "dropped", drop)
			}
		}
	}
}

func (p *Peer) writePump() {
	ticker := time.NewTicker(p.hub.cfg.PingPeriod)
	defer func() {
		ticker.Stop()
		p.close()
	}()
	for {
		select {
		case msg, ok := <-p.send:
			_ = p.conn.SetWriteDeadline(time.Now().Add(p.hub.cfg.WriteWait))
			if !ok {
				_ = p.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := p.conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			_ = p.conn.SetWriteDeadline(time.Now().Add(p.hub.cfg.WriteWait))
			if err := p.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case <-p.ctx.Done():
			return
		}
	}
}
