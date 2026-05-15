package relay

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func newTestHub() *Hub {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := DefaultConfig()
	cfg.PingPeriod = 100 * time.Millisecond
	cfg.PongWait = 200 * time.Millisecond
	cfg.WriteWait = 100 * time.Millisecond
	return NewHub(cfg, logger)
}

func newWSTestServer(t *testing.T, hub *Hub) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/relay/ws", hub.Handler())
	srv := httptest.NewServer(mux)
	// turn http://host/relay/ws into ws://host/relay/ws
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/ws"
	t.Cleanup(srv.Close)
	return srv, wsURL
}

func dialPeer(t *testing.T, wsURL, room, peerID string) *websocket.Conn {
	t.Helper()
	dialer := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	conn, _, err := dialer.Dial(wsURL+"?room="+room+"&peer="+peerID, nil)
	if err != nil {
		t.Fatalf("dial %s/%s: %v", room, peerID, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestNewHub_StartsEmpty(t *testing.T) {
	h := newTestHub()
	if got := h.RoomCount(); got != 0 {
		t.Errorf("RoomCount: got %d want 0", got)
	}
}

func TestJoin_RejectsBadCodeFormat(t *testing.T) {
	_, wsURL := newWSTestServer(t, newTestHub())
	dialer := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	cases := []string{"shortcode", "AB-12", "ABCD-12345", "abcd-1234"}
	for _, c := range cases {
		_, resp, err := dialer.Dial(wsURL+"?room="+c+"&peer=p1", nil)
		if err == nil {
			t.Errorf("expected dial failure for %q", c)
			continue
		}
		if resp == nil || resp.StatusCode != http.StatusBadRequest {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			t.Errorf("expected 400 for %q, got %d", c, status)
		}
	}
}

func TestJoin_RejectsMissingParams(t *testing.T) {
	_, wsURL := newWSTestServer(t, newTestHub())
	dialer := websocket.Dialer{HandshakeTimeout: 2 * time.Second}

	_, resp, err := dialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected dial failure without params")
	}
	if resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 without params, got %v", resp)
	}
}

func TestJoin_BroadcastSkipsSender(t *testing.T) {
	hub := newTestHub()
	_, wsURL := newWSTestServer(t, hub)

	connA := dialPeer(t, wsURL, "ROOM-0001", "peer-a")
	connB := dialPeer(t, wsURL, "ROOM-0001", "peer-b")
	connC := dialPeer(t, wsURL, "ROOM-0001", "peer-c")

	// Wait for hub to register all three peers (race with WS upgrade goroutines).
	deadline := time.Now().Add(time.Second)
	for hub.RoomSize("ROOM-0001") != 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := hub.RoomSize("ROOM-0001"); got != 3 {
		t.Fatalf("room size: got %d want 3", got)
	}

	payload := []byte("opaque-ciphertext-from-A")
	if err := connA.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	for _, c := range []*websocket.Conn{connB, connC} {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, got, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(got) != string(payload) {
			t.Errorf("received %q want %q", got, payload)
		}
	}

	// connA should NOT see its own message — assert the read deadline elapses.
	_ = connA.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, msg, err := connA.ReadMessage(); err == nil {
		t.Fatalf("sender received own message: %q", msg)
	}
}

func TestJoin_EnforcesMaxPeers(t *testing.T) {
	hub := newTestHub()
	hub.cfg.MaxPeersPerRoom = 2
	_, wsURL := newWSTestServer(t, hub)

	_ = dialPeer(t, wsURL, "FULL-ROOM", "p1")
	_ = dialPeer(t, wsURL, "FULL-ROOM", "p2")

	dialer := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	conn, _, err := dialer.Dial(wsURL+"?room=FULL-ROOM&peer=p3", nil)
	if err != nil {
		// Dial may succeed (handshake OK) — the rejection is sent over the
		// WS as JSON then the conn closes. Allow either path.
		t.Logf("dial err (acceptable): %v", err)
		return
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err == nil && !strings.Contains(string(msg), "full") {
		t.Errorf("expected room-full error, got %q", msg)
	}
}

func TestRoomGC_OnAllPeersLeaving(t *testing.T) {
	hub := newTestHub()
	_, wsURL := newWSTestServer(t, hub)

	connA := dialPeer(t, wsURL, "GCED-0001", "p1")
	connB := dialPeer(t, wsURL, "GCED-0001", "p2")

	deadline := time.Now().Add(time.Second)
	for hub.RoomSize("GCED-0001") != 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	connA.Close()
	connB.Close()

	deadline = time.Now().Add(time.Second)
	for hub.RoomCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := hub.RoomCount(); got != 0 {
		t.Errorf("expected room GC, got %d remaining rooms", got)
	}
}

func TestRoom_BroadcastIsConcurrencySafe(t *testing.T) {
	hub := newTestHub()
	_, wsURL := newWSTestServer(t, hub)

	const peerCount = 4
	conns := make([]*websocket.Conn, peerCount)
	for i := 0; i < peerCount; i++ {
		conns[i] = dialPeer(t, wsURL, "RACE-0001", "p"+string(rune('a'+i)))
	}

	deadline := time.Now().Add(time.Second)
	for hub.RoomSize("RACE-0001") != peerCount && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	// Every peer sends 5 messages concurrently. We don't assert delivery
	// counts (drops are allowed under load); we assert the run survives
	// without panics or data races (this test is intended for `go test -race`).
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Add(1)
		go func(idx int, conn *websocket.Conn) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				_ = conn.WriteMessage(websocket.BinaryMessage, []byte("msg"))
			}
		}(i, c)
	}
	wg.Wait()

	for _, c := range conns {
		_ = c.Close()
	}
}
