package relay

import (
	"net/http"

	"github.com/gorilla/websocket"
)

// Handler returns an http.HandlerFunc that performs the WebSocket
// upgrade, joins the requested room, and starts the peer's reader +
// writer pumps. Query params:
//
//	?room=XXXX-XXXX   required, validated against the room-code regex
//	?peer=<id>        required, any non-empty string (typically a UUID)
//
// Auth: the caller of NewRouter() decides whether to wrap this in JWT
// middleware. In ad-hoc Share/Join mode the relay is open (room code
// IS the secret). Team mode wraps with jwtauth + casbin checks before
// reaching Handler.
//
// CheckOrigin currently allows all origins so the studio's WKWebView
// can connect without an Origin header. Production deployments should
// inject an origin allowlist via cmd/relay (added in a follow-up).
func (h *Hub) Handler() http.HandlerFunc {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  h.cfg.ReadBufferBytes,
		WriteBufferSize: h.cfg.WriteBufferBytes,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	return func(w http.ResponseWriter, r *http.Request) {
		room := r.URL.Query().Get("room")
		peerID := r.URL.Query().Get("peer")

		if room == "" || peerID == "" {
			http.Error(w, "room and peer query params required", http.StatusBadRequest)
			return
		}
		if !roomCodePattern.MatchString(room) {
			http.Error(w, "invalid room code (want XXXX-XXXX uppercase alphanumerics)", http.StatusBadRequest)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			h.logger.Warn("ws upgrade failed", "err", err)
			return
		}
		peer := newPeer(peerID, conn, h)
		if err := h.join(room, peerID, peer); err != nil {
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"error":"`+sanitizeQuotes(err.Error())+`"}`))
			_ = conn.Close()
			return
		}
		h.logger.Info("relay peer joined", "room", room, "peer", peerID, "room_size", h.RoomSize(room))
		go peer.writePump()
		peer.readPump()
		h.logger.Info("relay peer left", "room", room, "peer", peerID, "room_size", h.RoomSize(room))
	}
}

// sanitizeQuotes prevents broken JSON when error strings contain `"`.
func sanitizeQuotes(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return string(out)
}
