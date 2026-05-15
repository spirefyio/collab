package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/spirefyio/collab/server/internal/config"
)

type healthResponse struct {
	Status  string    `json:"status"`
	Time    time.Time `json:"time"`
	Version string    `json:"version"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	resp := healthResponse{
		Status:  "ok",
		Time:    time.Now().UTC(),
		Version: config.Version,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

type readinessResponse struct {
	Status  string         `json:"status"`
	Time    time.Time      `json:"time"`
	Version string         `json:"version"`
	Checks  map[string]any `json:"checks"`
}

// readinessHandler is /health/ready — distinct from /health (liveness).
// Returns 200 only when every wired subsystem responds to its
// implementation-specific ping. Used by orchestrators (k8s readinessProbe,
// docker healthcheck) to gate traffic.
func readinessHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		checks := map[string]any{}
		allOK := true

		if deps.DB != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := deps.DB.Ping(ctx); err != nil {
				checks["db"] = map[string]string{"status": "fail", "err": err.Error()}
				allOK = false
			} else {
				checks["db"] = map[string]string{"status": "ok"}
			}
		} else {
			checks["db"] = map[string]string{"status": "not-configured"}
		}

		if deps.RelayHub != nil {
			checks["relay"] = map[string]any{"status": "ok", "rooms": deps.RelayHub.RoomCount()}
		} else {
			checks["relay"] = map[string]string{"status": "not-configured"}
		}

		status := http.StatusOK
		statusStr := "ready"
		if !allOK {
			status = http.StatusServiceUnavailable
			statusStr = "not-ready"
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(readinessResponse{
			Status:  statusStr,
			Time:    time.Now().UTC(),
			Version: config.Version,
			Checks:  checks,
		})
	}
}
