package api

import (
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
