package api

import (
	"encoding/json"
	"net/http"

	"github.com/spirefyio/collab/server/internal/auth"
)

type meResponse struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email,omitempty"`
	Name    string   `json:"name,omitempty"`
	Roles   []string `json:"roles,omitempty"`
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := auth.ClaimsFromContext(r.Context())
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	resp := meResponse{
		Subject: claims.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
		Roles:   claims.Roles,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
