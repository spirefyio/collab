package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/spirefyio/collab/server/internal/auth"
)

// teamProbeHandler is a placeholder demonstrating that:
//   - jwtauth.Authenticator runs before this handler (401 without token)
//   - RequireAccess(enf) runs before this handler (403 without an allowing role)
//   - chi's URL params are accessible
//
// Real CRUD lands in a follow-up commit alongside the Postgres store.
func teamProbeHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := auth.ClaimsFromContext(r.Context())
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	resp := map[string]any{
		"team_id": chi.URLParam(r, "teamID"),
		"caller":  claims.Subject,
		"roles":   claims.Roles,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
