package api

import (
	"net/http"

	"github.com/spirefyio/collab/server/internal/acl"
	"github.com/spirefyio/collab/server/internal/auth"
)

// RequireAccess produces a middleware that gates a route on the casbin
// enforcer using the JWT roles claim as the subject.
//
//	r.With(RequireAccess(enf)).Delete("/teams/{teamID}", handler)
//
// 401 if the request has no validated JWT (must run AFTER
// jwtauth.Authenticator). 403 if no role on the token grants the
// (path, method) tuple.
func RequireAccess(enf *acl.Enforcer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := auth.ClaimsFromContext(r.Context())
			if err != nil || claims == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if len(claims.Roles) == 0 {
				http.Error(w, "forbidden: no roles on token", http.StatusForbidden)
				return
			}
			ok, err := enf.HasAccess(claims.Roles, r.URL.Path, r.Method)
			if err != nil {
				http.Error(w, "authorization error", http.StatusInternalServerError)
				return
			}
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
