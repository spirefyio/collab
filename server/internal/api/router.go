// Package api wires the chi router for the collab HTTP API. Subsequent
// commits add casbin RBAC, OAuth handlers, team CRUD, and WebSocket
// relay routes.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/spirefyio/collab/server/internal/acl"
	"github.com/spirefyio/collab/server/internal/auth"
	"github.com/spirefyio/collab/server/internal/config"
	"github.com/spirefyio/collab/server/internal/relay"
)

// Deps bundles the cross-cutting handles the router needs. Fields may
// be nil when a feature surface is disabled (e.g. Issuer is nil when
// COLLAB_JWT_SECRET is unset and we're in dev mode — protected routes
// are not mounted in that case).
type Deps struct {
	Config   *config.Config
	Logger   *slog.Logger
	Issuer   *auth.Issuer
	Enforcer *acl.Enforcer
	RelayHub *relay.Hub
	DB       *pgxpool.Pool
}

func NewRouter(deps Deps) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(slogRequestLogger(deps.Logger))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/", rootHandler)
	r.Get("/health", healthHandler)
	r.Get("/health/ready", readinessHandler(deps))

	// Relay surface — open by default (room code is the secret in ad-hoc
	// mode). Team mode wraps this in jwtauth + casbin via a future commit
	// that adds /team-relay/ws with an Authorization-header gate.
	if deps.RelayHub != nil {
		r.Get("/relay/ws", deps.RelayHub.Handler())
	}

	// Protected surface — only mounted when JWT issuance is configured.
	// jwtauth.Verifier reads the token from the Authorization header or
	// the `jwt` cookie; jwtauth.Authenticator enforces signature + exp.
	if deps.Issuer != nil {
		r.Group(func(pr chi.Router) {
			pr.Use(jwtauth.Verifier(deps.Issuer.TokenAuth()))
			pr.Use(jwtauth.Authenticator(deps.Issuer.TokenAuth()))

			// Any authenticated user.
			pr.Get("/me", meHandler)

			// Role-gated surface — requires both JWT and casbin enforcer.
			// Full team/workspace CRUD lands in follow-up commits; the
			// demo endpoint below proves the pipe.
			if deps.Enforcer != nil {
				pr.With(RequireAccess(deps.Enforcer)).Get("/teams/{teamID}/probe", teamProbeHandler)
			}
		})
	}

	return r
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"service":"spirefyio/collab","version":"` + config.Version + `"}`))
}

func slogRequestLogger(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			logger.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"dur_ms", time.Since(start).Milliseconds(),
				"req_id", middleware.GetReqID(r.Context()),
			)
		})
	}
}
