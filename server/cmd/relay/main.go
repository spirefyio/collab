// Spirefy collab — relay + team service entrypoint.
//
// Boots an HTTP server (chi router) exposing:
//   - /health           liveness probe
//   - /                 service banner
//   - /relay/ws         WebSocket relay (added in a follow-up commit)
//   - /auth/oauth/*     OAuth callbacks (added in a follow-up commit)
//   - /teams/*          team CRUD (added in a follow-up commit)
//
// Graceful shutdown on SIGINT / SIGTERM with a 30s drain budget.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spirefyio/collab/server/internal/acl"
	"github.com/spirefyio/collab/server/internal/api"
	"github.com/spirefyio/collab/server/internal/auth"
	"github.com/spirefyio/collab/server/internal/config"
	"github.com/spirefyio/collab/server/internal/relay"
)

const shutdownGrace = 30 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(2)
	}

	relayCfg := relay.DefaultConfig()
	relayCfg.ReadBufferBytes = cfg.WSReadBufferBytes
	relayCfg.WriteBufferBytes = cfg.WSWriteBufferBytes
	hub := relay.NewHub(relayCfg, logger)
	logger.Info("relay hub ready",
		"max_peers_per_room", relayCfg.MaxPeersPerRoom,
		"max_message_bytes", relayCfg.MaxMessageBytes,
	)

	deps := api.Deps{
		Config:   cfg,
		Logger:   logger,
		RelayHub: hub,
	}
	if len(cfg.JWTSecret) >= 32 {
		issuer, err := auth.NewIssuer(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTTTL)
		if err != nil {
			logger.Error("jwt issuer init failed", "err", err)
			os.Exit(2)
		}
		deps.Issuer = issuer
		logger.Info("jwt issuer ready", "iss", cfg.JWTIssuer, "aud", cfg.JWTAudience, "ttl", cfg.JWTTTL)

		enf, err := acl.NewEnforcer()
		if err != nil {
			logger.Error("acl enforcer init failed", "err", err)
			os.Exit(2)
		}
		if err := enf.SeedDefaults(); err != nil {
			logger.Error("acl seed failed", "err", err)
			os.Exit(2)
		}
		deps.Enforcer = enf
		logger.Info("acl enforcer ready", "policies", len(enf.Policies()))
	} else {
		logger.Warn("jwt issuer not configured (COLLAB_JWT_SECRET unset or < 32 bytes) — /me + acl-gated routes disabled")
	}

	router := api.NewRouter(deps)
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("server listening", "addr", cfg.ListenAddr, "version", config.Version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	select {
	case err := <-serverErr:
		logger.Error("server failed", "err", err)
		os.Exit(1)
	case <-ctx.Done():
		logger.Info("shutdown signal received; draining")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
	logger.Info("server exited cleanly")
}
