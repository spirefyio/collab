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

	"github.com/spirefyio/collab/server/internal/api"
	"github.com/spirefyio/collab/server/internal/config"
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

	router := api.NewRouter(cfg, logger)
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
