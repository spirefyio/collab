// Package db owns the Postgres connection pool and migration runner.
//
// Pool semantics (pgxpool):
//   - production-sized defaults: 25 max conns, 2 min, 1h conn lifetime,
//     30m idle timeout — adequate for an MVP team service that fronts
//     a few hundred concurrent users
//   - Connect ping-tests so a misconfigured DATABASE_URL fails fast at
//     boot instead of producing first-request errors
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultMaxConns        = 25
	defaultMinConns        = 2
	defaultMaxConnLifetime = time.Hour
	defaultMaxConnIdleTime = 30 * time.Minute
	defaultPingTimeout     = 5 * time.Second
)

// NewPool parses the URL, applies the production defaults, opens a
// pgxpool, and returns it only after a successful Ping. Caller owns
// the lifecycle and must call pool.Close() at shutdown.
func NewPool(ctx context.Context, url string) (*pgxpool.Pool, error) {
	if url == "" {
		return nil, errors.New("database url is required")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse pg url: %w", err)
	}
	cfg.MaxConns = defaultMaxConns
	cfg.MinConns = defaultMinConns
	cfg.MaxConnLifetime = defaultMaxConnLifetime
	cfg.MaxConnIdleTime = defaultMaxConnIdleTime

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, defaultPingTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}
