package db

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	// Register pgx as a database/sql driver — needed because the
	// migrate pgx driver wants a *sql.DB to wrap.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// RunUp applies any unapplied migrations from migrationsFS against the
// database at url. Idempotent: a no-op when already at head.
//
// Uses a short-lived database/sql connection (closed immediately after
// migration) so the production pgxpool remains the canonical handle
// for runtime queries.
func RunUp(url string, migrationsFS fs.FS) error {
	if url == "" {
		return errors.New("database url is required")
	}

	src, err := iofs.New(migrationsFS, ".")
	if err != nil {
		return fmt.Errorf("iofs source: %w", err)
	}

	sqlDB, err := sql.Open("pgx", url)
	if err != nil {
		return fmt.Errorf("open sql: %w", err)
	}
	defer sqlDB.Close()

	driver, err := migratepgx.WithInstance(sqlDB, &migratepgx.Config{})
	if err != nil {
		return fmt.Errorf("migrate driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "pgx", driver)
	if err != nil {
		return fmt.Errorf("migrator: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}
