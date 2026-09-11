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

// ErrNoVersion is returned by Migrator.Version when no migration has been
// applied yet (an empty database). It is golang-migrate's own
// migrate.ErrNilVersion, re-exported so callers can distinguish "empty" from
// "broken" without importing golang-migrate themselves. Same value, so
// errors.Is matches either spelling.
var ErrNoVersion = migrate.ErrNilVersion

// Migrator is the operator surface over a migration set: the verbs an
// operator needs to move a schema forward, walk it back, inspect where it
// is, and recover it after a failed apply.
//
// Every verb is a thin, named entry point onto one golang-migrate instance —
// the mechanism is shared, the policy is not. Destructive policy (refusing a
// full teardown without explicit confirmation) lives at the CLI in
// cmd/collab-migrate, not here, so tests can tear down freely.
//
// The zero value is not usable; construct with NewMigrator and always Close.
type Migrator struct {
	m     *migrate.Migrate
	src   fs.FS
	sqlDB *sql.DB
}

// NewMigrator opens a short-lived database/sql connection and binds it to
// the migration set in migrationsFS. The production pgxpool (NewPool)
// remains the canonical handle for runtime queries; this connection exists
// only for the duration of the migration work and is released by Close.
func NewMigrator(url string, migrationsFS fs.FS) (*Migrator, error) {
	if url == "" {
		return nil, errors.New("database url is required")
	}

	src, err := iofs.New(migrationsFS, ".")
	if err != nil {
		return nil, fmt.Errorf("iofs source: %w", err)
	}

	sqlDB, err := sql.Open("pgx", url)
	if err != nil {
		return nil, fmt.Errorf("open sql: %w", err)
	}

	driver, err := migratepgx.WithInstance(sqlDB, &migratepgx.Config{})
	if err != nil {
		// sqlDB is not yet owned by the driver, so close it here. Past
		// this point the driver owns it and Migrator.Close releases it.
		sqlDB.Close()
		return nil, fmt.Errorf("migrate driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "pgx", driver)
	if err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("migrator: %w", err)
	}

	return &Migrator{m: m, src: migrationsFS, sqlDB: sqlDB}, nil
}

// Close releases the source and the database connection. migrate.Close
// closes the driver, and the pgx/v5 driver's Close closes the *sql.DB it
// wraps, so the extra sqlDB.Close here is belt-and-braces against a driver
// that stops doing that — sql.DB.Close is safe to call twice.
func (mg *Migrator) Close() error {
	if mg.m == nil {
		// A source-only Migrator (Versions/Head/PendingAfter, no database)
		// holds nothing to release.
		return nil
	}
	srcErr, dbErr := mg.m.Close()
	mg.sqlDB.Close()
	if srcErr != nil || dbErr != nil {
		return fmt.Errorf("close migrator: source: %v, database: %v", srcErr, dbErr)
	}
	return nil
}

// Up applies every unapplied migration. Idempotent: already-at-head is a
// no-op and returns nil, which is what lets the server call it on every
// boot without a restart turning into a fatal error.
func (mg *Migrator) Up() error {
	if err := mg.m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// Down reverses EVERY applied migration, leaving an empty schema. This is
// data loss by design; callers are expected to gate it behind explicit
// operator confirmation.
func (mg *Migrator) Down() error {
	if err := mg.m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate down: %w", err)
	}
	return nil
}

// Steps moves n migrations forward (n > 0) or back (n < 0). Asking for more
// steps than the set contains applies every one that exists and is reported
// as success, so a deploy script that over-steps does not fail the deploy.
//
// golang-migrate spells "ran out" two different ways and BOTH mean the work
// was done, which is why both are swallowed here:
//
//   - ErrShortLimit{k} — k fewer migrations existed than asked for, pushed
//     onto the migration channel AFTER the available ones were applied
//     (migrate.go readUp, the count > 0 branch). Measured by
//     TestMigrate_StepsForwardAndBack, which asserts the version actually
//     reached head — so if a future release changes this to mean "refused",
//     that test goes red rather than this silently under-migrating.
//   - fs.ErrNotExist — nothing at all was available to apply (count == 0).
func (mg *Migrator) Steps(n int) error {
	if n == 0 {
		return errors.New("steps must be non-zero")
	}
	err := mg.m.Steps(n)
	var short migrate.ErrShortLimit
	switch {
	case err == nil,
		errors.Is(err, migrate.ErrNoChange),
		errors.As(err, &short),
		errors.Is(err, fs.ErrNotExist):
		return nil
	default:
		return fmt.Errorf("migrate steps %d: %w", n, err)
	}
}

// Goto migrates up or down to exactly version v. Version 0 is equivalent to
// Down (empty schema).
func (mg *Migrator) Goto(v uint) error {
	if v == 0 {
		return mg.Down()
	}
	if err := mg.m.Migrate(v); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate goto %d: %w", v, err)
	}
	return nil
}

// Version reports the applied version and whether the schema is dirty.
// A dirty schema means a migration failed partway: golang-migrate refuses
// every further verb until an operator inspects the damage and calls Force
// with the version they have confirmed the schema actually matches.
//
// Returns ErrNoVersion when nothing has been applied yet.
func (mg *Migrator) Version() (version uint, dirty bool, err error) {
	version, dirty, err = mg.m.Version()
	if err != nil {
		return 0, false, err
	}
	return version, dirty, nil
}

// Force stamps the schema_migrations bookkeeping at version v and clears the
// dirty flag WITHOUT running any SQL. It is the recovery verb for a failed
// apply, and it is only correct when the operator has confirmed by
// inspection that the schema really is at v. Forcing the wrong version
// leaves the bookkeeping lying about the schema, which is worse than dirty.
func (mg *Migrator) Force(v int) error {
	if err := mg.m.Force(v); err != nil {
		return fmt.Errorf("migrate force %d: %w", v, err)
	}
	return nil
}

// Versions lists every version in the migration set, ascending.
//
// Reads only the migration set: no database connection is used, so this and
// the two verbs below work on a Migrator built without one.
//
// Derived from the source driver rather than from a filename glob so it
// agrees with what the migrator would actually run: a file golang-migrate
// declines to parse is absent from both.
func (mg *Migrator) Versions() ([]uint, error) {
	src, err := iofs.New(mg.src, ".")
	if err != nil {
		return nil, fmt.Errorf("iofs source: %w", err)
	}
	defer src.Close()

	v, err := src.First()
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // empty migration set
	}
	if err != nil {
		return nil, fmt.Errorf("first migration: %w", err)
	}
	versions := []uint{v}
	for {
		next, err := src.Next(v)
		if errors.Is(err, fs.ErrNotExist) {
			return versions, nil
		}
		if err != nil {
			return nil, fmt.Errorf("next after %d: %w", v, err)
		}
		versions = append(versions, next)
		v = next
	}
}

// Head returns the highest version in the migration set — where Up would
// land. Zero means the set is empty.
func (mg *Migrator) Head() (uint, error) {
	versions, err := mg.Versions()
	if err != nil || len(versions) == 0 {
		return 0, err
	}
	return versions[len(versions)-1], nil
}

// PendingAfter counts the migrations that Up would still apply on a schema
// sitting at version. Pass 0 for an empty database.
//
// It COUNTS the set rather than computing head-minus-version, because
// version numbers are not step counts: a merge that lands 0001 and 0003
// without a 0002 has two migrations, and the arithmetic answer is three.
func (mg *Migrator) PendingAfter(version uint) (int, error) {
	versions, err := mg.Versions()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, v := range versions {
		if v > version {
			n++
		}
	}
	return n, nil
}

// RunUp applies any unapplied migrations from migrationsFS against the
// database at url. Idempotent: a no-op when already at head.
//
// This is the boot-time entry point (cmd/relay calls it before opening the
// runtime pool); the other verbs are operator-driven and live on Migrator.
func RunUp(url string, migrationsFS fs.FS) error {
	mg, err := NewMigrator(url, migrationsFS)
	if err != nil {
		return err
	}
	defer mg.Close()
	return mg.Up()
}
