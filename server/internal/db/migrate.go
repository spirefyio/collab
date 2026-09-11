package db

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	migratedb "github.com/golang-migrate/migrate/v4/database"
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

// NilVersion is the version golang-migrate records for "no migration
// applied". Force accepts it; it is the recovery for a rollback that failed
// on its last step, which persists exactly this version with dirty set.
const NilVersion = -1

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
		// driver, not sqlDB: past WithInstance the driver owns the *sql.DB
		// AND holds a checked-out *sql.Conn of its own for advisory locking,
		// so closing sqlDB alone would leak that connection. Unreachable
		// against golang-migrate v4.19.1, whose NewWithInstance cannot fail —
		// kept correct rather than merely adequate, because the day it starts
		// returning the error its signature already promises, this branch
		// runs for real.
		driver.Close()
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
		// Two %w verbs (Go 1.20+) so a caller can errors.Is/As either cause;
		// %v would flatten both into text.
		return fmt.Errorf("close migrator: source: %w, database: %w", srcErr, dbErr)
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
//
// versionIsKnown reports whether v is a version this binary's migration set
// actually contains. NilVersion ("nothing applied") counts as known.
//
// This is the difference between "the schema is caught up" and "the schema is
// at a version this build has never heard of" — states that are trivially
// distinguishable here and, measured, indistinguishable from Steps's error.
func (mg *Migrator) versionIsKnown(v int64) (bool, error) {
	if v == NilVersion {
		return true, nil
	}
	versions, err := mg.Versions()
	if err != nil {
		return false, err
	}
	for _, known := range versions {
		if int64(known) == v {
			return true, nil
		}
	}
	return false, nil
}

// appliedVersionIsForeign reports whether the schema's recorded version is
// absent from this binary's migration set, which happens after a binary
// rollback (the database was migrated by a newer build) or a bad Force.
func (mg *Migrator) appliedVersionIsForeign() (bool, uint, error) {
	version, _, err := mg.Version()
	if errors.Is(err, ErrNoVersion) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, fmt.Errorf("read version: %w", err)
	}
	known, err := mg.versionIsKnown(int64(version))
	if err != nil {
		return false, 0, err
	}
	return !known, version, nil
}

func (mg *Migrator) Steps(n int) error {
	if n == 0 {
		return errors.New("steps must be non-zero")
	}
	err := mg.m.Steps(n)
	var short migrate.ErrShortLimit
	switch {
	case err == nil,
		errors.Is(err, migrate.ErrNoChange),
		errors.As(err, &short):
		return nil
	case errors.Is(err, fs.ErrNotExist):
		// fs.ErrNotExist reaches here from TWO different places inside
		// golang-migrate, and only one of them means the work is done:
		//
		//   (a) readUp/readDown ran out of migrations to apply (count == 0).
		//       The schema is at the end of the set. Success.
		//   (b) versionExists(from) failed at the TOP of readUp/readDown --
		//       the schema's CURRENT version has no file in this binary's
		//       set, so not one migration was even attempted.
		//
		// Measured 2026-09-10 against a real Postgres: with the database at
		// version 2 and a binary whose set stops at 0001, Steps(+1) and
		// Steps(-1) both returned nil with the version unchanged, while
		// Up() and Down() on the same Migrator refused with "no migration
		// found for version 2". Steps alone called that state success.
		//
		// Same defect class as the Force guard below: something was checked
		// for EXISTENCE (is this error fs.ErrNotExist?) and never for WHAT
		// IT COVERS (which of the two origins produced it).
		foreign, version, verr := mg.appliedVersionIsForeign()
		if verr != nil {
			return fmt.Errorf("migrate steps %d: %w", n, verr)
		}
		if foreign {
			return fmt.Errorf("migrate steps %d: the schema is at version %d, which does not exist in this binary's migration set (known: %v) -- nothing was applied; deploy the build that owns version %d, or force to a version this build knows", n, version, mustVersions(mg), version)
		}
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
//
// CAUTION: on the ErrNoVersion path the dirty flag is NOT reported, and that
// is golang-migrate's behaviour, not a choice made here — its Version()
// returns (0, false, ErrNilVersion) without consulting the dirty column when
// the recorded version is NilVersion (-1). That state is reachable: the final
// rollback of a set is stamped (-1, dirty=true) BEFORE its SQL runs
// (migrate.go readDown/runMigrations), so a rollback that fails on the last
// migration persists version -1 with dirty set. Callers reporting status MUST
// consult Dirty() on the ErrNoVersion path or they will describe a broken
// schema as an empty one. Measured 2026-09-10: the CLI did exactly that.
func (mg *Migrator) Version() (version uint, dirty bool, err error) {
	version, dirty, err = mg.m.Version()
	if err != nil {
		return 0, false, err
	}
	return version, dirty, nil
}

// Dirty reports the bookkeeping's dirty flag, independently of Version.
//
// It exists because Version cannot answer for a schema recorded at
// NilVersion (-1) — see the CAUTION on Version. A database that has never
// been migrated has no bookkeeping table at all, which is reported as not
// dirty rather than as an error.
//
// Reads through the same connection the migrator holds, and resolves the
// table through search_path exactly as the driver does, so a non-default
// migrations schema still answers correctly.
func (mg *Migrator) Dirty() (bool, error) {
	table := migratepgx.DefaultMigrationsTable

	var exists bool
	if err := mg.sqlDB.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
		return false, fmt.Errorf("look up %s: %w", table, err)
	}
	if !exists {
		return false, nil // never migrated
	}

	var dirty bool
	err := mg.sqlDB.QueryRow(`SELECT dirty FROM ` + table + ` LIMIT 1`).Scan(&dirty)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil // table present, no row recorded
	}
	if err != nil {
		return false, fmt.Errorf("read %s.dirty: %w", table, err)
	}
	return dirty, nil
}

// Status is the whole reportable state of a schema in one value, with
// golang-migrate's sentinels already normalized away.
//
// It exists because that normalization is operator-surface logic, not
// presentation: deciding that ErrNoVersion means "empty, not broken", and
// that the dirty flag has to come from Dirty() rather than Version() on that
// path, are exactly the judgements this package owns and the CLI should not
// re-derive. Keeping them here makes them testable against a real database
// instead of only reachable through a formatted string.
type Status struct {
	// Version is the applied migration version; meaningless unless Applied.
	Version uint
	// Applied is false for a database with no migration recorded.
	Applied bool
	// Dirty means a migration failed partway and every verb will refuse
	// until an operator resolves it. Correct even when Applied is false —
	// the version -1 case, which Version alone cannot report.
	Dirty bool
	// Head is the highest version in the migration set; 0 if the set is empty.
	Head uint
	// Pending counts the migrations Up would still apply.
	Pending int
	// Known reports whether Version exists in this binary's migration set.
	// False means the database was migrated by a different build (or forced
	// to a bogus version): every verb will refuse, and the numbers above
	// describe a set that does not contain the schema's actual position.
	// Meaningless unless Applied.
	Known bool
}

// Status gathers the schema's reportable state.
func (mg *Migrator) Status() (Status, error) {
	head, err := mg.Head()
	if err != nil {
		return Status{}, err
	}

	st := Status{Head: head}
	version, dirty, err := mg.Version()
	switch {
	case errors.Is(err, ErrNoVersion):
		// Nothing applied. The dirty flag must come from the bookkeeping
		// directly: see the CAUTION on Version.
		st.Dirty, err = mg.Dirty()
		if err != nil {
			return Status{}, err
		}
	case err != nil:
		return Status{}, fmt.Errorf("read version: %w", err)
	default:
		st.Version, st.Applied, st.Dirty = version, true, dirty
		st.Known, err = mg.versionIsKnown(int64(version))
		if err != nil {
			return Status{}, err
		}
	}

	st.Pending, err = mg.PendingAfter(st.Version)
	if err != nil {
		return Status{}, err
	}
	return st, nil
}

// Force stamps the schema_migrations bookkeeping at version v and clears the
// dirty flag WITHOUT running any SQL. It is the recovery verb for a failed
// apply, and it is only correct when the operator has confirmed by
// inspection that the schema really is at v. Forcing the wrong version
// leaves the bookkeeping lying about the schema, which is worse than dirty.
//
// v must be -1 ("no migration applied") or a version that exists in the
// migration set. Anything else is refused, because golang-migrate accepts it
// and the consequence is a silent false all-clear: measured 2026-09-10,
// `force 999` on a never-migrated database made the status command report
// `pending: 0, dirty: false` over a schema that had never been created. A
// version the set does not contain cannot describe any real schema, so there
// is no state in which accepting it is the right answer.
//
// This does NOT make Force safe — forcing a version that exists but does not
// match the schema on disk is still wrong, and still the operator's call to
// get right. It only removes the class of mistake the tool can detect.
func (mg *Migrator) Force(v int) error {
	if v != NilVersion {
		versions, err := mg.Versions()
		if err != nil {
			return err
		}
		found := false
		for _, known := range versions {
			if int64(known) == int64(v) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf(
				"migrate force %d: no migration %d exists in the set (known: %v; use -1 for \"no migration applied\")",
				v, v, versions)
		}
	}
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
// MigrationLockHeld reports whether some OTHER process currently holds the
// advisory lock golang-migrate takes around every migration run.
//
// It exists because of a measured, silent failure mode. golang-migrate's pgx
// driver runs ensureVersionTable inside WithInstance, and that function takes
// the advisory lock UNCONDITIONALLY -- before its own "does the table already
// exist" check -- on a Lock() whose own comment reads "This will wait
// indefinitely until the lock can be acquired." So the blocking happens
// during CONSTRUCTION, before any verb runs, and the 15-second
// DefaultLockTimeout that Migrate.lock races against never applies to it.
//
// Measured 2026-09-10 against a real Postgres, with a peer holding the lock:
//
//	NewMigrator -> still blocked after 40s, no timeout, no output
//	Up() on an ALREADY-constructed Migrator -> ErrLockTimeout after exactly 15s
//
// The boot path constructs and then runs, so the indefinite block is the one
// it actually hits: a second replica racing the first hangs at startup with
// nothing logged, and an orchestrator eventually SIGKILLs it past a readiness
// deadline leaving no diagnostic trail at all.
//
// Waiting is the correct behaviour -- the advisory lock is session-scoped, so
// a crashed holder releases it and the waiter proceeds. Silence is not. This
// function turns the hang into a logged wait; it is a diagnostic and never a
// gate, so the race between the probe and the subsequent lock attempt is
// harmless by construction.
//
// It cannot itself block: pg_try_advisory_lock returns immediately either way.
func MigrationLockHeld(url string) (bool, error) {
	sqlDB, err := sql.Open("pgx", url)
	if err != nil {
		return false, fmt.Errorf("open sql: %w", err)
	}
	defer sqlDB.Close()

	// Match the identifiers golang-migrate's pgx driver derives for itself,
	// or the computed lock id names a different lock than the real one.
	var dbName, schemaName string
	if err := sqlDB.QueryRow(`SELECT current_database(), current_schema()`).Scan(&dbName, &schemaName); err != nil {
		return false, fmt.Errorf("read database identity: %w", err)
	}
	aid, err := migratedb.GenerateAdvisoryLockId(dbName, schemaName, migratepgx.DefaultMigrationsTable)
	if err != nil {
		return false, fmt.Errorf("advisory lock id: %w", err)
	}

	var acquired bool
	if err := sqlDB.QueryRow(`SELECT pg_try_advisory_lock($1)`, aid).Scan(&acquired); err != nil {
		return false, fmt.Errorf("probe migration lock: %w", err)
	}
	if acquired {
		// Release immediately: holding it here would deadlock the very
		// construction this probe is meant to describe.
		if _, err := sqlDB.Exec(`SELECT pg_advisory_unlock($1)`, aid); err != nil {
			return false, fmt.Errorf("release probe lock: %w", err)
		}
		return false, nil
	}
	return true, nil
}

func RunUp(url string, migrationsFS fs.FS) error {
	mg, err := NewMigrator(url, migrationsFS)
	if err != nil {
		return err
	}
	defer mg.Close()
	return mg.Up()
}

// mustVersions renders the migration set for an error message. Reporting a
// lookup failure inside a message that is already reporting a failure would
// bury the real one, so this degrades to a placeholder instead.
func mustVersions(mg *Migrator) any {
	versions, err := mg.Versions()
	if err != nil {
		return "unreadable"
	}
	return versions
}
