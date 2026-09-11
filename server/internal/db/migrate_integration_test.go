package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/spirefyio/collab/server/migrations"
)

// These tests are the only place the migration SQL meets a real Postgres.
// Everything in migrate_test.go passes without a database, which means it
// cannot see a migration that parses fine and then fails to apply, and it
// cannot see a .down.sql that does not undo its .up.sql at all.
//
// Gate: COLLAB_TEST_DATABASE_URL must point at a Postgres the test may
// create and drop databases on. `make test-integration` starts the compose
// stack and sets it. A skipped test proves nothing, so the skip message says
// exactly how to un-skip, and a URL that IS set but unreachable FAILS rather
// than skipping — a silently-skipped integration test is worse than none.
//
// Each test runs against its own freshly created throwaway database, so the
// tests are order-independent and none of them can touch a dev database.

// tablesIn0001 is the schema 0001_init.up.sql is claimed to create. Asserted
// by name rather than by count so that adding a table to 0001 without adding
// it here is a visible omission rather than a silent one.
var tablesIn0001 = []string{
	"accounts",
	"teams",
	"team_members",
	"workspaces",
	"invites",
	"audit_log",
}

func requireTestURL(t *testing.T) string {
	t.Helper()
	raw := envTestURL()
	if raw == "" {
		t.Skip("COLLAB_TEST_DATABASE_URL unset — run `make test-integration` (starts the compose Postgres and sets it)")
	}
	return raw
}

func envTestURL() string {
	return strings.TrimSpace(os.Getenv("COLLAB_TEST_DATABASE_URL"))
}

// newTestDB creates a throwaway database on the server named by
// COLLAB_TEST_DATABASE_URL and returns a URL pointing at it. The database is
// dropped when the test ends, whether it passed or failed.
func newTestDB(t *testing.T) string {
	t.Helper()
	raw := requireTestURL(t)

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("COLLAB_TEST_DATABASE_URL is not a URL: %v", err)
	}

	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	name := "collab_mig_test_" + hex.EncodeToString(suffix[:])

	// CREATE/DROP DATABASE cannot run while connected to the target, so
	// administer from the maintenance database on the same server.
	admin := *u
	admin.Path = "/postgres"
	adminDB, err := sql.Open("pgx", admin.String())
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	defer adminDB.Close()

	// A set-but-unreachable URL is a failure, never a skip.
	if err := adminDB.Ping(); err != nil {
		t.Fatalf("COLLAB_TEST_DATABASE_URL is set but unreachable (%s): %v", admin.Redacted(), err)
	}

	if _, err := adminDB.Exec(`CREATE DATABASE ` + quoteIdent(name)); err != nil {
		t.Fatalf("create test database %s: %v", name, err)
	}
	t.Cleanup(func() {
		cleanup, err := sql.Open("pgx", admin.String())
		if err != nil {
			t.Logf("cleanup: reopen admin: %v", err)
			return
		}
		defer cleanup.Close()
		// FORCE terminates any leaked connection so a failing test cannot
		// leave an undroppable database behind.
		if _, err := cleanup.Exec(`DROP DATABASE IF EXISTS ` + quoteIdent(name) + ` WITH (FORCE)`); err != nil {
			t.Logf("cleanup: drop database %s: %v", name, err)
		}
	})

	target := *u
	target.Path = "/" + name
	return target.String()
}

// quoteIdent double-quotes a generated identifier. The names are built from
// hex here, but quoting keeps the helper safe if that ever changes.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func openMigrator(t *testing.T, dsn string) *Migrator {
	t.Helper()
	mg, err := NewMigrator(dsn, migrations.FS)
	if err != nil {
		t.Fatalf("NewMigrator: %v", err)
	}
	t.Cleanup(func() {
		if err := mg.Close(); err != nil {
			t.Logf("migrator close: %v", err)
		}
	})
	return mg
}

func tableExists(t *testing.T, dsn, table string) bool {
	t.Helper()
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open %s: %v", table, err)
	}
	defer conn.Close()
	var exists bool
	err = conn.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema = 'public' AND table_name = $1)`, table).Scan(&exists)
	if err != nil {
		t.Fatalf("query table %s: %v", table, err)
	}
	return exists
}

// TestMigrate_UpCreatesSchemaAndRecordsVersion fails if a migration applies
// without producing its schema, or lands on a version other than head —
// e.g. a file golang-migrate silently declines to parse, which would leave
// the server booting green against a schema its queries do not match.
func TestMigrate_UpCreatesSchemaAndRecordsVersion(t *testing.T) {
	dsn := newTestDB(t)
	mg := openMigrator(t, dsn)

	head, err := mg.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if head == 0 {
		t.Fatal("migration set is empty: Head returned 0")
	}

	if _, _, err := mg.Version(); !errors.Is(err, ErrNoVersion) {
		t.Fatalf("fresh database should report ErrNoVersion, got %v", err)
	}

	if err := mg.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	version, dirty, err := mg.Version()
	if err != nil {
		t.Fatalf("Version after Up: %v", err)
	}
	if version != head {
		t.Errorf("version after Up = %d, want head %d", version, head)
	}
	if dirty {
		t.Error("schema is dirty after a successful Up")
	}

	for _, table := range tablesIn0001 {
		if !tableExists(t, dsn, table) {
			t.Errorf("table %q missing after Up", table)
		}
	}
}

// TestMigrate_UpIsIdempotent fails if a second Up surfaces ErrNoChange as an
// error. cmd/relay calls RunUp on every boot, so that regression would turn
// every restart after the first into exit code 2.
func TestMigrate_UpIsIdempotent(t *testing.T) {
	dsn := newTestDB(t)
	mg := openMigrator(t, dsn)

	if err := mg.Up(); err != nil {
		t.Fatalf("first Up: %v", err)
	}
	first, _, err := mg.Version()
	if err != nil {
		t.Fatalf("Version after first Up: %v", err)
	}

	if err := mg.Up(); err != nil {
		t.Fatalf("second Up should be a no-op, got: %v", err)
	}
	second, dirty, err := mg.Version()
	if err != nil {
		t.Fatalf("Version after second Up: %v", err)
	}
	if second != first {
		t.Errorf("version moved on a no-op Up: %d -> %d", first, second)
	}
	if dirty {
		t.Error("schema dirty after a no-op Up")
	}

	// The boot-time wrapper must be idempotent too — that is the call
	// cmd/relay actually makes.
	if err := RunUp(dsn, migrations.FS); err != nil {
		t.Errorf("RunUp against an at-head database should be a no-op, got: %v", err)
	}
}

// TestMigrate_DownThenUpRoundTrips is the test that makes rollback a claim
// instead of a hope. It fails if a .down.sql does not undo its .up.sql:
// leftover tables after Down, or an Up that cannot re-apply over the
// residue. Before this test existed, 0001_init.down.sql had never been
// executed by anything.
func TestMigrate_DownThenUpRoundTrips(t *testing.T) {
	dsn := newTestDB(t)
	mg := openMigrator(t, dsn)

	if err := mg.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := mg.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}

	for _, table := range tablesIn0001 {
		if tableExists(t, dsn, table) {
			t.Errorf("table %q still exists after Down — the .down.sql does not undo its .up.sql", table)
		}
	}
	if _, _, err := mg.Version(); !errors.Is(err, ErrNoVersion) {
		t.Errorf("after Down, Version should be ErrNoVersion, got %v", err)
	}

	if err := mg.Up(); err != nil {
		t.Fatalf("Up after Down (re-apply over the rolled-back schema): %v", err)
	}
	for _, table := range tablesIn0001 {
		if !tableExists(t, dsn, table) {
			t.Errorf("table %q missing after the second Up", table)
		}
	}
}

// TestMigrate_StepsForwardAndBack fails on an off-by-one in the step verbs —
// the arm that catches a future multi-migration series where `down 1` walks
// back further than one migration.
func TestMigrate_StepsForwardAndBack(t *testing.T) {
	dsn := newTestDB(t)
	mg := openMigrator(t, dsn)

	if err := mg.Steps(1); err != nil {
		t.Fatalf("Steps(1): %v", err)
	}
	version, _, err := mg.Version()
	if err != nil {
		t.Fatalf("Version after Steps(1): %v", err)
	}
	if version != 1 {
		t.Errorf("Steps(1) from empty landed on %d, want 1", version)
	}

	if err := mg.Steps(-1); err != nil {
		t.Fatalf("Steps(-1): %v", err)
	}
	if _, _, err := mg.Version(); !errors.Is(err, ErrNoVersion) {
		t.Errorf("Steps(-1) from version 1 should empty the schema, Version gave %v", err)
	}

	if err := mg.Steps(0); err == nil {
		t.Error("Steps(0) should be rejected")
	}

	// Over-stepping must apply everything available and report success.
	// Asserting the VERSION, not just the absence of an error, is what makes
	// the ErrShortLimit arm in Steps a measurement instead of a reading: if
	// that error ever means "refused" rather than "ran out after applying",
	// this fails.
	head, err := mg.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if err := mg.Steps(int(head) + 99); err != nil {
		t.Fatalf("over-stepping forward should be a no-op, got: %v", err)
	}
	version, dirty, err := mg.Version()
	if err != nil {
		t.Fatalf("Version after over-stepping: %v", err)
	}
	if version != head {
		t.Errorf("over-stepping forward landed on %d, want head %d — Steps swallowed an error that meant work was NOT applied", version, head)
	}
	if dirty {
		t.Error("schema dirty after over-stepping forward")
	}

	// And the same in reverse: over-stepping back must empty the schema.
	if err := mg.Steps(-(int(head) + 99)); err != nil {
		t.Fatalf("over-stepping back should be a no-op, got: %v", err)
	}
	if _, _, err := mg.Version(); !errors.Is(err, ErrNoVersion) {
		t.Errorf("over-stepping back should empty the schema, Version gave %v", err)
	}
	for _, table := range tablesIn0001 {
		if tableExists(t, dsn, table) {
			t.Errorf("table %q still exists after over-stepping back", table)
		}
	}
}

// TestMigrate_ForceClearsDirty fails if an operator cannot recover from a
// half-applied migration. A dirty schema blocks every other verb, so without
// a working Force the only exit is hand-editing schema_migrations in
// production at 3am.
func TestMigrate_ForceClearsDirty(t *testing.T) {
	dsn := newTestDB(t)
	mg := openMigrator(t, dsn)

	if err := mg.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	applied, _, err := mg.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}

	// Simulate the state a migration that failed partway leaves behind.
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := conn.Exec(`UPDATE schema_migrations SET dirty = true`); err != nil {
		conn.Close()
		t.Fatalf("mark dirty: %v", err)
	}
	conn.Close()

	_, dirty, err := mg.Version()
	if err != nil {
		t.Fatalf("Version while dirty: %v", err)
	}
	if !dirty {
		t.Fatal("Version does not report a dirty schema — operators would get no warning")
	}

	if err := mg.Up(); err == nil {
		t.Error("Up against a dirty schema should refuse")
	} else if !strings.Contains(strings.ToLower(err.Error()), "dirty") {
		t.Errorf("Up against a dirty schema should say so, got: %v", err)
	}

	if err := mg.Force(int(applied)); err != nil {
		t.Fatalf("Force(%d): %v", applied, err)
	}
	version, dirty, err := mg.Version()
	if err != nil {
		t.Fatalf("Version after Force: %v", err)
	}
	if dirty {
		t.Error("Force did not clear the dirty flag")
	}
	if version != applied {
		t.Errorf("Force landed on version %d, want %d", version, applied)
	}
	if err := mg.Up(); err != nil {
		t.Errorf("Up after Force should succeed, got: %v", err)
	}
}

// TestMigrate_GotoWalksBothWays fails if `goto` cannot reach a version it
// has already passed — the verb a rollback-to-a-known-good-schema runbook
// depends on.
func TestMigrate_GotoWalksBothWays(t *testing.T) {
	dsn := newTestDB(t)
	mg := openMigrator(t, dsn)

	head, err := mg.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}

	if err := mg.Goto(head); err != nil {
		t.Fatalf("Goto(%d) from empty: %v", head, err)
	}
	version, _, err := mg.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if version != head {
		t.Errorf("Goto(%d) landed on %d", head, version)
	}

	// Version 0 is the documented spelling of "empty schema".
	if err := mg.Goto(0); err != nil {
		t.Fatalf("Goto(0): %v", err)
	}
	if _, _, err := mg.Version(); !errors.Is(err, ErrNoVersion) {
		t.Errorf("Goto(0) should empty the schema, Version gave %v", err)
	}
	for _, table := range tablesIn0001 {
		if tableExists(t, dsn, table) {
			t.Errorf("table %q still exists after Goto(0)", table)
		}
	}
}

func TestHead_MatchesMigrationSet(t *testing.T) {
	// Head is derived from the source driver, so it agrees with what the
	// migrator would run rather than with a filename glob. This arm fails
	// if a new migration pair lands that golang-migrate declines to parse:
	// the file would be present on disk and absent from head.
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var maxOnDisk uint64
	for _, e := range entries {
		m := migrationFileVersion(e.Name())
		if m > maxOnDisk {
			maxOnDisk = m
		}
	}

	mg := &Migrator{src: migrations.FS}
	head, err := mg.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if uint64(head) != maxOnDisk {
		t.Errorf("Head = %d but highest migration file on disk is %d — a migration file is not being parsed", head, maxOnDisk)
	}
}

func migrationFileVersion(name string) uint64 {
	if !strings.HasSuffix(name, ".sql") {
		return 0
	}
	i := strings.Index(name, "_")
	if i <= 0 {
		return 0
	}
	var v uint64
	if _, err := fmt.Sscanf(name[:i], "%d", &v); err != nil {
		return 0
	}
	return v
}
