package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	migratedb "github.com/golang-migrate/migrate/v4/database"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/spirefyio/collab/server/internal/dbtest"
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
//
// Two preconditions on whatever COLLAB_TEST_DATABASE_URL points at, because
// the harness administers rather than merely connecting:
//   - a `postgres` maintenance database must exist on the same server (that
//     is where CREATE/DROP DATABASE run from), and the credentials must be
//     allowed to create databases;
//   - Postgres 13 or newer, for DROP DATABASE ... WITH (FORCE).
// The compose stack satisfies both. A managed Postgres without a default
// maintenance database, or older than 13, fails in newTestDB with a clear
// message rather than silently skipping.
//
// One caveat on "order-independent": it means no arm depends on another's
// leftover state. It does not mean one arm's failure cannot stop another from
// running — a panic (as opposed to t.Fatal) kills the whole test binary, and
// arms ordered after it never execute. Read a truncated run accordingly.

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

// TestMigrate_UpCreatesSchemaAndRecordsVersion fails if a migration applies
// without producing its schema, or lands on a version other than head —
// e.g. a file golang-migrate silently declines to parse, which would leave
// the server booting green against a schema its queries do not match.
func TestMigrate_UpCreatesSchemaAndRecordsVersion(t *testing.T) {
	dsn := dbtest.NewDatabase(t)
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
		if !dbtest.TableExists(t, dsn, table) {
			t.Errorf("table %q missing after Up", table)
		}
	}
}

// TestMigrate_UpIsIdempotent fails if a second Up surfaces ErrNoChange as an
// error. cmd/relay calls RunUp on every boot, so that regression would turn
// every restart after the first into exit code 2.
func TestMigrate_UpIsIdempotent(t *testing.T) {
	dsn := dbtest.NewDatabase(t)
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
	dsn := dbtest.NewDatabase(t)
	mg := openMigrator(t, dsn)

	if err := mg.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := mg.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}

	for _, table := range tablesIn0001 {
		if dbtest.TableExists(t, dsn, table) {
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
		if !dbtest.TableExists(t, dsn, table) {
			t.Errorf("table %q missing after the second Up", table)
		}
	}
}

// TestMigrate_StepsForwardAndBack fails on an off-by-one in the step verbs —
// the arm that catches a future multi-migration series where `down 1` walks
// back further than one migration.
func TestMigrate_StepsForwardAndBack(t *testing.T) {
	dsn := dbtest.NewDatabase(t)
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
		if dbtest.TableExists(t, dsn, table) {
			t.Errorf("table %q still exists after over-stepping back", table)
		}
	}
}

// TestMigrate_ForceClearsDirty fails if an operator cannot recover from a
// half-applied migration. A dirty schema blocks every other verb, so without
// a working Force the only exit is hand-editing schema_migrations in
// production at 3am.
func TestMigrate_ForceClearsDirty(t *testing.T) {
	dsn := dbtest.NewDatabase(t)
	mg := openMigrator(t, dsn)

	if err := mg.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	applied, _, err := mg.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}

	// Simulate the state a migration that failed partway leaves behind.
	dbtest.Exec(t, dsn, `UPDATE schema_migrations SET dirty = true`)

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
	dsn := dbtest.NewDatabase(t)
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
		if dbtest.TableExists(t, dsn, table) {
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

// TestMigrate_DirtyAtNilVersionIsVisible is the arm for the state that a
// status command is most likely to describe wrongly: a rollback that failed
// on its LAST migration, leaving the bookkeeping at version -1 with dirty
// set. golang-migrate's Version() returns (0, false, ErrNilVersion) there and
// never consults the dirty column, so anything that trusts Version alone
// calls a broken schema an empty one — measured 2026-09-10, the CLI did.
//
// Fails if Dirty() stops reading the flag independently, and it also pins the
// upstream behaviour: if a future golang-migrate starts reporting dirty on
// the nil-version path, the first assertion goes red and Dirty() can be
// reconsidered.
func TestMigrate_DirtyAtNilVersionIsVisible(t *testing.T) {
	dsn := dbtest.NewDatabase(t)
	mg := openMigrator(t, dsn)

	// A database with no bookkeeping table at all is not dirty, and asking
	// must not error.
	dirty, err := mg.Dirty()
	if err != nil {
		t.Fatalf("Dirty on a never-migrated database: %v", err)
	}
	if dirty {
		t.Error("a never-migrated database reported dirty")
	}

	if err := mg.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if dirty, err := mg.Dirty(); err != nil || dirty {
		t.Errorf("after a clean Up: Dirty() = %v, %v; want false, nil", dirty, err)
	}

	// The state a rollback failing on its last migration leaves behind.
	dbtest.Exec(t, dsn, `UPDATE schema_migrations SET version = -1, dirty = true`)

	// Upstream discards the flag here. If this assertion fails, upstream
	// changed and the workaround can be revisited.
	if _, reportedDirty, err := mg.Version(); !errors.Is(err, ErrNoVersion) {
		t.Errorf("Version at -1: err = %v, want ErrNoVersion", err)
	} else if reportedDirty {
		t.Error("Version now reports dirty at nil version — upstream behaviour changed; Dirty() may be redundant")
	}

	dirty, err = mg.Dirty()
	if err != nil {
		t.Fatalf("Dirty at version -1: %v", err)
	}
	if !dirty {
		t.Error("Dirty() missed a dirty schema recorded at version -1 — a status command would call this an empty database")
	}
}

// TestRunUp_AppliesToAFreshDatabase covers the exact call cmd/relay makes on
// a first-ever deploy. Up() is proven elsewhere, but RunUp has its own
// construction and teardown per call, and it is the boot path: if it fails
// against an empty database, no server ever starts. Nothing proved that
// end-to-end until this arm.
func TestRunUp_AppliesToAFreshDatabase(t *testing.T) {
	dsn := dbtest.NewDatabase(t)

	if err := RunUp(dsn, migrations.FS); err != nil {
		t.Fatalf("RunUp against a fresh database: %v", err)
	}
	for _, table := range tablesIn0001 {
		if !dbtest.TableExists(t, dsn, table) {
			t.Errorf("table %q missing after RunUp", table)
		}
	}

	mg := openMigrator(t, dsn)
	head, err := mg.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	version, dirty, err := mg.Version()
	if err != nil {
		t.Fatalf("Version after RunUp: %v", err)
	}
	if version != head || dirty {
		t.Errorf("after RunUp: version=%d dirty=%t, want %d and false", version, dirty, head)
	}
}

// TestMigrate_DownIsIdempotent is the mirror of the Up idempotency arm. The
// CLI's down-all is meant to be safely re-runnable, and Down swallows
// ErrNoChange to make it so; nothing exercised that until this arm, which is
// the asymmetry that let it go unnoticed.
func TestMigrate_DownIsIdempotent(t *testing.T) {
	dsn := dbtest.NewDatabase(t)
	mg := openMigrator(t, dsn)

	if err := mg.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := mg.Down(); err != nil {
		t.Fatalf("first Down: %v", err)
	}
	if err := mg.Down(); err != nil {
		t.Errorf("second Down on an empty schema should be a no-op, got: %v", err)
	}
	if err := mg.Down(); err != nil {
		t.Errorf("third Down should still be a no-op, got: %v", err)
	}
	if _, _, err := mg.Version(); !errors.Is(err, ErrNoVersion) {
		t.Errorf("after repeated Down, Version should be ErrNoVersion, got %v", err)
	}
}

// TestMigrate_RealErrorsSurface pins the default: arms of Steps/Goto/Force —
// the branches that carry a genuine failure to the operator. Only Up's
// equivalent was exercised, so a regression that swallowed a real error on
// the other three would have shipped looking like success.
func TestMigrate_RealErrorsSurface(t *testing.T) {
	dsn := dbtest.NewDatabase(t)
	mg := openMigrator(t, dsn)

	if err := mg.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	// A version that does not exist in the set. Reachable by an operator
	// typo, since the CLI accepts any number.
	if err := mg.Goto(999); err == nil {
		t.Error("Goto to a nonexistent version should fail, not silently succeed")
	}

	// Every mutating verb must refuse a dirty schema rather than compound it.
	dbtest.Exec(t, dsn, `UPDATE schema_migrations SET dirty = true`)

	for name, call := range map[string]func() error{
		"Steps(-1)": func() error { return mg.Steps(-1) },
		"Steps(1)":  func() error { return mg.Steps(1) },
		"Goto(1)":   func() error { return mg.Goto(1) },
		"Down()":    func() error { return mg.Down() },
	} {
		if err := call(); err == nil {
			t.Errorf("%s against a dirty schema should fail", name)
		} else if !strings.Contains(strings.ToLower(err.Error()), "dirty") {
			t.Errorf("%s against a dirty schema should say why, got: %v", name, err)
		}
	}

	// Force to a version OTHER than the dirty one — the realistic recovery
	// where an operator inspects and concludes the schema is at N-1.
	if err := mg.Force(-1); err != nil {
		t.Fatalf("Force(-1): %v", err)
	}
	if _, _, err := mg.Version(); !errors.Is(err, ErrNoVersion) {
		t.Errorf("Force(-1) should leave no applied version, got %v", err)
	}
	if dirty, err := mg.Dirty(); err != nil || dirty {
		t.Errorf("Force(-1) should clear dirty: Dirty() = %v, %v", dirty, err)
	}
}

// TestMigrate_AcceptsCustomFS is the positive half of the custom-fs.FS claim
// that the DB-less arm in migrate_test.go cannot make: a caller-supplied
// migration set actually applies, and Head/Version agree with it. This is
// what makes RunUp's fs.FS parameter a real seam rather than a shape.
func TestMigrate_AcceptsCustomFS(t *testing.T) {
	dsn := dbtest.NewDatabase(t)
	custom := fstest.MapFS{
		"0001_first.up.sql":    {Data: []byte(`CREATE TABLE custom_one (id int primary key);`)},
		"0001_first.down.sql":  {Data: []byte(`DROP TABLE IF EXISTS custom_one;`)},
		"0002_second.up.sql":   {Data: []byte(`CREATE TABLE custom_two (id int primary key);`)},
		"0002_second.down.sql": {Data: []byte(`DROP TABLE IF EXISTS custom_two;`)},
	}

	mg, err := NewMigrator(dsn, custom)
	if err != nil {
		t.Fatalf("NewMigrator with a custom FS: %v", err)
	}
	defer mg.Close()

	if err := mg.Up(); err != nil {
		t.Fatalf("Up with a custom FS: %v", err)
	}
	version, dirty, err := mg.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if version != 2 || dirty {
		t.Errorf("custom FS applied to version=%d dirty=%t, want 2 and false", version, dirty)
	}
	for _, table := range []string{"custom_one", "custom_two"} {
		if !dbtest.TableExists(t, dsn, table) {
			t.Errorf("table %q missing — the custom migration did not apply", table)
		}
	}

	// And it rolls back, which also proves the set is a real pair-set and
	// not just two files that happened to parse.
	if err := mg.Down(); err != nil {
		t.Fatalf("Down with a custom FS: %v", err)
	}
	for _, table := range []string{"custom_one", "custom_two"} {
		if dbtest.TableExists(t, dsn, table) {
			t.Errorf("table %q survived Down with a custom FS", table)
		}
	}
}

// twoVersionFS and oneVersionFS are the same migration set at two different
// points in its history: what a newer build ships, and what an older build
// shipped. Pointing the second at a database migrated by the first is a
// binary rollback, and it is the only way to construct a schema whose
// recorded version this binary has never heard of.
func twoVersionFS() fstest.MapFS {
	return fstest.MapFS{
		"0001_first.up.sql":    {Data: []byte(`CREATE TABLE rollback_first (id int);`)},
		"0001_first.down.sql":  {Data: []byte(`DROP TABLE rollback_first;`)},
		"0002_second.up.sql":   {Data: []byte(`CREATE TABLE rollback_second (id int);`)},
		"0002_second.down.sql": {Data: []byte(`DROP TABLE rollback_second;`)},
	}
}

func oneVersionFS() fstest.MapFS {
	return fstest.MapFS{
		"0001_first.up.sql":   {Data: []byte(`CREATE TABLE rollback_first (id int);`)},
		"0001_first.down.sql": {Data: []byte(`DROP TABLE rollback_first;`)},
	}
}

// TestMigrate_StepsRefusesAForeignVersion pins the one state where Steps used
// to disagree with every other verb about whether anything had happened.
//
// Measured before the fix, against a database at version 2 and a binary whose
// set stops at 0001: Steps(+1) and Steps(-1) both returned nil with the
// version unchanged, while Up() and Down() on the SAME Migrator refused with
// "no migration found for version 2". An operator recovering from an incident
// with `collab-migrate up 1` would have been told it worked, forever.
//
// The defect was one errors.Is arm covering two unrelated origins of
// fs.ErrNotExist: "ran out of migrations" and "the schema's current version
// is not in this set". Only the first means the work is done.
func TestMigrate_StepsRefusesAForeignVersion(t *testing.T) {
	dsn := dbtest.NewDatabase(t)

	newer, err := NewMigrator(dsn, twoVersionFS())
	if err != nil {
		t.Fatalf("NewMigrator (newer build): %v", err)
	}
	if err := newer.Up(); err != nil {
		t.Fatalf("Up with the newer build: %v", err)
	}
	deployed, _, err := newer.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	newer.Close()
	if deployed != 2 {
		t.Fatalf("setup: want the newer build to reach version 2, got %d", deployed)
	}

	older, err := NewMigrator(dsn, oneVersionFS())
	if err != nil {
		t.Fatalf("NewMigrator (older build): %v", err)
	}
	defer older.Close()

	for _, n := range []int{1, -1} {
		err := older.Steps(n)
		if err == nil {
			t.Errorf("Steps(%d) against foreign version 2 returned nil: "+
				"the schema did not move and every other verb refuses this state", n)
			continue
		}
		// The message has to carry the diagnosis, because the operator's
		// next action depends entirely on it: redeploy the newer build, or
		// force. "file does not exist" would send them looking for a
		// missing file on disk.
		for _, want := range []string{"version 2", "does not exist in this binary's migration set"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("Steps(%d) error %q does not mention %q", n, err, want)
			}
		}
	}

	// And the version genuinely did not move, which is what makes a nil
	// return a lie rather than merely imprecise.
	after, _, err := older.Version()
	if err != nil {
		t.Fatalf("Version after refusals: %v", err)
	}
	if after != 2 {
		t.Errorf("version moved to %d; the refusals should not have applied anything", after)
	}
}

// TestStatus_ReportsAForeignVersionAsUnknown covers the reporting half of the
// same state. Without Known, `collab-migrate version` prints
//
//	version: 2   dirty: false   head: 1   pending: 0
//
// which is character-for-character the shape of a healthy, fully-migrated
// schema -- while every verb is in fact refusing. pending is counted against
// a set that does not contain the schema's position.
func TestStatus_ReportsAForeignVersionAsUnknown(t *testing.T) {
	dsn := dbtest.NewDatabase(t)

	newer, err := NewMigrator(dsn, twoVersionFS())
	if err != nil {
		t.Fatalf("NewMigrator: %v", err)
	}
	if err := newer.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	newer.Close()

	older, err := NewMigrator(dsn, oneVersionFS())
	if err != nil {
		t.Fatalf("NewMigrator: %v", err)
	}
	defer older.Close()

	st, err := older.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Applied {
		t.Fatal("Applied is false for a schema at version 2")
	}
	if st.Known {
		t.Errorf("Known is true for version %d against a set whose head is %d", st.Version, st.Head)
	}
	if st.Dirty {
		t.Error("Dirty is true; this schema is not dirty, it is foreign — two different recoveries")
	}
	if st.Pending != 0 {
		t.Errorf("Pending = %d; want 0 (nothing in the set is above version 2)", st.Pending)
	}

	// The healthy case must still report Known, or the warning fires on
	// every normal invocation and stops meaning anything.
	fresh := dbtest.NewDatabase(t)
	ok, err := NewMigrator(fresh, oneVersionFS())
	if err != nil {
		t.Fatalf("NewMigrator: %v", err)
	}
	defer ok.Close()
	if err := ok.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	okst, err := ok.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !okst.Known {
		t.Errorf("Known is false for version %d, which IS in the set", okst.Version)
	}
}

// TestMigrate_MidFileFailureRollsBackEverything measures what a failed
// migration actually leaves behind, because the recovery runbook's whole
// premise is that an operator can work out which version the schema matches.
//
// golang-migrate's pgx driver sends the entire .up.sql file as ONE
// wire-protocol Query message (MultiStatementEnabled is off), and Postgres
// wraps a multi-statement simple query in an implicit transaction. So a
// failure on statement 3 of 4 rolls back statements 1 and 2 as well: the
// schema is left at the PREVIOUS version's content, not partway through the
// failed one -- while schema_migrations durably records the failed version
// with dirty = true.
//
// That asymmetry is the whole finding. "dirty at version 1" reads as
// "version 1 is half-applied", and the tempting recovery is to force to 1.
// Measured here: nothing from version 1 exists, so forcing to 1 would mark a
// schema clean at a version whose tables are absent.
//
// This property depends on the statements chosen, not on the tooling: one
// CREATE INDEX CONCURRENTLY in a future migration breaks it, which is why
// migrations/README.md rule 6 exists and why this arm names the mechanism.
func TestMigrate_MidFileFailureRollsBackEverything(t *testing.T) {
	dsn := dbtest.NewDatabase(t)

	broken := fstest.MapFS{
		"0001_broken.up.sql": {Data: []byte(`
CREATE TABLE partial_one (id int);
CREATE TABLE partial_two (id int);
CREATE TABLE partial_boom (id int) NOT VALID SQL HERE;
`)},
		"0001_broken.down.sql": {Data: []byte(`DROP TABLE IF EXISTS partial_one;`)},
	}

	mg, err := NewMigrator(dsn, broken)
	if err != nil {
		t.Fatalf("NewMigrator: %v", err)
	}
	defer mg.Close()

	if err := mg.Up(); err == nil {
		t.Fatal("Up on a migration with a syntax error returned nil")
	}

	// The statements BEFORE the failure must be gone. If they survived, the
	// implicit-transaction assumption this runbook rests on is false and the
	// recovery advice has to change.
	for _, table := range []string{"partial_one", "partial_two"} {
		if dbtest.TableExists(t, dsn, table) {
			t.Errorf("table %q survived a failed migration: the file was NOT atomic, "+
				"so recovery cannot assume the schema is at the previous version", table)
		}
	}

	// ...and yet the bookkeeping says version 1.
	version, _, verr := mg.Version()
	if verr != nil {
		t.Fatalf("Version: %v", verr)
	}
	if version != 1 {
		t.Errorf("recorded version = %d, want 1 (stamped before the SQL ran)", version)
	}
	dirty, err := mg.Dirty()
	if err != nil {
		t.Fatalf("Dirty: %v", err)
	}
	if !dirty {
		t.Error("Dirty is false after a failed migration; nothing would warn the operator")
	}
}

// TestMigrationLockHeld_SeesAPeerHoldingIt covers the probe that turns a
// silent, unbounded startup hang into a logged wait.
//
// Measured 2026-09-10: with a peer holding the advisory lock, NewMigrator was
// still blocked after 40 seconds with no timeout and no output, because
// golang-migrate's ensureVersionTable takes the lock before its own
// table-exists check and Lock() waits indefinitely. The 15-second
// DefaultLockTimeout only guards verbs on an already-constructed Migrator
// (measured separately: Up() returned ErrLockTimeout after exactly 15s).
//
// The probe must be right in BOTH directions: a false negative restores the
// silent hang, and a false positive prints a contention warning on every
// ordinary boot until operators learn to ignore it.
func TestMigrationLockHeld_SeesAPeerHoldingIt(t *testing.T) {
	dsn := dbtest.NewDatabase(t)

	held, err := MigrationLockHeld(dsn)
	if err != nil {
		t.Fatalf("MigrationLockHeld on an uncontended database: %v", err)
	}
	if held {
		t.Fatal("reported contention on a database nobody is migrating")
	}

	// Probing must not leave the lock held, or the very next probe lies and
	// construction deadlocks against our own leftover.
	again, err := MigrationLockHeld(dsn)
	if err != nil {
		t.Fatalf("second probe: %v", err)
	}
	if again {
		t.Fatal("the probe did not release the lock it acquired")
	}

	// Now hold it the way a migrating peer does, computing the id the same
	// way the driver does rather than trusting a constant.
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	var dbName, schemaName string
	if err := conn.QueryRow(`SELECT current_database(), current_schema()`).Scan(&dbName, &schemaName); err != nil {
		t.Fatalf("identity: %v", err)
	}
	aid, err := migratedb.GenerateAdvisoryLockId(dbName, schemaName, migratepgx.DefaultMigrationsTable)
	if err != nil {
		t.Fatalf("lock id: %v", err)
	}
	peer, err := conn.Conn(t.Context())
	if err != nil {
		t.Fatalf("peer conn: %v", err)
	}
	defer peer.Close()
	if _, err := peer.ExecContext(t.Context(), `SELECT pg_advisory_lock($1)`, aid); err != nil {
		t.Fatalf("peer lock: %v", err)
	}

	held, err = MigrationLockHeld(dsn)
	if err != nil {
		t.Fatalf("MigrationLockHeld under contention: %v", err)
	}
	if !held {
		t.Error("did not see a peer holding the migration lock: a replica would hang at boot with nothing logged")
	}

	if _, err := peer.ExecContext(t.Context(), `SELECT pg_advisory_unlock($1)`, aid); err != nil {
		t.Fatalf("peer unlock: %v", err)
	}
	held, err = MigrationLockHeld(dsn)
	if err != nil {
		t.Fatalf("MigrationLockHeld after release: %v", err)
	}
	if held {
		t.Error("still reports contention after the peer released the lock")
	}
}

// TestMigrate_ForceRejectsAVersionOutsideTheSet closes the false all-clear
// that mutation testing found: `force 999` used to succeed, after which
// `collab-migrate version` printed pending 0, dirty false over a schema that
// had never been created.
func TestMigrate_ForceRejectsAVersionOutsideTheSet(t *testing.T) {
	dsn := dbtest.NewDatabase(t)
	mg := openMigrator(t, dsn)

	if err := mg.Force(999); err == nil {
		t.Error("Force(999) succeeded; the schema is now clean at a version that never existed")
	} else if !strings.Contains(err.Error(), "no migration 999 exists in the set") {
		t.Errorf("Force(999) error %q does not say why 999 is invalid", err)
	}

	// -1 is the one value outside the set that MUST be allowed: it is how an
	// operator says "this schema is genuinely empty", and per the mid-file
	// rollback above it is the correct target after a failed first migration.
	if err := mg.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	dbtest.Exec(t, dsn, `UPDATE schema_migrations SET dirty = true`)
	if err := mg.Force(NilVersion); err != nil {
		t.Errorf("Force(-1) was refused: %v; there is then no way to declare a schema empty", err)
	}
	if _, _, err := mg.Version(); !errors.Is(err, ErrNoVersion) {
		t.Errorf("after Force(-1), Version err = %v, want ErrNoVersion", err)
	}
}

// TestMigrate_StepsAtTheEndsOfTheSet covers the fs.ErrNotExist origin that
// genuinely DOES mean success, in both directions. Mutation testing proved
// this arm was missing: deleting the fs.ErrNotExist case from Steps left
// 65/65 tests green while breaking `collab-migrate up 1` at head.
func TestMigrate_StepsAtTheEndsOfTheSet(t *testing.T) {
	dsn := dbtest.NewDatabase(t)
	mg := openMigrator(t, dsn)

	// Forward, already at head: nothing to apply, and that is not an error.
	if err := mg.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	head, err := mg.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if err := mg.Steps(1); err != nil {
		t.Errorf("Steps(1) at head: %v; `collab-migrate up 1` on a caught-up schema must succeed", err)
	}
	if v, _, err := mg.Version(); err != nil || v != head {
		t.Errorf("after Steps(1) at head: version %d err %v, want %d", v, err, head)
	}

	// Backward, already empty: same shape, other end.
	if err := mg.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if err := mg.Steps(-1); err != nil {
		t.Errorf("Steps(-1) on an empty schema: %v; `collab-migrate down 1` must be safely re-runnable", err)
	}
	if _, _, err := mg.Version(); !errors.Is(err, ErrNoVersion) {
		t.Errorf("after Steps(-1) on empty: Version err = %v, want ErrNoVersion", err)
	}
}
