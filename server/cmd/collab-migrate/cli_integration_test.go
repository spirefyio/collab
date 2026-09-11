package main

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/spirefyio/collab/server/migrations"

	"github.com/spirefyio/collab/server/internal/dbtest"
)

// These are the CLI behaviours that cannot be decided without a database.
//
// main_test.go covers every gate that is decidable from the command line
// alone, which is most of them and is why it runs in CI with no services. The
// two here are different in kind: whether `goto v` is a rollback depends on
// the version the schema is ACTUALLY at, and the dirty exit code depends on
// what the bookkeeping says. Both were previously only reachable by hand.

// twoVersionSet is a two-migration history, which the shipped set is not.
// Without it there is no version to descend TO, and the runtime gate below
// cannot be exercised at all.
func twoVersionSet() fstest.MapFS {
	return fstest.MapFS{
		"0001_first.up.sql":    {Data: []byte(`CREATE TABLE cli_first (id int);`)},
		"0001_first.down.sql":  {Data: []byte(`DROP TABLE cli_first;`)},
		"0002_second.up.sql":   {Data: []byte(`CREATE TABLE cli_second (id int);`)},
		"0002_second.down.sql": {Data: []byte(`DROP TABLE cli_second;`)},
	}
}

// TestRun_DescendingGotoIsRefusedAtRuntime covers the only destructive gate in
// this CLI that argv cannot decide.
//
// `goto 1` is a forward migration on an empty schema and a rollback that drops
// cli_second on a schema at version 2. parsePlan sees the same plan either
// way, so destructive() correctly returns false and the gate has to run after
// the version is known.
//
// An earlier version of this arm used `goto 0` and passed with the runtime
// gate deleted, because goto 0 IS statically destructive and main_test.go
// already covers it. Two arms passing for the same reason are one arm.
func TestRun_DescendingGotoIsRefusedAtRuntime(t *testing.T) {
	dsn := dbtest.NewDatabase(t)
	set := twoVersionSet()

	if err := run([]string{"goto", "2"}, dsn, false, "", set); err != nil {
		t.Fatalf("ascending goto 2: %v", err)
	}
	if !dbtest.TableExists(t, dsn, "cli_second") {
		t.Fatal("setup: goto 2 did not apply 0002")
	}

	// Same argv shape, now a rollback.
	err := run([]string{"goto", "1"}, dsn, false, "", set)
	if err == nil {
		t.Fatal("descending goto 1 from version 2 succeeded without -yes; it drops what 0002 created")
	}
	for _, want := range []string{"rolls back from version 2", "-yes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not mention %q", err, want)
		}
	}
	if !dbtest.TableExists(t, dsn, "cli_second") {
		t.Error("cli_second is gone after a REFUSED goto")
	}

	// With -yes it must actually work, or the gate is a wall.
	if err := run([]string{"goto", "1"}, dsn, true, "", set); err != nil {
		t.Fatalf("descending goto 1 with -yes: %v", err)
	}
	if dbtest.TableExists(t, dsn, "cli_second") {
		t.Error("cli_second survived a confirmed rollback to version 1")
	}
	if !dbtest.TableExists(t, dsn, "cli_first") {
		t.Error("goto 1 rolled back past its target")
	}
}

// TestRun_DirtySchemaReportsTheDirtyExitCode pins the mapping main() uses to
// turn a dirty schema into exit code 3. An operator script that treats any
// non-zero exit as "the tool broke" would retry forever; 3 means "the SCHEMA
// needs a human", which is a different action.
func TestRun_DirtySchemaReportsTheDirtyExitCode(t *testing.T) {
	dsn := dbtest.NewDatabase(t)
	if err := run([]string{"up"}, dsn, false, "", migrations.FS); err != nil {
		t.Fatalf("up: %v", err)
	}

	// A clean schema must exit 0, or the code below means nothing.
	if err := run([]string{"version"}, dsn, false, "", migrations.FS); err != nil {
		t.Fatalf("version on a clean schema returned %v; want nil (exit 0)", err)
	}

	dbtest.Exec(t, dsn, `UPDATE schema_migrations SET dirty = true`)

	err := run([]string{"version"}, dsn, false, "", migrations.FS)
	if err == nil {
		t.Fatal("version on a dirty schema returned nil: a health check would read exit 0")
	}
	if !errors.As(err, &dirtyStatusError{}) {
		t.Errorf("version on a dirty schema returned %T (%v); main() maps only dirtyStatusError to exit 3", err, err)
	}
}

// TestRun_RefusesAForeignVersionThroughTheCLI carries the db-layer finding out
// to the surface an operator actually touches: after a binary rollback,
// `collab-migrate up 1` used to print nothing and exit 0 forever.
func TestRun_RefusesAForeignVersionThroughTheCLI(t *testing.T) {
	dsn := dbtest.NewDatabase(t)
	if err := run([]string{"up"}, dsn, false, "", migrations.FS); err != nil {
		t.Fatalf("up: %v", err)
	}
	// Stamp a version this build's set does not contain, the way a newer
	// build would have left it. Force would refuse this, by design, so it
	// goes in through the bookkeeping directly.
	dbtest.Exec(t, dsn, `UPDATE schema_migrations SET version = 9999, dirty = false`)

	err := run([]string{"up", "1"}, dsn, false, "", migrations.FS)
	if err == nil {
		t.Fatal("up 1 against a foreign version exited 0 having done nothing")
	}
	if !strings.Contains(err.Error(), "9999") {
		t.Errorf("refusal %q does not name the version that is foreign", err)
	}

	// `version` must still WORK in that state -- it is the one verb an
	// operator needs when everything else refuses.
	if err := run([]string{"version"}, dsn, false, "", migrations.FS); err != nil {
		t.Errorf("version refused to report a foreign schema: %v", err)
	}
}
