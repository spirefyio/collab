package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spirefyio/collab/server/migrations"
)

// unroutableURL is syntactically valid and cannot connect (RFC 5737
// documentation address). Any test that reaches a database through it fails
// with a connection error — which is exactly what makes it useful for
// proving that a refusal happened BEFORE the connection was attempted.
const unroutableURL = "postgres://u:p@192.0.2.1:5432/db?sslmode=disable&connect_timeout=1"

// TestPlanDestructive_CoversEveryRollbackVerb is the arm for the defect two
// reviewers found on the first gate of this CLI: `down n` ran rollback SQL
// with no confirmation while `down-all` required -yes, even though with a
// single-migration set the two do the same thing. Every verb that can run a
// .down.sql or rewrite the bookkeeping must be classified destructive.
func TestPlanDestructive_CoversEveryRollbackVerb(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
		why  string
	}{
		{args: []string{"down", "1"}, want: true, why: "runs one .down.sql"},
		{args: []string{"down", "9"}, want: true, why: "runs nine .down.sql"},
		{args: []string{"down-all"}, want: true, why: "runs every .down.sql"},
		{args: []string{"goto", "0"}, want: true, why: "equivalent to down-all"},
		{args: []string{"force", "1"}, want: true, why: "rewrites bookkeeping without SQL"},
		{args: []string{"force", "-1"}, want: true, why: "rewrites bookkeeping without SQL"},

		// Not statically destructive. `goto` with a positive version is a
		// rollback only when it descends, which needs the applied version —
		// gated at execution instead, covered by the integration suite.
		{args: []string{"up"}, want: false, why: "only applies forward"},
		{args: []string{"up", "2"}, want: false, why: "only applies forward"},
		{args: []string{"version"}, want: false, why: "read only"},
		{args: []string{"status"}, want: false, why: "read only"},
		{args: []string{"goto", "3"}, want: false, why: "direction unknown without the database"},
	} {
		p, err := parsePlan(tc.args[0], tc.args[1:])
		if err != nil {
			t.Fatalf("parsePlan(%q): %v", tc.args, err)
		}
		got, reason := p.destructive()
		if got != tc.want {
			t.Errorf("destructive(%q) = %t, want %t (%s)", tc.args, got, tc.want, tc.why)
		}
		if got && reason == "" {
			t.Errorf("destructive(%q) is true but gave no reason to show the operator", tc.args)
		}
	}
}

// TestRun_RefusesDestructiveWithoutYesBeforeConnecting is the ordering arm.
// The URL is unroutable, so if the gate ran after NewMigrator the error would
// be a connection failure. Getting the confirmation message instead proves
// the refusal costs no connection — which is what makes the gate testable at
// all, and what stops a typo against a production URL from touching it.
func TestRun_RefusesDestructiveWithoutYesBeforeConnecting(t *testing.T) {
	for _, args := range [][]string{
		{"down", "1"},
		{"down-all"},
		{"goto", "0"},
		{"force", "1"},
	} {
		err := run(args, unroutableURL, false, "migrations", migrations.FS)
		if err == nil {
			t.Errorf("run(%q) without -yes: expected refusal, got nil", args)
			continue
		}
		if !strings.Contains(err.Error(), "re-run with -yes") {
			t.Errorf("run(%q) without -yes: got %q, want a confirmation refusal (a connection error means the gate runs too late)", args, err)
		}
	}
}

func TestParsePlan_Validation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "unknown command", args: []string{"migrate"}, wantErr: "unknown command"},
		{name: "down needs a count", args: []string{"down"}, wantErr: "step count"},
		{name: "down rejects zero", args: []string{"down", "0"}, wantErr: "must be positive"},
		{name: "down rejects negative", args: []string{"down", "-1"}, wantErr: "must be positive"},
		{name: "down rejects non-numeric", args: []string{"down", "one"}, wantErr: "not a number"},
		{name: "up takes at most one arg", args: []string{"up", "1", "2"}, wantErr: "at most one"},
		{name: "goto needs a version", args: []string{"goto"}, wantErr: "target version"},
		{name: "goto rejects non-numeric", args: []string{"goto", "head"}, wantErr: "not a version number"},
		{name: "goto rejects negative", args: []string{"goto", "-1"}, wantErr: "not a version number"},
		{name: "force needs a version", args: []string{"force"}, wantErr: "requires a version"},
		{name: "force rejects below -1", args: []string{"force", "-2"}, wantErr: "not a valid version"},
		{name: "version takes no args", args: []string{"version", "1"}, wantErr: "takes no arguments"},
		{name: "down-all takes no args", args: []string{"down-all", "1"}, wantErr: "takes no arguments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parsePlan(tc.args[0], tc.args[1:]); err == nil {
				t.Fatalf("parsePlan(%q): expected an error containing %q, got nil", tc.args, tc.wantErr)
			} else if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("parsePlan(%q) = %q, want it to contain %q", tc.args, err, tc.wantErr)
			}
		})
	}

	// force -1 is golang-migrate's "no migration applied" and is the recovery
	// for a rollback that failed on its last step — it must be accepted.
	if p, err := parsePlan("force", []string{"-1"}); err != nil {
		t.Errorf("force -1 must be accepted (it is the version -1 recovery): %v", err)
	} else if p.v != -1 {
		t.Errorf("force -1 parsed to v=%d", p.v)
	}
}

// TestParsePlan_GotoRangeGuard pins the narrowing guard. Goto's signature
// takes a uint, so on a 32-bit build an out-of-range value would truncate —
// and a value truncating to 0 would reach Down having skipped the v == 0
// confirmation gate. Rejected at parse instead.
func TestParsePlan_GotoRangeGuard(t *testing.T) {
	// 2^64-1 exceeds uint on every platform where uint is 32-bit, and is
	// in-range where uint is 64-bit; 2^32 is the interesting one for a 32-bit
	// build. Assert only what holds on every platform: the value that cannot
	// round-trip is refused.
	const tooBig = "18446744073709551616" // 2^64, unparseable as uint64 at all
	if _, err := parsePlan("goto", []string{tooBig}); err == nil {
		t.Error("goto with a value beyond uint64 should be rejected")
	}
}

func TestRun_RequiresURLForDatabaseVerbs(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"up"}, {"down", "1"}, {"force", "1"}} {
		err := run(args, "", false, "migrations", migrations.FS)
		if err == nil || !strings.Contains(err.Error(), "no database URL") {
			t.Errorf("run(%q) with no URL = %v, want a missing-URL error", args, err)
		}
	}
}

// TestRun_CreateNeedsNoURL pins that scaffolding works offline: an engineer
// adding a migration should not need a database, or credentials, to do it.
func TestRun_CreateNeedsNoURL(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "0001_init.up.sql"), []byte("SELECT 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0001_init.down.sql"), []byte("SELECT 1;"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"create", "add_sessions"}, "", false, dir, migrations.FS); err != nil {
		t.Fatalf("create with no URL: %v", err)
	}
	for _, name := range []string{"0002_add_sessions.up.sql", "0002_add_sessions.down.sql"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to be created: %v", name, err)
		}
	}

	// Same name at a different version is the collision that matters: two
	// files differing only by number read as the same migration.
	err := run([]string{"create", "add_sessions"}, "", false, dir, migrations.FS)
	if err == nil || !strings.Contains(err.Error(), "already uses the name") {
		t.Errorf("re-creating the same name = %v, want a duplicate-name refusal", err)
	}

	// And a name that would not be a valid migration filename.
	if err := run([]string{"create", "Add Sessions!"}, "", false, dir, migrations.FS); err == nil {
		t.Error("create should reject a name with spaces and punctuation")
	}

	if err := run([]string{"create"}, "", false, dir, migrations.FS); err == nil {
		t.Error("create with no name should be rejected")
	}
	if err := run([]string{"create", "a", "b"}, "", false, dir, migrations.FS); err == nil {
		t.Error("create with two names should be rejected")
	}
}

func TestCreate_ReportsMissingDirectory(t *testing.T) {
	err := create(filepath.Join(t.TempDir(), "does-not-exist"), "add_thing")
	if err == nil {
		t.Fatal("expected an error for a missing migrations directory")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error should wrap os.ErrNotExist so the cause is clear, got %v", err)
	}
}
