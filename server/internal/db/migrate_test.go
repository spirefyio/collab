package db

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/spirefyio/collab/server/migrations"
)

func TestRunUp_RejectsEmptyURL(t *testing.T) {
	err := RunUp("", migrations.FS)
	if err == nil || !strings.Contains(err.Error(), "database url") {
		t.Fatalf("expected empty-url rejection, got %v", err)
	}
}

func TestRunUp_HandlesUnreachableDB(t *testing.T) {
	err := RunUp("postgres://user:pass@192.0.2.1:5432/db?sslmode=disable&connect_timeout=1", migrations.FS)
	if err == nil {
		t.Fatal("expected error against unreachable DB")
	}
}

func TestMigrationsFS_IncludesUpAndDown(t *testing.T) {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var hasUp, hasDown bool
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), ".up.sql"):
			hasUp = true
		case strings.HasSuffix(e.Name(), ".down.sql"):
			hasDown = true
		}
	}
	if !hasUp {
		t.Error("no .up.sql files found")
	}
	if !hasDown {
		t.Error("no .down.sql files found")
	}
}

func TestRunUp_AcceptsCustomFS(t *testing.T) {
	// Smoke: pass an empty in-memory FS — should fail at the
	// migrate.New step, not crash. Validates that the function
	// composes correctly with an arbitrary fs.FS.
	custom := fstest.MapFS{
		"0002_noop.up.sql":   {Data: []byte("SELECT 1;")},
		"0002_noop.down.sql": {Data: []byte("SELECT 1;")},
	}
	err := RunUp("postgres://user:pass@192.0.2.1:5432/db?sslmode=disable&connect_timeout=1", custom)
	if err == nil {
		t.Fatal("expected error against unreachable DB")
	}
}

// TestVersions_CountsTheSetNotTheArithmetic pins the gap case. Version
// numbers are not step counts, so a set of {1, 5} has two migrations and
// four is the wrong answer. This arm fails if PendingAfter ever goes back to
// computing head-minus-version — the defect a live run of `collab-migrate
// version` produced against a set with a missing 0002.
func TestVersions_CountsTheSetNotTheArithmetic(t *testing.T) {
	gapped := fstest.MapFS{
		"0001_first.up.sql":   {Data: []byte("SELECT 1;")},
		"0001_first.down.sql": {Data: []byte("SELECT 1;")},
		"0005_fifth.up.sql":   {Data: []byte("SELECT 1;")},
		"0005_fifth.down.sql": {Data: []byte("SELECT 1;")},
	}
	mg := &Migrator{src: gapped}
	defer mg.Close() // source-only Migrator: Close must tolerate a nil migrate instance

	versions, err := mg.Versions()
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 2 || versions[0] != 1 || versions[1] != 5 {
		t.Fatalf("Versions = %v, want [1 5]", versions)
	}

	head, err := mg.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if head != 5 {
		t.Errorf("Head = %d, want 5", head)
	}

	for _, tc := range []struct {
		at   uint
		want int
	}{
		{at: 0, want: 2}, // empty database: both pending, NOT five
		{at: 1, want: 1}, // at 1: only 0005 pending, NOT four
		{at: 5, want: 0},
		{at: 9, want: 0}, // ahead of the set (a rollback of the binary)
	} {
		got, err := mg.PendingAfter(tc.at)
		if err != nil {
			t.Fatalf("PendingAfter(%d): %v", tc.at, err)
		}
		if got != tc.want {
			t.Errorf("PendingAfter(%d) = %d, want %d", tc.at, got, tc.want)
		}
	}
}

func TestVersions_EmptySet(t *testing.T) {
	mg := &Migrator{src: fstest.MapFS{}}
	versions, err := mg.Versions()
	if err != nil {
		t.Fatalf("Versions on empty set: %v", err)
	}
	if len(versions) != 0 {
		t.Errorf("Versions = %v, want empty", versions)
	}
	head, err := mg.Head()
	if err != nil {
		t.Fatalf("Head on empty set: %v", err)
	}
	if head != 0 {
		t.Errorf("Head = %d, want 0", head)
	}
	pending, err := mg.PendingAfter(0)
	if err != nil {
		t.Fatalf("PendingAfter on empty set: %v", err)
	}
	if pending != 0 {
		t.Errorf("PendingAfter(0) = %d, want 0", pending)
	}
}
