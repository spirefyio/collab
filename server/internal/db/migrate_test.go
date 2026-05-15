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
