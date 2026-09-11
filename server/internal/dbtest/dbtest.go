// Package dbtest provides throwaway Postgres databases for tests that need a
// real server.
//
// It exists because two packages need the same thing and neither can import
// the other's test files: internal/db exercises the Migrator, and
// cmd/collab-migrate exercises the operator verbs whose destructive-gate
// decisions are made at runtime from the applied version, which cannot be
// reached without a database. One caller would not have justified a package;
// two with no other way to share do.
//
// Gate: COLLAB_TEST_DATABASE_URL must point at a Postgres these tests may
// create and drop databases on. `make test-integration` starts the compose
// stack and sets it. Two preconditions on that server, because this
// administers rather than merely connecting: a `postgres` maintenance
// database must exist and the credentials must be allowed to create
// databases, and it must be Postgres 13+ for DROP DATABASE ... WITH (FORCE).
package dbtest

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// EnvVar names the environment variable that enables the real-database tests.
const EnvVar = "COLLAB_TEST_DATABASE_URL"

// NewDatabase creates a throwaway database on the server named by
// COLLAB_TEST_DATABASE_URL and returns a URL pointing at it. The database is
// dropped when the test ends, pass or fail.
//
// Skips when the variable is unset, with a message naming the fix — a skipped
// test proves nothing, so it must be obvious how to un-skip it. A variable
// that IS set but unreachable FAILS rather than skipping: a silently-skipped
// integration test in an environment that meant to run it is worse than none.
func NewDatabase(t *testing.T) string {
	t.Helper()

	raw := strings.TrimSpace(os.Getenv(EnvVar))
	if raw == "" {
		t.Skipf("%s unset — run `make test-integration` (starts the compose Postgres and sets it)", EnvVar)
	}

	u, err := url.Parse(raw)
	if err != nil {
		// Deliberately not %v on the error: url.Parse returns *url.Error
		// whose Error() formats the whole raw input verbatim, password
		// included, and this text lands in CI output.
		t.Fatalf("%s is not a parseable URL (reason: %v)", EnvVar, unwrap(err))
	}

	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	name := "collab_test_" + hex.EncodeToString(suffix[:])

	// CREATE/DROP DATABASE cannot run while connected to the target, so
	// administer from the maintenance database on the same server.
	admin := *u
	admin.Path = "/postgres"
	adminDB, err := sql.Open("pgx", admin.String())
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	defer adminDB.Close()

	if err := adminDB.Ping(); err != nil {
		t.Fatalf("%s is set but unreachable (%s): %v", EnvVar, admin.Redacted(), err)
	}

	if _, err := adminDB.Exec(`CREATE DATABASE ` + pgx.Identifier{name}.Sanitize()); err != nil {
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
		if _, err := cleanup.Exec(`DROP DATABASE IF EXISTS ` + pgx.Identifier{name}.Sanitize() + ` WITH (FORCE)`); err != nil {
			t.Logf("cleanup: drop database %s: %v", name, err)
		}
	})

	target := *u
	target.Path = "/" + name
	return target.String()
}

// Exec runs one statement against dsn on its own short-lived connection.
// For test setup that has to reach past the code under test — marking a
// schema dirty, for instance, which no public verb can do.
func Exec(t *testing.T, dsn, statement string) {
	t.Helper()
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Exec(statement); err != nil {
		t.Fatalf("exec %q: %v", statement, err)
	}
}

// TableExists reports whether table is present in the public schema of dsn.
// Asks Postgres's own catalog rather than anything the code under test
// computes, so the oracle cannot agree with a broken implementation.
func TableExists(t *testing.T, dsn, table string) bool {
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

func unwrap(err error) error {
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok {
		if inner := u.Unwrap(); inner != nil {
			return inner
		}
	}
	return err
}
