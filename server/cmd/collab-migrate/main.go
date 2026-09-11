// collab-migrate is the operator CLI for the collab-server schema.
//
// The server applies pending migrations itself at boot (cmd/relay calls
// db.RunUp), so the happy path needs no CLI at all. This binary exists for
// everything the boot path deliberately cannot do: walk a schema BACK, ask
// where it currently is, recover it after a failed apply, and scaffold the
// next migration pair.
//
// The migration set is compiled in (migrations.FS), so `up`, `down`,
// `down-all`, `goto`, `force` and `version` run the exact SQL the matching
// server build ships — an operator cannot accidentally apply a different tree's
// migrations. `create` is the one exception: it writes new files, so it
// works against a source directory (-dir).
//
// There is deliberately NO default database URL. A hardcoded default is how
// an operator migrates the wrong database; the dev URL lives in the Makefile
// where it is visible.
//
// Usage:
//
//	collab-migrate [-url URL] <command> [args]
//
//	version              print applied version, dirty flag, head, pending count
//	up [n]               apply all pending migrations, or n of them
//	down n     -yes      roll back n migrations (drops what they created)
//	down-all   -yes      roll back EVERY migration (drops all data)
//	goto v     [-yes]    migrate to exactly version v; -yes required when that
//	                     means rolling back (v below the applied version, or 0)
//	force v    -yes      stamp version v and clear the dirty flag, running no SQL
//	create name [-dir d] scaffold the next NNNN_name.{up,down}.sql pair
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spirefyio/collab/server/internal/config"
	"github.com/spirefyio/collab/server/internal/db"
	"github.com/spirefyio/collab/server/migrations"
)

func main() {
	var (
		url     string
		confirm bool
		dir     string
	)
	flag.StringVar(&url, "url", os.Getenv("COLLAB_DATABASE_URL"), "postgres URL (default $COLLAB_DATABASE_URL)")
	flag.BoolVar(&confirm, "yes", false, "confirm a destructive command (down-all, force)")
	flag.StringVar(&dir, "dir", "migrations", "migration source directory, for `create` only")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	if err := run(args, url, confirm, dir, migrations.FS); err != nil {
		// A dirty schema is a reportable state, not a tool failure: the
		// warning is already on stderr, so exit distinctly and say no more.
		if errors.As(err, &dirtyStatusError{}) {
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "collab-migrate: %v\n", err)
		os.Exit(1)
	}
}

// plan is the parsed, validated form of a command line. Parsing is separated
// from execution so that argument validation and the confirmation gate are
// pure functions over a plan — they are decided BEFORE any database
// connection is opened, which is what makes them testable without a Postgres
// and what guarantees a refusal costs no connection.
type plan struct {
	cmd  string
	n    int   // step count for `up n` / `down n`
	v    int64 // target version for `goto` / `force`
	hasN bool
	hasV bool
}

func parsePlan(cmd string, rest []string) (plan, error) {
	p := plan{cmd: cmd}
	switch cmd {
	case "version", "status", "down-all":
		if len(rest) != 0 {
			return p, fmt.Errorf("%s takes no arguments", cmd)
		}

	case "up":
		switch len(rest) {
		case 0:
		case 1:
			n, err := positiveInt(rest[0])
			if err != nil {
				return p, fmt.Errorf("up: %w", err)
			}
			p.n, p.hasN = n, true
		default:
			return p, errors.New("up takes at most one argument: collab-migrate up [n]")
		}

	case "down":
		if len(rest) != 1 {
			return p, errors.New("down requires a step count (use down-all to roll back everything)")
		}
		n, err := positiveInt(rest[0])
		if err != nil {
			return p, fmt.Errorf("down: %w", err)
		}
		p.n, p.hasN = n, true

	case "goto":
		if len(rest) != 1 {
			return p, errors.New("goto requires a target version")
		}
		v, err := strconv.ParseUint(rest[0], 10, 64)
		if err != nil {
			return p, fmt.Errorf("goto: %q is not a version number", rest[0])
		}
		// Guard the uint64 -> uint narrowing that Goto's signature forces.
		// On a 32-bit build an out-of-range value would otherwise truncate,
		// and a value truncating to 0 would reach Down having skipped the
		// v == 0 confirmation gate below.
		if uint64(uint(v)) != v {
			return p, fmt.Errorf("goto: version %s is out of range on this platform", rest[0])
		}
		p.v, p.hasV = int64(v), true

	case "force":
		if len(rest) != 1 {
			return p, errors.New("force requires a version")
		}
		v, err := strconv.ParseInt(rest[0], 10, 64)
		if err != nil {
			return p, fmt.Errorf("force: %q is not a version number", rest[0])
		}
		if v < -1 {
			return p, fmt.Errorf("force: %d is not a valid version (-1 means \"no migration applied\")", v)
		}
		if v > int64(^uint(0)>>1) {
			return p, fmt.Errorf("force: version %s is out of range on this platform", rest[0])
		}
		p.v, p.hasV = v, true

	default:
		return p, fmt.Errorf("unknown command %q (try: version, up, down, down-all, goto, force, create)", cmd)
	}
	return p, nil
}

// destructive reports whether this plan runs rollback SQL or rewrites the
// schema bookkeeping, WITHOUT consulting the database. The one destructive
// case it cannot decide statically is `goto v` for v > 0, which is a rollback
// only when v is below the currently applied version — checked at execution,
// where the version is known.
//
// Every verb that runs a .down.sql is in here. `down n` was NOT, originally:
// with a single-migration set, `down 1` drops every table in the schema — the
// same blast radius as down-all, which has always required -yes. Two
// independent reviewers flagged it on the same commit.
func (p plan) destructive() (bool, string) {
	switch p.cmd {
	case "down":
		return true, fmt.Sprintf("down %d runs %d rollback migration(s) and drops what they created", p.n, p.n)
	case "down-all":
		return true, "down-all rolls back every migration and drops all data"
	case "force":
		return true, "force rewrites schema bookkeeping without running SQL; it is only correct if you have confirmed the schema matches that version"
	case "goto":
		if p.v == 0 {
			return true, "goto 0 is equivalent to down-all and drops all data"
		}
	}
	return false, ""
}

// run takes the migration set as a parameter rather than reaching for
// migrations.FS directly so that the descending-goto gate below is reachable
// from a test.
//
// That gate is the only destructive check in this file that cannot be decided
// from argv: `goto 1` is a forward migration on an empty schema and a rollback
// on a schema at version 2, so it has to read the applied version at
// execution time. The shipped set currently contains one migration, which
// means no non-zero descent exists to point it at -- an earlier test aimed
// `goto 0` at it and passed on the STATIC destructive() gate instead,
// confirming nothing. A parameter is the smallest seam that lets the arm
// construct a two-version history and actually exercise the runtime branch.
func run(args []string, url string, confirm bool, dir string, set fs.FS) error {
	cmd := args[0]
	rest := args[1:]

	// `create` touches files, never the database, so it runs before any
	// URL requirement — scaffolding a migration must work offline.
	if cmd == "create" {
		if len(rest) != 1 {
			return errors.New("create requires exactly one name: collab-migrate create add_sessions_table\n" +
				"(flags must come BEFORE the subcommand: `collab-migrate -dir DIR create NAME`, " +
				"not `create NAME -dir DIR` — Go's flag parser stops at the first non-flag argument, " +
				"so trailing flags arrive here as extra names)")
		}
		return create(dir, rest[0])
	}

	p, err := parsePlan(cmd, rest)
	if err != nil {
		return err
	}

	if url == "" {
		return errors.New("no database URL: pass -url or set COLLAB_DATABASE_URL")
	}

	// Gate before connecting: a refusal must not open a connection, and this
	// check must be decidable without one.
	destructive, why := p.destructive()
	if destructive && !confirm {
		// Name the target in the REFUSAL, not only in the echo below. The
		// refusal is the one message an operator who typed this out of
		// local-dev habit is guaranteed to read, and "which database" is
		// the fact that decides whether they should retype it with -yes.
		return fmt.Errorf("%s\ntarget:   %s\nre-run with -yes to confirm", why, redactURL(url))
	}

	// Name the TARGET, not just the intent. -yes and the Makefile's
	// CONFIRM=yes both confirm "be destructive"; neither confirms "against
	// this database". COLLAB_DATABASE_URL decides that silently, and an
	// operator with it exported for the running server gets no on-screen tell
	// that a habitual `down 1` is pointed at production. So every destructive
	// verb announces its resolved target first, credentials stripped.
	if destructive {
		fmt.Fprintf(os.Stderr, "%s\ntarget:   %s\n\n", why, redactURL(url))
	}

	// Same unbounded wait as the server's boot path, and the same reason to
	// announce it first: NewMigrator blocks inside golang-migrate's
	// ensureVersionTable while a peer holds the lock, so an operator who
	// typed a verb and got no output at all needs to know it is waiting
	// rather than wedged.
	if held, lerr := db.MigrationLockHeld(url); lerr != nil {
		fmt.Fprintf(os.Stderr, "note: could not probe the migration lock (%v); continuing\n", lerr)
	} else if held {
		fmt.Fprint(os.Stderr, "note: another process holds the migration lock; waiting for it to finish\n")
	}

	mg, err := db.NewMigrator(url, set)
	if err != nil {
		return err
	}
	defer mg.Close()

	switch p.cmd {
	case "version", "status":
		dirty, err := printStatus(mg)
		if err != nil {
			return err
		}
		if dirty {
			return dirtyStatusError{}
		}
		return nil

	case "up":
		if p.hasN {
			if err := mg.Steps(p.n); err != nil {
				return err
			}
		} else if err := mg.Up(); err != nil {
			return err
		}
		_, err := printStatus(mg)
		return err

	case "down":
		if err := mg.Steps(-p.n); err != nil {
			return err
		}
		_, err := printStatus(mg)
		return err

	case "down-all":
		if err := mg.Down(); err != nil {
			return err
		}
		_, err := printStatus(mg)
		return err

	case "goto":
		// The remaining destructive case: descending to a version below the
		// one applied runs rollback SQL, and only the database knows which
		// direction that is.
		if !confirm {
			st, err := mg.Status()
			if err != nil {
				return err
			}
			if st.Applied && uint64(p.v) < uint64(st.Version) {
				return fmt.Errorf("goto %d rolls back from version %d and drops what those migrations created; re-run with -yes to confirm", p.v, st.Version)
			}
		}
		if err := mg.Goto(uint(p.v)); err != nil {
			return err
		}
		_, err := printStatus(mg)
		return err

	case "force":
		if err := mg.Force(int(p.v)); err != nil {
			return err
		}
		_, err := printStatus(mg)
		return err
	}
	// parsePlan rejects every other command, so this is unreachable.
	return fmt.Errorf("unhandled command %q", p.cmd)
}

// dirtyStatusError makes `version`/`status` exit non-zero on a dirty schema.
// The command's whole job is to report health, and automation commonly gates
// on the exit code alone — returning 0 there is a false all-clear. It carries
// no message of its own because printStatus already wrote the warning, and
// main() maps it to exit 3 (distinct from 1 = failure, 2 = usage) without
// printing anything further.
type dirtyStatusError struct{}

func (dirtyStatusError) Error() string { return "schema is dirty" }

// redactURL renders a database URL safe to print: credentials stripped,
// everything an operator needs to recognize the target kept.
//
// It takes the raw string rather than a *url.URL because the failure path is
// the point: net/url.Error.Error embeds its raw input VERBATIM, password and
// all, so a parse failure reported with %w would leak exactly what this
// function exists to strip. On a URL we cannot parse we print a fixed string
// and say nothing about its contents.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparseable database URL)"
	}
	return u.Redacted()
}

// printStatus formats the status block and reports whether the schema is
// dirty. All normalization lives in db.Migrator.Status, which is tested
// against a real database; this function only renders.
func printStatus(mg *db.Migrator) (bool, error) {
	st, err := mg.Status()
	if err != nil {
		return false, err
	}

	// Which BINARY, not just which schema. The recovery runbook tells an
	// operator to match their checkout to the build the server was deployed
	// from, and until this line existed nothing here could answer that: the
	// Dockerfile stamped internal/config.Version onto this binary too, but
	// the package was never linked in, so the -X was a silent no-op
	// (measured: go list -deps ./cmd/collab-migrate does not include it).
	fmt.Printf("binary:   %s\n", config.Version)

	if !st.Applied {
		fmt.Printf("version:  none (empty database)\ndirty:    %t\nhead:     %d\npending:  %d\n",
			st.Dirty, st.Head, st.Pending)
		if st.Dirty {
			fmt.Fprint(os.Stderr,
				"\nWARNING: schema is DIRTY at version -1 — a rollback failed on its last\n"+
					"migration, so the schema is not actually empty and every other verb will\n"+
					"refuse. Inspect what the failed rollback left behind, then either:\n"+
					"  collab-migrate force -1 -yes        (schema really is empty)\n"+
					"  collab-migrate force <version> -yes (schema matches that version)\n")
		}
		return st.Dirty, nil
	}

	fmt.Printf("version:  %d\ndirty:    %t\nhead:     %d\npending:  %d\n",
		st.Version, st.Dirty, st.Head, st.Pending)
	if !st.Known {
		// Without this the output above is indistinguishable from a healthy,
		// fully-migrated schema: dirty false, pending 0. Every number in it
		// is computed against a set that does not contain the schema's
		// actual position.
		fmt.Fprintf(os.Stderr,
			"\nWARNING: version %d does not exist in this binary's migration set (head is %d).\n"+
				"The database was migrated by a different build, or forced to a version that was\n"+
				"never a migration. 'pending' above is counted against a set the schema is not in.\n"+
				"Run the build that owns version %d, or force to a version this build knows.\n",
			st.Version, st.Head, st.Version)
	}
	if st.Dirty {
		fmt.Fprintf(os.Stderr,
			"\nWARNING: schema is DIRTY — migration %d failed partway and every other verb\n"+
				"will refuse until this is resolved. Inspect the schema, decide which version it\n"+
				"actually matches, then: collab-migrate force <version> -yes\n", st.Version)
	}
	return st.Dirty, nil
}

func positiveInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", s)
	}
	if n <= 0 {
		return 0, fmt.Errorf("step count must be positive, got %d", n)
	}
	return n, nil
}

// nameRe keeps a scaffolded filename to what golang-migrate's filename
// parser accepts and what stays readable in a directory listing.
var nameRe = regexp.MustCompile(`^[a-z0-9]+(_[a-z0-9]+)*$`)

// migrationFileRe matches golang-migrate's NNNN_name.{up,down}.sql shape.
var migrationFileRe = regexp.MustCompile(`^(\d+)_.*\.(up|down)\.sql$`)

// create scaffolds the next version's up/down pair in dir. It refuses to
// overwrite, and it derives the next number from what is on disk rather than
// from the embedded set, so two branches each adding a migration collide
// visibly at the filename instead of silently at the same version number.
func create(dir, name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("name %q must be lowercase letters, digits and single underscores (e.g. add_sessions_table)", name)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	var highest uint64
	for _, e := range entries {
		m := migrationFileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			continue
		}
		if v > highest {
			highest = v
		}
	}

	// A duplicate NAME at a different version is the real collision risk:
	// two files that differ only in their number read as the same migration.
	// The version-number check below cannot catch it, because create always
	// picks an unused number.
	for _, e := range entries {
		if strings.Contains(e.Name(), "_"+name+".up.sql") || strings.Contains(e.Name(), "_"+name+".down.sql") {
			return fmt.Errorf("%s already uses the name %q — pick a more specific name", filepath.Join(dir, e.Name()), name)
		}
	}

	next := fmt.Sprintf("%04d", highest+1)
	upPath := filepath.Join(dir, next+"_"+name+".up.sql")
	downPath := filepath.Join(dir, next+"_"+name+".down.sql")

	for _, p := range []string{upPath, downPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists — pick another name or bump the version by hand", p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", p, err)
		}
	}

	title := strings.ReplaceAll(name, "_", " ")
	up := fmt.Sprintf(`-- %s: %s (up)
--
-- Forward migration. Keep it additive where possible: a column added with a
-- default, a new table, a new index. An older server build must survive
-- against this schema long enough to roll the deploy back.
--
-- Every statement here needs its exact inverse in the matching .down.sql —
-- the migration round-trip test in internal/db applies both against a real
-- Postgres and fails if this pair does not undo itself.

`, next, title)

	down := fmt.Sprintf(`-- %s: %s (down)
--
-- Reverse migration: undo exactly what the .up.sql did, in reverse order.
-- Use IF EXISTS so a partially-applied up can still be rolled back.

`, next, title)

	if err := os.WriteFile(upPath, []byte(up), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", upPath, err)
	}
	if err := os.WriteFile(downPath, []byte(down), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", downPath, err)
	}

	fmt.Printf("created %s\ncreated %s\n", upPath, downPath)
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "collab-migrate %s\n\n", config.Version)
	fmt.Fprint(os.Stderr, `collab-migrate — operator CLI for the collab-server schema

usage: collab-migrate [-url URL] <command> [args]

commands:
  version              applied version, dirty flag, head, pending count
  up [n]               apply all pending migrations, or only n of them
  down n -yes          roll back n migrations (DROPS what they created)
  down-all -yes        roll back every migration (DROPS ALL DATA)
  goto v [-yes]        migrate to exactly version v; -yes required when that
                       means rolling back (v below the applied version, or 0)
  force v -yes         stamp version v, clear dirty, run no SQL (recovery verb)
                       v may be -1, meaning "no migration applied" — the
                       recovery for a rollback that failed on its last step
  create name [-dir d] scaffold the next NNNN_name.{up,down}.sql pair

exit codes:
  0  success
  1  failure
  2  usage error (no command)
  3  version/status ran fine and the schema is DIRTY

flags:
  -url URL   postgres URL; defaults to $COLLAB_DATABASE_URL
  -yes       confirm a destructive command
  -dir DIR   migration source directory for create (default "migrations")

examples:
  collab-migrate version
  collab-migrate up
  collab-migrate down 1 -yes
  collab-migrate create add_sessions_table
`)
}
