// collab-migrate is the operator CLI for the collab-server schema.
//
// The server applies pending migrations itself at boot (cmd/relay calls
// db.RunUp), so the happy path needs no CLI at all. This binary exists for
// everything the boot path deliberately cannot do: walk a schema BACK, ask
// where it currently is, recover it after a failed apply, and scaffold the
// next migration pair.
//
// The migration set is compiled in (migrations.FS), so `up`, `down`, `goto`,
// `steps`, `force` and `version` run the exact SQL the matching server build
// ships — an operator cannot accidentally apply a different tree's
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
//	down n               roll back n migrations
//	down-all   -yes      roll back EVERY migration (drops all data)
//	goto v               migrate up or down to exactly version v (0 == down-all)
//	force v    -yes      stamp version v and clear the dirty flag, running no SQL
//	create name [-dir d] scaffold the next NNNN_name.{up,down}.sql pair
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

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

	if err := run(args, url, confirm, dir); err != nil {
		fmt.Fprintf(os.Stderr, "collab-migrate: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, url string, confirm bool, dir string) error {
	cmd := args[0]
	rest := args[1:]

	// `create` touches files, never the database, so it runs before any
	// URL requirement — scaffolding a migration must work offline.
	if cmd == "create" {
		if len(rest) != 1 {
			return errors.New("create requires exactly one name: collab-migrate create add_sessions_table")
		}
		return create(dir, rest[0])
	}

	if url == "" {
		return errors.New("no database URL: pass -url or set COLLAB_DATABASE_URL")
	}

	mg, err := db.NewMigrator(url, migrations.FS)
	if err != nil {
		return err
	}
	defer mg.Close()

	switch cmd {
	case "version", "status":
		return printStatus(mg)

	case "up":
		switch len(rest) {
		case 0:
			if err := mg.Up(); err != nil {
				return err
			}
		case 1:
			n, err := positiveInt(rest[0])
			if err != nil {
				return fmt.Errorf("up: %w", err)
			}
			if err := mg.Steps(n); err != nil {
				return err
			}
		default:
			return errors.New("up takes at most one argument: collab-migrate up [n]")
		}
		return printStatus(mg)

	case "down":
		if len(rest) != 1 {
			return errors.New("down requires a step count (use down-all -yes to roll back everything)")
		}
		n, err := positiveInt(rest[0])
		if err != nil {
			return fmt.Errorf("down: %w", err)
		}
		if err := mg.Steps(-n); err != nil {
			return err
		}
		return printStatus(mg)

	case "down-all":
		if !confirm {
			return errors.New("down-all drops every table and all data; re-run with -yes to confirm")
		}
		if err := mg.Down(); err != nil {
			return err
		}
		return printStatus(mg)

	case "goto":
		if len(rest) != 1 {
			return errors.New("goto requires a target version")
		}
		v, err := strconv.ParseUint(rest[0], 10, 64)
		if err != nil {
			return fmt.Errorf("goto: %q is not a version number", rest[0])
		}
		if v == 0 && !confirm {
			return errors.New("goto 0 is equivalent to down-all and drops all data; re-run with -yes to confirm")
		}
		if err := mg.Goto(uint(v)); err != nil {
			return err
		}
		return printStatus(mg)

	case "force":
		if len(rest) != 1 {
			return errors.New("force requires a version")
		}
		v, err := strconv.Atoi(rest[0])
		if err != nil {
			return fmt.Errorf("force: %q is not a version number", rest[0])
		}
		if !confirm {
			return errors.New("force rewrites schema bookkeeping without running SQL; only correct if you have confirmed the schema matches that version — re-run with -yes")
		}
		if err := mg.Force(v); err != nil {
			return err
		}
		return printStatus(mg)

	default:
		return fmt.Errorf("unknown command %q (try: version, up, down, down-all, goto, force, create)", cmd)
	}
}

func printStatus(mg *db.Migrator) error {
	head, err := mg.Head()
	if err != nil {
		return err
	}

	version, dirty, err := mg.Version()
	if errors.Is(err, db.ErrNoVersion) {
		version = 0
		dirty = false
	} else if err != nil {
		return fmt.Errorf("read version: %w", err)
	}

	pending, err := mg.PendingAfter(version)
	if err != nil {
		return err
	}

	if version == 0 {
		fmt.Printf("version:  none (empty database)\nhead:     %d\npending:  %d\n", head, pending)
		return nil
	}
	fmt.Printf("version:  %d\ndirty:    %t\nhead:     %d\npending:  %d\n", version, dirty, head, pending)
	if dirty {
		fmt.Fprintf(os.Stderr,
			"\nWARNING: schema is DIRTY — migration %d failed partway and every other verb\n"+
				"will refuse until this is resolved. Inspect the schema, decide which version it\n"+
				"actually matches, then: collab-migrate force <version> -yes\n", version)
	}
	return nil
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
	fmt.Fprint(os.Stderr, `collab-migrate — operator CLI for the collab-server schema

usage: collab-migrate [-url URL] <command> [args]

commands:
  version              applied version, dirty flag, head, pending count
  up [n]               apply all pending migrations, or only n of them
  down n               roll back n migrations
  down-all -yes        roll back every migration (DROPS ALL DATA)
  goto v               migrate up or down to exactly version v (0 == down-all)
  force v -yes         stamp version v, clear dirty, run no SQL (recovery verb)
  create name [-dir d] scaffold the next NNNN_name.{up,down}.sql pair

flags:
  -url URL   postgres URL; defaults to $COLLAB_DATABASE_URL
  -yes       confirm a destructive command
  -dir DIR   migration source directory for create (default "migrations")

examples:
  collab-migrate version
  collab-migrate up
  collab-migrate down 1
  collab-migrate create add_sessions_table
`)
}
