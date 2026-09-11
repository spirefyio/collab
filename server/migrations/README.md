# Schema migrations

Every change to the collab-server schema is a numbered pair of SQL files in
this directory. They are compiled into the binary (`embed.go`), so a given
server build always carries exactly the migrations it was built from — an
operator cannot apply a different tree's SQL by accident.

## Who applies them

`cmd/relay` calls `db.RunUp` at boot (`main.go`, before the runtime pool
opens) whenever `COLLAB_DATABASE_URL` is set. Deploying a new build therefore
migrates the database, and `RunUp` is idempotent, so a restart at head is a
no-op.

**A second replica racing the first will not double-apply, and will not fail —
it will WAIT, for as long as the first one takes.** golang-migrate holds a
Postgres advisory lock across the whole apply, so the no-double-application
guarantee is solid. What the lock costs is less obvious, and both halves were
measured (2026-09-10, against a real Postgres, with a peer holding the lock):

| Where the wait happens | Behaviour |
| --- | --- |
| `NewMigrator` / `RunUp` **construction** | blocks **indefinitely** — still waiting after 40s, no timeout |
| a verb on an already-constructed migrator | `ErrLockTimeout` after exactly **15s** |

The indefinite one is the one the boot path hits, because construction comes
first. The cause is upstream: golang-migrate's pgx driver takes the lock inside
`ensureVersionTable` — unconditionally, before its own "does the table already
exist" check — and that call bypasses the 15-second `DefaultLockTimeout` that
`Migrate.lock` races against. Its own comment reads "This will wait
indefinitely until the lock can be acquired."

Waiting is the right behaviour: the advisory lock is session-scoped, so a
holder that crashes releases it and the waiter proceeds. Waiting *silently* is
not — an orchestrator would SIGKILL the replica past a readiness deadline with
no diagnostic trail at all. So both the server and the CLI probe the lock
with `pg_try_advisory_lock` before constructing anything and say so:

```
WARN another process is holding the migration lock; waiting for it to finish
```

If a replica seems wedged at startup with no migration output, look for that
line first. The probe is a diagnostic and never a gate, so it cannot itself
block or refuse.

One consequence worth knowing: **`collab-migrate version` cannot be used to
inspect a schema that is mid-migration.** golang-migrate's own `Version()`
takes no lock, but there is no way to obtain a migrator without going through
the construction above, so the whole command blocks (measured: still blocked
after 20s with a peer holding the lock). When you need to know where a
migrating schema is, read the bookkeeping directly — this takes no lock and
returns immediately:

```bash
psql "$COLLAB_DATABASE_URL" -c 'SELECT version, dirty FROM schema_migrations'
```

Everything the boot path deliberately cannot do — walking a schema *back*,
asking where it is, recovering it after a failed apply — is in
`cmd/collab-migrate`. The `db-*` targets in the `Makefile` wrap it
(`db-version`, `db-up`, `db-down N=1 CONFIRM=yes`, `db-goto V=2`,
`db-force V=1 CONFIRM=yes`, `db-new NAME=...`, `db-reset CONFIRM=yes`), plus
`db-start` / `db-stop` / `db-destroy` for the compose Postgres itself.

## Adding one

```bash
make db-new NAME=add_sessions_table     # → 0002_add_sessions_table.{up,down}.sql
# write the forward SQL in .up.sql and its exact inverse in .down.sql
make test-integration                   # applies both against a real Postgres
```

`db-new` numbers from the highest file already present and refuses a name
already in use at any version, so two files that differ only by number cannot
both claim to be "the sessions migration".

## Rules

1. **Never edit a migration that has shipped.** Its checksum is not tracked,
   so an edit applies to new databases and silently skips every database
   already past it — the two then disagree forever. Add `000N+1` instead.

2. **Every `.up.sql` needs its exact inverse in `.down.sql`**, in reverse
   order, with `IF EXISTS` so a partially-applied up can still be rolled
   back. Three integration arms drive the down path against a real Postgres
   and assert the tables are gone (`TestMigrate_DownThenUpRoundTrips`,
   `TestMigrate_GotoWalksBothWays`, `TestMigrate_StepsForwardAndBack`), so any
   of them catches a `.down.sql` that does not undo its up. Only the
   round-trip arm goes on to re-apply `Up` on top of the rolled-back schema —
   that is what separates "we can roll back" from "we can roll back and
   cleanly roll forward again".

3. **Prefer additive forward changes** — a new table, a new index, a column
   added with a default. The previous server build has to survive against the
   new schema for as long as a rollback window lasts, and a dropped or
   renamed column breaks it immediately. When a destructive change is
   genuinely needed, split it: add in one release, stop writing in the next,
   drop in a third.

4. **One migration, one concern.** A failed apply leaves the schema dirty at
   that version, and the operator's next decision is "which version does this
   schema actually match" — a migration that did four unrelated things makes
   that question unanswerable.

5. **Extensions are cluster state, not schema state.** `0001_init.up.sql`
   does `CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`, and the matching down
   deliberately does *not* drop it: another database in the same cluster may
   depend on it. Note that managed Postgres offerings vary in whether a
   non-superuser may create extensions — on a provider that refuses, the
   extension has to be provisioned out-of-band before the first deploy.

6. **Do not break per-file atomicity.** Each `.sql` file is sent to Postgres
   as a single simple-query message, which Postgres runs in an implicit
   transaction, so a failure on any statement rolls back *every* statement in
   that file. The recovery procedure below depends on this. Two things forfeit
   it, and neither is rejected by any tool here:

   - a statement that cannot run in a transaction block — most realistically
     `CREATE INDEX CONCURRENTLY`, which is a common ask on a large table;
   - an explicit `BEGIN`/`COMMIT` inside the file.

   If a migration genuinely needs one of those, put it in a file of its own
   and say so in a comment at the top, so whoever recovers the schema knows
   this file can be half-applied.

7. **Roll the code fleet back BEFORE the schema, never concurrently.** Rule 3
   protects old code against new schema, which is the forward-deploy
   direction. It does nothing for the reverse: `db-down` / `db-goto` change
   the schema under any replica that is still running the newer build, and
   those replicas break immediately against structure that has just been
   dropped. Mid-incident this is the easy mistake to make, because `down 1`
   reads like a safe rollback lever. Drain or roll back the application first.

## Recovering a dirty schema

A migration that fails partway leaves `schema_migrations.dirty = true`, and
golang-migrate then refuses every verb. That refusal is deliberate: it is
asking a human which version the schema really matches.

**Read "dirty at version N" as "version N was ATTEMPTED", not "version N is
half-applied."** Because of rule 6, the usual case is that none of version N
landed at all. Measured: a four-statement migration whose third statement had
a syntax error left the schema with *zero* of its tables, while
`schema_migrations` durably recorded `version = 1, dirty = true`. Forcing to
the version the dirty flag shows is therefore the tempting answer and usually
the wrong one — it marks the schema clean at a version whose objects do not
exist, after which every query fails against missing relations with no dirty
flag left to protect you.

```bash
make db-version                  # prints the dirty warning and the version
psql "$COLLAB_DATABASE_URL"      # inspect: what did the failed migration leave?
make db-force V=<version> CONFIRM=yes   # stamp that version, run no SQL
make db-up                       # then continue forward
```

The version to force is **the last one whose objects you can actually see**,
which for a rule-6-compliant migration is `N-1`. If the failure was on the
*first* migration, that value is `-1`, not `0`:

```bash
make db-force V=-1 CONFIRM=yes   # "this schema is empty"
```

`-1` is the only value outside the migration set that `force` accepts; `0` is
rejected, because version 0 is not a migration (files start at `0001`) and
stamping it would leave every verb refusing a schema that reports itself as
empty. Any other out-of-set version is rejected too — `force 999` used to
succeed and then report `pending: 0, dirty: false` over a schema that had
never been created.

Two cautions for a non-local database:

- **`make db-psql` execs into the compose container, not `$DB_URL`.** For a
  remote schema use `psql "$COLLAB_DATABASE_URL"` directly, as above, or you
  will confidently inspect the wrong database.
- **`make db-force` rebuilds `collab-migrate` from whatever is checked out.**
  The "compiled-in migrations" safety property is per-build, so check out the
  commit or tag the running server was built from first — or skip the
  question entirely and use the image itself:
  `docker compose run --rm --build --entrypoint collab-migrate server version`.

If the schema is at a version this build has never heard of — a binary
rollback, or a bad force — `version` says so explicitly rather than printing a
healthy-looking `pending: 0`, and every verb refuses by name. The fix is to
run the build that owns that version, or force to one this build knows.

## Testing

`make test` runs without a database and therefore never executes any of this
SQL. `make test-integration` starts the compose Postgres, runs the same suite
with `COLLAB_TEST_DATABASE_URL` set, and exercises up / down / round-trip /
steps / goto / force / lock-contention / mid-file-failure against a real
server. Each test creates and drops its own throwaway database
(`internal/dbtest`), so it never touches the dev database.

When `COLLAB_TEST_DATABASE_URL` is unset those arms skip. When it is set but
unreachable they **fail** rather than skip, so a CI job with a broken Postgres
cannot come back green.
