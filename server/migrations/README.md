# Schema migrations

Every change to the collab-server schema is a numbered pair of SQL files in
this directory. They are compiled into the binary (`embed.go`), so a given
server build always carries exactly the migrations it was built from — an
operator cannot apply a different tree's SQL by accident.

## Who applies them

`cmd/relay` calls `db.RunUp` at boot (`main.go`, before the runtime pool
opens) whenever `COLLAB_DATABASE_URL` is set. Deploying a new build therefore
migrates the database. `RunUp` is idempotent, so a restart at head is a
no-op and a second replica racing the first is safe — golang-migrate takes an
advisory lock for the duration.

Everything the boot path deliberately cannot do — walking a schema *back*,
asking where it is, recovering it after a failed apply — is in
`cmd/collab-migrate`. See `make help`-adjacent targets in the `Makefile`
(`db-version`, `db-up`, `db-down N=1`, `db-goto V=2`, `db-force V=1
CONFIRM=yes`, `db-new NAME=...`, `db-reset CONFIRM=yes`).

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
   back. `TestMigrate_DownThenUpRoundTrips` applies the whole set down and
   back up against a real Postgres and fails if a pair does not undo itself.
   That test is the only thing standing between "we have a down migration"
   and "we can actually roll back".

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

## Recovering a dirty schema

A migration that fails partway leaves `schema_migrations.dirty = true`, and
golang-migrate then refuses every verb. That refusal is deliberate: it is
asking a human which version the schema really matches.

```bash
make db-version                  # prints the dirty warning and the version
make db-psql                     # inspect: what did the failed migration leave?
make db-force V=<version> CONFIRM=yes   # stamp that version, run no SQL
make db-up                       # then continue forward
```

`force` rewrites the bookkeeping without running SQL. Forcing the wrong
version leaves the bookkeeping lying about the schema, which is worse than
leaving it dirty — hence the two confirmation gates (`CONFIRM=yes` at the
Makefile, `-yes` at the CLI).

## Testing

`make test` runs without a database and therefore never executes any of this
SQL. `make test-integration` starts the compose Postgres, runs the same suite
with `COLLAB_TEST_DATABASE_URL` set, and exercises up / down / round-trip /
steps / goto / force against a real server. Each test creates and drops its
own throwaway database, so it never touches the dev database.
