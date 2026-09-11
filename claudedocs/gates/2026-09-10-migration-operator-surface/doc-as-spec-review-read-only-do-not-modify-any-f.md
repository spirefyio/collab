# DOC-AS-SPEC review, read-only. Do not modify any file.

_Gate lens on collab@fdc4a7a, 2026-09-10. Source transcript: a132bc2cd7715b170.output_

# DOC-AS-SPEC review — commit fdc4a7a (base ab130be)

Read-only review, no files modified. Worktree: `/private/tmp/claude-501/-Users-kevinduffey-projects-studio/0fe929e6-fb12-463c-b8d9-2d22454974c9/scratchpad/gate-fdc4a7a`. Verified `HEAD == fdc4a7a77cd924455d085c70f058ef6abb4ce0f4`, clean, detached.

External source verified: `github.com/golang-migrate/migrate/v4@v4.19.1` (pinned in `server/go.mod`), fetched into `$(go env GOMODCACHE)` via `go mod download` (network fetch only, no worktree file touched), plus Go 1.25 stdlib `database/sql`/`os` source on this machine.

---

## 1. Factual accuracy — findings

### CRITICAL — `server/README.md:97` "Destructive verbs are gated twice" is false for two of the six verbs

`down n` and non-zero `goto v` are **completely ungated** and can do exactly what `down-all`/`force`/`goto 0` do — empty or partially unwind the schema — with **zero** confirmation at either layer.

- `down`: CLI case has no `confirm` check at all (`server/cmd/collab-migrate/main.go:116-127`); Makefile target has no `CONFIRM` check either (`server/Makefile:100-102`, `db-down: build; ...; $(MIGRATE) ... down $(N)`). `Migrator.Steps` (`internal/db/migrate.go:129-144`) swallows `ErrShortLimit`/`fs.ErrNotExist` as success, so `down 999` on a database at version 1 empties it exactly like `down-all` — confirmed by the test's own over-stepping assertions (`migrate_integration_test.go:301-326`).
- `goto`: the CLI only checks `confirm` when `v == 0` (`main.go:146-148`); any other target — including going **backward** from a higher applied version to a lower one, which runs real `.down.sql` files and drops whatever those migrations created — needs no `-yes` at all (`main.go:138-152`). The Makefile's `db-goto` target passes neither `CONFIRM` nor `-yes` under any circumstance (`Makefile:109-111`).

Both doc examples reinforce the false impression: `server/README.md:89-90` shows `db-down N=1` and `db-goto V=1` with **no** `CONFIRM=yes`, sitting next to `db-reset`/`db-force` which **do** show it — a reader would reasonably (and wrongly) conclude the ones without `CONFIRM=yes` shown are non-destructive.

### CRITICAL — `server/README.md:8-10` "Components" list self-contradicts the same file's own Status section

```
- **jwtauth** — JWT auth middleware (added in a follow-up commit)      [README.md:8]
- **casbin** — RBAC enforcement (added in a follow-up commit)          [README.md:9]
- **gorilla/websocket** — opaque relay broker (added in a follow-up commit)  [README.md:10]
```

All three are false at this commit. All three are fully implemented and wired:
- jwtauth: `internal/auth/jwt.go` + `jwtauth.Verifier`/`Authenticator` in `internal/api/router.go:60-61`. Added in commit `c63cffb` ("Phase 0c.2").
- casbin: `internal/acl/enforcer.go` + `RequireAccess` middleware, `router.go:70`. Added in `5f668c5` ("Phase 0c.3").
- gorilla/websocket: `internal/relay/hub.go` (imports `github.com/gorilla/websocket`), mounted unconditionally at `router.go:52`. Added in `2f5651a` ("Phase 0c.4").

And this commit's own edit to the Status section, 20 lines later in the **same file**, says the opposite: *"Working today: the relay broker, JWT issuance and verification, casbin enforcement, the Postgres pool..."* (`README.md:126-127`). The diff (`git diff ab130be fdc4a7a -- server/README.md`) shows this commit touched the two adjacent bullets (`pgx`, `golang-migrate`) to fix the identical staleness pattern, and rewrote the Status section right below — but left these three untouched. It's not a blind spot in general, it's a sibling of an edit made in this exact commit.

### CRITICAL — `server/cmd/collab-migrate/main.go:9-13` claims a command that does not exist, and omits one that does

```go
// The migration set is compiled in (migrations.FS), so `up`, `down`, `goto`,
// `steps`, `force` and `version` run the exact SQL the matching server build
// ships — an operator cannot accidentally apply a different tree's
// migrations. `create` is the one exception...
```

`steps` is **not a CLI verb**. The `run()` switch (`main.go:93-172`) has cases only for `version`/`status`, `up`, `down`, `down-all`, `goto`, `force`; anything else — including literally typing `collab-migrate steps 2` — falls to the `default:` branch and errors: `unknown command "steps" (try: version, up, down, down-all, goto, force, create)` (`main.go:171`). `Steps` is only the internal `Migrator` method name (`internal/db/migrate.go:129`), never exposed as a verb. The correct `Usage:` block ten lines below in the **same doc-comment** (`main.go:19-29`) gets it right (no `steps`, includes `down-all`) — the two lists in one comment block disagree with each other. The intro sentence also **omits `down-all`**, arguably the single most important verb to name correctly given the finding above.

---

### HIGH — `server/Makefile:84-85` `db-psql` ignores `DB_URL` entirely — breaks the one runbook it's used in

```makefile
db-psql:
	$(COMPOSE) exec postgres psql -U collab -d collab
```

This always execs into the **local compose Postgres container**, never `psql "$(DB_URL)"`. But the Makefile's own header (`Makefile:9-11`) advertises that `db-*` targets "Honours COLLAB_DATABASE_URL when set so the same targets work against a staging or production database," and `db-psql` is prescribed as step 2 of exactly that scenario — the "Recovering a dirty schema" runbook (`migrations/README.md:66-77`), which exists precisely for production incidents. An operator recovering a dirty **remote** schema who runs `make db-psql` to "inspect: what did the failed migration leave?" gets a shell into an unrelated local database (or an error if no local Postgres is running), while believing they're looking at the broken one. `db-version`/`db-force`/`db-up` in the same runbook correctly use `$(DB_URL)`; `db-psql` is the odd one out and neither README flags it.

### HIGH — `server/README.md:58-63` "start only the server" is not what the shown command does

```
Self-host with external Postgres — start only the server and point
COLLAB_DATABASE_URL at the managed instance:

    COLLAB_DATABASE_URL=postgres://user:pass@db.example.com/collab \
      docker compose up server
```

`server`'s `depends_on: postgres: condition: service_healthy` (`docker-compose.yml:58-60`) has no `required: false`, so Compose auto-starts (and waits on the healthcheck of) the local `postgres` service too — standard Compose semantics for `up`/`run` on a named service. The stated goal ("start only the server") is not achieved; the correct invocation needs `--no-deps`. This is also in tension with the port-conflict warning three lines above it (`README.md:43-48`, "If port 5432 ... is already in use") — the exact local Postgres this recipe is trying to avoid starts anyway. I did not spin up Docker to observe this directly (read-only scope), so this is CONFIRMED-BY-READING against the unambiguous `depends_on` declaration and Compose's documented default, not a measured run.

---

### MED — `migrations/README.md:43-45` overclaims exclusivity for the round-trip test

> "`TestMigrate_DownThenUpRoundTrips` ... is the only thing standing between 'we have a down migration' and 'we can actually roll back'."

**PARTIAL.** Two other integration tests also drive the down path against real Postgres and assert `tablesIn0001` are gone afterward — `TestMigrate_GotoWalksBothWays` (`migrate_integration_test.go:412-422`, via `Goto(0)` → `Down()`) and `TestMigrate_StepsForwardAndBack` (`:281-286`, `:316-326`, via `Steps(-1)` and over-stepping back). Either would independently catch a `.down.sql` that fails to drop its tables. What's genuinely unique to `DownThenUpRoundTrips` is the second half — re-applying `Up()` on top of the rolled-back schema (`:253-260`) — which would also incidentally catch a broken new migration's down.sql via a Postgres "relation already exists" error on re-create. So "we can roll back" has three tests behind it; "we can roll back **and cleanly re-apply**" has one.

### MED — `server/README.md:119,129` "`internal/store/` is empty" — the directory does not exist

`git ls-tree -r fdc4a7a -- server/internal` and `find server/internal -maxdepth 2 -type d` both confirm no `store` path exists anywhere in the tree or on disk at this commit — not "empty," **absent** (git doesn't track empty directories, and there's no placeholder file). A reader who literally verifies this claim with `ls server/internal/store/` gets "No such file or directory," not an empty listing, which could read as the correction itself being unreliable.

### MED — `server/Makefile:109-111` `db-goto` has no confirmation wiring at all, and neither README explains the `goto 0 == down-all` equivalence

Unlike `db-down-all`/`db-force`/`db-reset`/`db-destroy`, the `db-goto` target never checks `CONFIRM` and never passes `-yes`. Net effect: `make db-goto V=0` can **never succeed**, under any invocation, because there is no path to satisfy the CLI's `v==0 && !confirm` gate (`main.go:146-148`) through `make`. That's fail-safe, but undocumented and inconsistent with its four siblings — and the fact that `goto 0` is destructive-equivalent to `down-all` is stated only in the CLI's own source comment (`main.go:27`, `:317`), never in `server/README.md` or `migrations/README.md`.

### MED — `server/README.md:23-31` `/me` row implies availability under a "zero-config (no DB, no auth)" boot; it actually 404s

```
Skeleton boots zero-config (no DB, no auth) and exposes:
GET  /me            JWT-protected (when COLLAB_JWT_SECRET is set)
```

With no `COLLAB_JWT_SECRET`, `cfg.JWTSecret` is empty, `deps.Issuer` stays nil (`cmd/relay/main.go:78-100`), and the **entire** protected route group — including `/me` — is never mounted (`router.go:58-73`). `curl localhost:8443/me` on a genuine zero-config boot returns a plain chi 404, not a 401. The parenthetical hints at conditionality but doesn't convey that the route disappears rather than merely gating.

---

### LOW findings

- `migrations/README.md:18` — "See `make help`-adjacent targets in the `Makefile`" — there is no `help:` target in the Makefile (`grep -n "^help:" server/Makefile` → none). Phrasing risk only; it doesn't literally instruct running `make help`, but a skimming reader could try it and get "No rule to make target 'help'."
- `server/README.md:18` — `make build # → bin/collab-server` names only one of the two binaries the target produces; `Makefile:22-25` also builds `bin/collab-migrate` in the same invocation. Not mentioned anywhere that `collab-migrate`'s binary path comes from this same command.
- `db-destroy` and `db-stop` (`Makefile:73-82`) are real, and `db-destroy` is fully destructive (`docker compose down --volumes`, correctly `CONFIRM=yes`-gated) — but neither appears in either README.
- Pre-existing, **not modified by this commit** but directly undermines the CORRECTION's completeness: `server/cmd/relay/main.go:1-9` and `server/internal/api/router.go:1-3` still describe `/relay/ws`, casbin RBAC, and team routes as "added in a follow-up commit" / "subsequent commits add" — the identical staleness pattern as the CRITICAL Components-list finding above, in files item 4's discoverability path leads a reader straight into. Flagged for awareness since it's the same defect class, not counted against this diff.

---

## 2. Can they act? — walking the procedures literally

**"Adding one" (`migrations/README.md:24-28`).** `make db-new NAME=add_sessions_table` → `Makefile:120-122` → `create(dir, name)` in `main.go:230-305`, which scans `migrations/` for the highest existing version (currently `0001`), refuses a duplicate name, and writes `0002_add_sessions_table.up.sql`/`.down.sql` with the exact boilerplate shown. Matches the `# → 0002_add_sessions_table.{up,down}.sql` comment precisely. `make test-integration` then rebuilds (fresh `go:embed`) and runs the full integration suite, which exercises whatever is newly on disk. No missing step, no ordering problem. (CONFIRMED-BY-READING; not executed, per the read-only scope.)

**"Recovering a dirty schema" (`migrations/README.md:72-77`).** Steps 1, 3, 4 (`db-version`, `db-force`, `db-up`) are accurate and correctly use `$(DB_URL)`. Step 2 (`db-psql`) is the HIGH finding above — it silently inspects the wrong database for anything but local dev. A second gap not stated anywhere: recovery rebuilds `collab-migrate` from whatever is currently checked out locally (`db-force: build`); the CLI's own "can't apply a different tree's migrations" safety property (main.go:9-12) is only as good as that checkout matching what's actually deployed — the runbook never says "checkout the same commit/tag as the running server first," and the alternative, safer path that guarantees parity (`docker compose run --entrypoint collab-migrate`, from `docker-compose.yml`'s own header) isn't cross-referenced from `migrations/README.md` at all.

---

## 3. Trust model and destruction

Not unmistakable. The framing at `server/README.md:97-99` sets up a clean mental model ("gated twice") that is false for `down n` and non-zero `goto` (CRITICAL finding above) — this is the most operationally dangerous gap in the review: an operator in a hurry, or a copy-paste/typo on `N=`, gets a full silent wipe from a command that looks as innocuous as `down 1`. `force` and `down-all` (the scary-sounding ones) are correctly gated twice; `goto` and `down` (innocuous-sounding) are not gated at all outside the single `goto 0` special case. The difference between `down n`, `down-all`, and `goto 0` is **not** explained in either README — the `goto 0 == down-all` equivalence exists only in CLI source comments never surfaced to the docs (MED finding above).

---

## 4. Discoverability

`server/README.md` links to `migrations/README.md` twice (Components bullet, `:12`; end of "Database migrations," `:100-101`) and names `cmd/collab-migrate` explicitly — the workflow, CLI, and conventions doc are all reachable from the README alone. Good.

The Go doc-comments in `internal/db/migrate.go` are unusually thorough and, aside from the round-trip-exclusivity phrasing, hold up well under direct source verification (see CHECKED CLEAN) — exported errors and invariants are genuinely discoverable via `go doc`. The one significant break is `cmd/collab-migrate/main.go`'s own package doc (phantom `steps`, missing `down-all`), and the two pre-existing stale package docs a reader would hit one hop further in (`cmd/relay`, `internal/api`) — noted as LOW above since out of this diff's scope.

---

## 5. The CORRECTION block — execution quality

Placement is correct per the org's own standard: it sits directly inside item 2 ("REST API"), the exact site that carried the false claim, not in a changelog or a separate doc. It's dated, states precisely what was false (verified: the diff shows the old text read exactly `/auth`, `/teams`, `/workspaces`, `/invites`), states what's real with file citations (`internal/api/teams.go`, `migrations/0001_init.up.sql`), and is honest about scope ("still owed"). This is good, disciplined retraction writing, and it's independently accurate on every specific claim it makes (six routes: confirmed exact; oauth2: confirmed absent) except the `internal/store/` "empty" vs. "absent" imprecision (MED, above).

The irony is that it's a **partial** sibling-class hunt: the same commit that wrote this careful correction, and in the same file fixed two of five identical "(added in a follow-up commit)" bullets three sections earlier, didn't apply the same scrutiny to the other three. A reader who trusts the CORRECTION block (reasonably — it's well-written) has no reason to suspect the Components list above it is equally wrong.

---

## 6. What a reader still cannot learn

- That `down n` and non-zero `goto` are exactly as destructive as `down-all`/`force`/`goto 0`, with none of the confirmation. (Real, high-impact gap — see CRITICAL/trust-model above.)
- That a migration failure at server boot is **fatal** to the process (`cmd/relay/main.go:63-66`, `os.Exit(2)`) — neither README connects "the server won't start and logged 'migration failed'" to "now go run the dirty-schema runbook."
- That `RunUp`'s advisory-lock safety claim ("a second replica racing the first is safe") is bounded by golang-migrate's `DefaultLockTimeout` (15s, `migrate.go:27`) — if the first replica's migration run takes longer than that, a second replica's `RunUp` can return `ErrLockTimeout` and, per the point above, crash that replica's boot. The no-double-application guarantee holds regardless; the no-boot-failure expectation doesn't, and nothing says so.
- That recovering a schema against a non-local database requires the operator's checkout (or image) to match what's actually deployed — the "compiled-in migrations" safety property is per-build, not enforced across a recovery session.
- That `db-destroy` exists as a distinct, more destructive lifecycle operation than anything in the migrations vocabulary (drops the Postgres volume itself, not just the schema).

---

## CHECKED CLEAN

- **Advisory lock, held for the duration** (`migrations/README.md:13-14`) — CONFIRMED-BY-READING. `Postgres.Lock()`/`Unlock()` in golang-migrate's pgx/v5 driver run `SELECT pg_advisory_lock($1)` / `pg_advisory_unlock($1)` (`.../database/pgx/v5/pgx.go:221-235,237-250`); `Migrate.Up/Down/Steps/Migrate` each call `m.lock()` before reading migrations and `m.unlockErr(m.runMigrations(ret))` after running them (`.../migrate.go:212-303`), so the lock spans the full apply, not just setup.
- **Checksum not tracked** (`migrations/README.md:36-38`) — CONFIRMED-BY-READING. `ensureVersionTable` creates `schema_migrations (version bigint not null primary key, dirty boolean not null)` (`pgx.go:465`) — no hash/checksum column exists anywhere in golang-migrate v4.19.1.
- **Down.sql is the exact reverse order of up.sql** (`migrations/README.md:40-41`) — CONFIRMED: `0001_init.down.sql`'s 7 statements mirror `0001_init.up.sql`'s creation order exactly.
- **Extension survives down** (`migrations/README.md:59-64`) — CONFIRMED: `0001_init.down.sql` never touches `uuid-ossp`.
- **Six mounted routes, exactly** (`server/README.md:115-118`) — CONFIRMED-BY-READING against `router.go:44-71`; exhaustive grep for `.Get(/.Post(/.Put(/.Delete(/.Patch(/.Mount(/.Handle(` across `internal/` and `cmd/` finds no others.
- **"nothing references `oauth2`"** (`server/README.md:120`) — CONFIRMED: whole-tree, all-file-type grep for "oauth2" hits only the doc's own prose and `.env.example`'s comment header; no import, no `go.mod`/`go.sum` dependency.
- **Status section "Working today" list** (`server/README.md:126-128`) — each item independently confirmed wired: relay broker (`hub.go`+`router.go:52`), JWT issuance/verification (`auth/jwt.go`+`router.go:60-61`), casbin (`acl/enforcer.go`+`router.go:69-71`), Postgres pool (`db/pool.go`+`cmd/relay/main.go:67-74`), migration surface (`migrate.go`+`main.go`+both test files).
- **`ErrNoVersion` same-value alias** (`internal/db/migrate.go:18-23`) — CONFIRMED against `migrate.go:31` (`ErrNilVersion = errors.New("no migration")`), a direct assignment.
- **`Close()`'s double-Close and driver-chain claims** (`migrate.go:77-80`) — CONFIRMED against golang-migrate's `Migrate.Close` (calls `databaseDrv.Close()`) and Go stdlib `database/sql/sql.go:927-931` ("Make DB.Close idempotent").
- **`Steps()`'s `ErrShortLimit`/`fs.ErrNotExist` mechanism** (`migrate.go:115-128`) — CONFIRMED-BY-READING against `readUp` (`migrate.go:532-601`) line for line, including the `count==0` vs. `count>0` branch split and `os.ErrNotExist == fs.ErrNotExist` (Go stdlib `os/error.go:23`).
- **`Goto(0) == Down()`** (`migrate.go:146-150`) — CONFIRMED, direct code match, also independently exercised by `TestMigrate_GotoWalksBothWays`.
- **`RunUp` runs before `NewPool` at boot** (`migrate.go:253-254`) — CONFIRMED against `cmd/relay/main.go:61-73`.
- **`make test` never touches a real database** (`migrations/README.md:86-87`) — CONFIRMED: no non-integration test opens a live connection; both "unreachable" tests target `192.0.2.1` (TEST-NET-1) deliberately.
- **Each integration test creates/drops its own throwaway DB** (`migrations/README.md:88-90`) — CONFIRMED via `newTestDB`/`t.Cleanup` in `migrate_integration_test.go:61-111`.
- **`docker compose down` vs. `down --volumes`** (`server/README.md:39-40`) and the **port-remap example** (`:47`) — CONFIRMED against the named `postgres-data` volume and `${POSTGRES_HOST_PORT:-5432}`/`${SERVER_HOST_PORT:-8443}` interpolations in `docker-compose.yml`.
- **`docker compose run --rm --entrypoint collab-migrate server version`/`down 1`** (`docker-compose.yml` header) — CONFIRMED-BY-READING: entrypoint override, binary path, and environment inheritance from the `server` service definition all check out; `down 1` correctly requires no `-yes`, matching the CLI's own `down` case.
- All Makefile invocations shown in both READMEs for `db-version`, `db-up`, `db-down N=`, `db-force V= CONFIRM=`, `db-new NAME=`, `db-reset CONFIRM=`, `db-start`, `test-integration` — CONFIRMED to exist with correct variable names and matching behavior (`db-goto`'s confirmation gap is called out separately above).
