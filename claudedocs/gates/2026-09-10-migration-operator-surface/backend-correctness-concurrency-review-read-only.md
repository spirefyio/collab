# Backend correctness / concurrency review, read-only. Do not modify any

_Gate lens on collab@fdc4a7a, 2026-09-10. Source transcript: af498e1e2573ae2e7.output_

## Backend correctness / concurrency review — commit fdc4a7a (base ab130be)

Scope confirmed: worktree HEAD is `fdc4a7a77cd924455d085c70f058ef6abb4ce0f4`, base `ab130be` is its parent-side ancestor, working tree clean. `server/cmd/relay/main.go` has **zero diff** between the two SHAs (`git diff ab130be fdc4a7a -- server/cmd/relay/main.go` is empty). Module versions actually resolved by `server/go.sum`: `golang-migrate/migrate/v4 v4.19.1`, `jackc/pgx/v5 v5.9.2` — I read both at those exact pinned versions in `$GOMODCACHE`. Everything below is a **reading** (static source inspection); nothing was built, run, or executed against a database. Where a claim depends on PostgreSQL server-side behavior rather than Go source, I say so explicitly.

---

### 1. CONCURRENT MIGRATION — `server/migrations/README.md:11-13` — **CRITICAL — FALSE CLAIM IN A DOC**

> "a restart at head is a no-op and a second replica racing the first is safe — golang-migrate takes an advisory lock for the duration"

**The mechanism is real; the "safe" conclusion is not, and fails in two different ways.**

Verified mechanism (CONFIRMED-BY-READING): `database/pgx/v5/pgx.go:221-235` (`Lock`) and `:237-250` (`Unlock`) issue `SELECT pg_advisory_lock($1)` / `pg_advisory_unlock($1)` on a single dedicated `*sql.Conn` (`pgx.go:57-58,120,126-127`). The lock ID is a pure, deterministic `CRC32(dbName·schema·table)` (`database/util.go:13-19`) — every replica connecting to the same DB/schema/table computes the identical ID, so this genuinely is a cross-process, session-scoped mutex, and a crashed holder's session-scoped lock is released automatically when Postgres notices the connection is gone (standard Postgres semantics, not something this code has to handle). That part is CHECKED CLEAN.

Where it breaks:

- **`migrate.go:887-932` (`Migrate.lock`)** races the real, blocking `m.databaseDrv.Lock()` call against a **15-second timer** (`DefaultLockTimeout`, `migrate.go:27`, wired into every `*Migrate` via `newCommon()` at `migrate.go:183-190`, `LockTimeout: DefaultLockTimeout` at line 187). Studio's `Migrator` (`server/internal/db/migrate.go:45-75`) never overrides `LockTimeout`, so 15s applies unconditionally to `Up`/`Down`/`Steps`/`Goto`/`Force`. If replica A's migration run takes longer than 15s, replica B's `m.lock()` returns `ErrLockTimeout` (`migrate.go:34,912`) — **not** `ErrNoChange` — so `Migrator.Up()` (`server/internal/db/migrate.go:98-103`) wraps and returns it, `cmd/relay/main.go:63-66` logs and calls `os.Exit(2)`. A "racing" replica crashes at boot instead of waiting.
  - Worse: `pgx.go:230` and `:245` hardcode `context.Background()` for the actual `pg_advisory_lock`/`unlock` calls, so when the 15s timer wins the race in `migrate.go:905-936`, the **losing goroutine that's still blocked inside `m.databaseDrv.Lock()` keeps running** with no way to be cancelled — a leaked goroutine racing any subsequent `Close()` on the same `*sql.Conn`.
- **Even earlier, with no timeout at all**: `migratepgx.WithInstance` (`pgx.go:66-137`) calls `ensureVersionTable()` (`pgx.go:437-471`), which **unconditionally** does its own `p.Lock()` at line 438 — a direct call, not routed through `Migrate.lock()`'s racing-timer wrapper at all. This runs on **every single `NewMigrator`/`RunUp` call**, i.e., every server boot and every `collab-migrate` invocation. If a replica's boot lands here while another process holds the same advisory lock for a real migration, this call blocks **indefinitely** — no timeout, no log line, no exit code. An orchestrator would eventually SIGKILL it past a startup-probe deadline with zero diagnostic trail, which is a worse failure than the loud 15s crash above.

**What "safe" would require but the doc doesn't state**: replica A's entire migration must complete in well under 15 seconds, *and* replica B's boot must not land inside A's held-lock window during A's `ensureVersionTable` step. Neither is guaranteed, and both failure modes get worse as migrations get bigger — precisely the case operators most need "safe" to be true.

**Disposition**: CONFIRMED-BY-READING (verified against `pgx.go` and `migrate.go` source at the pinned SHA/version as the task asked). What would upgrade this to CONFIRMED-BY-MEASUREMENT: run two `Migrator.Up()` calls concurrently against one Postgres where the first migration's `Run()` is artificially slowed past 15s (e.g., a `pg_sleep` migration), and print which of `ErrLockTimeout` / a hang / success each replica observes, plus `pg_locks` snapshots showing whether the losing goroutine's advisory-lock request is still outstanding after the timeout fires.

---

### 2. ERROR CLASSIFICATION — `server/internal/db/migrate.go:472-487` (`Migrator.Steps`) — **CRITICAL — the load-bearing question**

`Steps` swallows three signals as unconditional success:

| Sentinel | Origin (module) | n>0 (readUp) | n<0 (readDown) |
|---|---|---|---|
| `ErrNoChange` | `migrate.go:543-545` (readUp), `:643-645` (readDown) — only fires for `limit==0` | **Unreachable** via `Steps`: `Migrator.Steps` rejects `n==0` itself (`migrate.go:473-475` in studio's file) before calling `mg.m.Steps`. Dead for this path. | Same — unreachable via `Steps(n<0)`. |
| `ErrShortLimit{k}` | `migrate.go:598-601` (readUp), `:684-688` (readDown) — fires when `0<count<limit` | **Schema HAS moved** — by `count` (fewer than requested). Intentional and covered by studio's own `TestMigrate_StepsForwardAndBack` (over-step assertions). CHECKED CLEAN. | Same — schema moved by `count`, intentional, same test covers the backward over-step. CHECKED CLEAN. |
| `fs.ErrNotExist` | **Two distinct origins**, both matching `errors.Is(err, fs.ErrNotExist)` since `os.ErrNotExist == fs.ErrNotExist` (verified: `$GOROOT/src/os/error.go:23`) | | |
| — origin A | `migrate.go:594-596` (readUp: `limit>0 && count==0`) / `:655-657` (readDown: `from==-1 && limit>0`) — genuinely ran out, applied nothing | **Schema has NOT moved.** Documented, intended, matches studio's comment at `migrate.go:128` (studio file, "nothing at all was available to apply (count == 0)"). CHECKED CLEAN. | Same, CHECKED CLEAN. |
| — origin B | **`versionExists(from)` at the very top of both functions** — `migrate.go:536-540` (readUp), `:636-640` (readDown) — fires when the *current recorded version itself* has no up **or** down file in this build's embedded set. `versionExists` (`migrate.go:776-810`) wraps the final `os.ErrNotExist` at line 807: `fmt.Errorf("no migration found for version %d: %w", version, err)` — `errors.Is` still matches through this wrap. | **Schema has NOT moved — zero migrations were even attempted** — but this is not "caught up," it's "the version pointer is unrecognized by this binary's migration set." | Identical mechanism, identical result. |

**The answer to "is there a combination where Steps reports success but the schema did not move as the caller believes": yes, origin B.** `versionExists` failing is reachable in realistic operation — a `Force` to a version not in the set (see Q4), or the scenario the task names directly: a binary rollback to a build whose embedded migration set doesn't go as high as what's already applied. In that state, `collab-migrate up 1` / `down 1` (both route through `Migrator.Steps`, `server/cmd/collab-migrate/main.go:104-114,120-127`) return **success having done nothing**, indistinguishable from "already fully migrated." Studio's own doc comment on `Steps` (`server/internal/db/migrate.go:122-128`) only describes origin A ("nothing at all was available to apply (count == 0)") — origin B is not mentioned, and nothing in the new integration test suite constructs a foreign/unrecognized current version to exercise it. This is precisely the failure mode an operator would hit *while already trying to recover from an incident* using the one tool built for that purpose.

By contrast, a genuine mid-file SQL failure does **not** get swallowed by any of the three sentinels: `runMigrations` (`migrate.go:723-767`) calls `m.databaseDrv.Run()` at line 744 and returns that error directly (`:744-746`) if it fails — a real `*database.Error`, not one of the three sentinels. `Migrator.Up/Down/Goto/Force` correctly surface this. Only `Steps`'s `fs.ErrNotExist` branch has the blind spot, and only for the "current version not in the set" origin.

**Disposition**: CONFIRMED-BY-READING against `migrate.go` at v4.19.1 (line numbers above), cross-checked against `os.ErrNotExist == fs.ErrNotExist` in the Go 1.26 stdlib. What a measurement would look like: create two `Migrator`s pointed at two different `fstest.MapFS` sets against the same live throwaway database (one that applied version 2, one whose embedded set only has version 1), call `Steps(1)` on the second, and print the returned error and the actual `schema_migrations` row before/after — this is directly buildable as a unit test (no new Postgres feature needed) and would fail today.

---

### 3. `PendingAfter` — `server/internal/db/migrate.go:230-248` — **MED**

The raw arithmetic is **CHECKED CLEAN and intentional**: `migrate_test.go:92-108` (`TestVersions_CountsTheSetNotTheArithmetic`) explicitly asserts `PendingAfter(9) == 0` with the comment `// ahead of the set (a rollback of the binary)` — the author knew about and accepted this return value for the ahead-of-head case. So `PendingAfter` itself is not the defect.

The defect is one layer up: **`printStatus` in `server/cmd/collab-migrate/main.go:175-206` never compares `version` against `head`.** It computes both (`head, _ := mg.Head()` at line 176, `version, dirty, _ := mg.Version()` at line 181) and prints a dedicated `WARNING` block only for `dirty` (`:199-203`). There is no equivalent warning for `version > head`. Concretely: a schema left at version 9 by an operator error (Q4) or a genuine binary rollback, with `dirty=false`, prints:
```
version:  9
dirty:    false
head:     5
pending:  0
```
— textually identical in shape/tone to a completely healthy, fully-migrated schema. The tool has every number it needs to flag this (`version`, `head` are both already in scope at `main.go:176,181`) and simply doesn't compare them. This also compounds with the `dirty` case: when `dirty=true`, `pending` (line 189) is still computed and printed as if version N were cleanly, fully applied — which per Q6 is very likely false for a DDL migration that failed mid-file (the schema is probably back at N-1's actual content, not N's). Printing a specific pending count next to `dirty: true` implies a certainty about the schema's true position that `PendingAfter` cannot actually have.

**Disposition**: CONFIRMED-BY-READING (`PendingAfter`'s value is intentional per the existing test; the missing cross-check in `printStatus` is confirmed by reading the function body, which has no `if version > head` branch anywhere). No execution needed to confirm the absence of a branch; a measurement would just be running `collab-migrate version` against a database forced to a too-high version and eyeballing the (unchanged, unwarned) output.

---

### 4. FORCE semantics — `server/internal/db/migrate.go:177-182`(Migrator.Force) / `server/cmd/collab-migrate/main.go:154-168` — **HIGH**

`migrate.Migrate.Force` (`migrate.go:365-379`) only rejects `version < -1` (`ErrInvalidVersion`, line 366-368). Everything else — `-1`, `0`, and arbitrarily large positive ints — is accepted, locked, and passed straight to `databaseDrv.SetVersion(version, false)` (`pgx.go:339-371`). Studio adds **no bound of its own** at either `Migrator.Force` (`migrate.go:177-182`, a pure pass-through with error-wrap only) or the CLI (`main.go:158-167`, parses with plain `strconv.Atoi`, no range check against `Head()`).

Two concretely reachable, silently-corrupting values via `collab-migrate force <v> -yes`:

- **`v == 0` is a trap, not a synonym for "empty."** `SetVersion`'s insert guard at `pgx.go:356` is `if version >= 0 || (version == database.NilVersion && dirty)`. For `Force(0)`: `version >= 0` is true → it `INSERT`s a real row `(version=0, dirty=false)` (`pgx.go:357-363`). Version `0` is not a real migration (files are 1-indexed, `0001_init...`), so the very next `Up`/`Down`/`Goto` call hits `versionExists(0)` at the top of `readUp`/`readDown` (`migrate.go:536-540`, `:636-640`) and fails loudly (safe) — **except** through `Steps`, which (per Q2) silently swallows exactly this failure and reports success while doing nothing. An operator who runs `collab-migrate up 1` after a bad `force 0` will see "success," see `printStatus` print `"version:  none (empty database)"` (`main.go:194-196` triggers on the *literal* `version==0` value, not on `ErrNoVersion`) — which looks completely normal — and can loop `up 1` forever with no progress and no error. The semantically-correct reset-to-empty value is `-1` (`database.NilVersion`): for `Force(-1)`, `SetVersion`'s guard is false on both clauses (`-1 >= 0` is false; `dirty` is always `false` from `Force`, so the second clause is also false) → the table is `TRUNCATE`d with **no** insert (`pgx.go:345-350`), leaving it genuinely empty, and `readUp(-1, ...)` takes the correct `from == -1` fast path (`migrate.go:568-577`) with no `versionExists` check at all. This asymmetry is not documented anywhere in `migrations/README.md`'s recovery section or the CLI's own `usage()` text (`collab-migrate/main.go:313-338`), and it is not consistently handled even within this one CLI: `goto` has an explicit `v==0` special case with its own confirmation copy (`main.go:146-148`, "goto 0 is equivalent to down-all"), but `force` has no analogous awareness that `0` means something different from `-1` for this verb.
- **`v` far above `Head()`** (a typo, or a version copied from another branch/environment) succeeds unconditionally and produces exactly the Q3 "ahead of head" state: `dirty=false`, `pending=0`, indistinguishable from healthy in `printStatus`, and `Up()` becomes a durable, silent no-op (`ErrNoChange`) until manually corrected. No upper-bound check exists anywhere in the call chain.

**Disposition**: CONFIRMED-BY-READING (traced the exact `SetVersion` conditional at `pgx.go:356` against both `v=0` and `v=-1`, and confirmed no bound check exists in either `Migrator.Force` or the CLI's `force` case). A measurement would run `Force(0)` then `Version()`/`Steps(1)` against a real throwaway Postgres and print the resulting `schema_migrations` row plus `Steps`'s return value — directly buildable as an addition to `migrate_integration_test.go` and not present today.

---

### 5. BOOT PATH REGRESSION — `server/internal/db/migrate.go:255-262` (`RunUp`) vs. `ab130be:server/internal/db/migrate.go:24-55` — **CHECKED CLEAN, no behavior change**

`server/cmd/relay/main.go` is byte-identical between the two SHAs (empty diff, confirmed above), so any difference is entirely inside `RunUp`.

Edge-by-edge comparison (old: single inline function; new: `NewMigrator` + `defer mg.Close()` + `mg.Up()`):

- **Error strings/wrapping**: identical text at every step — `"database url is required"`, `"iofs source: %w"`, `"open sql: %w"`, `"migrate driver: %w"`, `"migrator: %w"`, `"migrate up: %w"` all appear verbatim in both versions (old: `ab130be` lines 26,31,36,42,47,52; new: `migrate.go:47,52,57,65,71,100`). The old code's `defer sqlDB.Close()`/`defer m.Close()` and the new `Migrator.Close()` both **discard** any error `Close()` itself returns when called via `RunUp` — that's unchanged, not a regression (it was already true that a `Close()` failure never reaches `RunUp`'s caller in the old code, since `defer m.Close()` and `defer sqlDb.Close()` are bare calls with no named-return capture).
- **Close ordering**: old code's defers run LIFO — `m.Close()` (registered second, at `ab130be:49`) fires before `sqlDB.Close()` (registered first, at `ab130be:38`). New code's `Migrator.Close()` (`migrate.go:81-93`) runs `mg.m.Close()` first (line 87) then the explicit `mg.sqlDB.Close()` second (line 88) — same order. `database/sql.DB.Close()` is confirmed idempotent by the stdlib itself (`$GOROOT/src/database/sql/sql.go:926-931`, `// Make DB.Close idempotent`), so the double-close in both versions is genuinely harmless, and the new code's own comment claiming this (`migrate.go:78-80`) is accurate.
- **Connection lifetime for the `RunUp` entry point specifically**: unchanged — opened in `NewMigrator`, used once by `Up()`, closed by `defer mg.Close()` before `RunUp` returns, all within one call, same as the old single function. (The connection becomes longer-lived only for *other* callers of `NewMigrator` — the CLI and the integration tests — which is the intended new capability, not a change to the boot path's own lifetime.)
- **Dirty-schema behavior**: both versions call the identical `m.Up()` (old: `ab130be:51`; new: `Migrator.Up`, `migrate.go:98-103`) with identical `!errors.Is(err, migrate.ErrNoChange)` gating — a dirty schema produces `ErrDirty` from `migrate.go:275-276`(module) in both cases, wrapped identically.
- **Empty migration set**: both versions call the same `m.Up()`; for a genuinely empty source, `readUp`'s `from==-1` branch calls `sourceDrv.First()` (`migrate.go:558-567`), which is unaffected by anything in this diff. Not a regression, though moot in practice since `migrations.FS` always embeds `0001_init.*.sql` (`server/migrations/embed.go:7`).

No behavioral delta found for the boot call site. This conclusion is a reading of both versions' source; nothing was compiled or run.

---

### 6. TRANSACTIONALITY — `server/migrations/0001_init.up.sql` + `server/migrations/README.md:70-88` — **CRITICAL**

**Correction to the premise first** (Claim Discipline): I count **13** top-level semicolon-terminated statements in `0001_init.up.sql`, not 9 — 1 `CREATE EXTENSION`, 6 `CREATE TABLE`, 1 `CREATE TYPE`, 5 `CREATE INDEX` (lines 19,21,33,42,44,52,54,63,65,77,78,80,90). The mechanism analyzed below doesn't depend on the exact count, but the number in the prompt doesn't match the file at this SHA.

**Confirmed mechanism, traced through three modules:**
1. `pgx.go:252-270` (`Run`) — with `MultiStatementEnabled` false (studio passes a zero-value `&migratepgx.Config{}` at `server/internal/db/migrate.go:60`), `Run` reads the **entire file** via `io.ReadAll` and calls `p.runStatement(migr)` **once** — the whole file is one query string (`pgx.go:265-269`).
2. `pgx.go:283` — `p.conn.ExecContext(ctx, query)` is called with **zero arguments**.
3. `jackc/pgx/v5@v5.9.2/conn.go:513-516` — `Conn.exec`'s explicit rule: `// Always use simple protocol when there are no arguments` → forces `QueryExecModeSimpleProtocol` regardless of the connection's configured default mode.
4. `conn.go:580-587` (`execSimpleProtocol`) → `pgconn/pgconn.go:1129-1159` (`PgConn.Exec`) → `pgConn.frontend.SendQuery(&pgproto3.Query{String: sql})` at line 1153 — the entire multi-statement file goes out as **one** Postgres wire-protocol `Query` message.

Per PostgreSQL's documented simple-query-protocol behavior (server-side fact, not verifiable from Go source — see below), multiple statements in one such message run inside an **implicit transaction block** unless the string itself contains explicit `BEGIN`/`COMMIT` or a statement that cannot run in a transaction block. None of the 13 statements in `0001_init.up.sql` is in that excluded set (`CREATE EXTENSION`, plain `CREATE TABLE`, `CREATE TYPE ... AS ENUM`, and plain `CREATE INDEX` without `CONCURRENTLY` are all ordinary transactional Postgres DDL). So a failure at **any** statement rolls back **all** of them — the practical answer to "statement 5 fails" is that the database ends with **zero** of this file's DDL applied, a full clean rollback to the pre-migration (empty) schema.

**But the bookkeeping doesn't reflect that.** `runMigrations` (`migrate.go:723-767`, module) calls `SetVersion(1, true)` **before** `Run()` (line 738) — a separate, already-`Commit()`ed transaction per `pgx.go:339-371` — and only calls `SetVersion(1, false)` **after** `Run()` succeeds (line 750). If `Run()` fails, `runMigrations` returns immediately at line 745 without ever reaching line 750. Result: `schema_migrations` durably says `version=1, dirty=true`, while the actual schema has none of version 1's tables/types/extension — dirty is being used here to mean "fully rolled back," not its conventional "partially applied" reading.

`migrations/README.md:70-88` (the recovery runbook) doesn't say this. It frames the dirty state as an open question — "inspect the schema, decide which version it actually matches" — and its worked example (`make db-force V=<version> CONFIRM=yes`) leaves `<version>` for the operator to fill in without steering them away from the tempting-but-wrong choice of forcing to the version `dirty` is already showing (1). For this migration, and any future one that avoids non-transactional DDL, the correct target is deterministically the version *before* the failed one (i.e., `-1`/empty — which, per Q4, is itself a footgun since the natural-looking `force 0` is wrong). Forcing to `1` instead would mark the schema clean at a version whose tables don't exist, and every runtime query would then fail against nonexistent relations with no further dirty-flag protection.

Also worth flagging forward: this whole-file atomicity is an artifact of the current file's statement choices and the zero-value `Config{}` (no `MultiStatementEnabled` override), not a rule the tooling enforces. `migrations/README.md`'s "Rules" section (1-5) has nothing warning a future migration author that adding `CREATE INDEX CONCURRENTLY` (a common real-world ask for large tables) would silently break the atomicity property the recovery story implicitly depends on.

**Disposition**: The Go-level mechanics (steps 1-4 above: whole file, zero args, forced simple protocol, one `Query` message) are CONFIRMED-BY-READING against the exact pinned module/library sources. The Postgres-server-side "implicit transaction wraps a multi-statement simple-query message" behavior is CONFIRMED-BY-READING of PostgreSQL's own documented protocol semantics — it is not determined by anything in this Go codebase, and I did not execute a database to observe it directly, so I'm not calling it CONFIRMED-BY-MEASUREMENT. The concrete witness that would upgrade it: take a scratch copy of `0001_init.up.sql`, inject a deliberate syntax error as, say, the 6th statement, run `Migrator.Up()` against a throwaway Postgres, then print (a) `SELECT * FROM information_schema.tables WHERE table_schema='public'` (expect: empty) and (b) `SELECT * FROM schema_migrations` (expect: `1, true`) — directly buildable as an addition to `migrate_integration_test.go`, and not present in the new suite today (the closest existing test, `TestMigrate_ForceClearsDirty`, *simulates* dirty via a hand-written `UPDATE schema_migrations SET dirty = true`, at `migrate_integration_test.go:961-964` — it never causes a real mid-file failure, so it cannot see this).

---

## CHECKED CLEAN

- **Advisory lock ID is deterministic and cross-process** (`database/util.go:13-19`) — not a per-process random value, so the lock genuinely coordinates across replicas when contention windows are short. 
- **`Up`/`Down`/`Steps`/`Migrate`(Goto)/`Force` all correctly wrap their work in `m.lock()`/`m.unlock()`** (`migrate.go:212-379`, module) — the doc's claim that the mechanism exists is directionally true; only the durational/timeout assumption is wrong (Q1).
- **A crashed replica does not leave a stuck lock** — `pg_advisory_lock` is session-scoped and Postgres releases it when the session ends; nothing in this code needs to (or does) handle that specially.
- **`ErrShortLimit` swallowing in `Steps`** (both directions) is intentional and has direct test coverage (`migrate_test.go` integration suite, `TestMigrate_StepsForwardAndBack`) — not a defect, and I'm not double-charging it alongside the real `fs.ErrNotExist`/origin-B defect in Q2.
- **`PendingAfter`'s gap-counting arithmetic** (counting the set rather than `head - version`) is correct and has direct unit coverage (`migrate_test.go:66-109`) including the exact ahead-of-head case (line 99) — the defect is downstream in `printStatus`'s missing cross-check, not in `PendingAfter` itself.
- **`Migrator.Close`'s nil-instance guard** (`migrate.go:82-86`) is load-bearing, not defensive filler: `(*sql.DB).Close()` on a nil receiver would panic (`db.mu.Lock()` dereferences `db`), and the source-only `Migrator{src: ...}` construction used by `Versions`/`Head`/`PendingAfter` (and by `migrate_test.go`) genuinely leaves both `m` and `sqlDB` nil. Correctly guarded, and matches the test's own comment.
- **The "belt-and-braces" `sqlDB.Close()` double-close comment** (`migrate.go:78-80`) is factually accurate — verified directly against `$GOROOT/src/database/sql/sql.go:926-931`'s idempotency guard.
- **Boot path (`cmd/relay` → `RunUp`) has zero observable behavior change** — see Q5 in full above.
- **A genuine mid-migration SQL failure is never mistaken for one of the three `Steps` sentinels** — `runMigrations` (`migrate.go:744-746`) returns the raw driver error immediately, which is not `ErrNoChange`, not `ErrShortLimit`, and not `fs.ErrNotExist`, so it always surfaces as a real error through every `Migrator` verb including `Steps`.
- **`errors.As(err, &short)` / `errors.Is(err, fs.ErrNotExist)` usage in `Migrator.Steps`** is mechanically correct Go (value-type error wrapped correctly, `os.ErrNotExist`/`fs.ErrNotExist` confirmed to be the literal same value in the stdlib) — the defect in Q2 is a classification/scope gap in the source library's error taxonomy that studio's code inherits, not a bug in how studio uses `errors.As`/`errors.Is`.

## Reading vs. execution — summary

Everything above is a reading of the pinned commit's diff, the two full files at both SHAs, and the exact-version module sources (`golang-migrate/migrate/v4@v4.19.1`, `jackc/pgx/v5@v5.9.2`) plus one stdlib fact (`database/sql`). No build, `go vet`, `go test`, or database was run, per the task's constraints. Each finding above states the specific executable witness that would move it from CONFIRMED-BY-READING to CONFIRMED-BY-MEASUREMENT; none of those witnesses exist in the current test suite (`migrate_test.go`, `migrate_integration_test.go`) — all four load-bearing findings (Q1 lock-timeout/hang, Q2 Steps-swallows-foreign-version, Q4 Force(0) trap, Q6 mid-file rollback vs. dirty-flag) are reachable through paths the new 465-line integration suite does not exercise.
