# Test DESIGN review, read-only. Do not modify any file.

_Gate lens on collab@fdc4a7a, 2026-09-10. Source transcript: byfjyf12b.output_

# Test Design Review — commit fdc4a7a (base ab130be)

Scope actually reviewed: `server/internal/db/migrate.go`, `server/internal/db/migrate_test.go` (6 arms: 4 pre-existing + 2 new — confirmed against `git diff ab130be fdc4a7a`), `server/internal/db/migrate_integration_test.go` (7 arms, new file), plus `server/cmd/collab-migrate/main.go`, `server/Makefile`, `server/docker-compose.yml`, `server/Dockerfile`, and `.github/workflows/build.yml` (needed to answer B honestly). Repo is `spirefyio/collab`; `server/` is a Go module with no wiring into the repo's Zig-only CI. Several claims below were settled by actually running `go build`, `go vet`, and `go test` against this checkout (Postgres itself unavailable in this sandbox, so the 6 DB-gated arms could not be executed to completion — everything else was).

---

## A. Every test arm — what it catches, whether it can fail

### migrate_test.go (no DB)

| # | Arm | Concrete input → wrong output it catches | Can fail? | Verdict |
|---|---|---|---|---|
|1| `TestRunUp_RejectsEmptyURL` (L11-16, pre-existing) | `RunUp("", …)`; catches the `url == ""` guard (`migrate.go:46-48`) being deleted or its message changed | Yes | ARMOR |
|2| `TestRunUp_HandlesUnreachableDB` (L18-23, pre-existing) | `RunUp` against `192.0.2.1` (TEST-NET-1, RFC 5737 — deterministically unroutable); catches `NewMigrator`/`RunUp` swallowing a connect failure | Yes, but coarse (`err != nil` only) | ARMOR, weak — see E |
|3| `TestMigrationsFS_IncludesUpAndDown` (L25-45, pre-existing) | Real `migrations.FS`; catches the `//go:embed` pattern in `embed.go` narrowing to exclude `.sql`, or the naming convention drifting | Yes | ARMOR |
|4| `TestRunUp_AcceptsCustomFS` (L47-59, pre-existing) | Claims to validate "composes correctly with an arbitrary fs.FS" | **Cannot fail for the claimed reason** — see E | **FALSE CONFIDENCE** |
|5| `TestVersions_CountsTheSetNotTheArithmetic` (L66-109, **new**) | Gapped set `{1,5}`; catches `PendingAfter` regressing to `head-version` arithmetic (5,4,0,-4 instead of 2,1,0,0) — a named, real historical incident (`collab-migrate version` against a set missing 0002) | Yes, hand-verifiable | ARMOR — highest-value unit arm |
|6| `TestVersions_EmptySet` (L111-134, **new**) | Empty `fstest.MapFS{}`; catches the `errors.Is(err, fs.ErrNotExist)` empty-set branch (`migrate.go:200-202`) breaking | Yes | ARMOR, distinct blind spot from #5 |

**Executed** (`go test ./internal/db/... -run . -v`, no `COLLAB_TEST_DATABASE_URL`): all 6 of these PASS. `go vet ./...` clean.

### migrate_integration_test.go (7 arms, all new)

| # | Arm | Concrete input → wrong output it catches | Can fail? |
|---|---|---|---|
|7| `TestMigrate_UpCreatesSchemaAndRecordsVersion` (L154-190) | Fresh DB; catches a 0001 statement that's silently a no-op, a wrong recorded version, or `dirty=true` left after a clean apply. Oracle (`tablesIn0001`, L36-43) is hand-written and independently verified by me against `0001_init.up.sql` — it matches exactly the 6 `CREATE TABLE`s — and it queries Postgres's own `information_schema.tables`, not anything `Migrator` computes. Non-circular. | Yes |
|8| `TestMigrate_UpIsIdempotent` (L195-226) | Second `Up()`, then a third call via the free function `RunUp` (the actual boot-path entry point); catches the `ErrNoChange` swallow (`migrate.go:99`) breaking — named consequence: "every restart after the first into exit code 2" | Yes |
|9| `TestMigrate_DownThenUpRoundTrips` (L233-261) | `Up→Down→assert empty→Up` again; catches `.down.sql` leaving tables behind. Bonus: I confirmed `0001_init.down.sql` also drops the `team_role` ENUM TYPE — if it didn't, the second `Up()`'s `CREATE TYPE` would itself fail, so this arm transitively also guards the type, not just the 6 tables it explicitly checks. | Yes — highest-value arm in the file |
|10| `TestMigrate_StepsForwardAndBack` (L266-327) | Forward/back steps, `Steps(0)` rejection, and over-stepping in both directions **asserting the landed VERSION**, not just nil-error. I read the pinned `golang-migrate v4.19.1` source (`readUp`/`readDown`/`runMigrations`, `migrate.go:532-610,632-700,723-767` in the dependency) and confirmed `ErrShortLimit` is only enqueued *after* every discovered migration has already been synchronously applied by `runMigrations` — so this assertion measures real, verified library behavior, not a guess. | Yes |
|11| `TestMigrate_ForceClearsDirty` (L333-386) | Hand-set `dirty=true` via direct SQL (a legitimate shortcut to a real production state — a real partial-failure would set the same flag); catches `Up()` not refusing a dirty schema, the refusal losing the word "dirty", or `Force` not clearing dirty/restoring version | Yes |
|12| `TestMigrate_GotoWalksBothWays` (L391-423) | `Goto(head)` then `Goto(0)`; catches `Goto`'s `v==0→Down()` delegation breaking | Yes, but see D — its own doc-comment ("fails if goto cannot reach a version it has *already passed*") is not actually demonstrated: the test never returns to a version it previously left (0→head→0 only, never 0→head→0→head) |
|13| `TestHead_MatchesMigrationSet` (L425-450) | **Not DB-gated at all** — runs unconditionally. Independent filename parser (`migrationFileVersion`, L452-465) vs. `mg.Head()` against the *real* embedded FS, not a synthetic one. Can fail if a future migration file's name parses under the test's loose regex but not under `iofs`/`DefaultParse`. | Yes in principle; today, trivially true (only one migration exists, so `maxOnDisk==head==1` — not vacuous, just currently low-yield) |

**Executed**: `go test ./cmd/... -v` confirms `cmd/collab-migrate [no test files]`. The 6 DB-gated arms above could not be run here (no Postgres in this sandbox) — their correctness is CONFIRMED-BY-READING against `migrate.go` and the pinned `golang-migrate`/`pgx` sources, not by execution. Running `make test-integration` would upgrade all six to CONFIRMED-BY-MEASUREMENT.

---

## B. Is the suite vacuous when `COLLAB_TEST_DATABASE_URL` is never set?

**Measured**, not just read: I ran the suite with the var unset.

```
--- SKIP: TestMigrate_UpCreatesSchemaAndRecordsVersion
--- SKIP: TestMigrate_UpIsIdempotent
--- SKIP: TestMigrate_DownThenUpRoundTrips
--- SKIP: TestMigrate_StepsForwardAndBack
--- SKIP: TestMigrate_ForceClearsDirty
--- SKIP: TestMigrate_GotoWalksBothWays
--- PASS: TestHead_MatchesMigrationSet
```

So: **6 of 7 are vacuous** in that environment (honest skip, with a message naming the fix). One (`TestHead_MatchesMigrationSet`) is not — small, real, unconditional signal.

**The mitigation** ("fails, doesn't skip, when the URL is set-but-unreachable") — I built the executable witness rather than trust the comment:

```
COLLAB_TEST_DATABASE_URL='postgres://user:pass@192.0.2.1:5432/db?...' go test -run TestMigrate_UpCreatesSchemaAndRecordsVersion -v
--- FAIL: TestMigrate_UpCreatesSchemaAndRecordsVersion
    migrate_integration_test.go:155: COLLAB_TEST_DATABASE_URL is set but unreachable (postgres://user:xxxxx@192.0.2.1:5432/postgres?...): dial error: timeout
```

CONFIRMED-BY-MEASUREMENT: it genuinely fails, not skips, and `url.Redacted()` correctly masks the password in the failure message. This mitigation is **sufficient for its own narrow target** — a CI job that sets the var but races/misconfigures Postgres cannot get a silent green.

It is **not sufficient for, and doesn't address, the actual question asked**: an environment that never sets the var at all bypasses `Ping()` entirely (`t.Skip` fires first). I checked whether *this repo's own CI* is such an environment:

- `HIGH` (pre-existing, not introduced by this diff — `git diff ab130be fdc4a7a -- .github/` is empty) — **`.github/workflows/build.yml` never runs any Go test at all**, gated or not. It is `workflow_dispatch`-only (manual), and its entire body is `zig build` / `zig build test`; it never touches `server/`, never runs `go test`, `make test`, or `make test-integration`, and never sets `COLLAB_TEST_DATABASE_URL`. So today, in this repo's only configured automation, not just the 6 new DB-gated arms but the *entire Go test suite* — including the fast, no-DB `migrate_test.go` arms — never executes automatically. I'm stating this as context essential to answering B honestly, not as a defect of commit fdc4a7a itself.

**What would make the skip safe**: (1) an automated (on-push/PR) trigger that runs `make test-integration` for changes under `server/`, since none exists today even for `go test ./...` bare; (2) a CI-side sentinel that greps test output for `--- SKIP` when the env var *should* be set and fails the build if any integration arm skipped — closing the loop the other direction, so a broken compose stack in CI reads as red, not as "ran clean." Until either exists, `make test-integration` is running only when a human remembers to type it.

---

## C. Test independence

Read `newTestDB` (L61-111) and `openMigrator` (L119-131) directly rather than trusting the header comment.

- **Own-DB claim**: CONFIRMED-BY-READING. `newTestDB` always administers via a *separate* connection to `/postgres` (the maintenance DB) and returns a DSN pointed at a freshly `CREATE DATABASE`d `collab_mig_test_<12 hex>` name; `openMigrator` connects only to that DSN. No arm ever opens a connection to the URL's original path, so the "never touches the dev database" claim holds.
- **Cleanup ordering**: `t.Cleanup` runs LIFO (confirmed from the exact installed Go source, `testing.go:1293-1295`: *"Cleanup functions will be called in last added, first called order"*). Since `openMigrator`'s `mg.Close()` cleanup is registered *after* `newTestDB`'s `DROP DATABASE …WITH (FORCE)` cleanup, `Close()` runs first — connections are released before the drop is attempted. Correct order, and `WITH (FORCE)` (Postgres 13+) is belt-and-braces on top of that.
- **No `t.Parallel()` anywhere** — sequential execution, so no arm can race another's throwaway DB. Confirmed by grep.
- **Panic mid-test — built an executable witness** (not just read Go's source) rather than assert from memory:

```go
func TestA(t *testing.T) {
    t.Cleanup(func() { println("CLEANUP-A-RAN") })
    var p *int
    _ = *p // nil deref
}
func TestB(t *testing.T) { println("B: ran") }
```
```
A: about to panic
CLEANUP-A-RAN
--- FAIL: TestA (panic: nil pointer dereference [recovered, repanicked])
FAIL
```
`TestB` **never printed** — the process crashed and no further test in the binary ran.

CONFIRMED-BY-MEASUREMENT, and it answers the question precisely: if any integration arm panics (as opposed to `t.Fatal`), that arm's *own* `t.Cleanup` (DB drop, migrator close) still runs — no leak from the panicking test itself — but the whole `go test` binary then dies, so every arm ordered after it in the same run silently never executes. This is generic Go behavior, not a defect this diff introduced, but it does mean the file's "order-independent" claim (L31) is true only in the narrow sense of "no arm depends on another's leftover state" — it is not true in the sense of "one arm's failure mode can't prevent another from running." Worth knowing before reading a partial CI log as "the rest passed."

`LOW`: nothing sweeps orphaned `collab_mig_test_*` databases left by a *harder* kill than a Go panic (SIGKILL, OOM-kill, power loss) — `t.Cleanup` never runs in that case. Operational hygiene gap, not a bug in the tests reviewed.

---

## D. Coverage gaps — named, specific

**`HIGH` — `cmd/collab-migrate/main.go` (332 new lines) has zero tests.** Measured: `go test ./cmd/... -v` → `[no test files]`. This is not a peripheral tool — the Dockerfile diff ships it into the production runtime image as the *only* recovery path for a dirty production schema (its own comment: "a failed migration in production would need a separate image to recover from" without it). Specifically unexercised:
- Every destructive-confirmation gate: `down-all` without `-yes` (main.go:130-131), `goto 0` without `-yes` (146-147), `force` without `-yes` (162-163). These are the entire safety net against an operator accidentally wiping data — none has a test.
- The doc-commented safety property "no default database URL" (main.go:15-17, enforced at 83-85) — a one-line, DB-free, trivial-to-write regression test (`run([]string{"version"}, "", false, "")` expects an error) that nobody wrote. A future PR could add a hardcoded fallback URL and nothing would catch it.
- `create()` (L230-305): name-collision-across-versions detection, filename numbering-from-disk, overwrite refusal — meaningfully complex, pure, file-only logic (no DB needed, trivially testable with `t.TempDir()`), completely unverified.
- `positiveInt`, `printStatus`'s `ErrNoVersion→0/false` branch, unknown-command handling — all untested.

**`MED` — `Migrator.Down()`'s idempotent/no-op path is never exercised.** Every arm that calls `Down()` (directly or via `Goto(0)`) calls it exactly once, from an at-head schema. Nothing calls `Down()` a second time (or on an already-empty schema) to verify the `ErrNoChange` swallow at `migrate.go:109`. Unlike `Up()`'s idempotency, which has a dedicated arm (`TestMigrate_UpIsIdempotent`), there is no `TestMigrate_DownIsIdempotent`. Since the CLI's `down-all` is meant to be safely re-runnable, this asymmetry is worth closing.

**`MED` — the real-error (`default:`) branches of `Steps`, `Goto`, and `Force` are never hit.** `migrate.go:141-143` (Steps), `152-154` (Goto), `178-180` (Force) each format-and-return a genuine failure — the exact signal an operator needs when something actually broke. Only `Up()`'s equivalent branch is exercised (via the dirty-schema refusal in arm #11). Concretely untested: `Steps`/`Goto` called against a dirty schema, or `Goto` to a version number that doesn't exist in the set (`goto 999` — a plausible operator typo, since the CLI takes an arbitrary `uint64`).

**`MED` — `RunUp` (the actual boot-time entry point `cmd/relay` calls) is never proven against a *fresh* real database end-to-end.** It's tested against an unreachable/malformed URL (unit) and against an *already-migrated* DB for idempotency (arm #8's third call). The "first-ever deploy, empty DB, `RunUp` creates the schema" scenario — arguably the single most important behavior for this function — is only verified via `Migrator.Up()` called directly (arm #7), not via `RunUp` itself, which has its own construction/teardown per call.

**`LOW`** — `Force()` is only exercised restoring to the version already correct, never to a version other than the one bookkeeping showed dirty at (the more realistic "operator inspected and decided it's actually N-1" recovery case). `Migrator.Close()`'s real error-formatting branch (`migrate.go:89-91`, `srcErr`/`dbErr` both non-nil) is never forced. `TestMigrate_GotoWalksBothWays`'s own doc-comment overclaims relative to what it demonstrates (see A#12) — will self-resolve once a second migration exists. `TestVersions_EmptySet` doesn't call `mg.Close()` the way its sibling arm does (harmless today — nothing was ever opened — but inconsistent). The `admin.Path = "/postgres"` assumption and `DROP DATABASE …WITH (FORCE)` (Postgres 13+ syntax) are undocumented preconditions on `COLLAB_TEST_DATABASE_URL`'s target server — fine for the shipped `postgres:16-alpine` compose stack, would break silently-into-Fatalf on an exotic managed Postgres lacking the default maintenance DB or predating v13.

---

## E. `TestRunUp_HandlesUnreachableDB` vs. `TestRunUp_AcceptsCustomFS`

**`MED` finding, CONFIRMED-BY-READING against the exact pinned dependency source** (`go.mod` pins `golang-migrate/migrate/v4 v4.19.1`; I read it from the local module cache, not from memory):

- `NewMigrator` (`migrate.go:45-74`) calls `iofs.New(migrationsFS, ".")` **first**, then `sql.Open` (lazy, never dials), then `migratepgx.WithInstance(sqlDB, …)`.
- `iofs.New`/`Init` (`source/iofs/iofs.go:47-73`) is a generic `fs.ReadDir` walk — it treats `fstest.MapFS` and `embed.FS` identically, and the test's `0002_noop.{up,down}.sql` pair parses under `source.DefaultParse` without issue.
- `migratepgx.WithInstance` (`database/pgx/v5/pgx.go:71`) is where the real network attempt happens: `instance.Ping()`.

So both tests fail at the *identical* line, for the *identical* reason (dial timeout to `192.0.2.1`), and in both cases `iofs.New` has already silently succeeded by the time that happens. The assertion in both (`err == nil → t.Fatal`) is satisfied identically whether the custom FS "composed correctly and failed downstream" or (hypothetically) failed to compose at all — **the test cannot distinguish those two outcomes**, so its own comment's claim ("Validates that the function composes correctly with an arbitrary fs.FS") is not actually what the assertion checks. It reconfirms arm #2's exact finding through a fixture that never gets to matter.

**Verdict: `TestRunUp_AcceptsCustomFS` adds nothing arm #2 doesn't already provide, and could pass for the wrong reason** (rules 1 "duplicate blind spot" and "wrong-reason pass" both apply). To make it real, it would need either a reachable throwaway DB (assert the custom migration actually applies — `Version()==2`) or, at minimum, an assertion on the error's *kind* (e.g. contains "pgx"/"dial"/"timeout") so an `iofs`-level regression would fail with a visibly different message instead of being absorbed into the same generic "err != nil."

---

## Findings by severity

| Sev | Finding | Location |
|---|---|---|
| HIGH | `cmd/collab-migrate` has zero tests, including every destructive-confirmation gate and the "no default URL" safety property, despite shipping in the production image | `server/cmd/collab-migrate/main.go` (whole file); measured via `go test ./cmd/...` |
| HIGH | No automated trigger runs any Go test (gated or not) for `server/` — `.github/workflows/build.yml` is manual-only and Zig-only. Pre-existing, not introduced by fdc4a7a, but decisive for B | `.github/workflows/build.yml` (unchanged by this diff) |
| MED | `TestRunUp_AcceptsCustomFS` duplicates `TestRunUp_HandlesUnreachableDB`'s blind spot and can't verify what its comment claims | `server/internal/db/migrate_test.go:47-59` |
| MED | `Migrator.Down()`'s `ErrNoChange`-swallow (idempotent Down) never exercised | `server/internal/db/migrate.go:108-113` |
| MED | Real-error branches of `Steps`/`Goto`/`Force` (dirty schema, nonexistent target version) never exercised | `migrate.go:141-143,152-154,178-180` |
| MED | `RunUp` never proven end-to-end against a fresh (never-migrated) real database | `migrate.go:255-262`; closest proxy is `migrate_integration_test.go:154-190` (calls `Up()` directly, not `RunUp`) |
| LOW | `Force()` only tested restoring to the already-correct version; `Close()` error-format branch unforced; `Goto` round-trip test doesn't demonstrate returning to a previously-departed non-zero version; hardcoded `/postgres` + PG13 `WITH (FORCE)` preconditions undocumented; no reaper for orphaned test DBs after a hard kill; `TestVersions_EmptySet` skips the `Close()` call its sibling makes | various, see D |

---

## CHECKED CLEAN

- `tablesIn0001` (`migrate_integration_test.go:36-43`) verified byte-for-byte against `0001_init.up.sql` — exactly the 6 created tables, no more, no less. Non-circular oracle (queries `information_schema.tables`, not anything `Migrator` computes).
- The over-stepping assertions in `TestMigrate_StepsForwardAndBack` (checking landed *version*, not just nil-error) are measuring real, verified `golang-migrate v4.19.1` behavior — confirmed by reading `readUp`/`readDown`/`runMigrations` in the pinned dependency: `ErrShortLimit` is only ever enqueued after every discoverable migration has already been synchronously applied by the consumer.
- `TestMigrate_DownThenUpRoundTrips` transitively also protects the `team_role` ENUM TYPE cleanup (not just the 6 tables it explicitly checks), because a leftover type would make the second `Up()`'s `CREATE TYPE` fail outright.
- `newTestDB`/`openMigrator`/`t.Cleanup` ordering (LIFO, confirmed against Go's own `testing.go`) is correct: migrator closes before the database drop is attempted; `WITH (FORCE)` on top of that; `url.Redacted()` correctly masks the password in every failure message I saw, including the one I generated myself.
- The "source-only `Migrator{src: …}`" construction used by the two new unit arms and `TestHead_MatchesMigrationSet` is not false confidence: I checked whether any production caller ever builds a Migrator this way (`grep -rn "Migrator{"` across `server/`) — none does; `cmd/collab-migrate` always goes through `NewMigrator`. But `Versions`/`Head`/`PendingAfter` read *only* `mg.src`, never `mg.m`/`mg.sqlDB` — the code path executed is byte-identical regardless of construction method, so the shortcut carries no divergence risk. `Close()`'s nil-tolerant branch this relies on is itself correctly guarded (`migrate.go:82-85`) and genuinely exercised.
- `go build ./...` and `go vet ./...` clean at fdc4a7a. All 13 no-DB-required arms across both files pass when actually executed.
- The set-but-unreachable "fail, don't skip" mitigation is real, not just claimed: reproduced with a live `go test` run against `192.0.2.1`, got `--- FAIL`, not `--- SKIP`.
- Panic-mid-test behavior (a registered `t.Cleanup` still fires; the rest of the binary's tests do not run) was verified with a throwaway executable witness, not asserted from memory of Go's testing internals.

**What further execution would settle**: running `make test-integration` (or equivalently standing up a disposable Postgres and setting `COLLAB_TEST_DATABASE_URL`) would upgrade all 6 DB-gated arms from CONFIRMED-BY-READING to CONFIRMED-BY-MEASUREMENT — I could not do that in this sandbox (no Postgres available). Everything else above was executed, not merely read.
