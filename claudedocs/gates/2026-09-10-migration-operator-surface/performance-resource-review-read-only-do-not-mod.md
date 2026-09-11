# Performance/resource review, read-only. Do not modify any file.

_Gate lens on collab@fdc4a7a, 2026-09-10. Source transcript: a1a8bc8865cef2dde.output_

## Lens applicability

**Does not apply, by the stated criteria — and the evidence confirms it rather than assuming it.** Migration code here runs exactly once at boot (`cmd/relay` calls `db.RunUp` synchronously, to completion, before `NewPool` is ever called — `server/cmd/relay/main.go:63-65`) or is invoked by hand/deploy-script through `collab-migrate` (one `*Migrator` per process). No hot path exists in this diff, no data structure over 1KB/instance is built (`Migrator` is three pointer-sized fields; the parsed migration index today holds exactly **1** version), nothing approaches 1000 instances (at most one `*Migrator`, one `*sql.DB`, one migration index per invocation), and there's no clone/copy path (`*Migrator` is passed by pointer everywhere in both `migrate.go` and `main.go`). What follows is measurement against the four named questions, not a lens-driven hunt for hot-path-shaped findings that boot/operator code structurally can't have.

All four items below were settled with an executed, printed measurement (real Postgres via `postgres:16-alpine` in Docker, real cross-compiled binaries with the Dockerfile's exact build flags, real vendored golang-migrate v4.19.1 source), not by reading alone. Work happened in a disposable copy under scratchpad — the pinned worktree at `fdc4a7a` was never written to (`git status` clean, `HEAD` unchanged, verified after all measurement work).

## Item 1 — repeated `iofs` walk (`migrate.go:192-248`, `cmd/collab-migrate/main.go:175-206`)

**Disposition: CONFIRMED-BY-MEASUREMENT — noise, at the actual N and at the review's own stated growth ceiling.**

Actual N today: **1** migration version, 2 files (`server/migrations/0001_init.{up,down}.sql`). `printStatus` calls `Head()` (→`Versions()`) then `PendingAfter()` (→`Versions()`) — two independent `iofs.New` + full-source walks per CLI status print, exactly as the brief describes (the third verb, `Version()`, hits the database, not the source driver, so it isn't a third walk).

Benchmarked the actual code path against the real embedded `migrations.FS` and against synthetic `fstest.MapFS` sets at increasing size (`go test -bench`, Apple M3, `benchtime` capped at 500-2000 iterations):

| N (versions) | `Versions()` | `Head()`+`PendingAfter()` combined |
|---|---|---|
| 1 (real) | 3.1 µs | 4.1 µs |
| 10 | 33 µs | — |
| 24 | 66 µs | — |
| 50 | 146 µs | — |
| 100 | ~490-580 µs | — |
| 300 | 4.19 ms | — |
| 1000 | 53.2 ms | — |

At N=1 and through the brief's stated growth ceiling ("dozens", N≈10-50), the doubled walk costs 4µs-0.3ms total — 2-4 orders of magnitude below a single Postgres round trip (which the same `printStatus` call already pays, for `Version()`) and below Go process-startup cost. Not a real cost at any scale this system is described as reaching.

**Separate, non-actionable observation, reported because I measured it and it's real, not because it clears a bar:** the growth above N=100 is not linear — read the vendored source to find why. `iofs.New`→`PartialDriver.Init` (`.../migrate/v4@v4.19.1/source/iofs/iofs.go:49-80`) calls `source.Migrations.Append` once per file; `Append` (`.../source/migration.go:48-66`) unconditionally calls `buildIndex()` (`:68-76`), which **rebuilds and re-sorts the entire version index from the map on every single insert**. That's O(n² log n) construction in the number of distinct versions — library-internal, not code this diff wrote, but this diff's `Versions()` pays that full reconstruction fresh on every call, and `printStatus` triggers it twice (a third, separate construction happens inside `NewMigrator` at `main.go:87` for the actual migrate instance). The 100→1000 measurement (10x → ~91-108x time) is consistent with that mechanism, not with linear scaling. It only becomes perceptible (tens-to-~150ms) around N≈300-1000, which is 6-20x past "dozens" and has no named workload driving toward it. **No fix recommended** — memoizing the walk or patching the dependency would be exactly the speculative optimization the brief asks me not to manufacture.

## Item 2 — connection/handle lifetime, boot path (`migrate.go:41-93,250-262`)

**Disposition: CONFIRMED-BY-MEASUREMENT — no leak, no change in lifetime versus ab130be.**

Diffed `ab130be`→`fdc4a7a` line-for-line. Old `RunUp`: `sql.Open` + immediate `defer sqlDB.Close()`, then `WithInstance`, then `defer m.Close()`, all in one function. New: `NewMigrator` opens `sqlDB` and closes it explicitly on the two post-open error branches (`migrate.go:60-66,68-72`); `RunUp` is now `NewMigrator` + `defer mg.Close()` + `mg.Up()`. Traced every branch: identical release behavior and identical LIFO close order (`m.Close()` before `sqlDB.Close()`) on both sides — this is a refactor, not a lifetime change. `cmd/relay` calls `RunUp` to completion (including its deferred `Close`) before `NewPool` opens the runtime pool (`server/cmd/relay/main.go:63-65`), so there's no overlap between the migrator's connection and the runtime pool either before or after this diff.

Then ran an executed witness against a live Postgres, reusing the exact boot-path function:

- 500 successful `RunUp` calls in a loop: open-FD count 10→13, goroutines 2→2. (4.54s total, ~9ms/call.)
- 20 `RunUp` calls against a guaranteed-unroutable DSN (`192.0.2.1`, forces `NewMigrator`'s error-return branches): FD count 13→13, zero growth.

Also checked the DB-side state, since "leak" isn't only client-side handles: `migratepgx`'s `ensureVersionTable` takes a Postgres advisory lock and releases it via `defer` **within that same function call** (`.../database/pgx/v5/pgx.go:434-441`) — it is never held across the `Migrator`'s lifetime, so there's no cross-call lock leak to worry about even on a path that skips `driver.Close()`.

## Item 3 — integration test cost (`migrate_integration_test.go`)

**Disposition: CONFIRMED-BY-MEASUREMENT — reasonable, and one correction to the framing.**

Correction: the file has 7 test functions, but only **6** call `newTestDB` (CREATE DATABASE + migrate + DROP DATABASE): `TestMigrate_UpCreatesSchemaAndRecordsVersion`, `UpIsIdempotent`, `DownThenUpRoundTrips`, `StepsForwardAndBack`, `ForceClearsDirty`, `GotoWalksBothWays`. The 7th, `TestHead_MatchesMigrationSet` (`:425-450`), builds a source-only `&Migrator{src: migrations.FS}` and never touches a database at all.

Measured against a real `postgres:16-alpine` container (loopback), 3 consecutive `-count=1` runs of the full file: **0.900s, 0.952s, 0.962s**. Verbose per-test breakdown from an earlier run: the 6 real-DB arms ran 0.06s-0.15s each; the 7th ran in 0.00s. The schema being applied is small (90-line `.up.sql`, 6 `CREATE TABLE`s, 7-line `.down.sql`), and Postgres `CREATE`/`DROP DATABASE` against a fresh cluster are metadata-only operations, which is why each round trip stays under 150ms.

Under 1 second, measured, for the only place (per the file's own doc-comment) that ever runs `0001_init.down.sql` against a real engine at all. Even a generous 3-5x CI-overhead multiplier lands at 3-5s — not competitive for "slowest thing in CI" against a Docker image build and two Go binary compiles in the same pipeline.

## Item 4 — Docker image size delta (`Dockerfile:29-36,45`)

**Disposition: CONFIRMED-BY-MEASUREMENT — measurable, and immaterial to this deployment story.**

Confirmed the diff is exactly one added `RUN go build ... -o /out/collab-migrate` and one added `COPY --from=builder /out/collab-migrate ...` — nothing else in the file changed. Built both binaries with the Dockerfile's exact flags (`CGO_ENABLED=0`, `-trimpath`, `-ldflags="-s -w ..."`), cross-compiled to `linux/amd64` (the realistic CI/registry target):

- `collab-server`: 14,979,234 bytes raw / 5,408,134 bytes gzip -9
- `collab-migrate`: 9,699,490 bytes raw / **3,446,793 bytes gzip -9**

Most of `collab-migrate`'s size is the dependency set (`pgx`, `golang-migrate`, `database/sql`) it shares with `collab-server`, which was already being linked into the image before this diff (`RunUp` existed pre-`ab130be` too) — this is a second static binary, not a second copy of a previously-absent dependency tree. Also measured the build-time side of "does this matter": a cold build of `cmd/relay` (empty `GOCACHE`) took 5.6s wall; the immediately-following build of `cmd/collab-migrate` against the now-warm cache — exactly what the Dockerfile's second sequential `RUN` layer experiences — took **0.23s**, because it shares nearly its entire dependency graph with the already-compiled `cmd/relay` and only compiles ~330 lines of CLI-unique code plus link.

~3.4MB compressed image growth and ~0.2s added build time don't matter for a persistent, `HEALTHCHECK`-gated, long-lived container service (this Dockerfile's own shape — not a FaaS/cold-start-per-invocation deployment).

## CHECKED CLEAN

- `Migrator` struct shape and ownership (`migrate.go:35-39`) — three small fields, no oversized or cloned data.
- Resource release on every `NewMigrator`/`RunUp` error branch, happy path and failure path alike — measured zero FD/goroutine growth over 500 successful and 20 failing calls.
- Advisory-lock lifetime in the vendored pgx driver — acquired and released within one function call, never held across `Migrator`'s lifetime.
- Boot-path connection sequencing (`RunUp` before `NewPool` in `cmd/relay`) — no overlap, unchanged from before `ab130be`.
- `Steps`/`Goto`/`Force`/`Version` (`migrate.go:129-182`) — single golang-migrate call each, no loops, no buffers, nothing scaling with anything.
- `collab-migrate create` (`main.go:230-305`) — one `os.ReadDir` over the source migrations directory (developer-machine-invoked, file count in the single digits today), two small file writes. Not a runtime path.
- Integration-test harness (`newTestDB`, `tableExists`) — one admin connection per test, closed via `t.Cleanup`/`defer`; no pooling or connection accumulation across the 6 arms.
