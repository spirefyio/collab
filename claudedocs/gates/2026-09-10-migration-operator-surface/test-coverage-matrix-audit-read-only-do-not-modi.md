# Test COVERAGE MATRIX audit, read-only. Do not modify any file. You MAY

_Gate lens on collab@fdc4a7a, 2026-09-10. Source transcript: a9c0b209e708a2494.output_

Everything has been cleaned up (no leaked databases, pinned worktree untouched — confirmed clean at `fdc4a7a`). Here is the full audit.

---

# Coverage Matrix Audit — `server/internal/db/migrate.go` + `server/cmd/collab-migrate/main.go`

**Commit:** `fdc4a7a` (base `ab130be`). Worktree confirmed untouched throughout (`git status --porcelain` empty at end). All live-fire verification below was done against disposable databases I created and dropped myself (`coverage_audit_*`), or against a separate mutated **copy** of the tree in scratchpad — never the pinned worktree — plus one direct build to a scratchpad binary. Zero files in the pinned worktree were modified.

Base commit had only a monolithic `RunUp`; this commit adds `Migrator` (9 new methods) and the entire `cmd/collab-migrate` binary (332 new lines, previously did not exist).

## Matrix 1 — `server/internal/db/migrate.go` symbols

| Symbol | Covered by (file:line) | Would FAIL if broken? | Gap |
|---|---|---|---|
| `ErrNoVersion` (23) | migrate_integration_test.go:166,249,284,319,415 (`errors.Is(err, ErrNoVersion)`) | YES — if the re-export diverged from `migrate.ErrNilVersion`, the very first assertion in `TestMigrate_UpCreatesSchemaAndRecordsVersion` (166) fails | Integration-only; no unit-level test in isolation (fine, it's a one-line alias) |
| `Migrator` struct / `src`-only construction | migrate_test.go:73,112; migrate_integration_test.go:442 (`&Migrator{src: ...}`) | Partial — pins the `src` field name/type only | `m`/`sqlDB` fields only exercised via `NewMigrator` |
| `NewMigrator` (45-75) | migrate_test.go:12,19,55 (url="" / unreachable DB / custom FS); migrate_integration_test.go:121 via `openMigrator`, called by all 6 integration tests | YES for: empty-URL guard (46-48); driver-init failure (60-66, confirmed below to be `migratepgx.WithInstance`'s internal `Ping()`); full success path | NOT exercised: `iofs.New` failure (50-53), `sql.Open` failure (55-58), `migrate.NewWithInstance` failure (68-72) — see Part A |
| `(mg *Migrator) Close()` (81-93) | migrate_test.go:74 (`defer mg.Close()` on a **source-only**, `m==nil` Migrator — hits the nil-guard 82-85 directly); migrate_integration_test.go:126 (`t.Cleanup`) on every real Migrator | YES for the nil-guard (a broken guard nil-derefs, panicking that test) | The **error-return branch** (89-91, `srcErr != nil \|\| dbErr != nil`) is never forced by any test, and note: `main.go`'s only caller (`defer mg.Close()`, line 91) discards this return value entirely regardless |
| `(mg *Migrator) Up()` (98-103) | UpCreatesSchemaAndRecordsVersion:170, UpIsIdempotent:199+207 (ErrNoChange-swallow), ForceClearsDirty:364 (real-error/dirty-refusal), DownThenUpRoundTrips:237,253 | YES, strongly — success, no-op, and real-error paths all independently asserted | None material |
| `(mg *Migrator) Down()` (108-113) | DownThenUpRoundTrips:240 (success, head→empty); GotoWalksBothWays:412 exercises it indirectly via `Goto(0)` | Partial — success path solid | The ErrNoChange-swallow arm (Down on an *already-empty* schema) and the wrapped-real-error arm (Down against dirty) are never independently tested — asymmetric with `Up`, which has both. Verified correct **by reading** the identical dirty-guard in golang-migrate's `Down()`/`Up()`/`Migrate()`/`Steps()` (all share the same `lock→Version→dirty check` shape) — not independently live-fired for `Down()` specifically |
| `(mg *Migrator) Steps(n int)` (129-144) | StepsForwardAndBack: n==0 (288), +1 from empty (270), -1 to empty (281), ErrShortLimit both directions (301,316) | YES for those 4 arms | The **`fs.ErrNotExist` swallow arm** (count==0: `up 1` a second time already at head, or any `down N` on a never-migrated DB) has **NO automated coverage at all** — confirmed by mutation (see Finding H-1). Also the `default:` real-error branch (Steps against dirty) untested by suite though live-verified correct |
| `(mg *Migrator) Goto(v uint)` (148-156) | GotoWalksBothWays: Goto(head) from empty (400), Goto(0)→Down() (412) | YES for those two | The `v>0`, real-error/ErrNoChange branch (152) has no automated coverage — live-verified correct (`goto 999` on a healthy DB refuses loudly, no partial effect) but zero regression protection |
| `(mg *Migrator) Version()` (164-170) | Used in every integration test (UpCreates…, UpIsIdempotent, DownThenUp, StepsForwardAndBack, ForceClearsDirty, GotoWalksBothWays) | YES, thoroughly, for both ErrNoVersion and plain paths | The non-ErrNoVersion real-error passthrough (166-168) is never exercised (needs e.g. mid-session connection loss) |
| `(mg *Migrator) Force(v int)` (177-182) | ForceClearsDirty:370 — Force to the exact, correct, already-applied version | YES for that one success path | **The error-wrap branch (178-180) has zero automated coverage.** Live-verified reachable and correctly wrapped (`force -2` → golang-migrate's `version must be >= -1`). More importantly: **Force performs no validation that `v` corresponds to any real migration** — this is Finding H-2 below, HIGH severity |
| `(mg *Migrator) Versions()` (192-218) | CountsTheSetNotTheArithmetic (gapped {1,5}), EmptySet, HeadMatchesMigrationSet (real embedded set) | YES, strongly, for 3 shapes | `iofs.New` failure (194-196) and the `src.First()`/`src.Next()` genuine-error branches (203-205, 212-214) — distinct from the plain "empty set" `fs.ErrNotExist` path, which IS tested — are unexercised; would need a colliding-version fixture |
| `(mg *Migrator) Head()` (222-228) | CountsTheSetNotTheArithmetic:84, EmptySet:120, HeadMatchesMigrationSet:443, + implicit in StepsForwardAndBack/GotoWalksBothWays | YES, strongly | Inherits `Versions()`'s gaps only |
| `(mg *Migrator) PendingAfter(uint)` (236-248) | CountsTheSetNotTheArithmetic:101 (4 sub-cases: 0,1,5,9 — this is the test that pins the exact historical regression named in the doc comment), EmptySet:127 | YES, specifically pinned against the "count not arithmetic" regression | None material for the function itself; its only consumer, `printStatus`, is untested (main.go gap, not this function's) |
| `RunUp(url, fs)` (255-262) | migrate_test.go:12,19,55; migrate_integration_test.go:223 (the actual `cmd/relay` boot call, asserted idempotent against a real DB) | YES, thoroughly | None material |

## Matrix 2 — `server/cmd/collab-migrate/main.go` (zero test files exist)

**No automated test reaches any row below.** "Live probe" = I built the real binary and drove it against disposable Postgres databases this session; this is manual verification, not regression protection — nothing catches a future break here.

| Path | Automated test | Live probe result | Verdict |
|---|---|---|---|
| No args → usage+exit(2) (58-62) | NONE | Correct: prints full usage to stderr, exit 2 | CHECKED CLEAN (untested) |
| Unknown command (170-171) | NONE | Message correct **when DB is reachable**; when DB is unreachable, a real connection attempt (with timeout) happens *first* — see Finding M-1 | PARTIAL — correct text, wrong ordering |
| Missing URL (83-85) | NONE | Correct, instant, no DB dial (this check IS ordered before `NewMigrator`) | CHECKED CLEAN |
| `version`/`status` (94-95, printStatus 175-206) | NONE | Correct output shapes for empty / clean / dirty; dirty WARNING correctly split to stderr | CHECKED CLEAN for output — but see Finding M-3 (exit code) |
| `up` (0 args) (99-102) | NONE | Correct | CHECKED CLEAN |
| `up n` (103-110) | NONE | Correct for valid n; **the boundary case "n ≥ available, already at head" is the untested `fs.ErrNotExist` arm from Matrix 1** | CHECKED CLEAN today, no safety net (Finding H-1) |
| `up` bad arg count (111-113) | NONE | Correct, but gated behind a DB dial when URL is unreachable (Finding M-1) | PARTIAL |
| `up abc` / `up 0` (positiveInt, 208-216) | NONE | Correct messages for non-numeric and non-positive | CHECKED CLEAN |
| `down n` (116-127) | NONE | Correct for valid n | CHECKED CLEAN |
| `down` bad arg count / non-numeric / zero (117-123) | NONE | Correct, same DB-dial-first caveat as `up` | PARTIAL |
| `down-all` without `-yes` (130-132) | NONE | Correct on a reachable DB; DB-dial-first caveat when unreachable | PARTIAL |
| `down-all -yes` (133-136) | NONE (delegates to `Migrator.Down()`, which IS integration-tested) | — | CHECKED CLEAN |
| `goto v` bad arg count / non-numeric (139-145) | NONE | Correct | CHECKED CLEAN |
| `goto 0` without `-yes` (146-148) | NONE | Correct, live-verified on reachable DB | CHECKED CLEAN |
| `goto v` to a version not in the set | NONE | Live-verified: refuses loudly, no partial effect | CHECKED CLEAN (untested) |
| `force v` bad arg count / non-numeric (155-160) | NONE | Correct | CHECKED CLEAN |
| `force` without `-yes` (162-164) | NONE | Correct, live-verified on reachable DB | CHECKED CLEAN |
| `force v -yes` where v doesn't match reality | NONE | **Live-verified to produce a false-healthy status (v too high) or an actively DIRTY schema (v too low, then `up`).** Finding H-2 | REAL GAP, HIGH |
| `create name` validation, numbering, collision (230-274) | NONE | All correct: bad-name regex (3 variants), ReadDir failure, numbering bump, duplicate-name collision, WriteFile failure (tested via chmod 555 dir) | CHECKED CLEAN (untested) |
| `create` with flags placed *after* the subcommand | NONE | **Silently misparses** — Go's stdlib `flag` stops at the first non-flag token, so `-dir X` after `create name` is swallowed as extra positional args, producing the generic "requires exactly one name" error. Fails safe (no wrong-directory write) but the message doesn't hint at the real cause | REAL GAP, MED (Finding M-2) |
| `create` Stat-preexistence branch (268-274, "already exists") | NONE | Not independently reachable in single-process use — the duplicate-name substring check (258-262) already catches same-name-any-version, including the freshly computed one. Only a genuine TOCTOU race between two concurrent `create` invocations reaches it | Effectively dead in single-process use; legitimate (if narrow) concurrency guard, not a bug |

## Part A — Unreached error returns

**`migrate.go`:** unreached by any automated test:
- `iofs.New` failure inside `NewMigrator` (52) and `Versions` (195) — same mechanism, both sites. Reachable via a genuine duplicate-version-number migration pair (confirmed by reading `iofs.PartialDriver.Init`, which returns `source.ErrDuplicateMigration` when two files parse to the same version+direction). No fixture exercises this.
- `sql.Open` failure inside `NewMigrator` (57) — plausible only for a syntactically-malformed DSN; all current tests use well-formed-but-unreachable URLs, which fail one level deeper at `Ping()` instead.
- `migrate.NewWithInstance` failure inside `NewMigrator` (71).
- `Close()`'s error-wrap (90) — nothing forces `mg.m.Close()` to fail, and the sole caller (main.go:91) discards the value anyway.
- `Down()`'s error-wrap (110) for a genuine non-ErrNoChange error (e.g., dirty schema) — `Up()` has this exact arm tested; `Down()` doesn't.
- `Steps()`'s `default:` wrap (142) for a genuine error (e.g., dirty schema via `Steps`) — live-verified correct, not test-covered.
- `Goto()`'s error-wrap (153) for a real error/nonexistent version — live-verified correct, not test-covered.
- `Version()`'s real-error passthrough (167).
- `Force()`'s error-wrap (179) — live-verified reachable and correct (`force -2`), not test-covered.
- `Versions()`'s `src.First()`/`src.Next()` genuine-error branches (204, 213), distinct from the tested `fs.ErrNotExist`/empty-set path.

**`main.go`:** every error return in the file is unreached by automated test (zero test files). Live-probe verdicts are in Matrix 2 above; the two real defects found (Finding H-2, M-1, M-2, M-3) are listed below, not repeated here.

## Part B — `cmd/collab-migrate` has no test file: what's untested, ranked

Ranked by what would actually break in an operator's hands (highest first):

1. **The DB-connection-before-argument-validation ordering** (Finding M-1). Every non-`create` command calls `db.NewMigrator(url, ...)` — a real network dial with driver `Ping()` — *before* `run()`'s switch validates the command name, argument count, or `-yes` confirmation. Verified live: `down-all` without `-yes` against an unreachable URL burns a full ~1s connection timeout and returns a scary connection error instead of the instant, correct "re-run with -yes" guardrail; identically for `force`, `goto`, and unknown-command typos. This specifically degrades the safety net at the moment it's most likely to matter (DB flaky/unreachable during an incident is disproportionately when someone reaches for this tool). **Worth extracting and testing**: validate `cmd` against the known verb set and check arg shapes *before* calling `NewMigrator`; that fix is pure logic, trivially unit-testable without a DB.

2. **`Force` accepts any version with zero validation against the real migration set** (Finding H-2, detailed below). This is the tool's designated recovery verb; a plausible fat-finger converts a healthy schema into a lying-healthy or actively DIRTY one. **Worth extracting and testing**: `Force` (or the CLI's `force` case) should at minimum warn when `v` isn't in `mg.Versions()` and isn't `0`/`-1`.

3. **`create`'s flag-after-subcommand footgun** (Finding M-2). Fails safe but confusingly. Low cost to add a table-driven test once the misparse is understood; more valuably, worth a one-line usage-string fix.

4. **`printStatus`'s three-way branch (empty/clean/dirty) and the WARNING text** — genuine presentation logic, currently untestable without a live DB because `printStatus(mg *db.Migrator)` takes the **concrete type**, not an interface. Introducing a tiny `interface{ Head()...; Version()...; PendingAfter()... }` seam would make this cheaply unit-testable with a fake. Worth extracting.

5. **`positiveInt` and `create`'s name-regex/numbering/collision logic** — pure functions/filesystem logic, zero DB dependency, currently in `package main` (which Go allows `_test.go` files in directly — no extraction even required). This is the cheapest, highest-value gap to close: a `main_test.go` with table-driven cases costs almost nothing and directly covers the numbering-bump and duplicate-detection invariants I verified by hand.

**Thin plumbing where a test would be ballast**: `main()`'s flag registration and `os.Exit` calls (re-tests the stdlib), `usage()`'s static string (re-tests copy, not logic), the `version`/`status` two-label alias in the switch, and the package-level `nameRe`/`migrationFileRe` declarations (already exercised through `create`'s behavior). None of these have independent logic worth isolating.

## Part C — Test suite runs (verbatim summary)

Postgres confirmed reachable and running (`collab-postgres` container, healthy, port 5432) before running.

```
cd <worktree>/server
go test -count=1 ./...
```
Result: **all packages `ok`**, 0 failures.
- `acl` 11 pass · `api` 12 pass · `auth` 13 pass · `config` 5 pass · `db` **10 pass + 6 SKIP** · `relay` 7 pass
- `cmd/collab-migrate`, `cmd/relay`, `migrations`: `[no test files]`
- **Totals: 59 PASS, 6 SKIP, 0 FAIL**
- Skipped, all in `internal/db`, all with the identical reason `COLLAB_TEST_DATABASE_URL unset — run 'make test-integration'...`:
  `TestMigrate_UpCreatesSchemaAndRecordsVersion`, `TestMigrate_UpIsIdempotent`, `TestMigrate_DownThenUpRoundTrips`, `TestMigrate_StepsForwardAndBack`, `TestMigrate_ForceClearsDirty`, `TestMigrate_GotoWalksBothWays`

```
COLLAB_TEST_DATABASE_URL="postgres://collab:collab@127.0.0.1:5432/collab?sslmode=disable" go test -count=1 ./...
```
Database was reachable — this is a real run, not a skip. Result: **all packages `ok`**, 0 failures, 0 skips.
- Same package breakdown, but `db` now **16 pass, 0 skip** (the 6 above all ran and passed).
- **Totals: 65 PASS, 0 SKIP, 0 FAIL.**
- Verified no side effects on the dev database: `SELECT datname FROM pg_database WHERE datname LIKE 'collab_mig_test_%'` → 0 rows, both before and after — each test's throwaway database was created and dropped as designed.

## Part D — Diff between the two runs

Exactly six tests differ, and only these six — a clean `diff` of the two `--- PASS/SKIP` line sets shows precisely:

```
TestMigrate_DownThenUpRoundTrips        SKIP → PASS
TestMigrate_ForceClearsDirty            SKIP → PASS
TestMigrate_GotoWalksBothWays           SKIP → PASS
TestMigrate_StepsForwardAndBack         SKIP → PASS
TestMigrate_UpCreatesSchemaAndRecordsVersion  SKIP → PASS
TestMigrate_UpIsIdempotent              SKIP → PASS
```

That set **is** the integration suite. Nothing else in the repo changes between the two runs. I grepped the whole `server/` tree for `t.Skip`/`testing.Short`/`SkipNow`: the single call site above (migrate_integration_test.go:49) is the *only* skip mechanism in the codebase, and it correctly un-skips when the DB is present (0 skips in run 2) — nothing silently skips in both runs.

## Findings (severity, each with a named, verified defect)

**HIGH — H-1: `Migrator.Steps`'s `fs.ErrNotExist`-swallow arm has zero coverage, confirmed by mutation.** I copied the tree to a private scratchpad location (never the pinned worktree), removed the `errors.Is(err, fs.ErrNotExist)` case from `Steps`'s switch, and reran **both** forms of the full suite: **65/65 tests still pass.** I then built the mutant CLI and ran `up 1` on a database already at head: real code → `version: 1, head: 1, pending: 0`, exit 0 (correct, silent no-op); mutant → `collab-migrate: migrate steps 1: file does not exist`, exit 1. Same result for `down 1` on a never-migrated database (an even more mundane operator action than the `up` case). **Disposition: CONFIRMED-BY-MEASUREMENT.** A future "cleanup" of that switch statement (plausible — it looks redundant with the `ErrShortLimit` case next to it) would break idempotent `up N`/`down N` at exactly the boundary conditions real deploy scripts hit, and the entire test suite would stay green.

**HIGH — H-2: `Force` performs no validation against the real migration set; a wrong version produces either a false-healthy status or an actively DIRTY schema.** Live-verified three ways against disposable databases: (a) `force 999 -yes` on a never-migrated DB → `version`/`status` (the primary health-check command) reports `pending: 0, dirty: false` — a false all-clear — while the real schema (`accounts`, `teams`, etc.) was never created; a subsequent full `up` *does* fail loudly here (`no migration found for version 999`), which **refutes** my initial worry that this wedges silently forever — but the operator has no reason to run `up` again after being told `pending: 0`. (b) `force -1 -yes` on a DB that already has migration 1 fully applied → status again claims "none (empty database)" while the real tables remain; running `up` afterward now **fails mid-migration with a real SQL error** (`relation "accounts" already exists`) and **leaves the schema DIRTY** — a healthy database converted into the exact "worse than dirty" state the function's own doc comment warns about, self-inflicted by the recovery verb itself. **Disposition: CONFIRMED-BY-MEASUREMENT** for both symptoms; **PARTIAL/REFUTED** for my initial "silently wedges forever" hypothesis specifically for the too-high-version sub-case. `TestMigrate_ForceClearsDirty` only ever forces to the one version known to be correct, so none of this is caught.

**MED — M-1: every argument/confirmation check for every non-`create` subcommand is gated behind a live DB connection.** Confirmed generally, not just for "unknown command": `down-all`, `force`, and `goto` all attempt a full `NewMigrator` dial (measured ~1.0s timeout against an unreachable host) before their own `-yes`/arg-count checks run. Not a safety bypass (the checks still fire correctly once connected) — but it means a usage mistake against an unreachable/misconfigured URL produces a misleading network-looking error instead of the instant, correct guardrail, in exactly the moment (DB trouble) an operator is likely to be reaching for this tool.

**MED — M-2: `create`'s flags must precede the subcommand, and violating that fails with a misleading message.** `collab-migrate create name -dir X` (a very natural ordering) is silently misparsed by Go's stdlib `flag` package (which stops parsing at the first non-flag token) into three positional args to `create`, producing the generic "requires exactly one name" error — which doesn't hint that the real issue is flag placement. Fails safe (confirmed: no file is written to an unintended directory), but confusing.

**MED — M-3: `version`/`status` always exits 0, even when the schema is dirty.** Verified live: exit code is 0 regardless of `dirty: true/false`; only the stderr WARNING text distinguishes the states. Any monitoring/automation that gates on exit code alone (a common ops pattern) gets a false-healthy signal from the one command whose job is to report health.

**LOW — remaining unreached arms** (Down vs Up dirty-refusal asymmetry; `Goto`/`Version`/`Close`/`Versions` real-error branches; `sql.Open`/`iofs.New` failure branches; `create`'s Stat-preexistence race guard): all either verified-correct-by-reading (identical mechanism to a tested sibling) or require exotic/low-probability conditions (malformed FS, concurrent races, mid-session connection loss). Named in Part A/Matrix 1 for completeness; none independently ship a concrete operator-facing defect beyond what's already captured above.

## CHECKED CLEAN

Symbols/paths with a real arm that would fail if broken, or live-verified-correct behavior even where untested:; `NewMigrator` (empty-URL + driver-init-failure + success), `Close` (nil-guard), `Up` (success + idempotent + dirty-refusal), `Down` (success path), `Steps` (n==0, ±1, both ErrShortLimit directions), `Goto` (both directions tested; untested-but-correct for nonexistent-version), `Version` (ErrNoVersion + plain, exhaustively), `Force` (correct success path; correct error-wrap and correct `<-1` rejection live-verified though untested), `Versions`/`Head`/`PendingAfter` (the historical arithmetic-regression is directly pinned), `RunUp` (all four shapes). On the CLI side: usage/no-args, missing-URL, all `positiveInt` messages, all bare argument-count/non-numeric checks for up/down/goto/force, all three `-yes` confirmation guards (`down-all`, `goto 0`, `force`), `create`'s name-regex/ReadDir-failure/numbering-bump/duplicate-collision/WriteFile-failure, and the dirty-schema stdout/stderr split — all live-verified correct today, none of it automated, all of it one refactor away from a silent regression.
