# CROSS-FILE duplication + decomposition review, read-only, own context.

_Gate lens on collab@fdc4a7a, 2026-09-10. Source transcript: a5e7efb8102987610.output_

## Cross-file duplication + decomposition review — commit `fdc4a7a` (base `ab130be`)

Reviewed read-only in the pinned worktree; no files modified. `HEAD` verified at `fdc4a7a77cd924455d085c70f058ef6abb4ce0f4`, working tree clean. Repo is `spirefyio/collab` (Go `server/` + Zig `src/`).

### Findings by severity

**HIGH — `down n` and `goto <nonzero>` are exempt from the confirmation gate the commit itself introduces, and today `down 1` has the identical blast radius as the gated `down-all`.**
`server/cmd/collab-migrate/main.go:116-127` (`case "down"`) has no `confirm` check at all — any `n` is accepted unconditionally, and `mg.Steps(-n)` runs real `.down.sql` files. `main.go:138-152` (`case "goto"`) only checks `confirm` when `v == 0`; `goto <nonzero v below current>` runs the same down-migrations unconfirmed. `server/internal/db/migrate.go:105-107` documents `Down` as "data loss by design; callers are expected to gate it behind explicit operator confirmation" — a standard `down`/`goto` (non-zero) do not meet. `server/migrations/0001_init.down.sql` is 7 `DROP TABLE/TYPE` statements. Because the migration set today has exactly one entry, `collab-migrate down 1` (or `make db-down N=1`, `server/Makefile:99-102`, itself ungated) drops every one of those 7 objects — byte-identical effect to `down-all` — with zero prompt, while `down-all` refuses without `-yes`. This isn't a future edge case; it's true the moment this ships. CONFIRMED-BY-READING (static; no DB executed, per the read-only scope of this review).

**MED — `make db-goto V=0` is unconditionally broken; the two "layers" named in the task disagree about this one verb.**
`server/Makefile:108-111` (`db-goto`) never reads `$(CONFIRM)` and never forwards `-yes`, unlike `db-down-all`/`db-force`/`db-reset` which all do. But the CLI's own `goto` handler refuses `v==0` without `-yes` (`main.go:146-148`). Result: no value of `CONFIRM` makes `make db-goto V=0` succeed — it always prints the CLI's refusal and exits 1. Fails closed (no data loss), but it's a shipped dead-end target with no documented workaround (neither README mentions calling `bin/collab-migrate -yes goto 0` directly). This is the concrete "disagreement about which verbs are destructive" the task asked to enumerate — see the full diff below.

**LOW — pre-existing (not introduced here) duplicate empty-URL check, now joined by a third differently-worded copy.**
`server/internal/db/pool.go:32-34` and `server/internal/db/migrate.go:46-48` both do `if url == "" { return nil, errors.New("database url is required") }`, byte-identical. `git diff ab130be fdc4a7a -- server/internal/db/migrate.go` shows this check already existed verbatim inside the old `RunUp` at `ab130be` — this commit only *relocated* it into `NewMigrator`, so the pool.go/migrate.go duplication predates fdc4a7a and is carried forward unchanged, not newly introduced. What IS new: `server/cmd/collab-migrate/main.go:83-85` adds a third instance with a different message (`"no database URL: pass -url or set COLLAB_DATABASE_URL"`). All three reject exactly the same input (empty string only) — not divergent in effect, just triplicated in text, and the CLI's version is deliberately more actionable. Optional cheap fix: an unexported `requireURL` in package `db` for the two in-package copies; leave the CLI's copy separate (different audience, fires before any `db` call).

**LOW — hand-rolled `quoteIdent` in the test reimplements a function the already-imported pgx package ships.**
`server/internal/db/migrate_integration_test.go:115-117`:
```go
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
```
`github.com/jackc/pgx/v5` (v5.9.2, resolved in this exact module via `go list -m`, already imported indirectly through the stdlib driver) ships `pgx.Identifier{name}.Sanitize()`, verified via `go doc -src`:
```go
func (ident Identifier) Sanitize() string {
	parts := make([]string, len(ident))
	for i := range ident {
		s := strings.ReplaceAll(ident[i], string([]byte{0}), "")
		parts[i] = `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return strings.Join(parts, ".")
}
```
Same quoting, plus NUL-byte stripping the hand-rolled version lacks. Not exploitable at this call site today (input is always `hex.EncodeToString` of random bytes), but it's dependency-owned behavior that didn't need writing — this is the item-E finding.

**LOW / informational — two independent "version-from-filename" parsers; not a copy, and should stay independent.**
`migrationFileRe` in `main.go:224` (used by `create`, requires strict `NNNN_name.{up,down}.sql`) vs. `migrationFileVersion` in `migrate_integration_test.go:452-465` (naive prefix-before-`_` + `.sql` suffix, used only to independently cross-check `Migrator.Head()` in `TestHead_MatchesMigrationSet`). Different packages (`main` vs `db`), different algorithms, different purposes — neither is the authoritative parser (that's golang-migrate's own `iofs` source driver, which `Migrator.Versions()` already delegates to). Recommend **not** merging: the test's independent implementation is deliberate oracle diversity against the production path, matching this repo's own doctrine of not sharing a comparison with the thing it's checking. Noted only because a malformed filename would be classified differently by the two — zero live impact since neither feeds the authoritative version-accounting path.

**LOW, no action — the `CONFIRM=yes` gate is repeated 4× verbatim in the Makefile, all new in this commit.**
`server/Makefile:81,105,116,126` (`db-destroy`, `db-down-all`, `db-force`, `db-reset`) all use `@[ "$(CONFIRM)" = "yes" ] || { echo "refusing: ...."; exit 1; }`. Confirmed via `git diff ab130be fdc4a7a -- server/Makefile` that none of this Makefile content pre-existed — all four are new in this one commit, in one file. This clears "two real callers eligible" several times over, but I recommend leaving it: a shared `define`/`call` macro would create one point of failure across four independent destructive gates and would make each target less self-contained/greppable for an ops-facing Makefile. Not a divergence — all four instances are shape-identical.

---

### A. Prior art in this repo (per candidate)

| Symbol / mechanism | Disposition | Basis |
|---|---|---|
| `db.RunUp@migrate.go:255` | **EXTEND/CANONICALIZE** | Verified by diff: old `RunUp` body (url check + iofs + sql.Open + driver + `m.Up()`) was moved almost verbatim into `NewMigrator`+`Up()`; `RunUp` is now a 7-line wrapper. `cmd/relay/main.go` (not in the diff's changed-file list) calls it with an unchanged signature. |
| `migrations.FS@embed.go:8` | **REUSE** | `embed.go` untouched by this diff; both `RunUp` and the new CLI pass it through unchanged. |
| `docker-compose.yml` postgres service | **REUSE** | Diff to that file is a pure comment addition (verified: `git diff` shows only 9 added comment lines, the `postgres:` block itself untouched). |
| `if url == "" {...}` in `pool.go:32-34` | **NONE** (not reused, not extended — a sibling copy) | See LOW finding above; same invariant, same input set, pre-existing duplication carried forward. Genuinely eligible for a shared in-package helper (two real callers, same package) but low value given how trivial the check is. |
| `pgx.Identifier.Sanitize()` (`github.com/jackc/pgx/v5`) | **NONE** — should have been REUSE | See LOW finding above; verified present in the exact resolved dependency version via `go doc`. |
| golang-migrate `cmd/migrate` `create` subcommand | **JUSTIFIED-FORK** | Confirmed present in `github.com/golang-migrate/migrate/v4@v4.19.1/cmd/migrate` (README: `create [-ext E] [-dir D] [-seq] ...`), but it lives in `package main` (`cmd/migrate/main.go`) — not importable by another Go binary. Even disregarding that, this repo's `create()` adds duplicate-*name*-at-different-version detection golang-migrate's own `create` doesn't do. The commit message's own claim ("`create` derives its numbering from the directory rather than reimplementing a timestamp scheme") is accurate — the deliberate divergence (sequential vs. golang-migrate CLI's default timestamp scheme) matches this repo's existing `0001_init` convention. |
| golang-migrate `*migrate.Migrate` public API | **NONE needed / correct composition** | `Versions()`/`Head()`/`PendingAfter()` have no golang-migrate equivalent on `*migrate.Migrate` (only `Up/Down/Steps/Migrate/Force/Version/Close` exist there) — the new code correctly composes the library's own `source.Driver.First()/Next()` primitives rather than reimplementing something the library already exposes. |
| `errors.Is`/`errors.As` classification of `ErrShortLimit`/`fs.ErrNotExist` | **NONE — justified, no sibling** | Grepped whole `server/` tree: no other file classifies golang-migrate errors; this pattern exists nowhere else to converge with. |

### B. Divergent safety/validation invariant?

`pool.go` and `migrate.go` reject **the same set** of bad URLs (only the empty string) with **the same error shape** (`errors.New("database url is required")`, byte-identical) — not divergent, just duplicated, and pre-existing (see LOW finding). No scope/format/scheme validation exists in either, so there's nothing else to diverge on for URL validation specifically.

The **real** divergent-safety-copy finding is not the URL check — it's the confirmation-gate coverage (HIGH finding above): `down`/`goto-nonzero` and `down-all`/`force`/`goto-0` are both "run destructive SQL that empties/shrinks the schema," and the code splits them into a protected group and an unprotected group in a way that (for the current single-migration schema) produces identical outcomes with different gating.

### C. Confirmation gate — enumerated and diffed

**Makefile targets requiring `CONFIRM=yes`:** `db-destroy`, `db-down-all`, `db-force`, `db-reset`.
**Makefile targets NOT requiring it:** `db-start`, `db-stop`, `db-psql`, `db-version`, `db-up`, `db-down`, `db-goto`, `db-new`.

**CLI commands requiring `-yes`:** `down-all`, `force <any v>`, `goto 0`.
**CLI commands NOT requiring it:** `version`/`status`, `up [n]`, `down n` (any n), `goto v` (any nonzero v, including backward), `create`.

**Diff:**
- `down-all`, `force` — present and consistent in both lists; Makefile forwards `-yes` correctly. No divergence.
- `goto 0` — CLI treats as destructive; Makefile's `db-goto` is not in its own destructive list and never forwards `-yes` → **divergence** (MED finding above): the Makefile target for this verb can never succeed.
- `down n` / `goto <nonzero>` — **both layers agree to leave these ungated**, so it isn't a Makefile-vs-CLI disagreement, but it is a gap in the underlying policy both layers inherit (HIGH finding above): the CLI's own list of "verbs requiring confirmation" is under-inclusive relative to what actually causes irreversible data loss.

Both `migrations/README.md:81-82` and `server/README.md:97-98` describe the two gates as intentional ("hence the two confirmation gates") — so the overall two-layer design reads as **deliberate**, not an accidental copy-paste; the `goto 0` passthrough gap and the `down`/`goto-nonzero` coverage gap are the two concrete places that design is incomplete.

### D. Decomposition verdict, per file touched

- **`server/internal/db/migrate.go`** (262 lines) — right size and shape. One type (`Migrator`), one cohesive responsibility (construction/lifecycle, mutating verbs, read-only introspection over one golang-migrate instance). Most of the growth is documentation carrying invariants/measurements (armor, not bloat per this repo's own standard). No split proposed.
- **`server/cmd/collab-migrate/main.go`** (332 lines) — borderline; two responsibilities are visible: (1) dispatch + DB-connected operator verbs + `printStatus`, and (2) `create` + its two regexes, which is explicitly filesystem-only and runs *before* any URL is required. A split into `main.go` + `create.go` (same package) would isolate the one offline command from the DB-connected ones at near-zero cost (no behavior change, one more file). Not urgent — flagging as a LOW forward-looking note, not a defect; there is no second caller motivating it yet.
- **`server/internal/db/migrate_integration_test.go`** (465 lines) — right shape: single purpose (Migrator against a real Postgres), well-factored into named helpers + 7 tests. The pre-existing split from `migrate_test.go` (DB-less vs. real-DB) is itself a good decomposition, worth preserving as-is. Only a minor intra-file note: `sql.Open("pgx", dsn)` is opened ad hoc 4 times in this one file; a `mustOpen(t, dsn) *sql.DB` helper would trim boilerplate, but this is intra-file, not the cross-file duplication this review is scoped to.
- **`server/Makefile`** (128 lines total) — right size, well-sectioned (`----- database lifecycle -----`, `----- schema migrations -----`). No split needed.
- **`server/migrations/README.md`, `server/Dockerfile`, `server/docker-compose.yml`** — single-purpose additions, no issues.
- **`server/README.md`** — the migration section is additive and on-topic; the inline-dated "CORRECTION (2026-09-10)" about the REST surface is an unrelated but transparently-labeled fix bundled into the same file — acceptable for a docs file, not a code-decomposition concern.

### E. Should not have been written because a dependency already owns it

`quoteIdent` in `migrate_integration_test.go:115-117` — `pgx.Identifier{name}.Sanitize()` from the already-imported `github.com/jackc/pgx/v5` does the same thing and more (verified above). Everything else checked (`Versions`/`Head`/`PendingAfter`, the `ErrShortLimit` classification, `create`'s scaffolding) is either composing a library primitive that has no ready-made equivalent, or is forced to be reimplemented because golang-migrate's own version of it lives in a non-importable `package main`.

---

### CHECKED CLEAN

**Textual** — `grep -rniE` across `server/**.go`, `Makefile`, `*.md`, `*.yml` for: `migrat` (11 files, all expected — the changed set plus `pool.go`/`README.md`/`docker-compose.yml` via incidental comment mentions); `schema_version|dirty|rollback` outside the migrate files (zero hits); `\bversion\b` (confined to migrate files + `health.go`/`router.go`/`config.go`, which is unrelated build-version reporting, inspected and confirmed distinct); `errors.Is(|errors.As(` (4 files, all in-scope); `Ping(` (3 files — `pool.go`, `health.go`, the new integration test — inspected, three different purposes, no collision); `confirm|"-yes"|.Steps(|.Force(|.Goto(` across the **whole repo** including `src/*.zig`, `scripts/*.sh`, `.github/workflows/*` (zero hits outside `server/`, confirming no third confirmation-gate copy anywhere).

**Structural** — read `migrate.go` and `pool.go` in full side by side (URL-open patterns: `sql.Open` vs `pgxpool.ParseConfig`+`NewWithConfig`, confirmed different pgx entry points forced by golang-migrate's `*sql.DB` driver contract — JUSTIFIED-FORK, not a duplicate); diffed `ab130be..fdc4a7a` for `Makefile`, `migrate.go`, `docker-compose.yml` to separate new code from relocated/pre-existing code; compared the two filename-version parsers; compared the four `CONFIRM=yes` blocks and the four `-n "$(V)"`-style argument-required blocks in the Makefile.

**Semantic** — read `cmd/relay/main.go`, `internal/config/config.go`, `internal/api/health.go` in full to rule out a third URL-validation or status-printing site; confirmed `cmd/relay/main.go` and `pool.go`/`pool_test.go` are absent from this commit's changed-file list (`git diff --stat ab130be fdc4a7a`, 9 files); confirmed `go.mod`/`go.sum` diff is empty (no new dependency, matching the author's claim); resolved `github.com/jackc/pgx/v5` to the exact in-use version (v5.9.2) via `go list -m` and read `Identifier.Sanitize()` source via `go doc -src`; located the actual `golang-migrate/migrate/v4@v4.19.1` module in the local module cache and confirmed `cmd/migrate` contains no importable `create` helper (package main, no `create.go`) and its README-documented `create` flag set (`-seq`, timestamp default).

**Cross-language (Zig `src/`, 16 files)** — `grep -rniE 'migrat|schema_version|dirty.*schema|rollback'` returned exactly two hits, both inspected and confirmed unrelated: `protocol.zig:118` ("a future migration to a different signature suite" — crypto-suite versioning, not schema) and `manager.zig:3901` ("put-OOM rollback" — in-memory connection-slot state undo, not schema). `version` hits in `websocket.zig`/`crdt_lww_map.zig`/`protocol.zig`/`manager.zig` are exclusively the CRDT wire-protocol version (`pv:2`/`pv:3`/`pv:4`), a distinct concept from a Postgres `schema_migrations` version — confirmed no naming-consistency-tenet applicability and no duplication.

**What I did not exhaustively re-verify**: the untouched files `acl/enforcer.go`, `api/me.go`, `api/middleware.go`, `api/router.go`, `api/teams.go`, `auth/jwt.go`, `relay/handler.go`, `relay/hub.go` and their `_test.go` siblings were covered by the targeted greps above (all came back clean for the relevant terms) rather than full reads, since nothing in this diff touches them and no grep signal pointed there.
