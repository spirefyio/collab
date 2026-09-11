# SIBLING-BUG-CLASS HUNT, read-only. Do not modify any file.

_Gate lens on collab@fdc4a7a, 2026-09-10. Source transcript: a271ec18ac1ffcccd.output_

## Sibling-Bug-Class Hunt — server/ Go tree, commit fdc4a7a (base ab130be)

**Repo identity confirmed**: worktree HEAD = `fdc4a7a77cd924455d085c70f058ef6abb4ce0f4`, parent = `ab130be88f788a4e35a1b2d1c45fc7025400662f`, clean tree, remote `git@github.com:spirefyio/collab.git`. This is the **collab** repo; `server/` is its only Go module (`github.com/spirefyio/collab/server`, single `go.mod`, no `vendor/`). `go build ./...` and `go vet ./...` both pass clean at this SHA — read-only, nothing modified.

**Tree size**: 25 `.go` files total — 15 non-test, 10 test. I read all 15 non-test files in full and grepped all 25 (including tests) for both defect shapes.

---

### CLASS 1 — errors.Is against a struct-typed error

**Method**: enumerated every `errors.Is(` and `errors.As(` call in `server/**/*.go` (`grep -rn "errors\.Is(\|errors\.As("`, 25 files covered, zero excluded). For each target, read the actual declaration at the exact vendored version in `go.mod` (`golang-migrate/migrate/v4@v4.19.1`, `/Users/kevinduffey/go/pkg/mod/.../migrate.go`) to classify sentinel-value vs struct-type. Also grepped separately for `sql.Err`, `net.Err`, `net.OpError`, `.Timeout()`, `pgconn.`, `pgerrcode.` (zero hits) and for any bare `err ==`/`.(type)`/`.(*Type)` error comparisons that would be the same mistake via different syntax (zero hits beyond plain `err == nil`).

**Full site enumeration (16 total: 15 `errors.Is`, 1 `errors.As`)**:

| Site | Target | Type | Verdict |
|---|---|---|---|
| `cmd/collab-migrate/main.go:182` | `db.ErrNoVersion` | sentinel (`var ErrNoVersion = migrate.ErrNilVersion`, itself `errors.New("no migration")`) | safe |
| `cmd/collab-migrate/main.go:271` | `os.ErrNotExist` | sentinel (`= fs.ErrNotExist`, oserror.ErrNotExist) | safe |
| `cmd/relay/main.go:118` | `http.ErrServerClosed` | sentinel (`errors.New(...)`) | safe |
| `internal/db/migrate.go:99` (Up) | `migrate.ErrNoChange` | sentinel | safe |
| `internal/db/migrate.go:109` (Down) | `migrate.ErrNoChange` | sentinel | safe |
| `internal/db/migrate.go:137` (Steps switch) | `migrate.ErrNoChange` | sentinel | safe |
| `internal/db/migrate.go:139` (Steps switch) | `fs.ErrNotExist` | sentinel, wrapped in `*fs.PathError` by golang-migrate's iofs driver (`source/iofs/iofs.go`), `Unwrap()`-compatible | safe |
| `internal/db/migrate.go:152` (Goto) | `migrate.ErrNoChange` | sentinel | safe |
| `internal/db/migrate.go:200` (Versions/First) | `fs.ErrNotExist` | sentinel, same wrapping | safe |
| `internal/db/migrate.go:209` (Versions/Next loop) | `fs.ErrNotExist` | sentinel, same wrapping | safe |
| `internal/db/migrate.go:138` | `migrate.ErrShortLimit` via **errors.As**, `var short migrate.ErrShortLimit` | struct type, value-receiver `Error()` | **correct** — this is the fix itself |
| `internal/db/migrate_integration_test.go:166,249,284,319,415` (5 sites) | `ErrNoVersion` | sentinel | safe (test-only) |

Verified in the pinned dependency source (`migrate.go` lines 30-52 of golang-migrate v4.19.1):
```
ErrNoChange = errors.New("no change")        // sentinel
ErrNilVersion = errors.New("no migration")   // sentinel
ErrInvalidVersion = errors.New(...)          // sentinel, unreferenced by this repo
ErrLocked = errors.New(...)                  // sentinel, unreferenced by this repo
ErrLockTimeout = errors.New(...)             // sentinel, unreferenced by this repo
type ErrShortLimit struct{ Short uint }       // STRUCT, value-receiver Error()
type ErrDirty struct{ Version int }           // STRUCT, value-receiver Error()
```
`ErrDirty` — the other struct-typed sentinel the task called out by name — is never referenced anywhere in `server/` (confirmed by `grep -rn "ErrDirty"`, zero hits). Dirty-state handling goes exclusively through `Migrator.Version()`'s `dirty bool` return value, never through error-type inspection, so there is no site where the `ErrDirty` mistake *could* occur — it simply isn't reached by any code path.

**Dependency scope not yet applicable**: `pgconn.PgError`, `database/sql` sentinels (`sql.ErrNoRows`, etc.), and `net`/`net.OpError` are imported only for constructors (`sql.Open`, `pgxpool`) — zero error-type inspection against any of them exists yet, because the code that would need it (team/workspace CRUD, per commit message: "Real CRUD lands in a follow-up commit alongside the Postgres store," `internal/store/` is empty, `teamProbeHandler` is an explicit placeholder) hasn't been written. This is an absence-of-surface fact, not a defect — flagging only as a forward note: `pgconn.PgError` is itself a pointer-typed struct (`*pgconn.PgError`), so whoever writes that follow-up should use `errors.As`, not `errors.Is`, for unique-violation/FK-violation handling. Not reporting this as a found instance since no code exists to be wrong.

**CLASS 1 verdict: REFUTED for "other instances."** Disposition: CONFIRMED-BY-READING (exhaustive enumeration of every call site against the exact pinned dependency source; no witness needed because the claim is "no other site exists" over a closed, fully-enumerated set, not a behavior to execute). Every `errors.Is` in the tree targets a genuine `errors.New` sentinel; the one `errors.As` correctly targets the one struct type; the sibling struct (`ErrDirty`) is unreferenced everywhere.

---

### CLASS 2 — count/position derived by arithmetic over identifiers instead of counting the set

**Method**: read all 15 non-test files in full. Then ran repo-wide (all 25 files, tests included) structural greps: (1) `[ident] - [ident]` (subtraction between two names/expressions) — **zero hits in code**, only inside string literals/comments; (2) increment/addition patterns (`x++`, `a + b`) — every hit is either a genuine per-item counter over real iteration (`n++`, `forwarded++`, `dropped++` in a `for range` loop) or a compile-time constant (`1 << 20` byte-size literal), never two independent identifiers combined to fabricate a count; (3) `%`, `<<`, `>>`, `/`, and `make(..., computed-size)` — no positional/capacity arithmetic found beyond the one literal above.

Sites specifically evaluated against "are these identifiers guaranteed dense/contiguous":

| Site | What it computes | Why safe |
|---|---|---|
| `internal/db/migrate.go:236-248` `PendingAfter` | pending count | **This is the fixed site** — now iterates `Versions()` and counts members `v > version`, doesn't subtract. Regression-pinned by `TestVersions_CountsTheSetNotTheArithmetic` (`internal/db/migrate_test.go:66-109`), which asserts a `{1,5}` gapped set reports 2, not 4-5. |
| `internal/db/migrate.go:220-228` `Head` | highest version | `versions[len(versions)-1]` — index derived from the actual returned slice's own length, not from a separate identifier; slice is built by real traversal (`src.First()`/`src.Next()`), guaranteed ascending and complete. Safe. |
| `internal/relay/hub.go:86` `RoomCount` | active room count | `len(h.rooms)` — direct map length. Safe. |
| `internal/relay/hub.go:163,179` `Room.add`/`size` | peer count vs `maxPeers` capacity | `len(r.peers)` — direct map length under `r.mu`; `maxPeers` is a fixed config constant, not a derived value. Safe. |
| `internal/acl/enforcer.go:96-103` `Policies` | policy-slice copy | `make([][]string, len(src))` sized directly from the real slice being copied, filled by index over that same slice. Safe. |
| `cmd/collab-migrate/main.go:239-264` `create` | next migration version number | `next := highest+1` where `highest` is found by scanning **every** matching filename (a real max-scan, not an endpoint subtraction). Examined and judged **not an instance**: this derives a fresh unique successor id, not a count — correctness only requires `next > every existing version`, which holds regardless of gaps below `highest` (e.g. `{1,3}` → `next=4` is a valid unused id, not a miscount of "how many exist"). Different operation from `PendingAfter`'s bug even though both touch version numbers. |
| `internal/auth/jwt.go:107` `exp := now.Add(i.ttl)` | token expiry | Duration arithmetic on a single monotonic timestamp, not a count over a non-contiguous identifier set. Safe — different shape entirely. |
| `internal/relay/handler.go:65-66` `sanitizeQuotes` | byte-copy loop | Index `i` ranges `0..len(s)` over the *same* string being copied, not two different identifiers. Safe. |

No casbin policy-count arithmetic, no JWT-exp identifier-pair subtraction, no pagination/cursor math, no buffer-capacity arithmetic beyond fixed constants, no relay/hub peer-count arithmetic beyond direct map length exist anywhere in the tree — confirmed by the zero-hit subtraction grep across all 25 files, not just by inspection of the files above.

**CLASS 2 verdict: REFUTED for "other instances."** Disposition: CONFIRMED-BY-READING (full-file read of all non-test production code + a repo-wide structural grep for the operator shape itself, which returned zero code-level hits outside the one already-fixed site).

---

### Negative-result summary, stated at the width actually searched

- 25/25 `.go` files covered by the `errors.Is`/`errors.As` grep (no exclusions); 15/15 non-test files read in full; all 10 test files grepped for both patterns and the one integration test file inspected around every hit.
- Queries run: `errors\.Is\(` , `errors\.As\(`, `err ==`, `\.(type)`, `\.(\*`, `sql\.Err|net\.Err|net\.OpError|\.Timeout\(\)|pgconn\.|pgerrcode\.`, `ErrDirty|ErrLocked|ErrLockTimeout|ErrInvalidVersion|ErrShortLimit`, `[ident] - [ident]` (subtraction), `[ident]\+\+|[ident] \+ [ident]`, `%|<<|>>|/[0-9]|make\(...,computed\)` — each run against the full 25-file tree.
- `go build ./...` and `go vet ./...` both clean at fdc4a7a, confirming the tree I read is the tree that actually compiles (not reading around a syntax break).
- Both defects were fixed exactly once, at their one production call site each, with no sibling left open, and each fix is now regression-pinned by a test that fails if the fix regresses (`TestMigrate_StepsForwardAndBack` for Class 1 via `errors.As`; `TestVersions_CountsTheSetNotTheArithmetic` for Class 2).

**No new instances of either class exist in `server/` at fdc4a7a.** The two defects found during authorship were the only two of their shape in the tree; this is a real "fixed once, fixed everywhere" outcome rather than "fixed in the diff, left open elsewhere."

Files read in full (paths for reference, all under `/private/tmp/claude-501/-Users-kevinduffey-projects-studio/0fe929e6-fb12-463c-b8d9-2d22454974c9/scratchpad/gate-fdc4a7a/server/`): `cmd/relay/main.go`, `cmd/collab-migrate/main.go`, `internal/db/migrate.go`, `internal/db/pool.go`, `internal/acl/enforcer.go`, `internal/auth/jwt.go`, `internal/config/config.go`, `internal/api/{health,me,middleware,router,teams}.go`, `internal/relay/{hub,handler}.go`, `migrations/embed.go`, plus `internal/db/migrate_test.go` in full and `internal/db/migrate_integration_test.go` at each `errors.Is` hit.
