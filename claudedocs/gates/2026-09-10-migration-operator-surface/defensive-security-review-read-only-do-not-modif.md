# DEFENSIVE security review, read-only. Do not modify any file. Do not r

_Gate lens on collab@fdc4a7a, 2026-09-10. Source transcript: a9ffdb6acc7b49881.output_

# Security Review — commit `fdc4a7a` (base `ab130be`), `server/` scope

Worktree: `/private/tmp/.../scratchpad/gate-fdc4a7a`, read-only, no builds run. Full contents read for every file in scope (`migrate.go` 262 lines, `main.go` 332 lines, `migrate_integration_test.go` 465 lines, `Makefile`, `Dockerfile`, `docker-compose.yml`, `migrations/README.md`, `server/README.md`, `0001_init.{up,down}.sql`, `embed.go`). Where the finding depends on a third-party library's error-formatting behavior, I read the actual vendored source at the exact pinned version (`pgx v5.9.2`, matching `go.mod`) rather than relying on memory, and cross-checked against Go stdlib source (local toolchain `go1.26.4`; project targets `go 1.25.0` — see caveat in Finding 2).

---

## FINDING 1 — HIGH — incomplete destructive-verb confirmation gating

**Where:** `server/cmd/collab-migrate/main.go:116-127` (`case "down"`) and `main.go:138-152` (`case "goto"`); mirrored at `server/Makefile:100-102` (`db-down`) and `Makefile:108-111` (`db-goto`).

**The gate that exists:** `down-all` (main.go:129-136) and `force` (main.go:154-168) both require `!confirm` → refuse without `-yes`, and the Makefile adds a second `CONFIRM=yes` check on top (`db-down-all`, `db-force`, `db-reset`, `db-destroy`). `goto 0` (main.go:146-148) also requires `-yes`, because it's documented as equivalent to `down-all`.

**The gap:** `down n` (any n) and `goto v` for `0 < v < current` have **no confirmation check at all** — not `-yes` at the CLI, not `CONFIRM=yes` at the Makefile. Both reach the same destructive code path as the gated verbs:
- `down n` → `Migrator.Steps(-n)` → `migrate.Migrate.Steps(-n)` → runs n `.down.sql` files.
- `goto v` (v>0, v<head) → `Migrator.Goto(v)` → `migrate.Migrate.Migrate(v)` → runs down migrations from head to v.

**Concrete input, current schema:** the migration set today is exactly one pair (`migrations/0001_init.{up,down}.sql` — confirmed by `ls migrations/`). `0001_init.down.sql` does `DROP TABLE IF EXISTS audit_log, invites, workspaces, team_members; DROP TYPE IF EXISTS team_role; DROP TABLE IF EXISTS teams, accounts;` — i.e. the entire schema. So **today**, `collab-migrate -url "$URL" down 1` (no `-yes`) — or `make db-down N=1` against whatever `$(DB_URL)`/`COLLAB_DATABASE_URL` resolves to, which the Makefile itself says may be "a staging or production database" — drops every table with **zero** confirmation prompt, in one command. This is byte-for-bit the same destructive effect as `down-all`/`goto 0`, which both require `-yes`.

The `goto v` (0<v<head) half of this is currently **latent** (no version exists strictly between 0 and 1 today) but is architecturally the same gap and will go live the moment a second migration ships (e.g. head=2: `goto 1` silently reverts migration 0002 with no confirmation).

**This contradicts the shipped documentation.** `server/README.md` (added in this diff) states: *"Destructive verbs are gated twice — `CONFIRM=yes` at the Makefile and `-yes` at the CLI"* — an unqualified claim covering all destructive verbs. It's true for `force`/`down-all`, false for `down n`/`goto v>0`. `server/docker-compose.yml`'s added comment even offers `docker compose run --rm --entrypoint collab-migrate server down 1` as the second example command in the whole file — i.e. the ungated path is the one actively taught to operators.

**Contributing fact:** `cmd/collab-migrate/` has no test file at all (`ls cmd/collab-migrate/` → only `main.go`). The confirmation logic in `run()` — the entire safety property this PR is supposed to deliver — has zero test coverage; nothing calls `run([]string{"down","1"}, url, false, dir)` and asserts refusal. That's consistent with how this gap could ship unnoticed alongside 465 lines of new integration tests that all test `Migrator` directly and bypass the CLI layer (the `migrate.go` doc comment says as much: "Destructive policy... lives at the CLI... so tests can tear down freely").

**Disposition:** CONFIRMED-BY-READING (I traced every case arm in `run()`, confirmed the migration set has one file, confirmed its down-SQL drops everything). Not CONFIRMED-BY-MEASUREMENT — I did not build or execute anything.

**What would settle it fully:** build the binary, `make db-start && make db-up`, then run `./bin/collab-migrate -url "$TEST_URL" down 1` *without* `-yes` and print whether it exits 0 and whether `tablesIn0001` still exist afterward. Expected result per the reading above: exit 0, tables gone.

---

## FINDING 2 — MEDIUM — credential leak on a malformed test-URL, one call site missing the redaction the sibling call site uses

**Where:** `server/internal/db/migrate_integration_test.go:65-67`

```go
u, err := url.Parse(raw)
if err != nil {
    t.Fatalf("COLLAB_TEST_DATABASE_URL is not a URL: %v", err)
}
```

vs. the correctly-redacted sibling four lines later (line 88): `t.Fatalf("...unreachable (%s): %v", admin.Redacted(), err)`.

**Concrete input:** `COLLAB_TEST_DATABASE_URL` set to a string `net/url.Parse` cannot parse — e.g. a password with an unescaped `%` (`postgres://collab:p%wd@host:5432/collab`) → `invalid URL escape "%wd"`.

**Wrong behavior:** I read Go's stdlib source (`net/url/url.go`, both local `go1.26.4` and this shape is unchanged across Go releases — see caveat below): `Parse` on failure returns `&Error{"parse", u, err}` where `u` is the **entire raw input, verbatim, password included** (only a `#fragment` is stripped first). `(*url.Error).Error()` is `fmt.Sprintf("%s %q: %s", e.Op, e.URL, e.Err)` — no redaction. So `t.Fatalf` at line 67 prints the full connection string, including the password, into the `go test`/`make test-integration` output — which is CI log output, typically readable by a broader audience than runtime error logs. The credential this exposes has CREATE/DROP DATABASE rights on the target server (that's what `newTestDB` requires it to have), so it's not a low-value secret.

I verified this is the *only* leak site, not a symptom of a wider pattern: every other DSN-touching failure in this diff and in `migrate.go`/`main.go` goes through the `pgx` driver, and I read the vendored `pgx v5.9.2` source (`pgconn/errors.go`, `pgconn/config.go`, `conn.go`, `stdlib/sql.go`) to confirm:
- `sql.Open("pgx", url)` **cannot fail on a bad DSN** — the pgx stdlib `Driver.OpenConnector` always returns a nil error; parsing is deferred to the first `Connect` (Ping/Exec/Query). So the `err != nil` branches at `migrate_integration_test.go:82` and `:95`, and in `NewMigrator`'s `sql.Open` check (`migrate.go:55-58`), are effectively dead for a malformed DSN.
- When parsing/connecting *does* fail (at first real use), it surfaces as `*pgconn.ParseConfigError` or `*pgconn.ConnectError`, and I confirmed both types self-redact: `ParseConfigError.Error()` calls `redactPW(e.ConnString)` before formatting; `ConnectError.Error()` only ever includes `user=%s database=%s` plus the low-level dial error, never the connection string.
- `*pgconn.PgError.Error()` (server-side SQL errors, e.g. from the `CREATE DATABASE`/`DROP DATABASE` execs) is `Severity + Message + SQLSTATE` only.

So `NewMigrator`, `openMigrator`, the `CREATE DATABASE`/`DROP DATABASE` exec failures, and every `Ping`/`Exec`/`QueryRow` failure elsewhere in this diff are safe by construction of the library, independent of whether the calling code remembers `.Redacted()`. Line 67 is the exception specifically because it calls Go's *own* `net/url.Parse`, not pgx's parser, and that type carries no such protection.

**Disposition:** CONFIRMED-BY-READING against pgx v5.9.2 source and Go stdlib source. Caveat: I read the stdlib at the locally-installed `go1.26.4`, while `go.mod` declares `go 1.25.0` and the Dockerfile builds with `golang:1.25-alpine` — I did not have that exact toolchain's source tree to diff, but `net/url.Error`'s format string has been in this shape for many Go release cycles with no security-motivated redaction ever added to it, so I have high confidence it applies unchanged, without treating that as a version-exact citation.

**What would settle it fully:** run `COLLAB_TEST_DATABASE_URL='postgres://collab:p%wd@localhost/collab' go test ./internal/db/... -run TestMigrate_UpCreatesSchemaAndRecordsVersion` and capture the literal failure text. Not run here (no builds).

---

## FINDING 3 — MEDIUM — database URL passed as a CLI argument in the Makefile (process-table exposure)

**Where:** `server/Makefile:93-117` — every `db-version`/`db-up`/`db-down`/`db-down-all`/`db-goto`/`db-force`/`db-reset` target does `$(MIGRATE) -url '$(DB_URL)' <verb>`.

**Is it real:** yes. `-url` becomes a literal argv element of the `collab-migrate` process for that process's entire runtime, and on POSIX systems argv is visible to *any* local user via `ps -ef`/`ps aux`/`/proc/<pid>/cmdline`, not just root or the owning UID. The Makefile's own comment says `DB_URL` "Honours `COLLAB_DATABASE_URL` when set so the same targets work against a staging or production database" — so this isn't confined to the hardcoded dev password; an operator pointing these targets at a real environment puts that credential in the process table for as long as the migration takes.

**Is there a safer form already available:** yes, and it's inconsistent with the rest of the same diff. `main.go:52` already defaults `-url` from `os.Getenv("COLLAB_DATABASE_URL")`, and the `test-integration` target two lines above (`Makefile:41-42`) already uses the safer shape: `COLLAB_TEST_DATABASE_URL='$(DB_URL)' $(GO) test ...` (env-var prefix, not a flag). The `db-*` targets could do the same — `COLLAB_DATABASE_URL='$(DB_URL)' $(MIGRATE) version` — and the CLI would pick it up via its existing default with no code change.

**Precision on how much this actually buys:** `make` executes each recipe line via `$(SHELL) -c "<recipe text>"`, so the substituted `$(DB_URL)` is present in *that* invocation's argv too, however briefly, regardless of which form is used — an env-var prefix doesn't erase that instant. What it *does* change: once `bash -c` execs into the final command (a tail-call, no fork, for a single simple command), the resulting process's argv is replaced. In the env-var form, that replacement leaves the secret only in `envp` (readable via `/proc/<pid>/environ`, restricted by default to the owning UID and root) for the entire runtime of the actual migrate process — which does the real (possibly multi-second) DB work. In the current `-url` form, the secret stays in argv (world-readable via `ps`) for that same, larger window. So the fix meaningfully shrinks the exposure window; it doesn't perfectly eliminate a sub-second parse-time flash inherent to how Make invokes shells either way.

**Disposition:** CONFIRMED-BY-READING (Makefile text + `main.go:52`'s existing env fallback + how Make invokes recipes).

**What would settle it fully:** start a `db-down N=1` (or any db-* target) against a long-enough-lived migration, and from a second shell run `ps -eo pid,command | grep collab-migrate` (Linux) or `ps -ax | grep collab-migrate` (macOS) while it's in flight. Not run here.

---

## Minor / not filed as findings (considered and rejected — stated so I'm not silently omitting them)

- **`goto 0`'s Makefile layer**: `db-goto` (Makefile:108-111) adds no `CONFIRM=yes` of its own, unlike `db-down-all`/`db-force`/`db-reset`/`db-destroy`. It still fails closed correctly today because the CLI's own `v==0 && !confirm` check (main.go:146-148) fires and the Makefile never passes `-yes`. This is a single-layer gate where the sibling destructive targets get two layers — worth tightening for consistency, but I would call it LOW: it does not currently fail open.
- **`-dir` on `create` is unvalidated** (main.go:54, :230-237): I looked for path traversal specifically and did not find one. `dir` is the CLI's own trust boundary (operator-supplied, same trust class as `-url`, deliberately un-defaulted for the same stated reason), not an untrusted segment crossing into a fixed base — there's no "trusted root + attacker segment" shape here for CWE-22 to apply to. `name` itself is fully blocked from traversal characters by `nameRe = ^[a-z0-9]+(_[a-z0-9]+)*$` (anchored both ends, no `/`, `.`, or `\` in the character class — verified complete). And `create` refuses to overwrite any pre-existing file regardless of where `-dir` resolves (`os.Stat` check at main.go:268-274 before either `os.WriteFile`). I'm not filing this — manufacturing an attacker-controlled-`-dir` scenario here has no production path in this CLI's design.
- **`uint64→uint` truncation in `goto`'s version parsing** (main.go:142, `uint(v)`): on a hypothetical 32-bit build, a value like `4294967296` would pass the `v == 0` check (it's nonzero as parsed) but truncate to `0` when cast, silently invoking `Down()` without the confirmation that a literal `0` would have required. This project's actual targets (`golang:1.25-alpine`/`GOOS=linux` in the Dockerfile, no 32-bit `GOARCH` set) are 64-bit, so `uint` is 64-bit and this has no reachable production path today. Noted, not filed.

---

## CHECKED CLEAN

- **SQL construction (point 1).** Grepped the entire diff for every `Exec(`/`QueryRow(`/string concatenation touching SQL text. Exactly two sites build SQL from a runtime value: `CREATE DATABASE ` + `quoteIdent(name)` (migrate_integration_test.go:91) and `DROP DATABASE IF EXISTS ` + `quoteIdent(name)` + ` WITH (FORCE)` (line 103). `quoteIdent` (line 115-117: wrap in `"`, double any embedded `"`) is the correct PostgreSQL quoted-identifier escaping algorithm, and Postgres double-quoted identifiers don't process backslash escapes, so there's no secondary escape character to worry about. `name` is always `"collab_mig_test_" + hex.EncodeToString(6 crypto/rand bytes)` — never environment- or attacker-influenced — so even without `quoteIdent` there'd be nothing to inject; the quoting is correctly-applied defense-in-depth exactly as the comment says. `tableExists`'s query correctly uses a `$1` bind parameter for the `table` value (a data position, not an identifier position) rather than string-building. `UPDATE schema_migrations SET dirty = true` (line 350) is a fixed literal. No other dynamic SQL exists anywhere in `migrate.go`/`main.go` — both files reach the database exclusively through golang-migrate's own API (`m.Up/Down/Steps/Migrate/Force/Version`), never raw SQL.
- **Destructive-path enumeration (point 2).** Traced all four verbs that can reach `Down()`, `Steps(n<0)`, `Goto(v)`, or `Force(v)` back to their exact CLI case arms; `down-all` and `force` are correctly double-gated (CLI `-yes` + Makefile `CONFIRM=yes`); `goto 0` is correctly single-gated at the CLI. See Finding 1 for the two shapes that are not gated.
- **Credential exposure (point 3).** Verified against the exact pinned `pgx v5.9.2` source that `sql.Open`, connection failures, and server-side SQL errors all route through error types that self-redact or never carry the DSN (`ParseConfigError.Error()`, `ConnectError.Error()`, `PgError.Error()` — all read directly from the vendored module cache, not from memory). The `admin.Redacted()` call (line 88) is correctly used at the one site the reviewer flagged. See Finding 2 for the one exception (`url.Parse` at line 67, a stdlib type with no such protection).
- **File permissions (point 5).** `create` writes both scaffold files with `0o644` (`os.WriteFile(upPath, ..., 0o644)` / same for `downPath`, main.go:296-300) — world-readable, not world-writable, appropriate for non-secret SQL comment templates that are meant to be committed to git anyway. Subject to normal umask; no secrets ever touch this path.
- **Path traversal via `name` (point 6).** `nameRe = ^[a-z0-9]+(_[a-z0-9]+)*$` is fully anchored at both ends and its character class contains no `/`, `.`, `\`, or NUL — traversal via `name` is not possible. `create` additionally refuses to clobber any pre-existing file at the computed path (`os.Stat` check before write), so even a hostile `-dir` can't be used to overwrite an unrelated file.
- **Go regexp / ReDoS.** Go's `regexp` package is RE2-based (linear time, no backtracking) — `nameRe` and `migrationFileRe` cannot be a catastrophic-backtracking vector regardless of input, structurally.
- **No command injection surface.** Neither `main.go` nor `migrate.go` imports `os/exec` or invokes a shell anywhere; `COLLAB_DATABASE_URL`/`-url` only ever reaches `sql.Open`/pgx APIs.
- **No new third-party dependencies.** `go.mod`/`go.sum` are untouched by this diff; `golang-migrate v4.19.1` and `pgx v5.9.2` were already pinned dependencies used by the pre-existing boot-time `RunUp`.
- **Dockerfile (point 7).** Diffed precisely: the only additions are a second `go build` stage for `collab-migrate` (same `CGO_ENABLED=0`, `-trimpath`, static) and one `COPY --from=builder` line. `USER collab` (pre-existing, unchanged, appears *after* both binaries are copied) and `ENTRYPOINT ["/usr/local/bin/collab-server"]` (unchanged) mean `collab-migrate` runs as the same non-root user and is not the container's default entrypoint — it's only reachable via an explicit `--entrypoint collab-migrate` override, which requires the same docker-exec-equivalent access that would already expose the running server's own `COLLAB_DATABASE_URL`. No new port, no new listening service, no widened remote attack surface.
- **docker-compose.yml.** Diffed precisely: the only change is a documentation comment block; no service, port, or environment-variable change. Not a new secret-handling surface.
- **`Versions()`/`Head()`/`PendingAfter()`** are confirmed read-only against the migration source (`fs.FS`) only — no database handle is touched, matching the doc comment, so they cannot be a destructive path themselves.

Key files (absolute paths):
- `/private/tmp/claude-501/-Users-kevinduffey-projects-studio/0fe929e6-fb12-463c-b8d9-2d22454974c9/scratchpad/gate-fdc4a7a/server/internal/db/migrate.go`
- `/private/tmp/claude-501/-Users-kevinduffey-projects-studio/0fe929e6-fb12-463c-b8d9-2d22454974c9/scratchpad/gate-fdc4a7a/server/cmd/collab-migrate/main.go`
- `/private/tmp/claude-501/-Users-kevinduffey-projects-studio/0fe929e6-fb12-463c-b8d9-2d22454974c9/scratchpad/gate-fdc4a7a/server/internal/db/migrate_integration_test.go`
- `/private/tmp/claude-501/-Users-kevinduffey-projects-studio/0fe929e6-fb12-463c-b8d9-2d22454974c9/scratchpad/gate-fdc4a7a/server/Makefile`
- `/private/tmp/claude-501/-Users-kevinduffey-projects-studio/0fe929e6-fb12-463c-b8d9-2d22454974c9/scratchpad/gate-fdc4a7a/server/Dockerfile`
- `/private/tmp/claude-501/-Users-kevinduffey-projects-studio/0fe929e6-fb12-463c-b8d9-2d22454974c9/scratchpad/gate-fdc4a7a/server/docker-compose.yml`
- `/private/tmp/claude-501/-Users-kevinduffey-projects-studio/0fe929e6-fb12-463c-b8d9-2d22454974c9/scratchpad/gate-fdc4a7a/server/migrations/0001_init.down.sql`
- `/private/tmp/claude-501/-Users-kevinduffey-projects-studio/0fe929e6-fb12-463c-b8d9-2d22454974c9/scratchpad/gate-fdc4a7a/server/README.md`
- `/private/tmp/claude-501/-Users-kevinduffey-projects-studio/0fe929e6-fb12-463c-b8d9-2d22454974c9/scratchpad/gate-fdc4a7a/server/migrations/README.md`
