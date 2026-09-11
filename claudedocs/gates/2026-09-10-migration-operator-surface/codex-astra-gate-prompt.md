You are performing an independent ADVERSARIAL CODE REVIEW, read-only, at a
pinned immutable commit. Do not modify, build, or run anything. Cite
path:line at THIS commit or the citation is dead.

COMMIT UNDER REVIEW: fdc4a7a77cd924455d085c70f058ef6abb4ce0f4
BASE: ab130be (collab/main)
SCOPE: everything in `git diff ab130be..HEAD` under server/. Read the full
files, not just the diff hunks.

## What the change is

golang-migrate was already wired in this Go server: `db.RunUp` applied
migrations at boot from an embedded FS. What was missing was every operator
verb after the happy path, and any test that ran the SQL against a real
Postgres. This change adds a `Migrator` type (Up/Down/Steps/Goto/Version/
Force/Versions/Head/PendingAfter), an operator CLI `cmd/collab-migrate`,
Makefile `db-*` targets, a real-Postgres integration test suite, a
conventions doc, and ships the CLI in the Docker image.

## The review standard (inlined — you cannot read our docs from here)

### Armor vs Ballast
We deliberately over-build. The question is never "is there too much code",
it is "is this kilogram ARMOR or BALLAST".
- ARMOR: bounds checks, fail-closed defaults, hostile-input validation at
  trust boundaries, assertions, tests, guards on states judged unreachable
  WITH the reachability argument written beside them, comments carrying a
  measurement or a retraction or a reason.
- BALLAST: an abstraction with one caller extracted for a speculative
  second; an error arm no production path can construct; a comment restating
  the line below it; test scaffolding costing more than it can catch.
- The dangerous kind is BALLAST THAT PRODUCES FALSE CONFIDENCE — an
  assertion that compares an output to another output of the same code, a
  metric the fixture controls, an arm that cannot fail (vacuous: a loop over
  an empty set, a skipped test), a state no production path can reach.
- Deleting armor is NEVER the answer to a ballast finding. If a check
  guards an unreachable state, the fix is to write down why it is
  unreachable, not to remove the check.

### "Beyond tested" has an operational definition
An assertion is armor if you can NAME what it fails for. Judge every new
test arm in this diff against that: what concrete input and wrong output
does it catch? Does its blind spot DIFFER from the arms already present? An
arm that passes for the same reason as another arm is one arm, not two.

### Claim Discipline
Every finding you report is a READING, not a measurement. Label each with a
severity AND state what would be required to settle it by measurement. For
any "value X is lost / not persisted / not checked" claim, answer all three:
does anything PRODUCE X on a production path, does the writer EMIT it, does
the reader RESTORE it. Two of three is half a finding.

## Required output sections — all five, none empty

1. FINDINGS — each as: severity (CRITICAL/HIGH/MED/LOW), path:line, the
   concrete input and wrong behaviour it produces, and what measurement
   would settle it. Order by severity.
2. BALLAST — weight in this diff that is not armor. Name it specifically.
   This section is the counterweight against correctness-maximalism; if you
   genuinely find none, say so and explain why the added weight is all
   load-bearing.
3. CHECKED CLEAN — what you examined and found correct. This is how we
   calibrate everything else you said, so be specific about what you
   verified, not just which files you opened.
4. FALSE-CONFIDENCE AUDIT — for each new test arm: can it fail? name the
   defect it catches. Flag any arm that is vacuous, that duplicates
   another's blind spot, or that could pass for the wrong reason.
5. CLAIMS I CANNOT SETTLE — what you would need to execute to decide.

## Specific questions, all defensive-hardening in intent

The threat model here is operator error and hostile/malformed input reaching
a database-migration tool. We want it to fail closed.

a. `Steps()` in internal/db/migrate.go swallows three error conditions as
   success: migrate.ErrNoChange, migrate.ErrShortLimit (via errors.As), and
   fs.ErrNotExist. We read golang-migrate v4.19.1's readUp/runMigrations and
   concluded ErrShortLimit is pushed onto the migration channel AFTER the
   available migrations are applied, so it means "ran out after doing the
   work". Is that right in BOTH directions (readUp and readDown)? Is there
   any input where one of those three is returned and the schema did NOT
   move as the caller believes?
b. `PendingAfter` counts set members strictly greater than the current
   version. Is there a state where that undercounts or overcounts what `Up`
   would actually apply?
c. `Version()` returns golang-migrate's error verbatim except for the
   ErrNoVersion re-export. Does any caller mishandle a dirty schema, or
   treat an error as "empty"?
d. The CLI's destructive verbs (down-all, force, goto 0) require -yes.
   Enumerate every path that reaches destructive SQL and confirm each is
   gated. Is there an argument shape that reaches a drop without
   confirmation?
e. `create` derives the next version number from the directory and refuses
   a duplicate NAME. What happens when two branches each add a migration?
   Is the failure visible or silent?
f. The integration test creates and drops throwaway databases and builds
   identifiers by hex-encoding random bytes, quoted via `quoteIdent`. Is
   there any interpolation path in the test helpers where an attacker- or
   environment-controlled string reaches SQL unquoted? The URL comes from
   COLLAB_TEST_DATABASE_URL.
g. The test suite SKIPS when COLLAB_TEST_DATABASE_URL is unset. That makes
   the whole integration suite vacuous in any environment that does not set
   it. Is the mitigation (a set-but-unreachable URL fails rather than skips)
   sufficient, or is this false confidence?
h. migrations/README.md claims "a second replica racing the first is safe —
   golang-migrate takes an advisory lock for the duration". Is that true for
   the pgx/v5 driver specifically? If not, that sentence is a false claim in
   a doc and must be reported.
i. `Migrator` has a source-only mode (Versions/Head/PendingAfter work
   without a database; Close tolerates a nil migrate instance). The tests
   construct `&Migrator{src: ...}` directly. Is that a footgun worth a
   constructor, or is the documented nil-tolerance sufficient?
j. Does anything in this diff change the behaviour of the existing boot path
   (cmd/relay -> db.RunUp)? That path is load-bearing: a regression there
   bricks every server start.
