# Gate record — collab server migration operator surface

Reviewed SHA: `fdc4a7a` (base `ab130be`), in a pinned read-only worktree.
Fixes landed in `8b1725a`, PR spirefyio/collab#6.

11-lens panel + Codex Astra adversarial gate, per the standing process
instruction. Each file is one lens's verbatim report.

## What the gate found that the author did not

Three lenses independently landed the same HIGH: `down n` and a descending
`goto v` had **no** confirmation gate at either layer, while the README
claimed "destructive verbs are gated twice" without qualification. With a
single-migration set, `collab-migrate down 1` had the same blast radius as
`down-all`, which did require `-yes`.

Mutation testing proved two more by measurement: deleting the `fs.ErrNotExist`
arm from `Steps` left 65/65 tests green while breaking `up 1` at head, and
`force 999` produced a false all-clear over a schema that was never created.

Codex Astra surfaced that a failed final rollback persists `version=-1,
dirty=true` while the CLI printed "empty database" — traced to
`migrate.Version()` discarding the dirty flag at NilVersion.

The backend lens then found the largest one: `Steps` reports success for a
schema whose recorded version is absent from the binary's migration set.
Measured — `Steps(±1)` returned nil with the version unchanged, while `Up()`
and `Down()` on the same Migrator refused by name.

## Dispositions

Every finding acted on was re-measured before acceptance; see `8b1725a`'s
commit body for the per-defect evidence. Two gate claims were corrected by
measurement rather than accepted as written:

- The lock claim. Both lenses read golang-migrate's 15s `DefaultLockTimeout`
  as the governing bound. Measured: construction blocks **indefinitely**
  (40s, no timeout) because `ensureVersionTable` takes the lock outside that
  racer, and the 15s bound only applies to a verb on an already-constructed
  migrator. The boot path hits the indefinite one.
- "`version` takes no lock." True of golang-migrate's own `Version()`, false
  of the command: there is no way to obtain a migrator without the blocking
  construction. Caught before it shipped into `migrations/README.md`.
