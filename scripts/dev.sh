#!/usr/bin/env bash
#
# dev.sh — build/test collab against your LOCAL sibling working copies instead
# of the pinned URLs in build.zig.zon.
#
# build.zig.zon pins each internal sibling (zora, desktop) to a git+https URL +
# hash — the contract an external/published consumer fetches. For local
# development you almost never want to fetch those from GitHub; you want to
# build against the working copy sitting next to this repo. Each `--fork=<dir>`
# overrides one url-dependency with a local package (Zig matches the fork to the
# dependency by PACKAGE NAME, so the local name must equal the pinned name).
#
# CI uses the exact same mechanism: it checks the siblings out next to this repo
# (via the org PAT) and passes the same --fork flags, so the private URLs are
# never fetched and no token is ever handed to Zig.
#
# Usage:
#   ./scripts/dev.sh test --summary all
#   ./scripts/dev.sh build
#   SPIREFY_FORK_ROOT=/path/to/projects ./scripts/dev.sh test   # custom layout
#
# A bare `zig build` (no fork) resolves the pinned URLs from GitHub instead —
# that is the published-consumer path (needs network + a token for private deps).
set -euo pipefail

# Default layout: siblings live next to this repo (…/projects/{collab,zora,desktop}).
ROOT="${SPIREFY_FORK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

# collab's transitive url-pinned siblings to override locally. zora + desktop
# are direct deps; ai is pulled in transitively by desktop, and a forked package
# may not contain path deps, so desktop's own deps (zora, ai) must be forked too.
SIBLINGS=(zora ai desktop)

forks=()
for s in "${SIBLINGS[@]}"; do
    if [ -f "$ROOT/$s/build.zig.zon" ]; then
        forks+=("--fork=$ROOT/$s")
    else
        echo "dev.sh: WARNING — no local '$s' at $ROOT/$s; it will fetch from the pinned URL" >&2
    fi
done

echo "dev.sh: forking ${#forks[@]} local sibling(s) under $ROOT: ${forks[*]:-<none>}" >&2
exec zig build "$@" "${forks[@]}"
