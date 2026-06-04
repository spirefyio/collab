#!/usr/bin/env bash
#
# verify.sh — build locally AND on GitHub CI, then confirm CI produced the same
# artifacts you did locally (artifact PRESENCE — the cross-platform-safe
# invariant; sizes/hashes differ across os/arch and are reported, not enforced).
#
# WHEN THIS CHECK IS MEANINGFUL:
#   * It compares the SET of installed artifact paths, so it only bites for repos
#     whose `zig build` INSTALLS artifacts (e.g. zora's libzora.a). A pure library
#     repo that installs nothing (desktop, collab today) has an empty set on both
#     sides — verify.sh then prints a clear "nothing to compare" NOTE and just
#     confirms CI still BUILDS, rather than a hollow "all 0 present" OK. The parity
#     check gains teeth once the repo ships an artifact (e.g. at release).
#   * Local and CI must build with the same artifact-affecting flags or the sets
#     diverge. Those flags live in scripts/verify.env (LOCAL_BUILD_ARGS) — the one
#     place that must match the CI manifest cell's flags.
#
#   ./scripts/verify.sh            # current branch
#   ./scripts/verify.sh dev        # a specific branch
#
# Requires `gh` (authenticated) and a dispatchable CI workflow for this repo.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
branch="${1:-$(git rev-parse --abbrev-ref HEAD)}"

# Artifact-affecting build flags that MUST match the CI manifest cell (see header).
LOCAL_BUILD_ARGS=""
[ -f "$here/verify.env" ] && . "$here/verify.env"

# Pull the artifact "path" values out of a manifest, sorted — no jq dependency.
paths_of() { grep -o '"path": *"[^"]*"' "$1" | sed 's/.*"path": *"//; s/"$//' | LC_ALL=C sort; }

local_manifest="$(mktemp)"; ci_dir="$(mktemp -d)"; run_id_file="$(mktemp)"
trap 'rm -rf "$local_manifest" "$ci_dir" "$run_id_file"' EXIT

echo "verify.sh: [1/4] building locally (dev.sh build $LOCAL_BUILD_ARGS) …" >&2
# shellcheck disable=SC2086  # LOCAL_BUILD_ARGS is an intentional, trusted arg list
"$here/dev.sh" build $LOCAL_BUILD_ARGS >/dev/null
"$here/manifest.sh" zig-out > "$local_manifest"
local_list="$(paths_of "$local_manifest" || true)"

if [ -z "$local_list" ]; then
    echo "verify.sh: NOTE — local build installed 0 artifacts; there is nothing to compare" >&2
    echo "          (library repo with no install step? parity gains teeth once it ships one)." >&2
    echo "verify.sh: running CI to confirm it still BUILDS, then stopping…" >&2
    rm -rf "$local_manifest" "$ci_dir" "$run_id_file"
    exec "$here/ci.sh" "$branch"   # CI build/test success is still verified; exit = CI's
fi

echo "verify.sh: [2/4] running CI on '$branch' (ci.sh) …" >&2
CI_RUN_ID_FILE="$run_id_file" "$here/ci.sh" "$branch"   # builds remotely; non-zero if CI fails
run_id="$(cat "$run_id_file" 2>/dev/null || true)"
[ -n "$run_id" ] || { echo "verify.sh: could not determine the CI run id." >&2; exit 1; }

echo "verify.sh: [3/4] fetching the CI manifest from run $run_id …" >&2
gh run download "$run_id" -n ci-manifest -D "$ci_dir"
[ -f "$ci_dir/ci-manifest.json" ] || {
    echo "verify.sh: run $run_id uploaded no ci-manifest artifact — cannot compare." >&2; exit 1; }

echo "verify.sh: [4/4] comparing artifact sets …" >&2
ci_list="$(paths_of "$ci_dir/ci-manifest.json" || true)"
missing="$(comm -23 <(printf '%s\n' "$local_list") <(printf '%s\n' "$ci_list") || true)"
extra="$(comm -13 <(printf '%s\n' "$local_list") <(printf '%s\n' "$ci_list") || true)"

rc=0
if [ -n "$missing" ]; then
    echo "verify.sh: FAIL — present locally but MISSING in CI:" >&2
    printf '%s\n' "$missing" | sed 's/^/  /' >&2
    rc=1
fi
if [ -n "$extra" ]; then
    echo "verify.sh: WARN — present in CI but not locally (platform-specific?):" >&2
    printf '%s\n' "$extra" | sed 's/^/  /' >&2
fi
[ "$rc" -eq 0 ] && echo "verify.sh: OK — all $(printf '%s\n' "$local_list" | grep -c .) local artifact(s) present in CI." >&2
exit "$rc"
