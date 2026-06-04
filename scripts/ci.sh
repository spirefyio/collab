#!/usr/bin/env bash
#
# ci.sh — run this repo's CI on GitHub (a manual, workflow_dispatch build) from
# your terminal, and stream it to completion. The REMOTE twin of dev.sh: dev.sh
# builds on your machine against local sibling forks; ci.sh builds on a GitHub
# runner that checks the siblings out and forks them the same way. Same build,
# different host — so "passes locally" and "passes in CI" mean the same thing.
#
#   ./scripts/ci.sh                 # CI for the current branch
#   ./scripts/ci.sh dev             # CI for a specific branch
#   ./scripts/ci.sh dev -f ref=dev  # extra args pass to gh as workflow_dispatch
#                                   #   inputs — only if this repo's workflow
#                                   #   declares them (desktop/collab do; zora/ai don't)
#
# Requires the GitHub CLI authenticated once: `gh auth login`. No token is
# stored in or read by this script — gh uses its own keychain session.
#
# Nothing here runs automatically: the workflow's only trigger is
# workflow_dispatch, so a build happens ONLY when you (or this script) ask. To
# be triggerable the workflow must exist on the repo's DEFAULT branch, and on the
# branch you target to build it — see the "CI cost policy" NOTE at the top of the
# build workflow in .github/workflows/ for the one-time setup. ci.sh picks the
# first build workflow (build.yml / build-matrix.yml), never a release pipeline.
#
# Integration: if $CI_RUN_ID_FILE is set, ci.sh writes the dispatched run id to
# that path before watching, so a caller (verify.sh) consumes the EXACT run
# rather than re-guessing it.
set -euo pipefail

command -v gh >/dev/null 2>&1 || {
    echo "ci.sh: GitHub CLI (gh) not found — install it, then run 'gh auth login'." >&2; exit 1; }
gh auth status >/dev/null 2>&1 || {
    echo "ci.sh: gh is not authenticated — run 'gh auth login' first." >&2; exit 1; }

# Pick the workflow: $CI_WORKFLOW wins; otherwise the first build workflow found.
WORKFLOW="${CI_WORKFLOW:-}"
if [ -z "$WORKFLOW" ]; then
    for c in build.yml build-matrix.yml ci.yml; do
        if [ -f ".github/workflows/$c" ]; then WORKFLOW="$c"; break; fi
    done
fi
[ -n "$WORKFLOW" ] || {
    echo "ci.sh: no build workflow under .github/workflows (set CI_WORKFLOW=<file>)." >&2; exit 1; }

BRANCH="${1:-$(git rev-parse --abbrev-ref HEAD)}"
[ $# -gt 0 ] && shift   # any args after the branch pass through to gh as -f inputs
case "$BRANCH" in
    -*) echo "ci.sh: refusing branch '$BRANCH' (begins with '-', would be read as a flag)." >&2; exit 1 ;;
esac

# Resolve the latest run id for OUR kind of trigger (manual dispatch) on this
# workflow+branch. Scoping to --event workflow_dispatch keeps us from latching
# onto an unrelated run.
list_latest() {
    gh run list --workflow "$WORKFLOW" --branch "$BRANCH" --event workflow_dispatch \
        --limit 1 --json databaseId --jq '.[0].databaseId // 0'
}
# Snapshot BEFORE dispatching, so we watch the run WE start, not a stale one.
prev=$(list_latest 2>/dev/null || echo 0)

echo "ci.sh: dispatching '$WORKFLOW' on branch '$BRANCH'…" >&2
gh workflow run "$WORKFLOW" --ref "$BRANCH" "$@"

# A dispatched run takes a moment to register; poll until a new id appears.
run_id=""
for _ in $(seq 1 30); do
    id=$(list_latest 2>/dev/null || echo 0)
    if [ "$id" != "$prev" ] && [ "$id" != 0 ]; then run_id="$id"; break; fi
    sleep 2
done
[ -n "$run_id" ] || {
    echo "ci.sh: timed out waiting for the run to start — check the Actions tab." >&2; exit 1; }

# Hand the exact run id to a caller (verify.sh) so it never re-guesses the run.
[ -n "${CI_RUN_ID_FILE:-}" ] && printf '%s\n' "$run_id" > "$CI_RUN_ID_FILE"

repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
echo "ci.sh: watching → https://github.com/$repo/actions/runs/$run_id" >&2
# --exit-status makes THIS script exit non-zero when the run fails, so it
# composes in pipelines (verify.sh relies on it) exactly like `zig build` does.
exec gh run watch "$run_id" --exit-status
