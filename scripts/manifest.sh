#!/usr/bin/env bash
#
# manifest.sh — emit a JSON manifest of the build artifacts under an output dir
# (default zig-out). Used by BOTH local builds (verify.sh) and CI, so the two
# compare apples-to-apples: ONE generator, ONE format.
#
#   ./scripts/manifest.sh                 # manifest of ./zig-out
#   ./scripts/manifest.sh path/to/out     # manifest of another dir
#
# sha256 is included but only matches across the SAME os/arch — a CI linux
# binary will not byte-match your macOS binary. The invariant that always holds
# (and what verify.sh enforces) is artifact PRESENCE: the same set of paths.
set -euo pipefail

OUT="${1:-zig-out}"

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi   # macOS has shasum, not sha256sum
}

# Escape a string for a JSON double-quoted scalar (backslash + quote). Control
# chars are out of scope — find's newline-delimited read can't carry them anyway.
json_escape() { local s=$1; s=${s//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "$s"; }

printf '{\n  "out": "%s",\n  "artifacts": [\n' "$(json_escape "$OUT")"
if [ -d "$OUT" ]; then
    first=1
    # LC_ALL=C sort → stable, locale-independent ordering for a deterministic diff.
    while IFS= read -r f; do
        [ "$first" -eq 1 ] || printf ',\n'
        first=0
        printf '    {"path": "%s", "bytes": %s, "sha256": "%s"}' \
            "$(json_escape "${f#"$OUT"/}")" "$(wc -c < "$f" | tr -d ' ')" "$(sha256 "$f")"
    done < <(find "$OUT" -type f | LC_ALL=C sort)
    [ "$first" -eq 1 ] || printf '\n'
fi
printf '  ]\n}\n'
