#!/usr/bin/env bash
# Checks a release tag before anything is built, and prints its version. The
# tag must be vX.Y.Z, on main, match Cargo.toml and have a CHANGELOG section.
# MAIN_REF, CARGO_MANIFEST and CHANGELOG override the defaults (used by the
# tests).
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <tag>   (e.g. $0 v1.1.0)" >&2
    exit 2
fi

tag=$1
scripts=$(dirname "$0")
main_ref=${MAIN_REF:-origin/main}
manifest=${CARGO_MANIFEST:-"$scripts/../Cargo.toml"}

if [[ ! $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "error: tag '$tag' is not vX.Y.Z; pre-release tags are not supported." >&2
    exit 1
fi
version=${tag#v}

if ! git rev-parse --quiet --verify "refs/tags/$tag" >/dev/null; then
    echo "error: tag '$tag' does not exist." >&2
    exit 1
fi

if ! git merge-base --is-ancestor "refs/tags/$tag" "$main_ref"; then
    echo "error: tag '$tag' is not on $main_ref." >&2
    exit 1
fi

manifest_version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$manifest" | head -n 1)
if [[ $manifest_version != "$version" ]]; then
    echo "error: tag '$tag' does not match version '$manifest_version' in Cargo.toml." >&2
    exit 1
fi

"$scripts/changelog-section.sh" "$version" >/dev/null

printf '%s\n' "$version"
