#!/usr/bin/env bash
# Packs a release binary with its licences and docs into a tar.gz and writes a
# SHA-256 file next to it. Prints the path of the archive.
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <version> <target> <binary> <output-dir>" >&2
    exit 2
fi

version=$1
target=$2
binary=$3
output=$4
root="$(dirname "$0")/.."
name="reachmap-$version-$target"

if [[ ! -f $binary ]]; then
    echo "error: no binary at '$binary'." >&2
    exit 1
fi

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT

mkdir -p "$output" "$staging/$name"
cp "$binary" "$staging/$name/reachmap"
cp "$root/CHANGELOG.md" "$root/LICENSE-APACHE" "$root/LICENSE-MIT" "$root/README.md" "$staging/$name/"

# COPYFILE_DISABLE keeps macOS metadata files out of the archive.
COPYFILE_DISABLE=1 tar -czf "$output/$name.tar.gz" -C "$staging" "$name"
(cd "$output" && shasum -a 256 "$name.tar.gz" >"$name.tar.gz.sha256")

printf '%s\n' "$output/$name.tar.gz"
