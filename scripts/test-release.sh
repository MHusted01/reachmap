#!/usr/bin/env bash
# Tests the release scripts against fixtures in a throwaway git repository.
# Usage: scripts/test-release.sh   (run by the CI lint job)
set -euo pipefail

scripts="$(cd "$(dirname "$0")" && pwd)"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

failures=0

fail() {
    echo "FAIL: $1" >&2
    failures=$((failures + 1))
}

# Runs a command and compares its exit status and standard output.
expect() {
    local name=$1 want_status=$2 want_output=$3 output status=0
    shift 3
    output=$("$@" 2>/dev/null) || status=$?
    if [[ $status != "$want_status" || $output != "$want_output" ]]; then
        fail "$name (exit $status, want $want_status)"
        printf '%s\n' "$output" >&2
    fi
}

# --- check-release.sh -------------------------------------------------------

repo="$work/repo"
git init --quiet --initial-branch=main "$repo"
git -C "$repo" config user.name test
git -C "$repo" config user.email test@example.com
git -C "$repo" config commit.gpgsign false
git -C "$repo" config tag.gpgsign false

cat >"$repo/Cargo.toml" <<'EOF'
[package]
name = "demo"
version = "1.2.3"

[dependencies]
clap = { version = "9.9.9" }
EOF
cat >"$repo/CHANGELOG.md" <<'EOF'
# Changelog

## [1.2.3] - 2026-01-02

### Added

- One.
EOF
git -C "$repo" add .
git -C "$repo" commit --quiet -m "first"
git -C "$repo" tag v1.2.3
git -C "$repo" tag v1.2.4
git -C "$repo" tag v1.2.3-rc.1
git -C "$repo" tag 1.2.3

git -C "$repo" switch --quiet -c side
git -C "$repo" commit --quiet --allow-empty -m "not on main"
git -C "$repo" tag side-tag
git -C "$repo" tag v9.9.9
git -C "$repo" switch --quiet main

check() {
    (cd "$repo" && MAIN_REF=main CARGO_MANIFEST=Cargo.toml CHANGELOG=CHANGELOG.md \
        "$scripts/check-release.sh" "$@")
}

expect "matching tag prints the version" 0 "1.2.3" check v1.2.3
expect "tag differs from Cargo.toml" 1 "" check v1.2.4
expect "pre-release tag" 1 "" check v1.2.3-rc.1
expect "tag without the v prefix" 1 "" check 1.2.3
expect "unknown tag" 1 "" check v7.7.7
expect "no argument" 2 "" check

# Same version as the manifest on the side branch, so only the branch differs.
git -C "$repo" switch --quiet side
sed -i.bak 's/^version = "1.2.3"/version = "9.9.9"/' "$repo/Cargo.toml"
printf '\n## [9.9.9] - 2026-01-03\n\n- Two.\n' >>"$repo/CHANGELOG.md"
expect "tag that is not on main" 1 "" check v9.9.9
git -C "$repo" checkout --quiet -- .
git -C "$repo" switch --quiet main

# A version in Cargo.toml and a tag on main, but no CHANGELOG section.
cat >"$repo/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

- One.
EOF
expect "no CHANGELOG section" 1 "" check v1.2.3
git -C "$repo" checkout --quiet -- .

# --- package-release.sh -----------------------------------------------------

binary="$work/reachmap"
printf 'binary\n' >"$binary"
dist="$work/dist"
target=x86_64-unknown-linux-musl
archive="reachmap-1.2.3-$target.tar.gz"

expect "package prints the archive path" 0 "$dist/$archive" \
    "$scripts/package-release.sh" 1.2.3 "$target" "$binary" "$dist"
expect "archive contents" 0 "$(printf '%s\n' \
    "reachmap-1.2.3-$target/CHANGELOG.md" \
    "reachmap-1.2.3-$target/LICENSE-APACHE" \
    "reachmap-1.2.3-$target/LICENSE-MIT" \
    "reachmap-1.2.3-$target/README.md" \
    "reachmap-1.2.3-$target/reachmap")" \
    bash -c "tar -tzf '$dist/$archive' | grep -v '/\$' | LC_ALL=C sort"
expect "checksum file verifies" 0 "$archive: OK" \
    bash -c "cd '$dist' && shasum -a 256 -c '$archive.sha256'"
expect "binary stays executable" 0 "ok" \
    bash -c "chmod +x '$binary'; '$scripts/package-release.sh' 1.2.3 $target '$binary' '$dist' >/dev/null
             tar -xzf '$dist/$archive' -C '$work' && test -x '$work/reachmap-1.2.3-$target/reachmap' && echo ok"
expect "missing binary" 1 "" \
    "$scripts/package-release.sh" 1.2.3 "$target" "$work/missing" "$dist"
expect "package without arguments" 2 "" "$scripts/package-release.sh"

# --- render-formula.sh ------------------------------------------------------

hash_of() { printf '%064d' "$1"; }

checksums="$work/checksums.txt"
cat >"$checksums" <<EOF
$(hash_of 1)  reachmap-1.2.3-aarch64-apple-darwin.tar.gz
$(hash_of 2)  reachmap-1.2.3-x86_64-apple-darwin.tar.gz
$(hash_of 3)  reachmap-1.2.3-aarch64-unknown-linux-musl.tar.gz
$(hash_of 4)  reachmap-1.2.3-x86_64-unknown-linux-musl.tar.gz
EOF

base=https://github.com/MHusted01/reachmap/releases/download/v1.2.3
formula=$(cat <<EOF
class Reachmap < Formula
  desc "Shows which services on a host can be reached, from where, and why"
  homepage "https://github.com/MHusted01/reachmap"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "$base/reachmap-1.2.3-aarch64-apple-darwin.tar.gz"
      sha256 "$(hash_of 1)"
    end
    on_intel do
      url "$base/reachmap-1.2.3-x86_64-apple-darwin.tar.gz"
      sha256 "$(hash_of 2)"
    end
  end

  on_linux do
    on_arm do
      url "$base/reachmap-1.2.3-aarch64-unknown-linux-musl.tar.gz"
      sha256 "$(hash_of 3)"
    end
    on_intel do
      url "$base/reachmap-1.2.3-x86_64-unknown-linux-musl.tar.gz"
      sha256 "$(hash_of 4)"
    end
  end

  def install
    bin.install "reachmap"
  end

  test do
    assert_equal "reachmap #{version}", shell_output("#{bin}/reachmap --version").strip
  end
end
EOF
)

expect "formula with four targets" 0 "$formula" "$scripts/render-formula.sh" 1.2.3 "$checksums"

grep -v x86_64-apple-darwin "$checksums" >"$work/missing.txt"
expect "a target without a checksum" 1 "" "$scripts/render-formula.sh" 1.2.3 "$work/missing.txt"

sed 's/^[0-9]*1  /abc  /' "$checksums" >"$work/short.txt"
expect "a checksum of the wrong length" 1 "" "$scripts/render-formula.sh" 1.2.3 "$work/short.txt"

cat "$checksums" "$checksums" >"$work/twice.txt"
expect "a target listed twice" 1 "" "$scripts/render-formula.sh" 1.2.3 "$work/twice.txt"

expect "checksums of another version" 1 "" "$scripts/render-formula.sh" 1.2.4 "$checksums"
expect "missing checksum file" 1 "" "$scripts/render-formula.sh" 1.2.3 "$work/none.txt"
expect "formula without arguments" 2 "" "$scripts/render-formula.sh"

if [[ $failures -ne 0 ]]; then
    exit 1
fi
echo "release script tests passed."
