#!/usr/bin/env bash
# Prints the Homebrew formula for a release. The checksum file holds one
# `<sha256>  <archive>` line per target, as written by package-release.sh.
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <version> <checksum-file>" >&2
    exit 2
fi

version=$1
checksums=$2
base="https://github.com/MHusted01/reachmap/releases/download/v$version"

if [[ ! -f $checksums ]]; then
    echo "error: no checksum file at '$checksums'." >&2
    exit 1
fi

# Prints the url and sha256 lines of one target, or fails if its checksum is
# not exactly one well-formed hash.
source_lines() {
    local archive="reachmap-$version-$1.tar.gz" hash
    hash=$(awk -v archive="$archive" '$2 == archive { print $1 }' "$checksums")
    if [[ ! $hash =~ ^[0-9a-f]{64}$ ]]; then
        echo "error: no single valid checksum for $archive in '$checksums'." >&2
        return 1
    fi
    printf '      url "%s/%s"\n      sha256 "%s"\n' "$base" "$archive" "$hash"
}

macos_arm=$(source_lines aarch64-apple-darwin)
macos_intel=$(source_lines x86_64-apple-darwin)
linux_arm=$(source_lines aarch64-unknown-linux-musl)
linux_intel=$(source_lines x86_64-unknown-linux-musl)

cat <<FORMULA
class Reachmap < Formula
  desc "Shows which services on a host can be reached, from where, and why"
  homepage "https://github.com/MHusted01/reachmap"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
$macos_arm
    end
    on_intel do
$macos_intel
    end
  end

  on_linux do
    on_arm do
$linux_arm
    end
    on_intel do
$linux_intel
    end
  end

  def install
    bin.install "reachmap"
  end

  test do
    assert_equal "reachmap #{version}", shell_output("#{bin}/reachmap --version").strip
  end
end
FORMULA
