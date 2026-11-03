#!/usr/bin/env bash
# Tests scripts/changelog-section.sh against a fixture CHANGELOG.
# Usage: scripts/test-changelog-section.sh   (run by the CI lint job)
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/changelog-section.sh"
fixture=$(mktemp)
trap 'rm -f "$fixture"' EXIT

cat >"$fixture" <<'EOF'
# Changelog

## [Unreleased]

## [1.1.0] - 2026-01-02

### Added

- One.

## [1.1] - 2026-01-01

## [1.0.0] - 2025-12-31

### Fixed

- Last.

[Unreleased]: https://example.com/compare/v1.1.0...HEAD
[1.1.0]: https://example.com/compare/v1.0.0...v1.1.0
EOF

failures=0

expect() {
    local name=$1 want_status=$2 want_output=$3 output status=0
    shift 3
    output=$(CHANGELOG="$fixture" "$script" "$@" 2>/dev/null) || status=$?
    if [[ $status != "$want_status" || $output != "$want_output" ]]; then
        echo "FAIL: $name (exit $status, want $want_status)" >&2
        printf '%s\n' "$output" >&2
        failures=$((failures + 1))
    fi
}

expect "section between headings" 0 $'### Added\n\n- One.' 1.1.0
expect "last section before link references" 0 $'### Fixed\n\n- Last.' 1.0.0
expect "empty section" 1 "" 1.1
expect "empty Unreleased" 1 "" Unreleased
expect "missing section" 1 "" 9.9.9
expect "version prefix does not match" 1 "" 1.0
expect "no argument" 2 ""

if [[ $failures -ne 0 ]]; then
    exit 1
fi
echo "changelog-section tests passed."
