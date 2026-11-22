#!/usr/bin/env bash
# Tests scripts/changelog-assemble.sh against fixture changelogs and fragments.
# Usage: scripts/test-changelog-assemble.sh   (run by the CI lint job)
set -euo pipefail

scripts="$(cd "$(dirname "$0")" && pwd)"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

repo="$work/repo"
url=https://github.com/MHusted01/reachmap/issues
failures=0

fail() {
    echo "FAIL: $1" >&2
    failures=$((failures + 1))
}

# Replaces $repo with the given CHANGELOG.md text and a changelog.d/ that holds
# only .gitkeep.
reset_repo() {
    rm -rf "$repo"
    mkdir -p "$repo/changelog.d"
    : >"$repo/changelog.d/.gitkeep"
    printf '%s\n' "$1" >"$repo/CHANGELOG.md"
}

# fragment <file name> <text>: writes one fragment file.
fragment() {
    printf '%s\n' "$2" >"$repo/changelog.d/$1"
}

assemble() {
    CHANGELOG="$repo/CHANGELOG.md" CHANGELOG_DIR="$repo/changelog.d" \
        "$scripts/changelog-assemble.sh" "$@"
}

# expect_file <name> <path> <want text>
expect_file() {
    if [[ $(<"$2") != "$3" ]]; then
        fail "$1"
        diff <(printf '%s\n' "$3") "$2" >&2 || true
    fi
}

# expect_error <name> <want status> <args...>: the script fails with a message
# and leaves CHANGELOG.md and changelog.d/ exactly as they were.
expect_error() {
    local name=$1 want=$2 status=0
    shift 2
    rm -rf "$work/before"
    cp -R "$repo" "$work/before"
    assemble "$@" >/dev/null 2>"$work/stderr" || status=$?
    if [[ $status != "$want" ]]; then
        fail "$name (exit $status, want $want)"
    fi
    if ! diff -r "$work/before" "$repo" >/dev/null; then
        fail "$name: changed files"
    fi
    if [[ ! -s "$work/stderr" ]]; then
        fail "$name: no error message"
    fi
}

released='# Changelog

Intro.

## [Unreleased]

See changelog.d/.

## [1.0.0] - 2026-01-01

### Added

- Old.'

# Success: categories in Keep a Changelog order (Removed before Fixed),
# entries newest issue first (numeric, so 10 before 9 before 2).
reset_repo "$released"
fragment 2.added.md "- Two ([#2]($url/2))."
fragment 9.added.md "- Nine, wrapped
  over two lines ([#9]($url/9))."
fragment 10.added.md "- Ten ([#10]($url/10))."
fragment 3.fixed.md "- Three ([#3]($url/3))."
fragment 4.removed.md "- Four ([#4]($url/4))."

section="### Added

- Ten ([#10]($url/10)).
- Nine, wrapped
  over two lines ([#9]($url/9)).
- Two ([#2]($url/2)).

### Removed

- Four ([#4]($url/4)).

### Fixed

- Three ([#3]($url/3))."

if ! assemble 1.1.0 2026-02-03 >/dev/null; then
    fail "assemble a release (non-zero exit)"
fi
expect_file "assemble a release" "$repo/CHANGELOG.md" "# Changelog

Intro.

## [Unreleased]

See changelog.d/.

## [1.1.0] - 2026-02-03

$section

## [1.0.0] - 2026-01-01

### Added

- Old."

read_back=$(CHANGELOG="$repo/CHANGELOG.md" "$scripts/changelog-section.sh" 1.1.0) || true
if [[ $read_back != "$section" ]]; then
    fail "changelog-section.sh reads the section back unchanged"
fi

remaining=$(cd "$repo/changelog.d" && ls -A)
if [[ $remaining != ".gitkeep" ]]; then
    fail "folded fragments are removed (left: $remaining)"
fi

# Success: the first release, with no older section, goes at the end; a leap
# day is a valid date.
reset_repo '# Changelog

## [Unreleased]'
fragment 1.security.md "- One ([#1]($url/1))."
if ! assemble 0.1.0 2028-02-29 >/dev/null; then
    fail "first release on a leap day (non-zero exit)"
fi
expect_file "first release on a leap day" "$repo/CHANGELOG.md" "# Changelog

## [Unreleased]

## [0.1.0] - 2028-02-29

### Security

- One ([#1]($url/1))."

# Success: link references at the end stay below the new section.
reset_repo "# Changelog

## [Unreleased]

[Unreleased]: https://example.com/compare/HEAD"
fragment 1.changed.md "- One ([#1]($url/1))."
if ! assemble 0.1.0 2026-01-01 >/dev/null; then
    fail "section before link references (non-zero exit)"
fi
expect_file "section before link references" "$repo/CHANGELOG.md" "# Changelog

## [Unreleased]

## [0.1.0] - 2026-01-01

### Changed

- One ([#1]($url/1)).

[Unreleased]: https://example.com/compare/HEAD"

# Error cases. Each starts from a valid fragment, so only the named problem
# makes the script fail, and the valid fragment must survive.
error_case() {
    reset_repo "$released"
    fragment 5.added.md "- Five ([#5]($url/5))."
}

error_case
expect_error "no arguments" 2
expect_error "one argument" 2 1.1.0
expect_error "three arguments" 2 1.1.0 2026-02-03 extra
expect_error "version with v prefix" 1 v1.1.0 2026-02-03
expect_error "version with two parts" 1 1.1 2026-02-03
expect_error "version with a leading zero" 1 1.01.0 2026-02-03
expect_error "pre-release version" 1 1.1.0-rc.1 2026-02-03
expect_error "existing version" 1 1.0.0 2026-02-03
expect_error "date without padding" 1 1.1.0 2026-2-3
expect_error "month 13" 1 1.1.0 2026-13-01
expect_error "day 0" 1 1.1.0 2026-02-00
expect_error "February 30" 1 1.1.0 2026-02-30
expect_error "February 29 outside a leap year" 1 1.1.0 2025-02-29
expect_error "February 29 in a century year" 1 1.1.0 2100-02-29

error_case
fragment 6.new.md "- Six ([#6]($url/6))."
expect_error "unknown category" 1 1.1.0 2026-02-03

error_case
fragment notes.md "- Notes."
expect_error "file name without an issue" 1 1.1.0 2026-02-03

error_case
fragment 06.added.md "- Six ([#6]($url/6))."
expect_error "issue number with a leading zero" 1 1.1.0 2026-02-03

error_case
: >"$repo/changelog.d/6.added.md"
expect_error "empty fragment" 1 1.1.0 2026-02-03

error_case
fragment 6.added.md "Six ([#6]($url/6))."
expect_error "fragment without a bullet" 1 1.1.0 2026-02-03

error_case
fragment 6.added.md "- Six.
- Seven ([#6]($url/6))."
expect_error "fragment with two bullets" 1 1.1.0 2026-02-03

error_case
fragment 6.added.md "- Six,

  continued ([#6]($url/6))."
expect_error "fragment with a blank line" 1 1.1.0 2026-02-03

error_case
fragment 6.added.md "- Six."
expect_error "fragment without an issue link" 1 1.1.0 2026-02-03

error_case
fragment 6.added.md "- Six ([#7]($url/7))."
expect_error "issue link for another issue" 1 1.1.0 2026-02-03

error_case
fragment 6.added.md "- Six ([#6](https://example.com/issues/6))."
expect_error "issue link to another site" 1 1.1.0 2026-02-03

reset_repo "$released"
expect_error "no fragments" 1 1.1.0 2026-02-03

rm -rf "$repo/changelog.d"
expect_error "no changelog.d directory" 1 1.1.0 2026-02-03

reset_repo '# Changelog

## [1.0.0] - 2026-01-01'
fragment 5.added.md "- Five ([#5]($url/5))."
expect_error "no Unreleased heading" 1 1.1.0 2026-02-03

# --check validates the fragments and changes nothing.
check() {
    local name=$1 want=$2 status=0
    rm -rf "$work/before"
    cp -R "$repo" "$work/before"
    assemble --check >/dev/null 2>&1 || status=$?
    if [[ $status != "$want" ]]; then
        fail "$name (exit $status, want $want)"
    fi
    if ! diff -r "$work/before" "$repo" >/dev/null; then
        fail "$name: changed files"
    fi
}

error_case
fragment 6.fixed.md "- Six ([#6]($url/6))."
check "check valid fragments" 0

reset_repo "$released"
check "check without fragments" 0

error_case
fragment 6.added.md "- Six."
check "check a malformed fragment" 1
expect_error "check a malformed fragment" 1 --check
expect_error "check with an extra argument" 2 --check 1.1.0

rm -rf "$repo/changelog.d"
expect_error "check without changelog.d" 1 --check

# A fragment that cannot be deleted after the section is written: the script
# fails and says how to recover. Root can delete anyway, so skip it there.
if [[ $(id -u) -ne 0 ]]; then
    error_case
    chmod a-w "$repo/changelog.d"
    status=0
    assemble 1.1.0 2026-02-03 >/dev/null 2>"$work/stderr" || status=$?
    chmod u+w "$repo/changelog.d"
    if [[ $status != 1 ]] || ! grep -q 'git restore' "$work/stderr"; then
        fail "fragments that cannot be deleted (exit $status, want 1 with recovery hint)"
    fi
fi

if [[ $failures -ne 0 ]]; then
    exit 1
fi
echo "changelog-assemble tests passed."
