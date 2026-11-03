#!/usr/bin/env bash
# Prints the body of one version's section in CHANGELOG.md, without its
# heading, for use as the GitHub Release body. Fails if the section is
# missing or empty. CHANGELOG overrides the file (used by the tests).
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <version>   (e.g. $0 1.1.0)" >&2
    exit 2
fi

changelog=${CHANGELOG:-"$(dirname "$0")/../CHANGELOG.md"}

# Command substitution drops the trailing blank lines; awk skips leading ones.
section=$(awk -v heading="## [$1]" '
    index($0, "## [") == 1 || /^\[.*\]: / {
        if (found) exit
        if (index($0, heading) == 1) found = 1
        next
    }
    found && (started || NF) { started = 1; print }
' "$changelog")

if [[ -z $section ]]; then
    echo "error: no '## [$1]' section with content in CHANGELOG.md." >&2
    exit 1
fi

printf '%s\n' "$section"
