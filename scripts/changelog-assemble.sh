#!/usr/bin/env bash
# Folds the fragments in changelog.d/ into a new "## [<version>] - <date>"
# section of CHANGELOG.md, directly below "## [Unreleased]", and deletes them.
# Every input is checked first: on any error nothing is changed.
# CHANGELOG and CHANGELOG_DIR override the defaults (used by the tests).
set -euo pipefail

# Keep a Changelog groups, in the order they appear in a section.
readonly categories=(added changed deprecated removed fixed security)
readonly titles=(Added Changed Deprecated Removed Fixed Security)
readonly issue_url=https://github.com/MHusted01/reachmap/issues
readonly unreleased='## [Unreleased]'

die() {
    echo "error: $*" >&2
    exit 1
}

check_version() {
    [[ $1 =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
        die "version '$1' is not X.Y.Z (e.g. 1.1.0, no 'v' and no pre-release)."
}

check_date() {
    [[ $1 =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})$ ]] ||
        die "date '$1' is not YYYY-MM-DD."
    local year=$((10#${BASH_REMATCH[1]})) month=$((10#${BASH_REMATCH[2]}))
    local day=$((10#${BASH_REMATCH[3]}))
    local days=(31 28 31 30 31 30 31 31 30 31 30 31)
    if ((year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))); then
        days[1]=29
    fi
    ((month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1])) ||
        die "date '$1' does not exist."
}

# Fails unless the changelog has "## [Unreleased]" and no section for $1 yet.
check_changelog() {
    [[ -f $changelog ]] || die "$changelog not found."
    awk -v heading="$unreleased" '$0 == heading { found = 1 } END { exit !found }' \
        "$changelog" || die "$changelog has no '$unreleased' heading."
    if awk -v heading="## [$1]" 'index($0, heading) == 1 { found = 1 } END { exit !found }' \
        "$changelog"; then
        die "$changelog already has a '## [$1]' section."
    fi
}

# Prints the position of category $1 in Keep a Changelog order.
category_rank() {
    local i
    for i in "${!categories[@]}"; do
        if [[ ${categories[i]} == "$1" ]]; then
            echo "$i"
            return 0
        fi
    done
    return 1
}

# A fragment is one Markdown bullet: "- " on the first line, two spaces on each
# continuation line, no blank lines, ending with the absolute link to issue $2.
check_fragment() {
    local path=$1 issue=$2 text link
    text=$(<"$path")
    [[ -n $text ]] || die "$path is empty."
    printf '%s\n' "$text" |
        awk 'NR == 1 ? !/^- [^[:space:]]/ : !/^  [^[:space:]]/ { bad = 1 } END { exit bad }' ||
        die "$path must hold one bullet: '- ' on the first line, two spaces on the others, no blank lines."
    link="([#$issue]($issue_url/$issue))."
    [[ $text == *"$link" ]] || die "$path must end with $link"
}

# Prints one "<rank> <issue> <path>" line per fragment, after checking it.
collect_fragments() {
    local path name rank
    for path in "$fragments_dir"/*; do
        [[ -e $path ]] || continue
        name=${path##*/}
        [[ -f $path && $name =~ ^([1-9][0-9]*)\.([a-z]+)\.md$ ]] ||
            die "$path is not named <issue>.<category>.md (e.g. 123.added.md)."
        rank=$(category_rank "${BASH_REMATCH[2]}") ||
            die "$path has unknown category '${BASH_REMATCH[2]}' (use one of: ${categories[*]})."
        check_fragment "$path" "${BASH_REMATCH[1]}"
        echo "$rank ${BASH_REMATCH[1]} $path"
    done
}

# Prints the new section from sorted "<rank> <issue> <path>" lines on stdin.
build_section() {
    local last_rank='' rank issue path
    printf '## [%s] - %s\n' "$version" "$date"
    while read -r rank issue path; do
        if [[ $rank != "$last_rank" ]]; then
            printf '\n### %s\n\n' "${titles[rank]}"
            last_rank=$rank
        fi
        printf '%s\n' "$(<"$path")"
    done
}

# Prints the changelog ($2) with the section ($1) inserted before the first
# version heading or link reference after "## [Unreleased]", or at the end.
insert_section() {
    awk -v heading="$unreleased" '
        NR == FNR { section = section $0 "\n"; next }
        below && !done && (index($0, "## [") == 1 || /^\[.*\]: /) {
            if (!blank) print ""
            printf "%s\n", section
            done = 1
        }
        { print; blank = ($0 == "") }
        $0 == heading { below = 1 }
        END {
            if (!done) {
                if (!blank) print ""
                printf "%s", section
            }
        }
    ' "$1" "$2"
}

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <version> <date>   (e.g. $0 1.1.0 2026-01-31)" >&2
    exit 2
fi

version=$1
date=$2
root="$(dirname "$0")/.."
changelog=${CHANGELOG:-"$root/CHANGELOG.md"}
fragments_dir=${CHANGELOG_DIR:-"$root/changelog.d"}

check_version "$version"
check_date "$date"
check_changelog "$version"
[[ -d $fragments_dir ]] || die "$fragments_dir not found."

# Command substitution runs in a subshell, so a failed check ends it with
# status 1 and the assignment fails, which stops this script too.
entries=$(collect_fragments)
[[ -n $entries ]] || die "no fragments in $fragments_dir; add one per change before a release."
sorted=$(sort -k1,1n -k2,2nr <<<"$entries")

section_file=''
new_changelog=''
trap 'rm -f "$section_file" "$new_changelog"' EXIT
section_file=$(mktemp)
build_section <<<"$sorted" >"$section_file"

# Write next to CHANGELOG.md with its permissions, then replace it in one step.
new_changelog=$(mktemp "$changelog.XXXXXX")
cp -p "$changelog" "$new_changelog"
insert_section "$section_file" "$changelog" >"$new_changelog"
mv "$new_changelog" "$changelog"

count=0
while read -r _ _ path; do
    rm -- "$path"
    count=$((count + 1))
done <<<"$sorted"
echo "Added '## [$version] - $date' to $changelog from $count fragments."
