#!/usr/bin/env bash
# Checks `reachmap scan` against a real Docker daemon: containers published on
# 127.0.0.1 and on all interfaces, with and without sudo, and a daemon that
# cannot be reached. Needs Linux, Docker access and passwordless sudo.
# Usage: scripts/test-docker-scan.sh target/debug/reachmap   (run by the CI test job)
set -euo pipefail

binary=$(realpath "$1")
image=busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
local_port=18080
all_port=18081
hostile_port=18082
names=(reachmap-test-local reachmap-test-all reachmap-test-hostile)
unreachable=unix:///nonexistent/docker.sock

cleanup() {
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
  rm -rf "${scratch:-}"
}
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  printf '%s\n' "${2:-}" >&2
  exit 1
}

# The row for a port and address, from the output in $1.
row() {
  awk -v port="$2" -v address="$3" '$1 == port && $3 == address' <<<"$1"
}

expect_in_row() {
  local output=$1 port=$2 address=$3 expected=$4 label=$5
  local found
  found=$(row "$output" "$port" "$address")
  [[ -n "$found" ]] || fail "$label: no row for $address:$port" "$output"
  [[ "$found" == *"$expected"* ]] || fail "$label: expected '$expected' in: $found" "$output"
}

expect_published_rows() {
  local label=$1 output
  shift
  output=$("$@" scan)
  expect_in_row "$output" "$local_port" 127.0.0.1 'web (container reachmap-test-local)' "$label"
  expect_in_row "$output" "$local_port" 127.0.0.1 'loopback address' "$label"
  expect_in_row "$output" "$all_port" 0.0.0.0 'container reachmap-test-all' "$label"
  expect_in_row "$output" "$all_port" 0.0.0.0 'all IPv4 addresses' "$label"
  [[ "$output" != *$'\033'* ]] || fail "$label: an escape character reached the output" "$output"
  expect_in_row "$output" "$hostile_port" 127.0.0.1 '\u{1b}[2J' "$label"
  printf 'ok: %s\n' "$label"
}

# Scans with $DOCKER_HOST on a socket that does not exist; the scan must still
# succeed, with one note and no container rows.
expect_unreachable_note() {
  local label=$1 owner=$2 output
  shift 2
  output=$("$@" scan 2>&1) || fail "$label: the scan failed" "$output"
  [[ $(grep -c '^note: ' <<<"$output") == 1 ]] || fail "$label: expected one note" "$output"
  grep -q '^note: could not ask Docker' <<<"$output" || fail "$label: wrong note" "$output"
  [[ "$output" != *'(container '* ]] || fail "$label: showed a container" "$output"
  expect_in_row "$output" "$local_port" 127.0.0.1 "$owner" "$label"
  printf 'ok: %s\n' "$label"
}

# A user without access to Docker's socket gets the sudo hint. The binary is
# copied because the checkout may not be readable by that user.
expect_sudo_hint() {
  local output
  scratch=$(mktemp -d)
  chmod 755 "$scratch"
  cp "$binary" "$scratch/reachmap"
  chmod 755 "$scratch/reachmap"
  output=$(sudo -u nobody "$scratch/reachmap" scan 2>&1) ||
    fail 'no Docker access: the scan failed' "$output"
  grep -q '^note: could not ask Docker' <<<"$output" ||
    fail 'no Docker access: expected a note' "$output"
  grep -q '^hint: run with sudo' <<<"$output" ||
    fail 'no Docker access: expected the sudo hint' "$output"
  printf 'ok: no Docker access\n'
}

docker run -d --rm --name reachmap-test-local -p "127.0.0.1:$local_port:80" \
  --label com.docker.compose.service=web "$image" sleep 300 >/dev/null
docker run -d --rm --name reachmap-test-all -p "$all_port:80" "$image" sleep 300 >/dev/null
docker run -d --rm --name reachmap-test-hostile -p "127.0.0.1:$hostile_port:80" \
  --label "com.docker.compose.service=$(printf 'evil\033[2J')" "$image" sleep 300 >/dev/null

expect_published_rows 'without sudo' "$binary"
expect_published_rows 'with sudo' sudo "$binary"
expect_unreachable_note 'unreachable daemon, without sudo' 'unknown' \
  env "DOCKER_HOST=$unreachable" "$binary"
expect_unreachable_note 'unreachable daemon, with sudo' 'docker-proxy' \
  sudo env "DOCKER_HOST=$unreachable" "$binary"
expect_sudo_hint
