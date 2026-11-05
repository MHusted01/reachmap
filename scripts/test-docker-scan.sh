#!/usr/bin/env bash
# Checks `reachmap scan` against a real Docker daemon: containers published on
# 127.0.0.1 and on all interfaces, with and without sudo, and a daemon that
# cannot be reached. Needs Linux, Docker access, passwordless sudo and UFW off.
# In GitHub Actions it then turns UFW on and repeats the checks that depend on
# it. That changes the host's firewall, so nowhere else does it run.
# Usage: scripts/test-docker-scan.sh target/debug/reachmap   (run by the CI test job)
set -euo pipefail

binary=$(realpath "$1")
image=busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
local_port=18080
all_port=18081
hostile_port=18082
names=(reachmap-test-local reachmap-test-all reachmap-test-hostile)
unreachable=unix:///nonexistent/docker.sock
# From the range reserved for documentation, so the rule matches no real host.
docker_user_rule=(DOCKER-USER -s 192.0.2.1 -j DROP)
ufw_conf=/etc/ufw/ufw.conf

cleanup() {
  if [[ -n "${firewall_changed:-}" ]]; then
    sudo iptables -D "${docker_user_rule[@]}" 2>/dev/null || true
    sudo ufw --force disable >/dev/null 2>&1 || true
  fi
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

# The UDP row for a port, from the output in $1.
udp_row() {
  awk -v port="$2" '$1 == port && $2 == "udp"' <<<"$1"
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
  [[ $(udp_row "$output" "$all_port") == *'container reachmap-test-all'* ]] ||
    fail "$label: no UDP row for the container" "$output"
  [[ $(grep -c '^note: UDP' <<<"$output") == 1 ]] || fail "$label: expected the UDP note" "$output"
  [[ "$output" != *$'\033'* ]] || fail "$label: an escape character reached the output" "$output"
  [[ "$output" != *'warning:'* ]] || fail "$label: UFW is off, so nothing to warn about" "$output"
  expect_in_row "$output" "$hostile_port" 127.0.0.1 '\u{1b}[2J' "$label"
  printf 'ok: %s\n' "$label"
}

# Scans with $DOCKER_HOST on a socket that does not exist; the scan must still
# succeed, with one note and no container rows.
expect_unreachable_note() {
  local label=$1 owner=$2 output
  shift 2
  output=$("$@" scan 2>&1) || fail "$label: the scan failed" "$output"
  [[ $(grep '^note: ' <<<"$output" | grep -vc '^note: UDP') == 1 ]] ||
    fail "$label: expected one note besides the UDP one" "$output"
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

# Scans and expects exit status 1, one warning line for exactly the port
# published on all interfaces, and a note on that port's row alone. $1 is the
# label, $2 the DOCKER-USER line to expect ('' for none), the rest the command.
expect_bypass_warning() {
  local label=$1 chain_line=$2 output status=0
  shift 2
  output=$("$@" scan 2>&1) || status=$?
  [[ $status == 1 ]] || fail "$label: expected exit status 1, got $status" "$output"
  grep -qx "warning: UFW is active, but it does not apply to these Docker ports: $all_port" \
    <<<"$output" || fail "$label: wrong UFW warning" "$output"
  expect_in_row "$output" "$all_port" 0.0.0.0 'Docker port: UFW does not apply' "$label"
  [[ $(udp_row "$output" "$all_port") == *'Docker port: UFW does not apply'* ]] ||
    fail "$label: the UDP port got no warning" "$output"
  [[ $(row "$output" "$local_port" 127.0.0.1) != *'UFW'* ]] || fail "$label: flagged a loopback port" "$output"
  [[ "${output,,}" != *protected* ]] || fail "$label: claimed protection" "$output"
  if [[ -n "$chain_line" ]]; then
    grep -qx "$chain_line" <<<"$output" || fail "$label: expected '$chain_line'" "$output"
  else
    [[ "$output" != *'DOCKER-USER'* ]] || fail "$label: unexpected chain line" "$output"
  fi
  printf 'ok: %s\n' "$label"
}

# With UFW on and Docker unknown, the scan must not look fine.
expect_docker_unknown_warning() {
  local output status=0
  output=$(env "DOCKER_HOST=$unreachable" "$binary" scan 2>&1) || status=$?
  [[ $status == 1 ]] || fail "unknown Docker: expected exit status 1, got $status" "$output"
  grep -q '^warning: UFW is active and Docker could not be asked' <<<"$output" ||
    fail 'unknown Docker: expected a warning' "$output"
  printf 'ok: active UFW, unknown Docker\n'
}

expect_active_ufw_warnings() {
  if [[ "${GITHUB_ACTIONS:-}" != true ]]; then
    printf 'skip: the UFW checks change the firewall, so they only run in CI\n'
    return
  fi
  sudo ufw version >/dev/null 2>&1 || sudo apt-get install -y -q ufw >/dev/null
  firewall_changed=1
  sudo ufw --force enable >/dev/null

  expect_bypass_warning 'active UFW, without sudo' \
    'warning: DOCKER-USER rules were not checked: run with sudo' "$binary"
  expect_bypass_warning 'active UFW, with sudo' '' sudo "$binary"
  sudo iptables -I "${docker_user_rule[@]}"
  expect_bypass_warning 'active UFW, rule in DOCKER-USER' \
    'warning: DOCKER-USER has rules, so filtering may apply, not verified' sudo "$binary"
  expect_docker_unknown_warning
}

if grep -qix 'enabled=yes' "$ufw_conf" 2>/dev/null; then
  fail 'UFW is active on this host; these checks start with it off, so run them in CI'
fi

docker run -d --rm --name reachmap-test-local -p "127.0.0.1:$local_port:80" \
  --label com.docker.compose.service=web "$image" sleep 300 >/dev/null
docker run -d --rm --name reachmap-test-all -p "$all_port:80" -p "$all_port:80/udp" \
  "$image" sleep 300 >/dev/null
docker run -d --rm --name reachmap-test-hostile -p "127.0.0.1:$hostile_port:80" \
  --label "com.docker.compose.service=$(printf 'evil\033[2J')" "$image" sleep 300 >/dev/null

expect_published_rows 'without sudo' "$binary"
expect_published_rows 'with sudo' sudo "$binary"
expect_unreachable_note 'unreachable daemon, without sudo' 'unknown' \
  env "DOCKER_HOST=$unreachable" "$binary"
expect_unreachable_note 'unreachable daemon, with sudo' 'docker-proxy' \
  sudo env "DOCKER_HOST=$unreachable" "$binary"
expect_sudo_hint
expect_active_ufw_warnings
