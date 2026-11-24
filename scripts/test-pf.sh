#!/usr/bin/env bash
# Verify macOS pf verdicts from `reachmap scan --json` against real pf rules and
# live TCP/UDP connection attempts on a disposable macOS runner.
# Never run on a developer machine: requires a GitHub-hosted runner
# (GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted) or --allow-pf-changes.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/test-pf.sh [--allow-pf-changes] <path-to-reachmap-binary>

Runs end-to-end macOS pf verification against live TCP and UDP listeners on a
dedicated loopback alias (127.0.0.2) and pf anchor (reachmap-test).

Safety guard:
  Refuses to modify pf unless running on a GitHub-hosted runner
  (GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted) or
  --allow-pf-changes is passed. Never run on a workstation or production Mac.
EOF
}

allow_pf_changes=false
binary_arg=""

while (($# > 0)); do
  case "$1" in
    --allow-pf-changes)
      allow_pf_changes=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      printf 'error: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ -n $binary_arg ]]; then
        printf 'error: unexpected extra argument: %s\n' "$1" >&2
        usage >&2
        exit 2
      fi
      binary_arg=$1
      shift
      ;;
  esac
done

if [[ -z $binary_arg ]]; then
  printf 'error: missing path to reachmap binary\n' >&2
  usage >&2
  exit 2
fi

if [[ $(uname -s) != Darwin ]]; then
  printf 'error: scripts/test-pf.sh requires macOS (Darwin); found %s\n' "$(uname -s)" >&2
  exit 1
fi

if [[ ( ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ) || $allow_pf_changes == true ]]; then
  :
else
  printf '%s\n' \
    'Refusing to modify pf outside a GitHub-hosted runner (GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted). Pass --allow-pf-changes only on a disposable macOS VM.' >&2
  exit 1
fi

if [[ ! -f $binary_arg || ! -x $binary_arg ]]; then
  printf 'error: reachmap binary is missing or not executable: %s\n' "$binary_arg" >&2
  exit 1
fi

for cmd in jq python3 shasum; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf 'error: required command not found: %s\n' "$cmd" >&2
    exit 1
  fi
done

for sysbin in /sbin/pfctl /sbin/ifconfig; do
  if [[ ! -x $sysbin ]]; then
    printf 'error: required macOS system binary not found: %s\n' "$sysbin" >&2
    exit 1
  fi
done

binary=$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$binary_arg")

if [[ $EUID -eq 0 ]]; then
  unpriv_user=${SUDO_USER:-nobody}
  if [[ -z $unpriv_user || $unpriv_user == root ]]; then
    unpriv_user=nobody
  fi
  run_unpriv() {
    sudo -u "$unpriv_user" "$@"
  }
  run_priv() {
    "$@"
  }
else
  if ! sudo -n true >/dev/null 2>&1; then
    printf 'error: passwordless sudo (or prior sudo credentials) required to manage pfctl and run privileged reachmap scans\n' >&2
    exit 1
  fi
  run_unpriv() {
    "$@"
  }
  run_priv() {
    sudo -n "$@"
  }
fi

readonly test_ip="127.0.0.2"
readonly port_a=24443
readonly port_b=24444
readonly anchor_name="reachmap-test"

scratch=$(mktemp -d)
listener_pid=""
added_alias=false
initial_enabled=false
pf_state_recorded=false

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  if (($# > 1)) && [[ -n $2 ]]; then
    printf '%s\n' "$2" >&2
  fi
  exit 1
}

pf_is_enabled() {
  run_priv /sbin/pfctl -s info 2>/dev/null | grep -Eq '^Status:[[:space:]]*Enabled'
}

pf_enable() {
  if ! pf_is_enabled; then
    run_priv /sbin/pfctl -e >/dev/null 2>&1
  fi
}

pf_disable() {
  if pf_is_enabled; then
    run_priv /sbin/pfctl -d >/dev/null 2>&1
  fi
}

flush_lab_states() {
  run_priv /sbin/pfctl -k "$test_ip" >/dev/null 2>&1 &&
    run_priv /sbin/pfctl -k 0.0.0.0/0 -k "$test_ip" >/dev/null 2>&1
}

verify_stock_baseline() {
  local anchors rules ifaces line trimmed
  [[ -r /etc/pf.conf ]] || fail "missing readable /etc/pf.conf; refusing to modify pf without a restorable stock baseline"

  anchors=$(run_priv /sbin/pfctl -sA 2>/dev/null) || fail "failed to inspect pfctl -sA before test run"
  while IFS= read -r line; do
    trimmed=${line#"${line%%[![:space:]]*}"}
    trimmed=${trimmed#/}
    [[ -z $trimmed ]] && continue
    if [[ $trimmed != com.apple ]]; then
      fail "non-stock pf anchor '$trimmed' is already loaded; refusing to overwrite custom pf state" "$anchors"
    fi
  done <<<"$anchors"

  rules=$(run_priv /sbin/pfctl -sr 2>/dev/null) || fail "failed to inspect pfctl -sr before test run"
  while IFS= read -r line; do
    trimmed=${line#"${line%%[![:space:]]*}"}
    [[ -z $trimmed || $trimmed == \#* ]] && continue
    case "$trimmed" in
      'scrub-anchor "com.apple/*"'*|'anchor "com.apple/*"'*|'dummynet-anchor "com.apple/*"'*) ;;
      *)
        fail "non-stock main pf rule detected: '$trimmed'; refusing to overwrite custom pf ruleset" "$rules"
        ;;
    esac
  done <<<"$rules"

  ifaces=$(run_priv /sbin/pfctl -v -s Interfaces 2>/dev/null) || fail "failed to inspect pfctl -v -s Interfaces before test run"
  if grep -Fq '(skip)' <<<"$ifaces"; then
    fail "pf already has skipped interfaces before test run; refusing to overwrite custom pf state" "$ifaces"
  fi
}

cleanup() {
  local rc=$? cleanup_failed=0
  trap - EXIT INT TERM
  set +e
  if [[ -n $listener_pid ]]; then
    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true
  fi
  if [[ $pf_state_recorded == true ]]; then
    if ! run_priv /sbin/pfctl -a "$anchor_name" -F all >/dev/null 2>&1; then
      printf 'cleanup error: failed to flush anchor %s\n' "$anchor_name" >&2
      cleanup_failed=1
    fi
    if ! flush_lab_states; then
      printf 'cleanup error: failed to flush pf states for %s\n' "$test_ip" >&2
      cleanup_failed=1
    fi
    if ! run_priv /sbin/pfctl -f /etc/pf.conf >/dev/null 2>&1; then
      printf 'cleanup error: failed to reload /etc/pf.conf\n' >&2
      cleanup_failed=1
    fi
    if [[ $initial_enabled == true ]]; then
      pf_enable || cleanup_failed=1
      if ! pf_is_enabled; then
        printf 'cleanup error: failed to restore pf enabled state\n' >&2
        cleanup_failed=1
      fi
    else
      pf_disable || cleanup_failed=1
      if pf_is_enabled; then
        printf 'cleanup error: failed to restore pf disabled state\n' >&2
        cleanup_failed=1
      fi
    fi
  fi
  if [[ $added_alias == true ]]; then
    if ! run_priv /sbin/ifconfig lo0 -alias "$test_ip" >/dev/null 2>&1; then
      printf 'cleanup error: failed to remove alias %s from lo0\n' "$test_ip" >&2
      cleanup_failed=1
    elif /sbin/ifconfig lo0 | grep -Fq "inet $test_ip "; then
      printf 'cleanup error: alias %s still present on lo0 after cleanup\n' "$test_ip" >&2
      cleanup_failed=1
    fi
  fi
  if [[ -d $scratch ]] && ! rm -r -- "$scratch" 2>/dev/null; then
    printf 'cleanup error: failed to remove scratch directory %s\n' "$scratch" >&2
    cleanup_failed=1
  fi
  if [[ $rc -eq 0 && $cleanup_failed -ne 0 ]]; then
    exit 1
  fi
  exit "$rc"
}
trap 'exit 130' INT
trap 'exit 143' TERM
trap cleanup EXIT

printf '=== Environment ===\n'
sw_vers
uname -a
"$binary" --version
ls -l /sbin/pfctl
shasum -a 256 /sbin/pfctl
what /sbin/pfctl 2>/dev/null || true
printf '=== Initial pfctl -s info ===\n'
run_priv /sbin/pfctl -s info || true

verify_stock_baseline

if pf_is_enabled; then
  initial_enabled=true
fi
pf_state_recorded=true

if ! /sbin/ifconfig lo0 | grep -Fq "inet $test_ip "; then
  run_priv /sbin/ifconfig lo0 alias "$test_ip" up
  added_alias=true
fi

cat >"$scratch/listeners.py" <<'PY'
import socketserver
import sys
import threading

ip = sys.argv[1]
ports = [int(p) for p in sys.argv[2:]]


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(64)
        if data:
            self.request.sendall(data)


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        if data:
            sock.sendto(data, self.client_address)


class ReusableTcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ReusableUdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


servers = []
for port in ports:
    tcp_srv = ReusableTcpServer((ip, port), TcpEcho)
    udp_srv = ReusableUdpServer((ip, port), UdpEcho)
    servers.extend((tcp_srv, udp_srv))
    threading.Thread(target=tcp_srv.serve_forever, daemon=True).start()
    threading.Thread(target=udp_srv.serve_forever, daemon=True).start()

print("READY", flush=True)
threading.Event().wait()
PY

python3 "$scratch/listeners.py" "$test_ip" "$port_a" "$port_b" >"$scratch/listeners.out" 2>"$scratch/listeners.err" &
listener_pid=$!

probe_tcp() {
  local ip=$1 port=$2
  python3 - "$ip" "$port" <<'PY'
import socket
import sys

ip = sys.argv[1]
port = int(sys.argv[2])
try:
    with socket.create_connection((ip, port), timeout=0.8) as sock:
        sock.settimeout(0.8)
        sock.sendall(b"ping\n")
        reply = sock.recv(16)
        print("open" if reply == b"ping\n" else "error:unexpected_reply")
except TimeoutError:
    print("blocked")
except OSError as exc:
    print(f"error:{type(exc).__name__}:{exc.errno}")
PY
}

probe_udp() {
  local ip=$1 port=$2
  python3 - "$ip" "$port" <<'PY'
import socket
import sys

ip = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.8)
try:
    sock.connect((ip, port))
    sock.send(b"ping")
    reply = sock.recv(16)
    print("open" if reply == b"ping" else "error:unexpected_reply")
except TimeoutError:
    print("blocked")
except OSError as exc:
    print(f"error:{type(exc).__name__}:{exc.errno}")
finally:
    sock.close()
PY
}

probe_proto() {
  local proto=$1 port=$2 result
  if ! kill -0 "$listener_pid" 2>/dev/null; then
    fail "test listener process exited unexpectedly before $proto/$port probe"
  fi
  case "$proto" in
    tcp) result=$(probe_tcp "$test_ip" "$port") ;;
    udp) result=$(probe_udp "$test_ip" "$port") ;;
    *) fail "internal error: unknown proto $proto" ;;
  esac
  if [[ $result == error:* ]]; then
    fail "probe $proto/$port failed unexpectedly ($result)"
  fi
  printf '%s\n' "$result"
}

anchor_block_packets() {
  local proto=$1 out
  out=$(run_priv /sbin/pfctl -a "$anchor_name" -v -sr 2>/dev/null) ||
    fail "failed to read pfctl counters for anchor $anchor_name"
  awk -v proto="$proto" '
    /^[^[:space:]]/ {
      in_block = ($0 ~ /^block / && $0 ~ (" proto " proto "([[:space:]]|$)"))
      next
    }
    in_block && match($0, /Packets:[[:space:]]*[0-9]+/) {
      val = substr($0, RSTART, RLENGTH)
      sub(/^Packets:[[:space:]]*/, "", val)
      sum += val + 0
    }
    END { printf "%d\n", sum + 0 }
  ' <<<"$out"
}

probe_with_drop_check() {
  local case_name=$1 proto=$2 port=$3 expected_obs=$4
  local before_drops=0 after_drops=0 obs
  if [[ $expected_obs == blocked ]]; then
    before_drops=$(anchor_block_packets "$proto")
  fi
  obs=$(probe_proto "$proto" "$port")
  if [[ $expected_obs == blocked ]]; then
    after_drops=$(anchor_block_packets "$proto")
    if ((after_drops <= before_drops)); then
      local counters
      counters=$(run_priv /sbin/pfctl -a "$anchor_name" -v -sr 2>/dev/null || true)
      fail "$case_name ($proto/$port): probe returned '$obs' without incrementing pf block packet counters (before=$before_drops, after=$after_drops)" "$counters"
    fi
  fi
  printf '%s\n' "$obs"
}

load_ruleset() {
  local main_conf=$1 anchor_conf=$2
  run_priv /sbin/pfctl -f "$main_conf" >/dev/null 2>&1
  if [[ -n $anchor_conf ]]; then
    run_priv /sbin/pfctl -a "$anchor_name" -f "$anchor_conf" >/dev/null 2>&1
  else
    run_priv /sbin/pfctl -a "$anchor_name" -F all >/dev/null 2>&1 || true
  fi
  pf_enable
  flush_lab_states
}

write_main_conf() {
  local path=$1 skip_lo0=$2
  {
    if [[ $skip_lo0 == true ]]; then
      printf 'set skip on lo0\n'
    fi
    cat <<EOF
scrub in all fragment reassemble
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
anchor "$anchor_name"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
EOF
  } >"$path"
}

scan_priv_json() {
  local out
  if ! out=$(run_priv "$binary" scan --json); then
    fail "privileged reachmap scan --json exited non-zero" "$out"
  fi
  printf '%s' "$out"
}

scan_unpriv_json() {
  local out
  if ! out=$(run_unpriv "$binary" scan --json); then
    fail "unprivileged reachmap scan --json exited non-zero" "$out"
  fi
  printf '%s' "$out"
}

pf_status() {
  jq -er '.macos.pf.status' <<<"$1"
}

pf_port_verdict() {
  local json=$1 port=$2 proto=$3
  jq -er --argjson port "$port" --arg proto "$proto" --arg addr "$test_ip" '
    .macos.pf.ports[]
    | select(.port == $port and .protocol == $proto and .address == $addr and .family == "ipv4")
    | .interfaces[]
    | select(.interface == "lo0")
    | .verdict
  ' <<<"$json"
}

pf_port_reason() {
  local json=$1 port=$2 proto=$3
  jq -er --argjson port "$port" --arg proto "$proto" --arg addr "$test_ip" '
    .macos.pf.ports[]
    | select(.port == $port and .protocol == $proto and .address == $addr and .family == "ipv4")
    | .interfaces[]
    | select(.interface == "lo0")
    | .reason
  ' <<<"$json"
}

assert_case_port() {
  local case_name=$1 json=$2 proto=$3 port=$4 expected_verdict=$5 expected_obs=$6 reason_substr=${7:-}
  local actual_verdict actual_reason actual_obs
  actual_verdict=$(pf_port_verdict "$json" "$port" "$proto") ||
    fail "$case_name ($proto/$port): missing lo0 pf verdict in scan JSON" "$json"
  actual_reason=$(pf_port_reason "$json" "$port" "$proto") ||
    fail "$case_name ($proto/$port): missing lo0 pf reason in scan JSON" "$json"
  actual_obs=$(probe_with_drop_check "$case_name" "$proto" "$port" "$expected_obs")

  if [[ $actual_verdict != "$expected_verdict" ]]; then
    fail "$case_name ($proto/$port): reachmap verdict='$actual_verdict' (reason='$actual_reason'), expected='$expected_verdict', observed='$actual_obs'"
  fi
  if [[ $actual_obs != "$expected_obs" ]]; then
    fail "$case_name ($proto/$port): observed connection='$actual_obs', expected='$expected_obs', reachmap verdict='$actual_verdict' (reason='$actual_reason')"
  fi
  if [[ -n $reason_substr && $actual_reason != *"$reason_substr"* ]]; then
    fail "$case_name ($proto/$port): reachmap reason='$actual_reason' did not contain '$reason_substr' (verdict='$actual_verdict', observed='$actual_obs')"
  fi
  printf '  ok: %s %s/%d -> reachmap=%s (%s), observed=%s\n' \
    "$case_name" "$proto" "$port" "$actual_verdict" "$actual_reason" "$actual_obs"
}

# Wait until all four listeners answer when pf is disabled for baseline readiness.
pf_disable
ready=false
for _ in $(seq 1 25); do
  if [[ $(probe_tcp "$test_ip" "$port_a") == open &&
        $(probe_udp "$test_ip" "$port_a") == open &&
        $(probe_tcp "$test_ip" "$port_b") == open &&
        $(probe_udp "$test_ip" "$port_b") == open ]]; then
    ready=true
    break
  fi
  sleep 0.2
done
if [[ $ready != true ]]; then
  cat "$scratch/listeners.err" >&2 || true
  fail "test listeners on $test_ip:$port_a,$port_b did not become ready"
fi

# Case 1: pf disabled
printf 'Case 1: pf disabled\n'
pf_disable
json=$(scan_priv_json)
status=$(pf_status "$json")
obs_tcp_a=$(probe_proto tcp "$port_a")
obs_udp_a=$(probe_proto udp "$port_a")
obs_tcp_b=$(probe_proto tcp "$port_b")
obs_udp_b=$(probe_proto udp "$port_b")
[[ $status == disabled ]] ||
  fail "Case 1: reachmap pf status='$status' (expected disabled); observed probes tcp/$port_a=$obs_tcp_a udp/$port_a=$obs_udp_a tcp/$port_b=$obs_tcp_b udp/$port_b=$obs_udp_b" "$json"
for pair in "tcp:$port_a:$obs_tcp_a" "udp:$port_a:$obs_udp_a" "tcp:$port_b:$obs_tcp_b" "udp:$port_b:$obs_udp_b"; do
  IFS=: read -r proto port obs <<<"$pair"
  [[ $obs == open ]] || fail "Case 1 ($proto/$port): reachmap pf status='$status', observed='$obs' (expected open)"
  printf '  ok: pf_disabled %s/%d -> reachmap=disabled, observed=%s\n' "$proto" "$port" "$obs"
done

# Case 2: pf enabled with default anchors (/etc/pf.conf)
printf 'Case 2: pf enabled with default anchors\n'
run_priv /sbin/pfctl -a "$anchor_name" -F all >/dev/null 2>&1 || true
run_priv /sbin/pfctl -f /etc/pf.conf >/dev/null 2>&1
pf_enable
flush_lab_states
json=$(scan_priv_json)
status=$(pf_status "$json")
[[ $status == enabled ]] || fail "Case 2: expected pf status=enabled, got status='$status'" "$json"
for proto in tcp udp; do
  assert_case_port "default_anchors" "$json" "$proto" "$port_a" pass open
  assert_case_port "default_anchors" "$json" "$proto" "$port_b" pass open
done

# Case 3: block in default with a pass exception for one port
printf 'Case 3: block in default with pass exception\n'
write_main_conf "$scratch/main_noskip.conf" false
cat >"$scratch/case3_anchor.conf" <<EOF
block drop in on lo0 inet proto tcp from any to $test_ip
block drop in on lo0 inet proto udp from any to $test_ip
pass in on lo0 inet proto tcp from any to $test_ip port $port_a
pass in on lo0 inet proto udp from any to $test_ip port $port_a
EOF
load_ruleset "$scratch/main_noskip.conf" "$scratch/case3_anchor.conf"
json=$(scan_priv_json)
for proto in tcp udp; do
  assert_case_port "block_with_pass_exception" "$json" "$proto" "$port_a" pass open
  assert_case_port "block_with_pass_exception" "$json" "$proto" "$port_b" block blocked
done

# Case 4: quick ordering vs last-match-wins
printf 'Case 4: quick ordering\n'
cat >"$scratch/case4_anchor.conf" <<EOF
block drop in quick on lo0 inet proto tcp from any to $test_ip port $port_b
block drop in quick on lo0 inet proto udp from any to $test_ip port $port_b
pass in on lo0 inet proto tcp from any to $test_ip port $port_b
pass in on lo0 inet proto udp from any to $test_ip port $port_b
block drop in on lo0 inet proto tcp from any to $test_ip port $port_a
block drop in on lo0 inet proto udp from any to $test_ip port $port_a
pass in on lo0 inet proto tcp from any to $test_ip port $port_a
pass in on lo0 inet proto udp from any to $test_ip port $port_a
EOF
load_ruleset "$scratch/main_noskip.conf" "$scratch/case4_anchor.conf"
json=$(scan_priv_json)
for proto in tcp udp; do
  assert_case_port "quick_ordering" "$json" "$proto" "$port_a" pass open
  assert_case_port "quick_ordering" "$json" "$proto" "$port_b" block blocked
done

# Case 5: set skip on lo0
printf 'Case 5: set skip on lo0\n'
write_main_conf "$scratch/main_skip.conf" true
cat >"$scratch/case5_anchor.conf" <<EOF
block drop in on lo0 inet proto tcp from any to $test_ip
block drop in on lo0 inet proto udp from any to $test_ip
EOF
load_ruleset "$scratch/main_skip.conf" "$scratch/case5_anchor.conf"
json=$(scan_priv_json)
for proto in tcp udp; do
  assert_case_port "set_skip_lo0" "$json" "$proto" "$port_a" pass open "set skip"
  assert_case_port "set_skip_lo0" "$json" "$proto" "$port_b" pass open "set skip"
done

# Case 6: rule using a table (explicit unknown)
printf 'Case 6: rule using a pf table (explicit unknown)\n'
cat >"$scratch/case6_anchor.conf" <<EOF
table <lab_targets> const { $test_ip }
pass in quick on lo0 inet proto tcp from any to $test_ip port $port_a
pass in quick on lo0 inet proto udp from any to $test_ip port $port_a
block drop in on lo0 inet proto tcp from any to <lab_targets> port $port_b
block drop in on lo0 inet proto udp from any to <lab_targets> port $port_b
EOF
load_ruleset "$scratch/main_noskip.conf" "$scratch/case6_anchor.conf"
json=$(scan_priv_json)
for proto in tcp udp; do
  assert_case_port "table_unknown" "$json" "$proto" "$port_a" pass open
  assert_case_port "table_unknown" "$json" "$proto" "$port_b" unknown blocked "table"
done

# Case 7: run without sudo (evidence gap)
printf 'Case 7: run without sudo (evidence gap)\n'
unpriv_uid=$(run_unpriv id -u)
[[ $unpriv_uid -ne 0 ]] || fail "Case 7: unprivileged scan user resolved to UID 0"
load_ruleset "$scratch/main_noskip.conf" "$scratch/case3_anchor.conf"
json=$(scan_unpriv_json)
status=$(pf_status "$json")
reason=$(jq -er '.macos.pf.reason' <<<"$json") ||
  fail "Case 7: missing .macos.pf.reason in unprivileged scan JSON" "$json"
obs_tcp_a=$(probe_with_drop_check "no_sudo" tcp "$port_a" open)
obs_udp_a=$(probe_with_drop_check "no_sudo" udp "$port_a" open)
obs_tcp_b=$(probe_with_drop_check "no_sudo" tcp "$port_b" blocked)
obs_udp_b=$(probe_with_drop_check "no_sudo" udp "$port_b" blocked)
[[ $status == unknown ]] ||
  fail "Case 7: reachmap pf status='$status' (reason='$reason', expected unknown); observed probes tcp/$port_a=$obs_tcp_a udp/$port_a=$obs_udp_a tcp/$port_b=$obs_tcp_b udp/$port_b=$obs_udp_b" "$json"
[[ $reason == *sudo* || $reason == *"root privileges"* ]] ||
  fail "Case 7: reachmap pf reason='$reason' did not mention sudo/root privileges; observed probes tcp/$port_a=$obs_tcp_a udp/$port_a=$obs_udp_a tcp/$port_b=$obs_tcp_b udp/$port_b=$obs_udp_b" "$json"
for pair in "tcp:$port_a:$obs_tcp_a:open" "udp:$port_a:$obs_udp_a:open" "tcp:$port_b:$obs_tcp_b:blocked" "udp:$port_b:$obs_udp_b:blocked"; do
  IFS=: read -r proto port obs expected <<<"$pair"
  [[ $obs == "$expected" ]] ||
    fail "Case 7 ($proto/$port): reachmap pf status='$status' (reason='$reason'), observed='$obs' (expected $expected)"
  printf '  ok: no_sudo %s/%d -> reachmap=%s (%s), observed=%s\n' "$proto" "$port" "$status" "$reason" "$obs"
done

printf 'All 7 macOS pf verification cases passed.\n'
