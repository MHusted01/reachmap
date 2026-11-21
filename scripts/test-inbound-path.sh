#!/usr/bin/env bash
# Exercise Linux inbound predictions in a fresh network and mount namespace.
set -euo pipefail

binary=$(realpath "${1:?pass the path to the reachmap binary}")
namespace=$(readlink /proc/self/ns/net)
if [[ -z ${2:-} ]]; then
  exec unshare --mount --net --propagation private "$0" "$binary" "$namespace"
fi
[[ $namespace != "$2" ]] || { printf '%s\n' 'Network isolation failed.' >&2; exit 1; }

scratch=$(mktemp -d)
client="reachmap-path-$BASHPID"
pids=()
client_created=false
cleanup() {
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [[ $client_created == true ]]; then
    ip netns del "$client"
  fi
  rm -r -- "$scratch"
}
trap cleanup EXIT

ip netns add "$client"
client_created=true
ip link set lo up
ip link add rmhost type veth peer name rmpeer netns "$client"
ip link set rmhost up
ip addr add 192.0.2.1/24 dev rmhost
ip -6 addr add 2001:db8::1/64 dev rmhost nodad
ip -n "$client" link set lo up
ip -n "$client" link set rmpeer up
ip -n "$client" addr add 192.0.2.2/24 dev rmpeer
ip -n "$client" -6 addr add 2001:db8::2/64 dev rmpeer nodad

port=24443
for destination in 192.0.2.1 2001:db8::1; do
  python3 -m http.server "$port" --bind "$destination" >"$scratch/server-${#pids[@]}" 2>&1 &
  pids+=("$!")
done

probe() {
  ip netns exec "$client" "$binary" probe "$1" --ports "$port" --timeout 0.4 --json
}

prediction() {
  local mode=$1 destination=$2 source=$3
  shift 3
  "$binary" path "$mode" --host-ref test-host --source "$source" --ingress rmhost \
    --destination "$destination" --port "$port" "$@"
}

assert_json() {
  local output=$1 filter=$2
  if ! jq -e "$filter" <<<"$output" >/dev/null; then
    printf 'Expected %s in output:\n%s\n' "$filter" "$output" >&2
    exit 1
  fi
}

check_family() {
  local destination=$1 source=$2 report initially_open=false
  for _ in {1..20}; do
    if probe "$destination" | jq -e '.results[0].result.kind == "open"' >/dev/null; then
      initially_open=true
      break
    fi
    sleep 0.1
  done
  if [[ $initially_open != true ]]; then
    cat "$scratch"/server-* >&2
    printf 'Listener never opened at %s\n' "$destination" >&2
    exit 1
  fi
  report=$(prediction predict "$destination" "$source" --json)
  assert_json "$report" '.verdict == "listener_reachable" and .steps[1].stage == "routing"
    and .steps[2].stage == "input" and .steps[3].listeners[0].inode > 0'
  prediction capture "$destination" "$source" >"$scratch/path.json"
  # Replaying from an empty network namespace demonstrates it uses the file only.
  report=$(unshare --net "$binary" path replay "$scratch/path.json" --json)
  assert_json "$report" '.verdict == "listener_reachable" and .steps[3].listeners[0].inode > 0'
}

check_blocked() {
  local destination=$1 source=$2 report
  report=$(prediction predict "$destination" "$source" --json)
  assert_json "$report" '.verdict == "blocked" and .steps[-1].stage == "input"'
  assert_json "$(probe "$destination")" '.results[0].result.kind == "no_answer"'
}

nft add table inet sample
nft 'add chain inet sample input { type filter hook input priority 0; policy accept; }'
check_family 192.0.2.1 192.0.2.2
check_family 2001:db8::1 2001:db8::2

nft add rule inet sample input tcp dport "$port" drop
check_blocked 192.0.2.1 192.0.2.2
check_blocked 2001:db8::1 2001:db8::2

nft flush chain inet sample input
nft add rule inet sample input ct state new drop
report=$(prediction predict 192.0.2.1 192.0.2.2 --json)
assert_json "$report" '.verdict == "unknown" and .steps[-1].stage == "input"'
assert_json "$(probe 192.0.2.1)" '.results[0].result.kind == "no_answer"'

nft 'add chain inet sample pre { type filter hook prerouting priority -150; policy accept; }'
report=$(prediction predict 2001:db8::1 2001:db8::2 --json)
assert_json "$report" '.verdict == "unknown" and .steps[-1].stage == "ingress"
  and (.steps[-1].reason | contains("prerouting"))'

printf '%s\n' 'Linux TCP predictions matched IPv4 and IPv6 connections and identified unsupported stages.'
