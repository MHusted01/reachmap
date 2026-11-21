#!/usr/bin/env bash
# Exercise kernel DNAT in an isolated daemon and network namespace.
set -euo pipefail

if [[ ${1:-} != --inside-lab ]]; then
    binary=$(realpath "${1:?Usage: test-docker-path.sh STATIC_LINUX_REACHMAP_BINARY}")
    script=$(realpath "$0")
    # Use the pinned Docker 29.1.3 image and its native nftables backend.
    exec docker run --rm --privileged \
        --mount "type=bind,source=$binary,target=/reachmap,readonly" \
        --mount "type=bind,source=$script,target=/test-docker-path.sh,readonly" \
        --entrypoint /bin/sh \
        docker:29.1.3-dind@sha256:173f284a4299164772a90f52b373e73e087583c0963f1334c9995f190ef6f3f5 \
        -ec 'apk add --no-cache bash iproute2 nftables jq && exec bash /test-docker-path.sh --inside-lab'
fi

if [[ ! -x /reachmap || ! -f /.dockerenv ]]; then
    echo 'Run this test through its disposable Docker lab.' >&2
    exit 1
fi
sysctl -w net.ipv4.ip_forward=1
dockerd --firewall-backend=nftables --userland-proxy=false \
    --storage-driver=vfs --bip=198.51.100.1/24 >/tmp/dockerd.log 2>&1 &
daemon=$!
trap 'kill "$daemon" 2>/dev/null || true' EXIT
for _ in {1..40}; do
    if docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$daemon" 2>/dev/null; then
        break
    fi
    sleep 0.25
done
if ! docker version --format 'Docker Engine {{.Server.Version}}'; then
    cat /tmp/dockerd.log >&2
    exit 1
fi
backend=$(docker info --format '{{.FirewallBackend.Driver}}')
echo "Firewall backend $backend"
[[ $backend == nftables ]]

ip netns add reachmap-client
ip link add entry0 type veth peer name client0 netns reachmap-client
ip address add 192.0.2.1/24 dev entry0
ip link set entry0 up
ip -n reachmap-client link set lo up
ip -n reachmap-client address add 192.0.2.2/24 dev client0
ip -n reachmap-client link set client0 up

web_image=busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
web_command='echo reachmap-test >/tmp/index.html; exec httpd -f -p 8080 -h /tmp'

connect() {
    ip netns exec reachmap-client wget -q -O - -T 2 "http://192.0.2.1:$1/"
}

assert_path() {
    local kind=$1 port=$2 address=$3 bridge=$4
    local args=(--host-ref example-host --source 192.0.2.2 --ingress entry0 --destination 192.0.2.1 --port "$port")
    /reachmap path predict "${args[@]}" --json >"/tmp/$kind-live.json"
    /reachmap path capture "${args[@]}" >"/tmp/$kind-snapshot.json"
    ip netns exec reachmap-client /reachmap path replay "/tmp/$kind-snapshot.json" --json >"/tmp/$kind-replay.json"
    for source in live replay; do
        jq -e --arg verdict "$kind" --arg target "$address:8080" \
            --arg original "192.0.2.1:$port" --arg bridge "$bridge" '
            .verdict == $verdict and
            .steps[1].translation == {original:$original,translated:$target} and
            .steps[2].stage == "routing" and (.steps[2].reason | endswith(" through " + $bridge)) and
            (if $verdict == "blocked" then
                .steps[-1].stage == "forward" and (.steps[-1].reason | contains("test_policy"))
             else
                any(.steps[]; .stage == "forward" and .decision == "continue") and
                .steps[-1].stage == "socket" and (.steps[-1].listeners | length > 0)
             end)
        ' "/tmp/$kind-$source.json" || { cat "/tmp/$kind-$source.json" >&2; return 1; }
    done
    diff -u <(jq -S '.steps' "/tmp/$kind-live.json") <(jq -S '.steps' "/tmp/$kind-replay.json")
}

test_publish() {
    local port=$1 address=$2 bridge=$3
    echo "Testing published port on $bridge"
    # Allow server startup before sampling so listeners and real connections use the same state.
    for _ in {1..10}; do
        if connect "$port" >/dev/null; then break; fi
        sleep 0.1
    done
    [[ $(connect "$port") == reachmap-test ]]
    assert_path listener_reachable "$port" "$address" "$bridge"

    nft add table inet test_policy
    nft 'add chain inet test_policy forward { type filter hook forward priority 10; policy drop; }'
    if connect "$port"; then
        echo 'Expected the forwarding policy to block the connection.' >&2
        return 1
    fi
    assert_path blocked "$port" "$address" "$bridge"
    nft delete table inet test_policy
    [[ $(connect "$port") == reachmap-test ]]
}

docker run -d --name example-web --publish 192.0.2.1:8443:8080 "$web_image" sh -ec "$web_command"
address=$(docker inspect -f '{{(index .NetworkSettings.Networks "bridge").IPAddress}}' example-web)
test_publish 8443 "$address" docker0

cat >/tmp/compose.yaml <<EOF
services:
  web:
    image: $web_image
    command: [sh, -ec, '$web_command']
    ports: ['192.0.2.1:8444:8080']
EOF
compose=(docker compose --project-name example --file /tmp/compose.yaml)
"${compose[@]}" up -d
container=$("${compose[@]}" ps -q web)
address=$(docker inspect -f '{{(index .NetworkSettings.Networks "example_default").IPAddress}}' "$container")
network_id=$(docker network inspect -f '{{.Id}}' example_default)
test_publish 8444 "$address" "br-${network_id:0:12}"
echo 'Docker path predictions and replay matched real TCP connections on both bridges.'
