#!/usr/bin/env bash
# Exercise Caddy reverse proxy collection, client observations, offline replay, and secret redaction in a disposable Linux lab.
set -euo pipefail

if [[ ${1:-} != --inside-lab ]]; then
    binary=$(realpath "${1:?Usage: test-caddy-routes.sh STATIC_LINUX_REACHMAP_BINARY}")
    script=$(realpath "$0")
    exec docker run --rm --privileged --network bridge \
        --mount "type=bind,source=$binary,target=/reachmap,readonly" \
        --mount "type=bind,source=$script,target=/test-caddy-routes.sh,readonly" \
        caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0 \
        /bin/sh -ec 'apk add --no-cache bash iproute2 python3 curl jq util-linux >/dev/null && exec bash /test-caddy-routes.sh --inside-lab'
fi

if [[ ! -f /.dockerenv || ! -x /reachmap ]]; then
    echo 'Run this test through its disposable Docker lab.' >&2
    exit 1
fi

binary=/usr/local/bin/reachmap
work=/var/tmp/caddy-lab
config=/etc/caddy/Caddyfile
caddy_pid=''
backend_pid=''
netns_created=false

stop_caddy() {
    if [[ -n $caddy_pid ]]; then
        kill "$caddy_pid" 2>/dev/null || true
        wait "$caddy_pid" 2>/dev/null || true
        caddy_pid=''
    fi
}

cleanup() {
    stop_caddy
    if [[ -n $backend_pid ]]; then
        kill "$backend_pid" 2>/dev/null || true
        wait "$backend_pid" 2>/dev/null || true
    fi
    if [[ $netns_created == true ]]; then
        ip netns del caddy-client 2>/dev/null || true
    fi
    rm -f -- "$config"
    rm -r -- "$work" 2>/dev/null || true
}
trap cleanup EXIT

install -m 755 /reachmap "$binary"
mkdir -p "$work/web/app" "$work/web/admin" "$work/web/dynamic" /etc/caddy
cd "$work"

ip netns add caddy-client
netns_created=true
ip link set lo up
ip link add entry0 type veth peer name client0 netns caddy-client
ip link set entry0 up
ip addr add 192.0.2.1/24 dev entry0
ip -n caddy-client link set lo up
ip -n caddy-client link set client0 up
ip -n caddy-client addr add 192.0.2.2/24 dev client0

adduser -D -s /bin/sh auditor

for page in app admin dynamic; do
    printf 'reachmap-caddy-ok\n' >"$work/web/$page/index.html"
done
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$work/web" >"$work/backend.log" 2>&1 &
backend_pid=$!

secret_comment='SYNTHETIC_SECRET_COMMENT_9f8e7d6c'
secret_token='SYNTHETIC_SECRET_TOKEN_1a2b3c4d'
secret_realm='SYNTHETIC_REALM_SECRET_5e6f7a8b'
secret_hash=$(caddy hash-password --plaintext labpass)

assert_no_secrets() {
    local file marker
    for file in "$@"; do
        for marker in "$secret_comment" "$secret_token" "$secret_realm" "$secret_hash"; do
            if grep -Fq -- "$marker" "$file"; then
                printf 'Synthetic secret marker leaked into %s\n' "$file" >&2
                exit 1
            fi
        done
    done
}

# Writes a Caddyfile serving http://app.example.test:8080 with the given site body.
write_config() {
    cat >"$config" <<CONF
# $secret_comment
{
	admin off
	auto_https off
}

http://app.example.test:8080 {
$1
}
CONF
}

start_caddy() {
    stop_caddy
    caddy run --config "$config" --adapter caddyfile >"$work/caddy.log" 2>&1 &
    caddy_pid=$!
    for _ in {1..50}; do
        if ss -Hltn 'sport = :8080' | grep -q .; then
            return
        fi
        sleep 0.1
    done
    echo 'Caddy did not start listening on port 8080' >&2
    cat "$work/caddy.log" >&2
    exit 1
}

client_http() {
    local path=$1
    shift || true
    ip netns exec caddy-client curl --noproxy '*' --silent --show-error \
        --max-time 3 --retry 5 --retry-connrefused \
        -H 'Host: app.example.test' \
        -o "$work/curl.body" -w '%{http_code}' "$@" "http://192.0.2.1:8080${path}"
}

capture_and_replay() {
    local name=$1 expected_exit=$2 status=0
    "$binary" scan --caddy-routes >"$work/$name.live.txt" 2>"$work/$name.live.stderr" || status=$?
    if [[ $status != "$expected_exit" || -s $work/$name.live.stderr ]]; then
        printf 'Unexpected live scan result for %s (exit %s)\n' "$name" "$status" >&2
        cat "$work/$name.live.txt" "$work/$name.live.stderr" >&2
        exit 1
    fi

    status=0
    "$binary" scan --caddy-routes --snapshot --host-ref "caddy-lab-$name" \
        >"$work/$name.snapshot.json" 2>"$work/$name.snap.stderr" || status=$?
    if [[ $status != "$expected_exit" || -s $work/$name.snap.stderr ]]; then
        printf 'Unexpected snapshot result for %s (exit %s)\n' "$name" "$status" >&2
        cat "$work/$name.snapshot.json" "$work/$name.snap.stderr" >&2
        exit 1
    fi
    jq -e '.snapshot_version == 1 and .scope == "caddy_routes"' "$work/$name.snapshot.json" >/dev/null

    status=0
    unshare --net "$binary" replay "$work/$name.snapshot.json" \
        >"$work/$name.replay.txt" 2>"$work/$name.replay.stderr" || status=$?
    if [[ $status != "$expected_exit" || -s $work/$name.replay.stderr ]]; then
        printf 'Unexpected replay result for %s (exit %s)\n' "$name" "$status" >&2
        cat "$work/$name.replay.txt" "$work/$name.replay.stderr" >&2
        exit 1
    fi

    diff -u "$work/$name.live.txt" <(tail -n +2 "$work/$name.replay.txt")
    assert_no_secrets "$work/$name.live.txt" "$work/$name.snapshot.json" "$work/$name.replay.txt"
}

expect_text() {
    local file=$1 text=$2
    if ! grep -Fq -- "$text" "$file"; then
        printf 'Missing %q in %s:\n' "$text" "$file" >&2
        cat "$file" >&2
        exit 1
    fi
}

"$binary" --version
uname -sr
caddy version
ip -V
awk -F= '/^PRETTY_NAME=/{gsub(/"/, "", $2); print $2}' /etc/os-release

# The official image ships /usr/bin/caddy owned by a non-root user; reachmap
# refuses to run it. Make it root-owned, as a distribution package installs it.
write_config '	respond "ok"'
status=0
"$binary" scan --caddy-routes >"$work/untrusted.out" 2>"$work/untrusted.err" || status=$?
if [[ $status != 1 || -s $work/untrusted.out ]] || ! grep -qF 'refusing to run /usr/bin/caddy' "$work/untrusted.err"; then
    printf 'Unexpected result for a non-root-owned caddy binary (exit %s)\n' "$status" >&2
    cat "$work/untrusted.out" "$work/untrusted.err" >&2
    exit 1
fi
chown root:root /usr/bin/caddy
printf 'ok: untrusted_binary (non-root-owned caddy refused, exit 1)\n'

# Case 1: Live reverse proxy to a running loopback backend.
write_config "	handle /app/* {
		reverse_proxy 127.0.0.1:18080 {
			header_up Authorization \"Bearer $secret_token\"
		}
	}"
start_caddy
code=$(client_http /app/)
[[ $code == 200 && $(<"$work/curl.body") == reachmap-caddy-ok ]]
capture_and_replay live_backend 0
expect_text "$work/live_backend.live.txt" 'listen: :8080 (TCP listener [::]:8080)'
expect_text "$work/live_backend.live.txt" 'upstream 127.0.0.1:18080 (TCP listener 127.0.0.1:18080)'
printf 'ok: live_backend (HTTP %s, listener matched, exit 0)\n' "$code"

# Case 2: Stopped loopback backend -> HTTP 502 with no local listener.
write_config "	handle /missing/* {
		reverse_proxy 127.0.0.1:18081
	}"
start_caddy
code=$(client_http /missing/)
[[ $code == 502 ]]
capture_and_replay missing_backend 0
expect_text "$work/missing_backend.live.txt" 'upstream 127.0.0.1:18081 (no matching TCP listener)'
printf 'ok: missing_backend (HTTP %s, no matching TCP listener, exit 0)\n' "$code"

# Case 3: basic_auth route -> HTTP 401 without credentials, 200 with them.
write_config "	handle /admin/* {
		basic_auth bcrypt \"$secret_realm\" {
			labuser $secret_hash
		}
		reverse_proxy 127.0.0.1:18080
	}"
start_caddy
code=$(client_http /admin/)
[[ $code == 401 ]]
authed_code=$(client_http /admin/ -u labuser:labpass)
[[ $authed_code == 200 && $(<"$work/curl.body") == reachmap-caddy-ok ]]
capture_and_replay basic_auth 0
expect_text "$work/basic_auth.live.txt" 'proxy auth: http_basic; application auth: unverified'
printf 'ok: basic_auth (HTTP %s unauth, HTTP %s authed, exit 0)\n' "$code" "$authed_code"

# Case 4: Upstream chosen at runtime from a request header -> explicit unknown.
write_config "	handle /dynamic/* {
		reverse_proxy {http.request.header.X-Upstream}
	}"
start_caddy
code=$(client_http /dynamic/ -H 'X-Upstream: 127.0.0.1:18080')
[[ $code == 200 && $(<"$work/curl.body") == reachmap-caddy-ok ]]
capture_and_replay dynamic_unknown 1
expect_text "$work/dynamic_unknown.live.txt" 'Configuration uncertainties:'
expect_text "$work/dynamic_unknown.live.txt" 'runtime placeholder'
jq -e '(.evidence.config.uncertainties | length) >= 1' "$work/dynamic_unknown.snapshot.json" >/dev/null
printf 'ok: dynamic_unknown (HTTP %s via a header-chosen upstream, uncertainty reported, exit 1)\n' "$code"

# Case 5: Unprivileged collector without config read permission -> clean evidence gap.
chmod 600 "$config"
status=0
su -s /bin/sh auditor -c "$binary scan --caddy-routes" \
    >"$work/unprivileged.out" 2>"$work/unprivileged.err" || status=$?
if [[ $status != 1 || -s $work/unprivileged.out ]] || ! grep -qiF 'permission denied' "$work/unprivileged.err"; then
    printf 'Unexpected unprivileged collector result (exit %s)\n' "$status" >&2
    cat "$work/unprivileged.out" "$work/unprivileged.err" >&2
    exit 1
fi
assert_no_secrets "$work/unprivileged.err"
printf 'ok: unprivileged_gap (permission denied, no secret leak, exit 1)\n'

echo 'All Linux Caddy route verification, replay, and secret-redaction checks passed.'
