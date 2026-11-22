#!/usr/bin/env bash
# Exercise Nginx reverse proxy collection, client observations, offline replay, and secret redaction in a disposable Linux lab.
set -euo pipefail

if [[ ${1:-} != --inside-lab ]]; then
    binary=$(realpath "${1:?Usage: test-nginx-routes.sh STATIC_LINUX_REACHMAP_BINARY}")
    script=$(realpath "$0")
    exec docker run --rm --privileged --network bridge \
        --mount "type=bind,source=$binary,target=/reachmap,readonly" \
        --mount "type=bind,source=$script,target=/test-nginx-routes.sh,readonly" \
        alpine:3.21@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab \
        /bin/sh -ec 'apk add --no-cache bash iproute2 nginx python3 curl jq util-linux && exec bash /test-nginx-routes.sh --inside-lab'
fi

if [[ ! -f /.dockerenv || ! -x /reachmap ]]; then
    echo 'Run this test through its disposable Docker lab.' >&2
    exit 1
fi

binary=/usr/local/bin/reachmap
work=/var/tmp/nginx-lab
backend_pid=''
netns_created=false

stop_nginx() {
    if [[ -s /run/nginx/nginx.pid ]]; then
        local pid
        pid=$(</run/nginx/nginx.pid)
        nginx -s quit >/dev/null 2>&1 || true
        for _ in {1..20}; do
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
    fi
}

cleanup() {
    stop_nginx
    if [[ -n $backend_pid ]]; then
        kill "$backend_pid" 2>/dev/null || true
        wait "$backend_pid" 2>/dev/null || true
    fi
    if [[ $netns_created == true ]]; then
        ip netns del nginx-client 2>/dev/null || true
    fi
    rm -f /etc/nginx/http.d/lab.conf /etc/nginx/synthetic_htpasswd_secret_9a8b7c6d
    rm -r -- "$work" 2>/dev/null || true
}
trap cleanup EXIT

install -m 755 /reachmap "$binary"
mkdir -p "$work/web" /run/nginx /etc/nginx/http.d /var/log/nginx
chmod 755 /var/log/nginx
: >/var/log/nginx/error.log
: >/var/log/nginx/access.log
chmod 666 /var/log/nginx/error.log /var/log/nginx/access.log
cd "$work"

ip netns add nginx-client
netns_created=true
ip link set lo up
ip link add entry0 type veth peer name client0 netns nginx-client
ip link set entry0 up
ip addr add 192.0.2.1/24 dev entry0
ip -n nginx-client link set lo up
ip -n nginx-client link set client0 up
ip -n nginx-client addr add 192.0.2.2/24 dev client0

adduser -D -s /bin/sh auditor

printf 'reachmap-nginx-ok\n' >"$work/web/index.html"
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$work/web" >"$work/backend.log" 2>&1 &
backend_pid=$!

# Generate an htpasswd entry without relying on Python's removed crypt module.
python3 -c '
import base64, hashlib
digest = base64.b64encode(hashlib.sha1(b"labpass").digest()).decode("ascii")
print(f"labuser:{{SHA}}{digest}")
' >/etc/nginx/synthetic_htpasswd_secret_9a8b7c6d
chmod 644 /etc/nginx/synthetic_htpasswd_secret_9a8b7c6d

cat >/etc/nginx/nginx.conf <<'NGINX'
user nginx;
worker_processes 1;
pid /run/nginx/nginx.pid;
error_log /var/log/nginx/error.log warn;

events {
}

http {
    access_log /var/log/nginx/access.log;
    include /etc/nginx/http.d/*.conf;
}
NGINX
rm -f /etc/nginx/http.d/*.conf

secret_comment='SYNTHETIC_SECRET_COMMENT_9f8e7d6c'
secret_token='SYNTHETIC_SECRET_TOKEN_1a2b3c4d'
secret_realm='SYNTHETIC_REALM_SECRET_5e6f7a8b'
secret_htpasswd='synthetic_htpasswd_secret_9a8b7c6d'

assert_no_secrets() {
    local file marker
    for file in "$@"; do
        for marker in "$secret_comment" "$secret_token" "$secret_realm" "$secret_htpasswd"; do
            if grep -Fq "$marker" "$file"; then
                printf 'Synthetic secret marker %s leaked into %s\n' "$marker" "$file" >&2
                exit 1
            fi
        done
    done
}

start_nginx() {
    stop_nginx
    nginx -t -q
    nginx
}

client_http() {
    local path=$1
    shift || true
    ip netns exec nginx-client curl --noproxy '*' --silent --show-error \
        --max-time 3 --retry 5 --retry-connrefused \
        -H 'Host: app.example.test' \
        -o "$work/curl.body" -w '%{http_code}' "$@" "http://192.0.2.1:8080${path}"
}

capture_and_replay() {
    local name=$1 expected_exit=$2 status=0
    "$binary" scan --nginx-routes >"$work/$name.live.txt" 2>"$work/$name.live.stderr" || status=$?
    if [[ $status != "$expected_exit" || -s $work/$name.live.stderr ]]; then
        printf 'Unexpected live scan result for %s (exit %s)\n' "$name" "$status" >&2
        cat "$work/$name.live.txt" "$work/$name.live.stderr" >&2
        exit 1
    fi

    status=0
    "$binary" scan --nginx-routes --snapshot --host-ref "nginx-lab-$name" \
        >"$work/$name.snapshot.json" 2>"$work/$name.snap.stderr" || status=$?
    if [[ $status != "$expected_exit" || -s $work/$name.snap.stderr ]]; then
        printf 'Unexpected snapshot result for %s (exit %s)\n' "$name" "$status" >&2
        cat "$work/$name.snapshot.json" "$work/$name.snap.stderr" >&2
        exit 1
    fi
    jq -e '.snapshot_version == 1 and .scope == "nginx_routes"' "$work/$name.snapshot.json" >/dev/null

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

"$binary" --version
uname -sr
nginx -v 2>&1
ip -V
awk -F= '/^PRETTY_NAME=/{gsub(/"/, "", $2); print $2}' /etc/os-release

# Case 1: Live reverse proxy to running loopback backend.
cat >/etc/nginx/http.d/lab.conf <<CONF
# $secret_comment
server {
    listen 192.0.2.1:8080;
    server_name app.example.test;

    location /app/ {
        proxy_set_header Authorization "Bearer $secret_token";
        proxy_pass http://127.0.0.1:18080/;
    }
}
CONF
start_nginx
code=$(client_http /app/)
[[ $code == 200 && $(<"$work/curl.body") == reachmap-nginx-ok ]]
capture_and_replay live_backend 0
grep -Fq 'listen: 192.0.2.1:8080 (TCP listener 192.0.2.1:8080)' "$work/live_backend.live.txt"
grep -Fq 'target: http://127.0.0.1:18080/ (TCP listener 127.0.0.1:18080)' "$work/live_backend.live.txt"
printf 'ok: live_backend (HTTP %s, listener matched, exit 0)\n' "$code"

# Case 2: Stopped/missing loopback backend -> HTTP 502 with absent local listener.
cat >/etc/nginx/http.d/lab.conf <<CONF
# $secret_comment
server {
    listen 192.0.2.1:8080;
    server_name app.example.test;

    location /missing/ {
        proxy_pass http://127.0.0.1:18081/;
    }
}
CONF
start_nginx
code=$(client_http /missing/)
[[ $code == 502 ]]
capture_and_replay missing_backend 0
grep -Fq 'listen: 192.0.2.1:8080 (TCP listener 192.0.2.1:8080)' "$work/missing_backend.live.txt"
grep -Fq 'target: http://127.0.0.1:18081/ (no matching TCP listener)' "$work/missing_backend.live.txt"
printf 'ok: missing_backend (HTTP %s, no matching TCP listener, exit 0)\n' "$code"

# Case 3: Proxy-auth-protected route (auth_basic -> HTTP 401 without credentials).
cat >/etc/nginx/http.d/lab.conf <<CONF
# $secret_comment
server {
    listen 192.0.2.1:8080;
    server_name app.example.test;

    location /admin/ {
        auth_basic "$secret_realm";
        auth_basic_user_file /etc/nginx/$secret_htpasswd;
        proxy_pass http://127.0.0.1:18080/;
    }
}
CONF
start_nginx
code=$(client_http /admin/)
[[ $code == 401 ]]
authed_code=$(client_http /admin/ -u labuser:labpass)
[[ $authed_code == 200 && $(<"$work/curl.body") == reachmap-nginx-ok ]]
capture_and_replay auth_basic 0
grep -Fq 'proxy auth: auth_basic=on; application auth: unverified' "$work/auth_basic.live.txt"
printf 'ok: auth_basic (HTTP %s unauth, HTTP %s authed, exit 0)\n' "$code" "$authed_code"

# Case 4: Dynamic directive (if / rewrite -> explicit unknown / incomplete).
cat >/etc/nginx/http.d/lab.conf <<CONF
# $secret_comment
server {
    listen 192.0.2.1:8080;
    server_name app.example.test;

    location /dynamic/ {
        if (\$arg_mode = bypass) {
            return 204;
        }
        rewrite ^/dynamic/(.*)\$ /app/\$1 break;
        proxy_pass http://127.0.0.1:18080/;
    }
}
CONF
start_nginx
capture_and_replay dynamic_unknown 1
grep -Fq 'Configuration uncertainties:' "$work/dynamic_unknown.live.txt"
grep -Fq "dynamic control flow (\`if\`)" "$work/dynamic_unknown.live.txt"
grep -Fq "dynamic routing (\`rewrite\`)" "$work/dynamic_unknown.live.txt"
jq -e '(.evidence.config.uncertainties | length) >= 2' "$work/dynamic_unknown.snapshot.json" >/dev/null
printf 'ok: dynamic_unknown (uncertainties reported, exit 1)\n'

# Case 5: Unprivileged collector lacking config read permission -> clean evidence gap.
chmod 600 /etc/nginx/http.d/lab.conf
status=0
su -s /bin/sh auditor -c "$binary scan --nginx-routes" \
    >"$work/unprivileged.out" 2>"$work/unprivileged.err" || status=$?
if [[ $status != 1 || -s $work/unprivileged.out ]] || ! grep -qiF 'permission denied' "$work/unprivileged.err"; then
    printf 'Unexpected unprivileged collector result (exit %s)\n' "$status" >&2
    cat "$work/unprivileged.out" "$work/unprivileged.err" >&2
    exit 1
fi
assert_no_secrets "$work/unprivileged.err"
printf 'ok: unprivileged_gap (permission denied, no secret leak, exit 1)\n'

echo 'All Linux Nginx route verification, replay, and secret-redaction checks passed.'
