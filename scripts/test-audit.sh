#!/usr/bin/env bash
# Exercise the SSH audit CLI and real TCP handshakes in a disposable Linux lab.
set -euo pipefail

if [[ ${1:-} != --inside-lab ]]; then
    binary=$(realpath "${1:?Usage: test-audit.sh STATIC_LINUX_REACHMAP_BINARY}")
    script=$(realpath "$0")
    # The default bridge avoids an extra DNS NAT chain on the collector.
    exec docker run --rm --privileged --network bridge \
        --mount "type=bind,source=$binary,target=/reachmap,readonly" \
        --mount "type=bind,source=$script,target=/test-audit.sh,readonly" \
        --entrypoint /bin/sh \
        docker:29.1.3-dind@sha256:173f284a4299164772a90f52b373e73e087583c0963f1334c9995f190ef6f3f5 \
        -ec 'apk add --no-cache bash iproute2 nftables jq openssh-server openssh-client python3 curl && exec bash /test-audit.sh --inside-lab'
fi

if [[ ! -f /.dockerenv || ! -x /reachmap ]]; then
    echo 'Run this test through its disposable Docker lab.' >&2
    exit 1
fi

binary=/usr/local/bin/reachmap
work=/var/tmp/audit-lab
install -m 755 /reachmap "$binary"
mkdir -p /run/sshd "$work"
cd "$work"

ip netns add audit-client
ip link add entry0 type veth peer name client0 netns audit-client
ip link set entry0 up
ip addr add 192.0.2.1/24 dev entry0
ip -6 addr add 2001:db8::1/64 dev entry0 nodad
ip -n audit-client link set lo up
ip -n audit-client link set client0 up
ip -n audit-client addr add 192.0.2.2/24 dev client0
ip -n audit-client -6 addr add 2001:db8::2/64 dev client0 nodad

# Restrict both lab logins to the capture wrapper and use disposable keys.
adduser -D -s /bin/bash auditor
passwd -d root >/dev/null
passwd -d auditor >/dev/null
for key in client host wrong-host; do
    ssh-keygen -qt ed25519 -N '' -C "audit-lab-$key" -f "$key"
done
for home_dir in /root /home/auditor; do
    install -d -m 700 "$home_dir/.ssh"
    {
        printf 'restrict,command="%s/capture" ' "$work"
        cat client.pub
    } >"$home_dir/.ssh/authorized_keys"
    chmod 600 "$home_dir/.ssh/authorized_keys"
done
chown -R auditor:auditor /home/auditor/.ssh
awk '{print "[192.0.2.1]:2222 "$1" "$2}' host.pub >known_hosts
awk '{print "[192.0.2.1]:2222 "$1" "$2}' wrong-host.pub >wrong_hosts

cat >capture <<'CAPTURE'
#!/usr/bin/env bash
set -euo pipefail
read -r -a request <<< "${SSH_ORIGINAL_COMMAND:-}"
[[ ${#request[@]} == 13 && ${request[*]:0:3} == '/usr/local/bin/reachmap path capture' ]]
cd /var/tmp/audit-lab
if [[ $EUID != 0 ]]; then
    exec "${request[@]}"
fi
case $(cat mode) in
    normal) "${request[@]}" | tee snapshot.json ;;
    incompatible) "${request[@]}" | jq '.snapshot_version = 2' ;;
    mismatched) "${request[@]}" | jq '.flow.port += 1' ;;
    denied) echo 'permission denied by lab collection policy' >&2; exit 1 ;;
    *) exit 1 ;;
esac
CAPTURE
chmod 755 capture
echo normal >mode

cat >sshd_config <<'SSHD'
ListenAddress 192.0.2.1
Port 2222
HostKey /var/tmp/audit-lab/host
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
AllowUsers root auditor
DisableForwarding yes
PermitTTY no
SSHD
/usr/sbin/sshd -f "$work/sshd_config" -E "$work/sshd.log"

sysctl -w net.ipv4.ip_forward=1
# This is an IPv4 bridge publish. Leave the IPv6 listener path free of
# Docker's IPv6 prerouting hooks, which are outside the supported scope.
dockerd --firewall-backend=nftables --ip6tables=false --userland-proxy=false \
    --storage-driver=vfs --bip=198.51.100.1/24 >dockerd.log 2>&1 &
daemon=$!
trap 'kill "$daemon" 2>/dev/null || true' EXIT
for _ in {1..40}; do
    if docker info --format '{{.FirewallBackend.Driver}}' >backend 2>/dev/null; then
        break
    fi
    sleep 0.25
done
[[ $(cat backend) == nftables ]] || { cat dockerd.log >&2; exit 1; }
web_image=busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
docker run -d --publish 192.0.2.1:8444:8080 "$web_image" \
    sh -ec 'echo reachmap-test >/tmp/index.html; exec httpd -f -p 8080 -h /tmp'
mkdir web
printf 'reachmap-test\n' >web/index.html
for address in 192.0.2.1 2001:db8::1; do
    python3 -m http.server 8443 --bind "$address" --directory web >"http-$address.log" 2>&1 &
done

"$binary" --version
uname -sr
nft --version
ip -V
ssh -V
docker version --format 'Docker Engine {{.Server.Version}}'

audit() {
    local endpoint=$1 source=$2 login=${3:-root} hosts=${4:-known_hosts}
    ip netns exec audit-client "$binary" audit --ssh-host 192.0.2.1 --ssh-port 2222 \
        --ssh-user "$login" --known-hosts "$work/$hosts" --identity-file "$work/client" \
        --endpoint "$endpoint" --source "$source" --ingress entry0 --confirm-direct-path
}

assert_audit() {
    local name=$1 expected_exit=$2 verdict=$3 outcome=$4 comparison=$5 reason=$6 status=0
    shift 6
    audit "$@" >"$name.json" 2>"$name.stderr" || status=$?
    if [[ $status != "$expected_exit" ]] || ! jq -e \
        --arg verdict "$verdict" --arg outcome "$outcome" --arg comparison "$comparison" --arg reason "$reason" '
        .report_version == 1 and .prediction.verdict == $verdict and
        .observation.outcome.kind == $outcome and .comparison.status == $comparison and
        (.comparison.reason // "") == $reason
    ' "$name.json" >/dev/null; then
        printf 'Unexpected %s status or report (exit %s).\n' "$name" "$status" >&2
        cat "$name.json" "$name.stderr" >&2
        exit 1
    fi
    printf 'ok: %s (%s, %s, %s, exit %s)\n' "$name" "$verdict" "$outcome" "$comparison" "$status"
}

replay() {
    local report=$1
    unshare --net "$binary" path replay "$work/snapshot.json" --json >replay.json
    diff -u <(jq -S '.prediction' "$report.json") <(jq -S . replay.json)
}

http() {
    ip netns exec audit-client curl --noproxy '*' --fail --silent --show-error \
        --max-time 3 --retry 5 --retry-connrefused "$1"
}

table() {
    nft add table inet audit_test
    nft "add chain inet audit_test $1 { type filter hook $1 priority $2; policy accept; }"
}

counter() {
    nft -j list chain inet audit_test "$1" |
        jq -e '[.nftables[].rule.expr[]?.counter | select(. != null) | .packets] |
            length == 1 and (.[0] > 0) == $hit' --argjson hit "$2" >/dev/null
}

for endpoint in 192.0.2.1:8443 '[2001:db8::1]:8443' 192.0.2.1:8444; do
    [[ $(http "http://$endpoint/") == reachmap-test ]]
done
assert_audit ipv4 0 listener_reachable open consistent '' 192.0.2.1:8443 192.0.2.2
replay ipv4
assert_audit ipv6 0 listener_reachable open consistent '' '[2001:db8::1]:8443' 2001:db8::2
replay ipv6
assert_audit docker 0 listener_reachable open consistent '' 192.0.2.1:8444 192.0.2.2
jq -e 'any(.prediction.steps[]; .translation == {original:"192.0.2.1:8444", translated:"198.51.100.2:8080"}) and
    any(.prediction.steps[]; .stage == "forward")' docker.json >/dev/null
replay docker

table input 0
nft add rule inet audit_test input iifname entry0 tcp dport 8443 counter drop
assert_audit ingress_drop 0 blocked no_answer consistent '' 192.0.2.1:8443 192.0.2.2
jq -e '.prediction.steps[-1].stage == "input"' ingress_drop.json >/dev/null
counter input true
replay ingress_drop
nft delete table inet audit_test

table output 0
nft 'add rule inet audit_test output oifname entry0 tcp sport 8443 tcp flags & (syn | ack) == (syn | ack) counter drop'
assert_audit return_drop 2 listener_reachable no_answer unavailable negative_outcome_inconclusive 192.0.2.1:8443 192.0.2.2
counter output true
replay return_drop
nft delete table inet audit_test
[[ $(http http://192.0.2.1:8443/) == reachmap-test ]]

table prerouting -150
assert_audit unsupported 2 unknown open unavailable prediction_inconclusive 192.0.2.1:8443 192.0.2.2
jq -e '.prediction.steps[-1] | .stage == "destination_nat" and (.reason | contains("prerouting"))' unsupported.json >/dev/null
replay unsupported
nft delete table inet audit_test

assert_audit restricted 2 unknown open unavailable prediction_inconclusive 192.0.2.1:8443 192.0.2.2 auditor
jq -e 'any(.evidence_gaps[]; .collector == "nftables" and (.reason | test("permission|permitted|root"; "i")))' restricted.json >/dev/null

assert_failure() {
    local name=$1 diagnostic=$2 status=0
    shift 2
    audit 192.0.2.1:8443 192.0.2.2 "$@" >"$name.json" 2>"$name.stderr" || status=$?
    if [[ $status != 2 || -s $name.json ]] || ! grep -qiF "$diagnostic" "$name.stderr"; then
        printf 'Unexpected %s failure (exit %s).\n' "$name" "$status" >&2
        cat "$name.json" "$name.stderr" >&2
        exit 1
    fi
    printf 'ok: %s (%s, exit %s)\n' "$name" "$diagnostic" "$status"
}

table input 0
nft add rule inet audit_test input iifname entry0 tcp dport 8443 counter
assert_failure wrong_host 'Host key verification failed' root wrong_hosts
echo denied >mode
assert_failure denied 'permission denied by lab collection policy'
echo incompatible >mode
assert_failure incompatible 'unsupported inbound TCP snapshot version 2'
echo mismatched >mode
assert_failure mismatched 'snapshot for a different TCP flow'
counter input false
nft delete table inet audit_test
[[ $(http http://192.0.2.1:8443/) == reachmap-test ]]

echo 'All Linux audit and offline replay cases passed.'
