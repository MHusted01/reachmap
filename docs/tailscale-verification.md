# Verify Tailscale Serve and Funnel routes

Use a fresh, disposable Linux node in an authorized test tailnet. The procedure
changes the node's Tailscale configuration and temporarily publishes synthetic
content through public Funnel. Get approval for the node, test tailnet, and public
endpoint before making those changes.

Use a Reachmap build with Tailscale route capture support, a current Tailscale CLI
and running daemon, Bash, Python 3, `ss` (iproute2), `jq`, and `curl`. Set up a
second device in the test tailnet with access to the node on TCP 8443, and a
client outside the test tailnet for Funnel. The test tailnet needs MagicDNS,
HTTPS certificates, and a `funnel` node attribute covering the disposable node.
The hostname appears in public certificate transparency logs. Pick a synthetic
node name and have the test tailnet admin approve any required policy changes.
See the [Serve CLI reference](https://tailscale.com/docs/reference/tailscale-cli/serve),
[Funnel prerequisites](https://tailscale.com/docs/features/tailscale-funnel#requirements-and-limitations),
and [HTTPS certificate setup](https://tailscale.com/docs/how-to/set-up-https-certificates).

For a Docker lab, use [Tailscale userspace networking](https://tailscale.com/docs/concepts/userspace-networking)
to run the nodes without a TUN device. Send the tailnet client's requests
through its Tailscale SOCKS5 proxy. Use an unauthenticated container with direct
internet access for the outside-client requests. Running each daemon with
`--state=mem:` makes it an [ephemeral node](https://tailscale.com/docs/features/ephemeral-nodes).

## Set up the disposable node

Run in Bash on the Linux node. Start with an empty Serve configuration and
confirm that `ss` prints no listeners on the three test backend ports. A
configuration or listener already present means this setup needs a fresh node.

```sh
umask 077
work=$(mktemp -d)
tailscale version > "$work/tailscale-version.txt"
reachmap --version > "$work/reachmap-version.txt"
tailscale serve status --json
ss -H -ltn '( sport = :18080 or sport = :18081 or sport = :18082 )'
node=$(tailscale status --json | jq -er '.Self.DNSName | rtrimstr(".") | select(length > 0)')

mkdir "$work/serve" "$work/funnel"
printf '%s\n' 'reachmap serve test' > "$work/serve/index.html"
printf '%s\n' 'reachmap funnel test' > "$work/funnel/index.html"
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$work/serve" &
serve_pid=$!
python3 -m http.server 18082 --bind 127.0.0.1 --directory "$work/funnel" &
funnel_pid=$!
```

Confirm that `ss` now shows `127.0.0.1:18080` and `127.0.0.1:18082` listening
and still shows no listener on port 18081. In the same shell, add two Serve
paths to port 8443 and a separate Funnel entry point on port 443. Use an
authorized Tailscale operator or run the configuration commands with approved
`sudo` access. Check the status before continuing.

```sh
tailscale serve --bg --https=8443 http://127.0.0.1:18080
tailscale serve --bg --https=8443 --set-path=/missing http://127.0.0.1:18081
tailscale funnel --bg --https=443 http://127.0.0.1:18082
tailscale serve status
```

## Record client observations

In Bash on each client, define this function and set `node` to the test node's
fully qualified Tailscale DNS name. Each invocation records its starting time
in UTC, the client vantage point, the target URL, the response body and HTTP
status (if received), and the curl exit code. Keep the output private.

```sh
observe() {
    local vantage="$1" url="$2" status=0
    shift 2
    printf '\n%s %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$vantage" "$url"
    curl -q --noproxy '*' "$@" --silent --show-error --connect-timeout 10 --max-time 30 \
        --write-out '\nHTTP status: %{http_code}\n' "$url" || status=$?
    printf 'curl exit: %s\n' "$status"
}
```

On the second device in the test tailnet, run:

```sh
observe tailnet "https://${node}:8443/"
observe tailnet "https://${node}:8443/missing"
```

For a Docker client using a userspace SOCKS5 proxy on port 1055, set
`server_ip` to the server node's tailnet IPv4 address. The proxy connects to
that address while curl verifies TLS against the hostname in the URL.

```sh
proxy_options=(--noproxy '' --socks5-hostname 127.0.0.1:1055
    --connect-to "${node}:8443:${server_ip}:8443")
observe tailnet "https://${node}:8443/" "${proxy_options[@]}"
observe tailnet "https://${node}:8443/missing" "${proxy_options[@]}"
```

On the outside client, run:

```sh
observe outside-tailnet "https://${node}/"
```

Expect HTTP 200 and the corresponding synthetic text for each live backend.
Record the actual frontend result for `/missing`, including HTTP errors. An HTTP
error confirms a frontend response for that request. The lack of a local
listener is a separate observation. If curl prints status `000`, record its
error as a request that received no HTTP response.

The first HTTPS request can time out while Tailscale obtains the certificate.
Public DNS for Funnel can also take time to become available. If either is
still pending, keep the initial result and retry after it is ready.
If a public resolver returns an address for the Funnel hostname while the
client's resolver still fails, record the resolver used and retry with
`curl --resolve` using that address. Keep the hostname in the URL and leave
TLS verification enabled.

## Compare live evidence and offline replay

On the disposable node, keep the same routes and listeners in place during
the scan and snapshot. Both commands should exit successfully.

```sh
reachmap scan --tailscale-routes > "$work/live.txt"
reachmap scan --tailscale-routes --snapshot --host-ref test-node > "$work/routes.json"
jq -e --arg node "$node" '
    def route($port; $sharing; $mount; $backend):
        any(.evidence.routes[];
            .entry == {host: $node, port: $port, sharing: $sharing}
            and .mount == $mount
            and .backend.kind == "http_proxy"
            and .backend.targets == [$backend]);
    .scope == "tailscale_routes"
    and .evidence.collection.status == "complete"
    and route(8443; "tailnet"; "/"; "127.0.0.1:18080")
    and route(8443; "tailnet"; "/missing"; "127.0.0.1:18081")
    and route(443; "funnel"; "/"; "127.0.0.1:18082")
    and .evidence.inventory.status == "collected"
    and ([.evidence.inventory.listeners[].address] | sort)
        == ["127.0.0.1:18080", "127.0.0.1:18082"]
' "$work/routes.json"
```

Copy the snapshot and live report to a machine or container without network
access. Set `work` to the directory holding the copies. Replay should exit
successfully and print a capture header. Compare the rest of the report with
the live output.

```sh
reachmap replay "$work/routes.json" > "$work/replay.txt"
tail -n +2 "$work/replay.txt" > "$work/replayed-routes.txt"
diff -u "$work/live.txt" "$work/replayed-routes.txt"
```

Check that both reports identify a TCP listener for each live backend and that
the Serve row for `/missing` says `no matching TCP listener`. Match the rows to
the HTTP observations by hostname, port, and path. The Reachmap reports describe
configured HTTP reverse proxies to local loopback TCP sockets. They leave
upstream policy, DNS, TLS, and application authentication unverified. Each
client observation applies to that client, URL, and time.

## Tear down

On the disposable node, remove the test routes and confirm that status shows
an empty configuration. Stop the two servers from the shell that started them.

```sh
tailscale funnel --bg --https=443 off
tailscale serve --bg --https=8443 --set-path=/missing off
tailscale serve --bg --https=8443 off
tailscale serve status
kill "$serve_pid" "$funnel_pid"
```

Remove the test node from the test tailnet and dispose of the Linux environment
when finished. Keep raw captures, hostnames, and any credentials private. In a
shared verification record, use a synthetic target label and retain the port,
path, vantage point, timestamp, HTTP result, and Tailscale version.
