# Verify Caddy reverse proxy paths

Use a fresh, disposable Linux container with a real Caddy, a local loopback
backend, and an isolated client network namespace. The lab exercises
`reachmap scan --caddy-routes`, `--snapshot`, and offline `reachmap replay`
against real Caddyfiles that `caddy adapt` turns into JSON, and checks that
synthetic secrets never appear in snapshots or reports.

## Five-layer evidence model

The pure offline correlation core (`reachmap::caddy::routes::audit`) compares
one `caddy_routes` snapshot with one scoped client HTTP observation. It shares
its observation types and decision table with the Nginx audit
(`reachmap::proxy_audit`) and keeps five layers independent, so HTTP errors or
failed probes never become firewall or safety claims:

1. **Configured Caddy route.** Finds the one server whose `listen` address
   accepts the observed destination, checks its TLS mode against the request
   scheme, and follows its routes the way Caddy does: in order, host and path
   matchers, the first matching route of a `group`, subroutes, and `terminal`.
   The walk ends at a `reverse_proxy`, a responder, or no handler (Caddy then
   sends an empty `200`). Whether a running Caddy loaded the on-disk
   configuration remains unverified.
2. **TCP connectivity.** Records an optional direct TCP handshake or scoped
   Linux inbound TCP path verdict independently; never inferred from HTTP
   errors.
3. **HTTP observation.** Records a scoped client request with explicit
   destination, `Host`, normalized path, TLS status, and HTTP status class
   (`2xx`, `3xx`, `401`/`403`, `404`, `502`/`503`/`504`, other, or no
   response).
4. **Backend reachability.** Evaluates local TCP listener presence for the
   matched `reverse_proxy` upstreams separately from HTTP `502`/`503`/`504`
   responses. Remote, host-name, incomplete and partly present upstream sets
   stay unverified.
5. **Proxy and application authentication.** Records the `authentication`
   handlers (`http_basic`, other providers) and `forward_auth`-shaped proxies
   on the request's path alongside HTTP `401`/`403`, while leaving
   application-level authentication and upstream policy explicitly
   `unverified`.

The result is `consistent`, `disagrees`, or `unavailable` with the first
evidence gap. Every unmodeled construct fails closed: configuration
uncertainties, partial collection, overlapping listeners, unmodeled matchers or
handlers on the path, unnormalized request paths (`//`, dot segments, percent
escapes), and servers whose TLS mode automatic HTTPS decides at runtime all
report a gap instead of a verdict.

## Run the Linux lab

Build a static Linux binary matching the architecture of the Docker engine.
This example builds on Linux or macOS ARM64; use `x86_64-unknown-linux-musl`
on x86-64.

```sh
docker run --rm -v "$PWD":/src:ro -v /tmp/reachmap-caddy-lab:/out \
  -e CARGO_TARGET_DIR=/tmp/target -w /src rust:latest \
  sh -ec 'rustup target add aarch64-unknown-linux-musl && \
    cargo build --locked --target aarch64-unknown-linux-musl && \
    cp /tmp/target/aarch64-unknown-linux-musl/debug/reachmap /out/reachmap'
scripts/test-caddy-routes.sh /tmp/reachmap-caddy-lab/reachmap
```

The script requires a Docker engine capable of running a `--privileged`
container. It uses the digest-pinned official `caddy:2.11.9-alpine` image and
installs `bash`, `iproute2`, `python3`, `curl`, `jq`, and `util-linux` at
runtime. Inside the container, it:

- creates a `caddy-client` network namespace connected over a `veth` pair
  (`192.0.2.2/24` to `192.0.2.1/24`) and sends every HTTP request from there;
- starts a Python HTTP backend on `127.0.0.1:18080` and runs Caddy with
  `admin off` and `auto_https off` on `http://app.example.test:8080`;
- plants four synthetic secrets: a Caddyfile comment, a `header_up` bearer
  token, a `basic_auth` realm, and the bcrypt hash of the lab password;
- removes the Caddyfile, work directory, namespace, and container on exit.

The official image ships `/usr/bin/caddy` owned by a non-root user. The lab
first checks that reachmap refuses to run that binary, then makes it
root-owned, as a distribution package installs it.

## Test matrix

| Case | Client HTTP observation | Local TCP and config evidence | Exit | Replay and secret checks |
| --- | --- | --- | --- | --- |
| Non-root-owned `caddy` binary | N/A | `refusing to run /usr/bin/caddy` on stderr, empty stdout | `1` | N/A |
| Live reverse proxy to running loopback backend | `200` with `reachmap-caddy-ok` | Frontend `:8080` linked to `[::]:8080`; upstream `127.0.0.1:18080` linked to its listener | `0` | Empty-netns replay matches live stdout; no synthetic secrets |
| Stopped loopback backend | `502` from Caddy | Frontend linked; upstream `127.0.0.1:18081` reports `no matching TCP listener` | `0` | Empty-netns replay matches live stdout; no synthetic secrets |
| `basic_auth` route | `401` unauthenticated; `200` with Basic credentials | `proxy auth: http_basic; application auth: unverified` | `0` | Empty-netns replay matches live stdout; realm and hash omitted |
| Upstream from a request header (`{http.request.header.X-Upstream}`) | `200` through the header-chosen upstream | `Configuration uncertainties` lists a `runtime placeholder` | `1` | Empty-netns replay matches live stdout; uncertainty preserved in JSON |
| Unprivileged collector (`chmod 600` Caddyfile) | N/A | Clean `permission denied` diagnostic on stderr, empty stdout | `1` | No synthetic secrets on stderr |

The correlation outcomes for the same route shapes (live, stopped and
partly present upstreams, `basic_auth`, `forward_auth`, remote upstreams,
responders, groups, `terminal`, TLS modes, stale or mismatched scopes) are
unit-tested against real `caddy adapt` output in
`tests/fixtures/caddy/audit/lab.json`.

## Scope and evidence limits

- reachmap reads the configuration file on disk, never the admin API, so a
  configuration loaded through the API or not yet reloaded is not seen.
- Automatic HTTPS decides at runtime which servers speak TLS and which
  redirects exist. A server's TLS mode is only known when it has explicit TLS
  connection policies or automatic HTTPS is disabled; otherwise correlation
  reports `automatic_https_unverified`.
- Only `host` and `path` matchers with exact, prefix and leading-wildcard
  patterns are evaluated. Other matchers, request rewrites and unknown handlers
  are configuration uncertainties.
- Non-loopback upstreams cannot be proven reachable locally and remain
  separate from remote connectivity checks. Host-name upstreams need DNS and
  are not linked.
- Failed HTTP requests (no response) or `502`/`503`/`504` responses never
  establish a firewall verdict by themselves.
- Application-level authentication and upstream authorization policy always
  remain `unverified`.

## Verification record

The Linux lab and offline replay parity checks passed using reachmap `0.6.0`
(built from `feat/119-caddy-route-audit`), Caddy `v2.11.9`, `Alpine Linux
v3.24` (`Linux 7.2.12-orbstack-00394-gbecdd6130068` on ARM64), and
`iproute2-v7.0.0`.
