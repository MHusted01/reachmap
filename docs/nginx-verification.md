# Verify Nginx reverse proxy paths

Use a fresh, disposable Linux host or container with real Nginx, local
loopback backends, and an isolated client network namespace. The lab exercises
`reachmap scan --nginx-routes`, `--snapshot`, and offline `reachmap replay`
against real `nginx -T` output while checking that synthetic secrets never
appear in snapshots or reports.

## Five-layer evidence model

The pure offline correlation core (`reachmap::nginx::audit`) keeps five
layers independent so HTTP errors or failed probes never collapse into
unsupported firewall or safety claims:

1. **Configured Nginx route.** Matches on-disk `nginx -T` `server` and
   `location` blocks and local frontend `listen` TCP sockets. Whether the
   running Nginx master has reloaded the on-disk configuration remains
   unverified.
2. **TCP connectivity.** Records an optional direct TCP handshake or scoped
   Linux inbound TCP path verdict independently; never inferred from HTTP
   errors.
3. **HTTP observation.** Records a scoped client request with explicit
   destination, `Host`, normalized path, TLS status, and HTTP status class
   (`2xx`, `3xx`, `401`/`403`, `404`, `502`/`503`/`504`, other, or no
   response).
4. **Backend reachability.** Evaluates local loopback/host TCP listener
   presence behind `proxy_pass` and static `upstream` groups separately from
   HTTP `502`/`503`/`504` responses.
5. **Proxy and application authentication.** Records Nginx proxy-layer signals
   (`auth_basic`, `auth_request`, `ssl_verify_client`, `allow`/`deny`)
   alongside HTTP `401`/`403`, while leaving application-level authentication
   and upstream policy explicitly `unverified`.

## Run the Linux lab

Build a static Linux binary matching the architecture of the Docker engine.
This example builds on Linux or macOS ARM64; use `x86_64-unknown-linux-musl`
on x86-64.

```sh
docker run --rm -v "$PWD":/src:ro -v /tmp/reachmap-nginx-lab:/out \
  -e CARGO_TARGET_DIR=/tmp/target -w /src rust:latest \
  sh -ec 'rustup target add aarch64-unknown-linux-musl && \
    cargo build --locked --target aarch64-unknown-linux-musl && \
    cp /tmp/target/aarch64-unknown-linux-musl/debug/reachmap /out/reachmap'
scripts/test-nginx-routes.sh /tmp/reachmap-nginx-lab/reachmap
```

The script requires a Docker engine capable of running a `--privileged`
container. It uses a digest-pinned `alpine:3.21` image and installs `bash`,
`iproute2`, `nginx`, `python3`, `curl`, `jq`, and `util-linux` at runtime.
Inside the container, it creates a `nginx-client` network namespace connected
over a `veth` pair (`192.0.2.2/24` to `192.0.2.1/24`), starts a Python HTTP
backend on `127.0.0.1:18080`, plants four synthetic secret markers (a config
comment, a `proxy_set_header` bearer token, an `auth_basic` realm, and an
`auth_basic_user_file` path), and removes all temporary files, namespaces, and
containers on exit.

## Test matrix

| Case | Client HTTP observation | Local TCP and config evidence | Exit | Replay and secret checks |
| --- | --- | --- | --- | --- |
| Live reverse proxy to running loopback backend | `200` with `reachmap-nginx-ok` | Frontend `192.0.2.1:8080` and backend `127.0.0.1:18080` listeners matched | `0` | Empty-netns replay matches live stdout; no synthetic secrets |
| Stopped/missing loopback backend | `502` from Nginx frontend | Frontend listener matched; backend `127.0.0.1:18081` reports `no matching TCP listener` | `0` | Empty-netns replay matches live stdout; no synthetic secrets |
| Proxy-auth-protected route (`auth_basic`) | `401` unauthenticated; `200` with Basic credentials | `proxy auth: auth_basic=on; application auth: unverified` | `0` | Empty-netns replay matches live stdout; realm and htpasswd path omitted |
| Dynamic route directives (`if` and `rewrite`) | Not assumed static | `Configuration uncertainties` lists `dynamic control flow` (`if`) and `dynamic routing` (`rewrite`) | `1` | Empty-netns replay matches live stdout; uncertainties preserved in JSON |
| Unprivileged collector (`chmod 600` route file) | N/A | Clean `permission denied` diagnostic on stderr, empty stdout | `1` | Raw config lines and synthetic secrets do not leak into stderr |

## Scope and evidence limits

- `nginx -T` inspects the on-disk configuration rather than the running Nginx
  master's active worker state.
- Non-loopback static targets cannot be proven reachable locally and remain
  separate from remote connectivity checks.
- Failed HTTP requests (`000` / no response) or `502`/`503`/`504` responses
  never establish a firewall verdict by themselves.
- Application-level authentication and upstream authorization policy always
  remain `unverified`.

## Verification record

The five-case Linux lab and offline replay parity checks passed using
Reachmap `0.5.0` (built from `feat/110-nginx-verification` on top of
`26dbeb9`), `Alpine Linux v3.21` (`Linux 7.2.12-orbstack-00394-gbecdd6130068`
on ARM64), `nginx/1.26.3`, and `iproute2-6.11.0`.
