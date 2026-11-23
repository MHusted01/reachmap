# reachmap

**Which services on this host can be reached, from where, and why?**

reachmap inventories listening services and identifies the process behind each.
On Linux it also identifies published Docker ports and estimates which networks
can reach a service from its bind address and local configuration. A separate
probe can check TCP access from another machine.

```
$ sudo reachmap scan
PORT  PROTO  ADDRESS    SERVICE                     REACHABLE FROM                   WHY
22    tcp    0.0.0.0    sshd (812)                  this host, Docker, tailnet, LAN  all IPv4 addresses
3306  tcp    127.0.0.1  mysqld (1201)               this host                        loopback address
8080  tcp    0.0.0.0    web (container shop-web-1)  this host, Docker, tailnet, LAN  all IPv4 addresses; Docker port: UFW does not apply

warning: UFW is active, but it does not apply to these Docker ports: 8080
```

> **Status.** v0.6.0 adds `reachmap scan --nginx-routes` on Linux: configured
> Nginx reverse proxy routes, with frontend listeners and backend targets linked
> to local TCP listeners, snapshot capture and offline `reachmap replay`. It
> reads the configuration on disk at Nginx's built-in path, which can differ
> from what a running Nginx has loaded, and leaves application authentication
> unverified. v0.5.0 added Tailscale Serve and Funnel routes and
> single-endpoint Linux TCP audits over authenticated SSH.
> [Changelog](CHANGELOG.md) ·
> [Scan](docs/scan.md) · [JSON](docs/json.md) · [Probe](docs/probe.md) · [Diff](docs/diff.md) · [Egress](docs/egress.md) · [TCP path](docs/scan.md#linux-inbound-tcp-paths) · [Tailscale routes](docs/scan.md#tailscale) · [Nginx routes](docs/scan.md#nginx) · [SSH audit](docs/audit.md)

## Install

```sh
brew install mhusted01/tap/reachmap   # macOS and Linux
cargo install reachmap                # from crates.io
```

Prebuilt binaries for Linux and macOS (x86_64 and aarch64) are attached to each
[GitHub Release](https://github.com/MHusted01/reachmap/releases). The Linux
binaries are static, so they run on any distribution.

`reachmap scan`, `reachmap probe` and `reachmap diff` run on Linux and macOS.
See the [macOS scan scope](docs/scan.md#macos).

## Features

- **Read-only.** reachmap reports; it never changes firewall rules, containers
  or settings.
- **Explains itself.** Every verdict says why, so you can check it.
- **Honest about gaps.** When it cannot know something (for example without
  root), it says so instead of guessing "safe".
- **Notices changes.** `reachmap diff` compares a host with a saved scan and
  exits with 1 when something changed, for cron jobs.
- **No telemetry.** Network traffic comes from the `probe`, `egress` and `audit` checks you start yourself.

Background: [why Docker ports can bypass UFW](docs/docker-and-ufw.md).

See the [roadmap](docs/roadmap.md) for deeper path analysis, platform support
and upcoming work.

## Development

```sh
make check   # lint, tests with coverage gate, cargo-deny, build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
