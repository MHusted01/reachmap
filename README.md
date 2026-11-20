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

> **Status.** v0.1.0 ships Linux TCP inventory, JSON and Docker/UFW warnings.
> The main branch also includes UDP inventory, Tailscale Serve and Funnel
> awareness, TCP probes, baseline diffs, macOS socket inventory and Linux
> container egress checks. Scan results
> describe potential exposure based on local evidence. [Changelog](CHANGELOG.md) ·
> [Scan](docs/scan.md) · [JSON](docs/json.md) · [Probe](docs/probe.md) · [Diff](docs/diff.md) · [Egress](docs/egress.md)

## Install

```sh
brew install mhusted01/tap/reachmap   # macOS and Linux
cargo install reachmap                # from crates.io
```

Prebuilt binaries for Linux and macOS (x86_64 and aarch64) are attached to each
[GitHub Release](https://github.com/MHusted01/reachmap/releases). The Linux
binaries are static, so they run on any distribution.

On the main branch, `reachmap scan`, `reachmap probe` and `reachmap diff` run on
Linux and macOS. See the [macOS scan scope](docs/scan.md#macos).

## Features

- **Read-only.** reachmap reports; it never changes firewall rules, containers
  or settings.
- **Explains itself.** Every verdict says why, so you can check it.
- **Honest about gaps.** When it cannot know something (for example without
  root), it says so instead of guessing "safe".
- **Notices changes.** `reachmap diff` compares a host with a saved scan and
  exits with 1 when something changed, for cron jobs.
- **No telemetry.** Network traffic comes from the `probe` and `egress` checks you start yourself.

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
