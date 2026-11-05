# reachmap

**Which services on this host can be reached, from where, and why?**

reachmap lists every listening service on a Linux host, the program or
container behind it, and who can connect to it: only the host itself, the
local network, your Tailscale tailnet, or everyone. It explains each verdict,
including the classic trap where ports published by Docker skip UFW.

```
$ sudo reachmap scan
PORT  PROTO  ADDRESS    SERVICE                     REACHABLE FROM                   WHY
22    tcp    0.0.0.0    sshd (812)                  this host, Docker, tailnet, LAN  all IPv4 addresses
3306  tcp    127.0.0.1  mysqld (1201)               this host                        loopback address
8080  tcp    0.0.0.0    web (container shop-web-1)  this host, Docker, tailnet, LAN  all IPv4 addresses; Docker port: UFW does not apply

warning: UFW is active, but it does not apply to these Docker ports: 8080
```

> **Status:** v0.1. `reachmap scan` lists listening TCP and UDP sockets on Linux with
> their bind address, the process or Docker container behind each, and the
> networks (this host, Docker, tailnet, LAN, internet) they can be reached from,
> before firewall rules, and warns when Docker-published ports skip an active
> UFW ([details](docs/scan.md)). `reachmap scan --json` prints the same findings
> for scripts ([fields](docs/json.md)). `reachmap probe` tries to connect to a
> host's TCP ports from another machine ([details](docs/probe.md)).

## Install

```sh
brew install mhusted01/tap/reachmap   # macOS and Linux
cargo install reachmap                # from crates.io
```

Prebuilt binaries for Linux and macOS (x86_64 and aarch64) are attached to each
[GitHub Release](https://github.com/MHusted01/reachmap/releases). The Linux
binaries are static, so they run on any distribution.

`reachmap scan` needs Linux for now; macOS support is planned. `reachmap probe`
runs on both.

## Features

- **Read-only.** reachmap reports; it never changes firewall rules, containers
  or settings.
- **Explains itself.** Every verdict says why, so you can check it.
- **Honest about gaps.** When it cannot know something (for example without
  root), it says so instead of guessing "safe".
- **No telemetry.** The only network traffic is a probe you start yourself.

Background: [why Docker ports can bypass UFW](docs/docker-and-ufw.md).

## Development

```sh
make check   # lint, tests with coverage gate, cargo-deny, build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
