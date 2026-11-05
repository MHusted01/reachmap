# reachmap

**Which services on this host can be reached, from where, and why?**

reachmap lists every listening service on a Linux host, the program or
container behind it, and who can connect to it: only the host itself, the
local network, your Tailscale tailnet, or everyone. It explains each verdict,
including the classic trap where ports published by Docker skip UFW.

```
$ sudo reachmap scan

PORT   SERVICE               REACHABLE FROM     WHY
22     sshd                  LAN, tailnet       bound to 0.0.0.0
80     nginx (docker)        LAN, tailnet       published on 0.0.0.0
5432   postgres (docker)     LAN  (!)           Docker port: UFW does not apply
6379   redis-server          this host only     bound to 127.0.0.1
```

> **Status:** early development. The example shows the planned v0.1 output.
> Today `reachmap scan` lists listening TCP sockets with their bind address,
> the process or Docker container behind each, and the networks (this host,
> Docker, tailnet, LAN, internet) it can be reached from, before firewall rules,
> and warns when Docker-published ports skip an active UFW
> ([details](docs/scan.md)); follow the
> [v0.1 milestone](https://github.com/MHusted01/reachmap/milestones) for progress.

## Install

Not released yet. v0.1.0 will be available through:

```sh
brew install mhusted01/tap/reachmap   # macOS and Linux
cargo install reachmap                # from crates.io
```

Prebuilt binaries for Linux (x86_64, aarch64) and macOS will be attached to each
[GitHub Release](https://github.com/MHusted01/reachmap/releases).

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
