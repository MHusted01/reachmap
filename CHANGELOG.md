# Changelog

All notable changes to reachmap are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `reachmap diff --ignore <ports>` leaves ports and ranges out of the comparison,
  on every protocol, so an unattended check stays quiet about known noise. A note
  says how many differences were left out, even when that is 0, and `--json` gains
  an `ignored` field. Left-out differences do not change the exit status
  ([#43](https://github.com/MHusted01/reachmap/issues/43)).
- `reachmap probe <host> --scan scan.json [--from <network>]` takes the TCP ports
  from a saved `reachmap scan --json`, probes them and reports where the two
  disagree: a connection the scan rules out, or none where the scan expects one.
  Either sets exit status 1, and `--json` gains a `comparison` object. The network
  is worked out from the address the probe connects to, and `--from` overrides it
  ([#41](https://github.com/MHusted01/reachmap/issues/41)).
- `reachmap scan` recognises a socket bound to a subnet's broadcast address, as
  Samba's `nmbd` does. The row used to say that no interface has the address and
  show `unknown`; WHY now names the interface, REACHABLE FROM shows its network,
  and `--json` has the new reason `broadcast`. `reachmap diff` reports such a row
  once as changed against a baseline saved before this
  ([#39](https://github.com/MHusted01/reachmap/issues/39)).
- `reachmap scan` reads `tailscale serve status --json`. A row that Tailscale
  forwards to gains `tailnet`, and with Funnel also `internet`, and WHY says so.
  Every Funnel port is a warning, so the scan exits with 1, and a `tailscale`
  that cannot be asked is reported as unknown. `--json` has the new reason
  `tailscale_shared`, the warnings `tailscale_funnel` and `tailscale_unknown` and
  the collector `tailscale`
  ([#12](https://github.com/MHusted01/reachmap/issues/12)).
- `reachmap diff <baseline> [<current>]` compares a saved `reachmap scan --json`
  with a fresh scan, or with a second file, and reports new, removed, changed and
  unverified rows, with `--json` for scripts. It exits with 0 when nothing needs
  attention, 1 when something does and 2 when it could not compare
  ([#11](https://github.com/MHusted01/reachmap/issues/11)).
- `reachmap probe <host> --ports 22,80,8000-8100` tries to connect to TCP ports
  from this machine and reports each as open, closed, no answer, unreachable or
  failed. It runs on macOS too, tries every address of a host name, and has
  `--timeout`, `--concurrency` and `--json`
  ([#10](https://github.com/MHusted01/reachmap/issues/10)).
- `reachmap scan` lists UDP sockets that can receive from any peer, as `udp` and
  `udp6`, with their owner, verdict and socket options. A note under the table
  says that a connect probe cannot confirm UDP rows; it does not change the exit
  status. `--json` reports them with `"protocol": "udp"`
  ([#9](https://github.com/MHusted01/reachmap/issues/9)).
- Docker's published UDP ports are listed and get the UFW warnings
  ([#9](https://github.com/MHusted01/reachmap/issues/9)).
- A socket bound to a multicast address says so in WHY, instead of
  `no interface has this address`
  ([#9](https://github.com/MHusted01/reachmap/issues/9)).

### Fixed

- A failed request for socket options no longer discards what the kernel already
  reported, so those sockets keep their checked verdicts
  ([#9](https://github.com/MHusted01/reachmap/issues/9)).

## [0.1.0] - 2026-11-05

### Added

- `reachmap scan` lists the TCP sockets listening on a Linux host (IPv4 and
  IPv6) with their port and bind address, sorted by port
  ([#2](https://github.com/MHusted01/reachmap/issues/2)).
- `reachmap scan` shows the process behind each socket in a new SERVICE
  column, e.g. `sshd (812)`. Without root, sockets of other users' processes
  show `unknown (run with sudo for details)`
  ([#3](https://github.com/MHusted01/reachmap/issues/3)).
- `reachmap scan` shows where each socket can be reached from in two new
  columns, REACHABLE FROM (this host, Docker, tailnet, LAN, or internet) and
  WHY. It compares the bind address with the host's interfaces from
  `ip -j addr`; public addresses are reported as
  `internet (if not filtered upstream)`, never as safe. Without `ip`, the
  scan warns and shows `unknown`
  ([#4](https://github.com/MHusted01/reachmap/issues/4)).
- `reachmap scan` shows the Docker container behind each published port, e.g.
  `web (container shop-web-1)`, instead of `docker-proxy`. A published port
  without a host socket gets its own row, marked in WHY. When Docker is
  missing, unreachable or hung, the scan continues with a note. Commands now
  have a timeout, and names and messages from other programs are cleaned of
  terminal escape sequences before printing
  ([#5](https://github.com/MHusted01/reachmap/issues/5)).
- `reachmap scan` warns when UFW is active and Docker publishes a port on
  anything but loopback: WHY says `Docker port: UFW does not apply`, and a
  summary follows the table. Rules in `DOCKER-USER` are reported as
  `filtering may apply, not verified`. When UFW's state or Docker's ports are
  unknown, the warning says so instead of passing
  ([#6](https://github.com/MHusted01/reachmap/issues/6)).
- `reachmap scan --json` prints the same findings as versioned JSON for
  scripts, including what could not be collected. The fields are documented in
  [docs/json.md](docs/json.md)
  ([#7](https://github.com/MHusted01/reachmap/issues/7)).
- `reachmap scan` asks the kernel which device a socket is bound to and
  whether it is IPv6-only. A socket bound to `tailscale0` now shows `tailnet`
  and `only on tailscale0` instead of every network, an IPv6-only `::` socket
  counts IPv6 addresses only and no longer takes the name of a container
  published on `0.0.0.0`, and WHY drops "not checked" where the kernel answered.
  In JSON, `all_addresses` and `no_addresses` now have `covers` instead of
  `family`, and `all_addresses` has `checked`. If the kernel cannot be asked, the
  scan continues with a note and the old wording
  ([#21](https://github.com/MHusted01/reachmap/issues/21)).
- reachmap can be installed with Homebrew, `cargo install`, or as a prebuilt
  binary for Linux and macOS (x86_64 and aarch64) from the GitHub Release
  ([#8](https://github.com/MHusted01/reachmap/issues/8)).

### Changed

- `reachmap scan` exits with status 1 when it prints a warning, so it fits
  scripts ([#6](https://github.com/MHusted01/reachmap/issues/6)).

### Fixed

- `reachmap scan` shows `unknown (run with sudo for details)` when `/proc` is
  mounted with `hidepid` and hides other users' processes, instead of a plain
  `unknown` ([#20](https://github.com/MHusted01/reachmap/issues/20)).
