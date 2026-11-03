# Changelog

All notable changes to reachmap are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
