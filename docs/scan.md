# reachmap scan

`reachmap scan` lists every TCP socket on this host that is waiting for
connections (the LISTEN state) and every port Docker publishes, sorted by port,
with the program or container behind it and the networks it can be reached
from.

```
$ sudo reachmap scan
PORT  PROTO  ADDRESS          SERVICE                     REACHABLE FROM                   WHY
22    tcp    0.0.0.0          sshd (812)                  this host, Docker, tailnet, LAN  all IPv4 addresses (bound device not checked)
22    tcp6   ::               sshd (812)                  this host, Docker, tailnet, LAN  all IPv6 and IPv4 addresses (IPv6-only and bound device not checked)
53    tcp    127.0.0.53       systemd-resolve (640)       this host                        loopback address
631   tcp6   ::1              cupsd (1033)                this host                        loopback address
3000  tcp    127.0.0.1        web (container shop-web-1)  this host                        loopback address
3306  tcp    127.0.0.1        mysqld (1201)               this host                        loopback address
8080  tcp    192.168.1.20     python3 (4410)              LAN                              only on enp1s0
9000  tcp    0.0.0.0          container metrics           this host, Docker, tailnet, LAN  all IPv4 addresses (bound device not checked)
9100  tcp    100.101.102.103  node_exporter (902)         tailnet                          only on tailscale0
```

## Columns

| Column  | Meaning |
|---------|---------|
| PORT    | The TCP port the service listens on. |
| PROTO   | `tcp` for IPv4, `tcp6` for IPv6. |
| ADDRESS | The local address the socket is bound to (see below). |
| SERVICE | The program that has the socket open, as `name (pid)`, or the Docker container the port is published for (see below). |
| REACHABLE FROM | The networks whose clients can connect (see below). |
| WHY | The fact behind REACHABLE FROM, including what was not checked. |

## Reading the address

The bind address is the first clue to who can connect:

| Address | Bound to |
|---------|----------|
| `0.0.0.0`, `::` | every interface: loopback, LAN, VPN, Docker bridges |
| `127.0.0.1`, `::1`, `127.0.0.53` | loopback only: this host |
| a specific address, e.g. `192.168.1.20` | that interface only |
| `::ffff:a.b.c.d` | an IPv4 address seen through an IPv6 socket |

A `tcp6` socket bound to `::` usually accepts IPv4 connections as well (unless
the kernel setting `net.ipv6.bindv6only` is on), even though it is listed only
once, as `tcp6`. Services such as sshd open one socket per protocol, so their
port appears as both `tcp` and `tcp6`.

## Reading REACHABLE FROM and WHY

reachmap compares the bind address with the addresses of this host's network
interfaces, as `ip -j addr` lists them. Each interface address belongs to one
network:

| Network | Interface addresses that belong to it |
|---------|----------------------------------------|
| `this host` | loopback addresses (`127.0.0.0/8`, `::1`); other addresses on `lo`, such as anycast or virtual IPs, follow the rules below |
| `Docker` | addresses on Docker's interfaces: `docker0`, `br-<12 hex digits>` (one per user-defined network) and `veth*` (container links) |
| `tailnet` | anything on `tailscale0`, and Tailscale's IPv6 prefix `fd7a:115c:a1e0::/48` on any interface |
| `LAN` | other private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) and link-local ones (`169.254.0.0/16`, `fe80::/10`) |
| `internet (if not filtered upstream)` | every other address: a public IPv4 or IPv6 address |

The rules are checked in that order, so `172.18.0.1` on a Docker bridge is
`Docker`, not `LAN`.

Interfaces are recognized by name. A Docker bridge renamed with the
`com.docker.network.bridge.name` option counts as `LAN`, and `veth*` links
created by other container tools (Podman, LXC) count as `Docker`.

Tailscale's IPv4 addresses come from `100.64.0.0/10`, which internet providers
also use for carrier-grade NAT. Such an address on any interface other than
`tailscale0` is therefore not taken as the tailnet; it is not a private range
either, so it counts as `internet (if not filtered upstream)`.

A socket is reachable from the networks of the addresses it accepts
connections on:

| WHY | Meaning |
|-----|---------|
| `loopback address` | Bound to `127.0.0.1`, `::1` or another loopback address: only programs on this host can connect. Needs no interface facts. |
| `only on enp1s0` | Bound to one address; the interface that has it decides the network. |
| `all IPv4 addresses (bound device not checked)` | Bound to `0.0.0.0`: every network with an IPv4 address on this host. |
| `all IPv6 and IPv4 addresses (IPv6-only and bound device not checked)` | Bound to `::`: every network with any address on this host. |
| `no interface has this address` | Bound to an address that no interface has (for example, an interface that went away). REACHABLE FROM is `unknown`. |
| `no interface has an IPv4 address` | Bound to `0.0.0.0` on a host without IPv4 addresses (or `::` on a host without any). REACHABLE FROM is `unknown`. |
| `...; no host socket, Docker forwards this port` | Docker publishes the port but no socket listens on the host (see [Docker](#docker)). The first part is the usual reason for the published address. |
| `could not list interfaces` | `ip -j addr` failed; a warning on stderr says why. REACHABLE FROM is `unknown`, except for loopback addresses. |

**Internet means "not filtered by this host's address".** A public address
puts a socket on the internet unless a router, cloud security group or
firewall in front of the host drops the traffic. reachmap cannot see those, so
it never calls such a socket safe.

**What "not checked" means.** Two socket options narrow who can connect but
are not visible in `/proc/net/tcp`:

- A socket can be bound to one device (`SO_BINDTODEVICE`); `ss` shows this as
  `0.0.0.0%tailscale0:PORT`. It then accepts traffic from that interface only.
- A `::` socket accepts IPv4 too, unless it is IPv6-only (`IPV6_V6ONLY`).
  Services such as sshd set this and open a separate IPv4 socket.

Until reachmap reads them
([#21](https://github.com/MHusted01/reachmap/issues/21)), it assumes the wider
case, so REACHABLE FROM may list more networks than can actually connect,
never fewer.

**Not a firewall verdict.** REACHABLE FROM says who could connect if no firewall
interferes. UFW's rules are not evaluated. The one firewall fact reachmap reports
is that UFW does not apply to Docker's published ports; see
[Why Docker ports can bypass UFW](docker-and-ufw.md#what-reachmap-reports).

## Reading the service

The name is the short program name the kernel keeps for each process (at most
15 characters, so `systemd-resolved` shows as `systemd-resolve`). When several
processes share one socket, such as a web server and the workers it started,
the one with the lowest process ID is shown; that is usually the parent.

The exception is systemd. With socket activation, systemd opens a port and
hands it to a service such as sshd, so both hold the socket; reachmap then
shows the service. `systemd (1)` appears only when systemd is the sole holder:
a socket unit (for example `cockpit.socket`) whose service has not started
yet. The same applies to per-user `systemd --user` instances.

| SERVICE | Meaning |
|---------|---------|
| `sshd (812)` | Process 812, named `sshd`, has the socket open. |
| `web (container shop-web-1)` | Docker publishes the port for container `shop-web-1`, service `web` of a Compose project. |
| `container metrics` | Docker publishes the port for container `metrics`, which is not part of a Compose project. |
| `unknown (run with sudo for details)` | Some processes belong to other users and could not be inspected; run `sudo reachmap scan` to see them. |
| `unknown` | No visible process holds the socket. This happens for sockets the kernel opens itself (for example NFS), for a process that exited during the scan, and for processes hidden by `hidepid` (see below). |

Names come from other programs and may hold anything, so characters that could
change how the terminal shows the output, such as escape sequences and line
breaks, are printed as visible text, e.g. `\u{1b}`.

## Docker

reachmap asks Docker for the running containers with `docker ps -q` and
`docker inspect`, and matches their published TCP ports to the sockets on this
host by address and port. The socket's row then shows the container instead of
the process holding it, which is `docker-proxy` or, with `userland-proxy: false`,
`dockerd`. This needs no root as long as you can use `docker`, and only reads.

A socket on `::` counts as serving a port published on `0.0.0.0`, as it usually
accepts IPv4 too. Until reachmap reads the IPv6-only flag
([#21](https://github.com/MHusted01/reachmap/issues/21)), an unrelated IPv6-only
socket on the same port takes the container's name and hides the `0.0.0.0` row;
its own row still lists IPv4 networks, so reach is not understated.

A published port that no socket listens on still gets a row, marked in WHY,
with the verdict for the published address. A port that is only exposed
(`EXPOSE`, or `expose:` in Compose) is not reachable from the host's networks
and gets no row. Containers on the host network (`network_mode: host`) publish
nothing: their sockets show up as ordinary processes.

When Docker cannot be asked, the scan continues and prints one `note:` on
stderr. Sockets of published ports then show `docker-proxy`, `dockerd` or
`unknown`, and ports without a socket are missing:

| Note | Meaning |
|------|---------|
| `Docker was not found` | There is no `docker` command. |
| `could not ask Docker for its containers` | `docker` failed or did not finish within 5 seconds; the note ends with the reason, for example that the daemon is not running. If you lack access to Docker's socket, a hint suggests `sudo`. |
| `could not understand Docker's output` | Likely a reachmap bug or a new Docker format; a hint says where to report it. |

reachmap runs the first of `/usr/bin/docker`, `/usr/local/bin/docker`,
`/bin/docker` and `/snap/bin/docker` that exists, and looks `docker` up through
`PATH` only if none does. `docker` follows `DOCKER_HOST` and the current Docker
context. If they point at another machine, its containers are listed as if they
ran here, as ports without a host socket.

## Requirements and limits

- **Linux only for now.** On other systems `scan` prints
  `reachmap scan is Linux only for now` and exits with status 1.
- **Root shows more.** The sockets come from `/proc/net/tcp` and
  `/proc/net/tcp6`, which every user can read. Finding the process behind a
  socket means reading `/proc/<pid>/fd`, which only works for your own
  processes unless you run `scan` with `sudo`. reachmap only reads; it never
  changes anything, with or without root.
- **Hidden processes.** When `/proc` is mounted with `hidepid=2` (or
  `hidepid=invisible`), other users' processes are invisible rather than
  locked. reachmap cannot tell them apart from sockets without a process yet,
  so their sockets show `unknown` without the sudo hint. Running with `sudo`
  still finds them.
- **One network namespace.** `scan` sees the sockets of the namespace it runs
  in. Docker containers on their own network have separate sockets, so only
  their published ports appear (see [Docker](#docker)).
- **`DOCKER-USER` needs root.** Reading the chain runs `iptables -S DOCKER-USER`,
  which only works with `sudo`. reachmap runs the first of `/usr/sbin/iptables`,
  `/sbin/iptables`, `/usr/bin/iptables` and `/bin/iptables` that exists, and looks
  `iptables` up through `PATH` only if none does.
- **Interfaces need `ip`.** The interface list comes from `ip -j addr`
  (package `iproute2`, installed on nearly every Linux distribution). reachmap
  runs the first of `/usr/sbin/ip`, `/usr/bin/ip`, `/sbin/ip` and `/bin/ip`
  that exists, and looks `ip` up through `PATH` only if none does. Without
  it, the scan still lists every socket, prints a warning, and shows
  REACHABLE FROM as `unknown` for all but loopback addresses.
- **TCP only.** UDP is planned for v0.2, for Docker's published ports too.
- When IPv6 is disabled in the kernel, `/proc/net/tcp6` does not exist and
  only IPv4 sockets are listed.

## Exit status

| Status | Meaning |
|--------|---------|
| 0 | The scan finished without warnings (also when nothing is listening). |
| 1 | The scan finished with [warnings](docker-and-ufw.md#what-reachmap-reports) under the table, or it failed and printed the reason on stderr. |
| 2 | Invalid arguments. |
