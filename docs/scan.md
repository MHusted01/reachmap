# reachmap scan

`reachmap scan` lists every TCP socket on this host that is waiting for
connections (the LISTEN state), every UDP socket that can receive from any peer
(see [UDP](#udp)) and every port Docker publishes, sorted by port, with the
program or container behind it and the networks it can be reached from.

```
$ sudo reachmap scan
PORT  PROTO  ADDRESS          SERVICE                     REACHABLE FROM                   WHY
22    tcp    0.0.0.0          sshd (812)                  this host, Docker, tailnet, LAN  all IPv4 addresses
22    tcp6   ::               sshd (812)                  this host, tailnet, LAN          all IPv6 addresses
53    tcp    127.0.0.53       systemd-resolve (640)       this host                        loopback address
53    udp    127.0.0.53       systemd-resolve (640)       this host                        loopback address
631   tcp6   ::1              cupsd (1033)                this host                        loopback address
3000  tcp    127.0.0.1        web (container shop-web-1)  this host                        loopback address
3306  tcp    127.0.0.1        mysqld (1201)               this host                        loopback address
8080  tcp    192.168.1.20     python3 (4410)              LAN                              only on enp1s0
9000  tcp    0.0.0.0          container metrics           this host, Docker, tailnet, LAN  all IPv4 addresses
9100  tcp    100.101.102.103  node_exporter (902)         tailnet                          only on tailscale0
9200  tcp    0.0.0.0          grafana (1544)              tailnet                          only on tailscale0

note: UDP has no connection handshake, so a connect probe cannot confirm that UDP rows are reachable
```

## Columns

| Column  | Meaning |
|---------|---------|
| PORT    | The TCP or UDP port the service listens on. |
| PROTO   | `tcp` or `udp` for IPv4, `tcp6` or `udp6` for IPv6. |
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
| `only on enp1s0` | Bound to one address, or to this device; the interface decides the network. |
| `broadcast address of enp1s0` | Bound to the broadcast address of a subnet, as Samba's `nmbd` does. The socket receives what is broadcast there, not what is sent to this host's own address. REACHABLE FROM is the network of that interface. A TCP socket can bind such an address, but no client can connect to it; reachmap reports it the same way, so the row can show more reach than there is. |
| `all IPv4 addresses` | Bound to `0.0.0.0`: every network with an IPv4 address on this host. |
| `all IPv6 and IPv4 addresses` | Bound to `::`: every network with any address on this host. |
| `all IPv6 addresses` | Bound to `::` with the IPv6-only option: every network with an IPv6 address on this host. |
| `all IPv4 addresses (bound device not checked)` | Like `all IPv4 addresses`, but the socket's options are unknown (see below). |
| `all IPv6 and IPv4 addresses (IPv6-only and bound device not checked)` | Like `all IPv6 and IPv4 addresses`, but the socket's options are unknown (see below). |
| `no interface has this address` | Bound to an address that no interface has (for example, an interface that went away). REACHABLE FROM is `unknown`. Also shown for `255.255.255.255`, and for the broadcast address of a subnet configured without one (`ip addr add` without `brd`), because `ip -j addr` does not list those. |
| `multicast address, group membership not checked` | A UDP socket bound to a multicast group, such as `239.255.255.250`. It receives what is sent to the group, and reachmap does not read which groups this host joined. REACHABLE FROM is `unknown`. Needs no interface facts. |
| `no interface has an IPv4 address` | Bound to `0.0.0.0` on a host without IPv4 addresses (or an IPv6-only `::` on a host without IPv6 addresses, or `::` on a host without any). REACHABLE FROM is `unknown`. |
| `bound to eth1, which has no address it can use` | Bound to a device without a suitable address, such as a VRF device whose addresses are on other interfaces. REACHABLE FROM is `unknown`. |
| `...; shared by Tailscale Funnel on 443` | Tailscale forwards connections to this socket (see [Tailscale](#tailscale)). The first part is the socket's own reason. |
| `...; no host socket, Docker forwards this port` | Docker publishes the port but no socket listens on the host (see [Docker](#docker)). The first part is the usual reason for the published address. |
| `could not list interfaces` | `ip -j addr` failed; a warning on stderr says why. REACHABLE FROM is `unknown`, except for loopback addresses. |

**Internet means "not filtered by this host's address".** A public address
puts a socket on the internet unless a router, cloud security group or
firewall in front of the host drops the traffic. reachmap cannot see those, so
it never calls such a socket safe.

**Socket options.** Two options narrow who can connect but are not visible in
the kernel's socket tables, so reachmap asks the kernel for them through netlink
`sock_diag`, the interface `ss` uses. This needs no root and only reads.

- A socket can be bound to one device (`SO_BINDTODEVICE`); `ss` shows this as
  `0.0.0.0%tailscale0:PORT`. It then accepts traffic from that interface only,
  so REACHABLE FROM lists that interface's network and WHY says
  `only on tailscale0`. The kernel also does this by itself for a link-local
  address, which keeps its own verdict.
- A `::` socket accepts IPv4 too, unless it is IPv6-only (`IPV6_V6ONLY`).
  Services such as sshd set this and open a separate IPv4 socket.

**What "not checked" means.** When the kernel gives no answer for a socket,
reachmap assumes the wider case, so REACHABLE FROM may list more networks than
can actually connect, never fewer. If a request fails, a note on stderr says
why and the scan continues; the exit code does not change. TCP is asked first,
so when only the UDP request fails, TCP rows keep their facts. Docker-forwarded
ports without a host socket always show this wording, as there is no socket
to ask about.

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
| `unknown (run with sudo for details)` | Some processes belong to other users and could not be inspected, or `/proc` may hide them (see below); run `sudo reachmap scan` to see them. |
| `unknown` | No process holds the socket. This happens for sockets the kernel opens itself (for example NFS) and for a process that exited during the scan. |

Names come from other programs and may hold anything, so characters that could
change how the terminal shows the output, such as escape sequences and line
breaks, are printed as visible text, e.g. `\u{1b}`.

## UDP

UDP has no LISTEN state and no connections. reachmap lists the sockets that are
not connected to one peer, as `ss -uln` does, because those can receive from
anyone. A connected socket only accepts its peer, so it is left out. Three things
follow:

- **Not every row is a server.** A client that sent a datagram without connecting
  looks exactly like a server to the kernel, so short-lived rows on high port
  numbers are common. reachmap lists them: they do receive traffic. They also
  show up in [`reachmap diff`](diff.md#udp-rows).
- **A row means the socket accepts traffic, not that anything answers.** Without
  a handshake, a service can stay silent, so a connect probe such as
  [`reachmap probe`](probe.md) cannot confirm a UDP row. The note under the
  table says so. It is not a warning, so it does
  not change the exit status.
- **Some sockets belong to the kernel.** Tunnels such as VXLAN and kernel
  WireGuard hold a socket that no process has open, so SERVICE stays `unknown`,
  also with `sudo`.

## Docker

reachmap asks Docker for the running containers with `docker ps -q` and
`docker inspect`, and matches their published TCP and UDP ports to the sockets on
this host by protocol, address and port. The socket's row then shows the container instead of
the process holding it, which is `docker-proxy` or, with `userland-proxy: false`,
`dockerd`. This needs no root as long as you can use `docker`, and only reads.

A socket on `::` counts as serving a port published on `0.0.0.0`, as it usually
accepts IPv4 too. An IPv6-only socket does not, so it keeps its own process and
the `0.0.0.0` row stays. If the socket's options are unknown it counts as
serving the port; its row then lists IPv4 networks, so reach is not understated.

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

## Tailscale

`tailscale serve` shares a program with the tailnet, and `tailscale funnel`
shares it with the internet. Tailscale accepts these connections itself and
forwards them, usually to a program on loopback, so the program's socket says
nothing about them. reachmap therefore asks `tailscale serve status --json`,
which only reads and needs no root.

A row that Tailscale forwards to gains `tailnet`, and with Funnel also
`internet (if not filtered upstream)`. WHY keeps the socket's own reason and
adds the ports clients connect to:

```text
loopback address; shared by Tailscale Funnel on 443
all IPv4 addresses; shared by Tailscale Serve on 8443 and Funnel on 443
```

A row whose reach is `unknown` stays `unknown`, because other networks may
connect too; WHY still names Tailscale's ports.

A wildcard socket counts when it accepts the target's address. A `::` socket
counts for IPv4 targets too, even if it is IPv6-only, so a row can list more
networks than can connect, never fewer.

Every Funnel port is a warning under the table, so the scan exits with 1, also
when you share the port on purpose. Serve alone is no warning.

- **No `tailscale` command.** Nothing is reported, as a host without it shares
  nothing.
- **`tailscale` fails.** For example when `tailscaled` is stopped. The scan
  continues with a note on stderr and a warning that it is unknown what is
  shared, so it exits with 1. Rows keep the reach of their socket.
- **Some targets have no row.** A file, a text, a redirect, a Unix socket and
  a host name other than `localhost` have no address to match, and an address
  on another machine has no socket here. Funnel ports are
  still listed in the warning; a port shared with the tailnet alone does not
  show.
- **The shared port itself may have no row.** Tailscale can accept the
  connection without a socket in the kernel's tables.
- **Funnel counts per port.** When one port is shared under two names, or by a
  Tailscale Service as well, and Funnel is on for one of them, all of them
  count as Funnel.
- **Tailscale in a container is not seen.** reachmap asks the `tailscale`
  command on this host. Tailscale Services in `Tun` mode forward no port that
  reachmap can name, so they do not show either.

## Requirements and limits

- **Linux only for now.** On other systems `scan` prints
  `reachmap scan is Linux only for now` and exits with status 1.
- **Root shows more.** The sockets come from `/proc/net/tcp`, `/proc/net/udp`
  and their IPv6 twins `tcp6` and `udp6`, which every user can read. Finding the process behind a
  socket means reading `/proc/<pid>/fd`, which only works for your own
  processes unless you run `scan` with `sudo`. reachmap only reads; it never
  changes anything, with or without root.
- **Hidden processes.** When `/proc` is mounted with `hidepid=2` or
  `hidepid=4` (also written `invisible` and `ptraceable`), other users'
  processes are invisible rather than locked. reachmap reads the mount options
  from `/proc/self/mountinfo` and shows the sudo hint on sockets without an
  owner, and `sudo` finds those owners. If that file cannot be read or does
  not list `/proc`, reachmap assumes processes may be hidden and shows the hint
  too, without a warning. Root never gets the hint, even in a restricted
  container where root lacks `CAP_SYS_PTRACE` and processes stay hidden.
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
- **Tailscale needs `tailscale`.** reachmap runs the first of
  `/usr/bin/tailscale`, `/usr/local/bin/tailscale`, `/bin/tailscale` and
  `/snap/bin/tailscale` that exists, and looks `tailscale` up through `PATH` only
  if none does.
- **TCP and UDP only.** Other protocols, such as a port Docker publishes as
  `sctp`, are not listed.
- When IPv6 is disabled in the kernel, `/proc/net/tcp6` and `/proc/net/udp6` do
  not exist and only IPv4 sockets are listed.

## JSON

`reachmap scan --json` prints the same findings as JSON for scripts, with the
same exit status. See [JSON output](json.md).

## Exit status

| Status | Meaning |
|--------|---------|
| 0 | The scan finished without warnings (also when nothing is listening). |
| 1 | The scan finished with warnings under the table (see [Docker and UFW](docker-and-ufw.md#what-reachmap-reports) and [Tailscale](#tailscale)), or it failed and printed the reason on stderr. |
| 2 | Invalid arguments. |
