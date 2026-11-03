# reachmap scan

`reachmap scan` lists every TCP socket on this host that is waiting for
connections (the LISTEN state), sorted by port, with the program behind it and
the networks it can be reached from.

```
$ sudo reachmap scan
PORT  PROTO  ADDRESS          SERVICE                REACHABLE FROM                   WHY
22    tcp    0.0.0.0          sshd (812)             this host, Docker, tailnet, LAN  all IPv4 addresses (bound device not checked)
22    tcp6   ::               sshd (812)             this host, Docker, tailnet, LAN  all IPv6 and IPv4 addresses (IPv6-only and bound device not checked)
53    tcp    127.0.0.53       systemd-resolve (640)  this host                        loopback address
631   tcp6   ::1              cupsd (1033)           this host                        loopback address
3306  tcp    127.0.0.1        mysqld (1201)          this host                        loopback address
8080  tcp    192.168.1.20     python3 (4410)         LAN                              only on enp1s0
9100  tcp    100.101.102.103  node_exporter (902)    tailnet                          only on tailscale0
```

## Columns

| Column  | Meaning |
|---------|---------|
| PORT    | The TCP port the service listens on. |
| PROTO   | `tcp` for IPv4, `tcp6` for IPv6. |
| ADDRESS | The local address the socket is bound to (see below). |
| SERVICE | The program that has the socket open, as `name (pid)` (see below). |
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
| `this host` | loopback addresses (`127.0.0.0/8`, `::1`) and anything on `lo` |
| `Docker` | addresses on Docker's interfaces: `docker0`, `br-<12 hex digits>` (one per user-defined network) and `veth*` (container links) |
| `tailnet` | Tailscale addresses (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) and anything on `tailscale0` |
| `LAN` | other private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) and link-local ones (`169.254.0.0/16`, `fe80::/10`) |
| `internet (if not filtered upstream)` | every other address: a public IPv4 or IPv6 address |

The rules are checked in that order, so `172.18.0.1` on a Docker bridge is
`Docker`, not `LAN`.

A socket is reachable from the networks of the addresses it accepts
connections on:

| WHY | Meaning |
|-----|---------|
| `loopback address` | Bound to `127.0.0.1`, `::1` or another loopback address: only programs on this host can connect. Needs no interface facts. |
| `only on enp1s0` | Bound to one address; the interface that has it decides the network. |
| `all IPv4 addresses (bound device not checked)` | Bound to `0.0.0.0`: every network with an IPv4 address on this host. |
| `all IPv6 and IPv4 addresses (IPv6-only and bound device not checked)` | Bound to `::`: every network with any address on this host. |
| `no interface has this address` | Bound to an address that no interface has (for example, an interface that went away). REACHABLE FROM is `unknown`. |
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

**Not yet a firewall verdict.** REACHABLE FROM says who could connect if no
firewall interferes. UFW and Docker's published ports are checked in later
versions.

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
| `unknown (run with sudo for details)` | Some processes belong to other users and could not be inspected; run `sudo reachmap scan` to see them. |
| `unknown` | No visible process holds the socket. This happens for sockets the kernel opens itself (for example NFS), for a process that exited during the scan, and for processes hidden by `hidepid` (see below). |

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
  in. Docker containers on their own network have separate sockets; ports
  that Docker publishes show up through `docker-proxy` on the host. Container
  details arrive in a later version.
- **Interfaces need `ip`.** The interface list comes from `ip -j addr`
  (package `iproute2`, installed on nearly every Linux distribution). Without
  it, the scan still lists every socket, prints a warning, and shows
  REACHABLE FROM as `unknown` for all but loopback addresses.
- **TCP only.** UDP is planned for v0.2.
- When IPv6 is disabled in the kernel, `/proc/net/tcp6` does not exist and
  only IPv4 sockets are listed.

## Exit status

| Status | Meaning |
|--------|---------|
| 0 | The scan finished (also when nothing is listening). |
| 1 | The scan failed; the reason is printed on stderr. |
| 2 | Invalid arguments. |
