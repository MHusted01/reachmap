# reachmap scan

On Linux, `reachmap scan` lists every TCP socket on this host that is waiting for
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

## macOS

Run `reachmap scan` to list IPv4 and IPv6 TCP listeners and UDP sockets bound
to receive from any peer. Each row includes the bind address, port and process
name and PID. The scan uses the bundled `/usr/sbin/lsof`, so the inventory is
limited to processes it can inspect. Running with `sudo` may make more sockets
visible. Compare saved scans taken with the same privileges because a missing
row can reflect a change in visibility.

If lsof reports an incomplete inventory with usable records, the scan displays
those rows with a diagnostic. IPv6 scopes distinguish sockets during collection.
Two sockets on different scopes may display the same IP address.

Loopback binds show `this host`. For other binds the scan shows the address
and reports remote reachability as unknown. The application firewall's global
setting appears below the table as enabled, disabled or unknown. App-specific
rules, pf, Docker publishes and Tailscale shares are outside the macOS scan
scope.

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
| `broadcast address of enp1s0` | Bound to the broadcast address of a subnet, as Samba's `nmbd` does. The socket receives what is broadcast there, not what is sent to this host's own address. REACHABLE FROM is the network of that interface. A TCP socket can bind such an address, but no client can connect to it; reachmap reports it the same way, so the row can show more reach than there is. Reachmap recognizes the address configured with `brd` and the usual broadcast address derived from the subnet prefix. It computes the usual address for IPv4 prefixes shorter than `/31`. |
| `limited broadcast address, every IPv4 interface` | Bound to `255.255.255.255`, which belongs to no interface. The socket receives what is broadcast on any link, so REACHABLE FROM is every network with an IPv4 address on this host, as for `0.0.0.0`. No router forwards such a broadcast, so only devices on the same link can send it, and the row can show more reach than there is, such as `internet` for an interface with a public address. A link whose interface has no IPv4 address can send it too, but has no network to show. A TCP socket can bind the address, but no client can connect to it. A socket bound to a device shows `only on <device>`. |
| `all IPv4 addresses` | Bound to `0.0.0.0`: every network with an IPv4 address on this host. |
| `all IPv6 and IPv4 addresses` | Bound to `::`: every network with any address on this host. |
| `all IPv6 addresses` | Bound to `::` with the IPv6-only option: every network with an IPv6 address on this host. |
| `all IPv4 addresses (bound device not checked)` | Like `all IPv4 addresses`, but the socket's options are unknown (see below). |
| `all IPv6 and IPv4 addresses (IPv6-only and bound device not checked)` | Like `all IPv6 and IPv4 addresses`, but the socket's options are unknown (see below). |
| `no interface has this address` | Bound to an address that no interface has (for example, an interface that went away). REACHABLE FROM is `unknown`. |
| `multicast address, group membership not checked` | A UDP socket bound to a multicast group, such as `239.255.255.250`. It receives what is sent to the group, and reachmap does not read which groups this host joined. REACHABLE FROM is `unknown`. Needs no interface facts. |
| `no interface has an IPv4 address` | Bound to `0.0.0.0` on a host without IPv4 addresses (or an IPv6-only `::` on a host without IPv6 addresses, or `::` on a host without any). REACHABLE FROM is `unknown`. |
| `bound to eth1, which has no address it can use` | Bound to a device without a suitable address, such as a VRF device whose addresses are on other interfaces. REACHABLE FROM is `unknown`. |
| `...; shared by Tailscale Funnel on 443` | Tailscale forwards connections to this socket (see [Tailscale](#tailscale)). The first part is the socket's own reason. |
| `accepted by Tailscale Funnel; no listening port behind it` | Tailscale shares the port, and it forwards to no port with a row (see [Tailscale](#tailscale)). |
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

REACHABLE FROM estimates who could connect before firewall filtering. The
[nftables input check](#nftables-input) describes one part of that filtering.
Docker publishes also get the [UFW bypass warning](docker-and-ufw.md#what-reachmap-reports)
when applicable.

## nftables input

The scan reads `nft -j list ruleset` from a standard system path. Reading the
ruleset usually needs root or `CAP_NET_ADMIN`. The output below the table shows
what the input chains do with packets for each native TCP or UDP socket port,
bind address, IP family and incoming interface. For example, a port might show
`eth0 accept (all applicable input chains accept)` or
`lo drop (chain policy in inet filter input)`. Each socket is checked
only on the interfaces it can receive on: a socket bound to a loopback address
on `lo`, one bound to a host address on the interface that has it, and a
wildcard such as `0.0.0.0` on every interface with an address of that family.
A socket bound to an address no interface has is not checked.

For IPv4 and IPv6, reachmap checks active base chains at the `input` hook in
the applicable `ip`, `ip6` and `inet` tables, from lowest to highest priority
value. It checks filter chains and skips `counter` and `log` statements.

- TCP and UDP `dport` support numbers, inclusive ranges, anonymous sets and named
  `inet_service` sets. `!=` negates membership and still checks the protocol.
- `iifname` supports exact names, anonymous sets and named `ifname` sets, with
  equality or `!=`. Wildcard names stay `unknown`.
- `meta l4proto` matches TCP and UDP by name or protocol number. `th dport`
  reads the destination port of the TCP or UDP socket being checked.

Named sets come from the same family and table as the rule. Missing sets,
unsupported element types and timed sets can produce `unknown`. nft can print
a named interface set and a quoted interface name like `"@ingress"` as the same
JSON string. If those two interpretations disagree, the verdict is `unknown`.
Conditions on source addresses, connection state and marks are also unsupported.

A `jump` into a regular chain resumes after the jump if that chain returns
explicitly or reaches its end. A `goto` skips the rest of the current chain.
When execution returns with no pending jump, the check uses the base chain's
policy. Missing or recursive targets, more than 32 nested chain transfers, or
more than 4,096 rules visited for a packet produce `unknown`.

Every applicable base chain must accept for the result to be `accept`. A drop
or supported reject ends the check if the chain is guaranteed to run. An earlier
known mismatch skips the rule. Reaching an unsupported statement, unsupported
chain type or missing chain data can make the result `unknown`. Chains with the
same priority can run in either order, so an unknown in that group takes
precedence over a drop in the same group. Drop and chain-specific unknown reasons
include the family, table and chain. The socket findings are informational.

Each check assumes a packet arrives at the input hook on the listed interface.
Other hooks, upstream filters, routing and whether the socket would receive the
packet are outside this check. It covers native host sockets. Docker publishes
have their own [IPv6 evidence](#ipv6-docker-publishes). A dual-stack socket
bound to `::` gets one line for each family. An IPv4-mapped address is checked
for IPv4.
When the scan could not read whether a socket is IPv6-only, it assumes the
widest case, as the rest of the scan does. With no host socket ports, the output
says so. If `nft` fails to run, the reason says reading the ruleset usually
needs root or `CAP_NET_ADMIN`.

## Host-input evidence snapshots

Capture the inputs to the Linux [nftables input check](#nftables-input) and
replay the verdicts and reasons later. The shell creates the file. Use a
private directory and restrict permissions because the snapshot contains
details about the host's network and firewall.

```sh
(umask 077; sudo reachmap scan --snapshot --host-ref example-host > host-input.json)
reachmap replay host-input.json
reachmap replay host-input.json --json
```

`--host-ref` is a label you choose to recognise the capture. Its accuracy
depends on the person taking the snapshot. The timestamp records when the scan
started, in Unix seconds. Collectors run in sequence, so interfaces, sockets
and rules can change while a capture is in progress.

Version 1 records the scope `linux_host_input` for the native TCP and UDP socket
input check in the scan's network namespace. It records the bind addresses,
ports, protocols, packet IP families and interface names the evaluator uses,
plus the JSON returned by `nft -j list ruleset` when available. Docker inventory
status is included because the scan uses it to exclude Docker publishes from
the native socket check. The separate IPv6 Docker publish findings, forwarding,
routing and other hooks are outside the replay scope.

The snapshot records which collectors succeeded, failed or were unavailable.
An empty ruleset indicates a successful read with no rules. A socket options
collector that failed after reporting some options is marked `partial`. Replay
uses the same socket targets selected during capture, including the live scan's
fallback when socket options are missing. JSON replay emits the same finding
shape as the `nftables` object in a scan report.

Treat snapshots as sensitive. The full ruleset may reveal internal addresses,
networks, comments and firewall configuration outside the input check. The
scope and host label are supplied as part of the file. A file can be edited,
and a replay describes the evidence in that file. Share the smallest output
that serves your purpose, such as the replay findings when the ruleset itself
is unnecessary.

Replay works offline on Linux and macOS. It accepts regular JSON files up to
64 MiB and reports invalid data or an unsupported version with exit status 1.
Successful capture or replay exits with 0, including when optional evidence is
missing and the input verdict is `unknown`.

Keep using `reachmap scan --json` for `probe --scan` and `diff`. The scan report
has its own `schema_version`. Evidence snapshots use `snapshot_version` and
are read by `reachmap replay`.

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

reachmap reads the running containers through the Docker Engine API over
`/var/run/docker.sock`. It matches their published TCP and UDP ports to sockets
on this host by protocol, address and port. A matching row shows the container
name and its Compose service when available. You can scan without root if
your account can connect to the socket. The Docker CLI is optional.
If a container disappears during the Docker read, the scan still reports the
other containers.

A socket on `::` counts as serving a port published on `0.0.0.0`, as it usually
accepts IPv4 too. An IPv6-only socket does not, so it keeps its own process and
the `0.0.0.0` row stays. If the socket's options are unknown it counts as
serving the port; its row then lists IPv4 networks, so reach is not understated.

A published port that no socket listens on still gets a row, marked in WHY,
with the verdict for the published address. A Docker `::` binding without a
socket covers IPv6 addresses. Docker reports any IPv4 binding separately.
A port that is only exposed (`EXPOSE`, or `expose:` in Compose) is not
reachable from the host's networks
and gets no row. Containers on the host network (`network_mode: host`) publish
nothing: their sockets show up as ordinary processes.

When Docker cannot be asked, the scan continues and prints one `note:` on
stderr. Sockets of published ports then show `docker-proxy`, `dockerd` or
`unknown`, and ports without a socket are missing:

| Note | Meaning |
|------|---------|
| `Docker was not found` | The default socket is missing and no Docker daemon executable was found in the standard installation paths. |
| `could not ask Docker for its containers` | The note gives the reason, such as an inaccessible socket or the Docker collection exceeding its 5-second deadline. A socket permission error includes a hint to use `sudo`. |
| `could not understand Docker's output` | The API response could not be read. A hint says where to report it. |

Set `DOCKER_HOST` to an absolute Unix endpoint such as
`unix:///run/user/1000/docker.sock` to use another local socket. Reachmap ignores
Docker contexts and accepts only Unix endpoints.

### IPv6 Docker publishes

The **Docker publishes** section lists each address, port, protocol and
container that Docker reports. A dual-stack publish can show both `0.0.0.0`
and `::` even when the main table has one row for the socket.

- **IPv4 only** means reachmap can evaluate the active IPv4 input chains
  for this binding's protocol, port and interfaces, and the ruleset has no
  active `ip6` or `inet` input chain. The scan emits a warning for affected
  bindings outside loopback and exits with status 1.
  Loopback bindings show the same evidence as an informational finding.
- **IPv6 evidence** means reachmap can evaluate the applicable `ip6` and
  `inet` input chains for the binding's protocol, port and interfaces. Either
  an accept or a drop decision counts as evidence.
- **Unknown** is informational and includes the reason, such as missing
  privileges, no applicable chain, an unsupported rule or missing interface
  addresses.

These findings describe the nftables host input hook. Effective Docker
reachability depends on the packet path, including routing, NAT and forwarding
rules.

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

A shared port that forwards to no row gets a row of its own, on each Tailscale
address of this host. That is a port serving a file, a text or a redirect, or
one that forwards to a Unix socket, another machine or a program that is not
running. SERVICE says `Tailscale`, and REACHABLE FROM is `tailnet`, with Funnel
also `internet (if not filtered upstream)`:

```text
PORT  PROTO  ADDRESS     SERVICE    REACHABLE FROM  WHY
8443  tcp    100.64.0.1  Tailscale  tailnet         accepted by Tailscale Serve; no listening port behind it
```

Such a row stands beside a socket on the same address and port, because the
share can reach further than the socket.

Every Funnel port is a warning under the table, so the scan exits with 1, also
when you share the port on purpose. Serve alone is no warning.

- **No `tailscale` command.** Nothing is reported, as a host without it shares
  nothing.
- **`tailscale` fails.** For example when `tailscaled` is stopped. The scan
  continues with a note on stderr and a warning that it is unknown what is
  shared, so it exits with 1. Rows keep the reach of their socket.
- **No Tailscale address is known.** A shared port with no row behind it needs
  an address to show on. Without one, for example when the interfaces could not
  be listed or Tailscale runs without `tailscale0`, a warning names the ports
  shared with the tailnet, so the scan exits with 1. Funnel ports are in their
  own warning.
- **A host name counts as nothing behind it.** A target with a host name other
  than `localhost` has no address to match, so the shared port gets its own row
  even if that name is this host.
- **A port that forwards to a row has no row itself.** The row it forwards to
  shows the reach, and WHY names the port clients connect to.
- **A Tailscale Service has its own address.** The serve config names no
  address, so its ports show on this host's Tailscale addresses, which can list
  more than clients really use.
- **Funnel counts per port.** When one port is shared under two names, or by a
  Tailscale Service as well, and Funnel is on for one of them, all of them
  count as Funnel.
- **Tailscale in a container is not seen.** reachmap asks the `tailscale`
  command on this host. Tailscale Services in `Tun` mode forward no port that
  reachmap can name, so they do not show either.

## Requirements and limits

- **Linux and macOS.** On other systems `scan` exits with status 1 and lists
  the supported platforms. The remaining requirements below are for Linux.
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
| 1 | The scan finished with warnings under the table (see [Docker and UFW](docker-and-ufw.md#what-reachmap-reports), [IPv6 Docker publishes](#ipv6-docker-publishes) and [Tailscale](#tailscale)), or it failed and printed the reason on stderr. |
| 2 | Invalid arguments. |
