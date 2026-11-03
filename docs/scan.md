# reachmap scan

`reachmap scan` lists every TCP socket on this host that is waiting for
connections (the LISTEN state), sorted by port.

```
$ reachmap scan
PORT  PROTO  ADDRESS
22    tcp    0.0.0.0
22    tcp6   ::
53    tcp    127.0.0.53
631   tcp6   ::1
3306  tcp    127.0.0.1
8080  tcp    192.168.0.87
```

## Columns

| Column  | Meaning |
|---------|---------|
| PORT    | The TCP port the service listens on. |
| PROTO   | `tcp` for IPv4, `tcp6` for IPv6. |
| ADDRESS | The local address the socket is bound to (see below). |

## Reading the address

The bind address is the first clue to who can connect:

| Address | Bound to |
|---------|----------|
| `0.0.0.0`, `::` | every interface: loopback, LAN, VPN, Docker bridges |
| `127.0.0.1`, `::1`, `127.0.0.53` | loopback only: this host |
| a specific address, e.g. `192.168.0.87` | that interface only |
| `::ffff:a.b.c.d` | an IPv4 address seen through an IPv6 socket |

A `tcp6` socket bound to `::` usually accepts IPv4 connections as well (unless
the kernel setting `net.ipv6.bindv6only` is on), even though it is listed only
once, as `tcp6`. Services such as sshd open one socket per protocol, so their
port appears as both `tcp` and `tcp6`.

The address alone does not tell you whether a firewall lets traffic through.
Later versions of reachmap combine it with interfaces, Docker and UFW facts
into a verdict.

## Requirements and limits

- **Linux only for now.** On other systems `scan` prints
  `reachmap scan is Linux only for now` and exits with status 1.
- **No root needed.** The data comes from `/proc/net/tcp` and `/proc/net/tcp6`,
  which every user can read.
- **One network namespace.** `scan` sees the sockets of the namespace it runs
  in. Docker containers on their own network have separate sockets; ports
  that Docker publishes show up through `docker-proxy` on the host. Container
  details arrive in a later version.
- **TCP only.** UDP is planned for v0.2.
- When IPv6 is disabled in the kernel, `/proc/net/tcp6` does not exist and
  only IPv4 sockets are listed.

## Exit status

| Status | Meaning |
|--------|---------|
| 0 | The scan finished (also when nothing is listening). |
| 1 | The scan failed; the reason is printed on stderr. |
| 2 | Invalid arguments. |
